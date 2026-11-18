package nginx

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/rom/qnginxscanner/internal/probe"
)

// Probe definitions. The scanner issues these and hands the responses back to
// Analyze. Keeping the catalogue here lets the detection logic and the scanner
// agree on what is collected. Every probe is a read-only request; none submit
// data or attempt exploitation.

// NotFoundPath is a guaranteed-missing path: the reply is the server's own
// 404 page (nginx's default error page identifies it, and leaks the version
// when server_tokens is on) and doubles as the soft-404 baseline.
const NotFoundPath = "/qnginxscanner_probe_404"

// StatusProbePaths are read-only endpoints where nginx commonly exposes its
// status (stub_status, the NGINX Plus API, nginx-module-vts). Deep mode.
func StatusProbePaths() []string {
	return []string{
		"/nginx_status",
		"/stub_status",
		"/basic_status",
		"/nginx-status",
		"/status",
		"/server-status",
		"/api/",
		"/status/format/json",
	}
}

// PlusAPIFollowUp inspects a /api/ response and, when it is the NGINX Plus API
// version list, returns the path that reports the nginx version and build.
func PlusAPIFollowUp(resp *probe.Response) string {
	if resp == nil || resp.Err != "" || resp.Status != 200 {
		return ""
	}
	body := strings.TrimSpace(resp.BodyString())
	if !rePlusAPIRoot.MatchString(body) {
		return ""
	}
	nums := strings.Split(strings.Trim(body, "[] \r\n\t"), ",")
	last := strings.TrimSpace(nums[len(nums)-1])
	if _, err := strconv.Atoi(last); err != nil {
		return ""
	}
	return "/api/" + last + "/nginx"
}

// CRLFProbePath requests a path whose decoded form ends in CR LF plus a header
// line. A server that copies the decoded URI into a response header (the
// classic `return 301 https://$host$uri;`) echoes CRLFProbeHeader back as a
// real header. The probe is a harmless GET that only affects its own reply.
const (
	CRLFProbePath   = "/%0D%0AX-Qnginxscanner-Probe:%20crlf"
	CRLFProbeHeader = "X-Qnginxscanner-Probe"
)

// RawProbe is a hand-built HTTP/1.x request for probe.Fetcher.Raw.
type RawProbe struct {
	Name    string
	Payload []byte
	// Cleartext sends the payload without TLS even though the port speaks TLS.
	Cleartext bool
}

// RawProbes returns the raw-request fingerprint probes for a service.
//
//	no-host         HTTP/1.1 without a Host header: the server itself must
//	                answer 400, so the reply is the front server's own error
//	                page even when every normal request is proxied elsewhere.
//	plain-on-tls    cleartext HTTP to a TLS port: nginx answers with its
//	                distinctive "plain HTTP request was sent to HTTPS port".
//	unknown-method  (deep) an unknown method: nginx's static handler replies
//	                "405 Not Allowed".
//	long-uri        (deep) a request line above nginx's default 8k header
//	                buffer: "414 Request-URI Too Large".
func RawProbes(hostHeader, userAgent string, tls, deep bool) []RawProbe {
	common := "User-Agent: " + userAgent + "\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	withHost := "Host: " + hostHeader + "\r\n" + common
	probes := []RawProbe{
		{Name: "no-host", Payload: []byte("GET / HTTP/1.1\r\n" + common)},
	}
	if tls {
		probes = append(probes, RawProbe{Name: "plain-on-tls", Cleartext: true, Payload: []byte("GET / HTTP/1.1\r\n" + withHost)})
	}
	if deep {
		probes = append(probes,
			RawProbe{Name: "unknown-method", Payload: []byte("QNGX / HTTP/1.1\r\n" + withHost)},
			RawProbe{Name: "long-uri", Payload: []byte("GET /" + strings.Repeat("a", 9000) + " HTTP/1.1\r\n" + withHost)},
		)
	}
	return probes
}

// AliasCandidate describes one off-by-slash alias-traversal check: a public
// static asset, the same asset re-requested through "<segment>../<segment>/",
// and a control that must NOT resolve.
type AliasCandidate struct {
	Segment   string
	Original  string // e.g. /static/app.css
	Traversed string // e.g. /static../static/app.css
	Control   string // e.g. /static../qnginxscanner-nx/app.css
}

// AliasProbe is an AliasCandidate with its three responses.
type AliasProbe struct {
	Candidate AliasCandidate
	Original  *probe.Response
	Traversed *probe.Response
	Control   *probe.Response
}

var reAssetRef = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"'#?\s]+\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|map|webp))(?:\?[^"']*)?["']`)

// maxAliasCandidates bounds the alias checks issued per service.
const maxAliasCandidates = 3

// AliasCandidates extracts same-origin static asset paths from an HTML page
// and builds one traversal check per distinct first path segment.
//
// The misconfiguration is `location /static { alias /srv/app/static/; }` (no
// trailing slash on the location): "/static../" then maps to the parent of the
// alias target. When that parent contains a directory with the segment's own
// name — the common layout — "/static../static/<file>" returns the very same
// public file, which proves the traversal without reading anything private.
func AliasCandidates(pageURL, body string) []AliasCandidate {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	var out []AliasCandidate
	seen := map[string]bool{}
	for _, m := range reAssetRef.FindAllStringSubmatch(body, 200) {
		ref, err := url.Parse(m[1])
		if err != nil {
			continue
		}
		u := base.ResolveReference(ref)
		if !strings.EqualFold(u.Host, base.Host) {
			continue
		}
		p := u.EscapedPath()
		parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(parts[0], ".") || strings.Contains(p, "..") {
			continue
		}
		seg := parts[0]
		if seen[seg] {
			continue
		}
		seen[seg] = true
		out = append(out, AliasCandidate{
			Segment:   seg,
			Original:  "/" + seg + "/" + parts[1],
			Traversed: "/" + seg + "../" + seg + "/" + parts[1],
			Control:   "/" + seg + "../qnginxscanner-nx/" + parts[1],
		})
		if len(out) >= maxAliasCandidates {
			break
		}
	}
	return out
}
