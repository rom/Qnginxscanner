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
		"/metrics",
	}
}

// SensitiveFile is a file that nginx serves like any other static file unless
// the configuration denies it — unlike Apache, nginx has no built-in rule for
// dotfiles or .ht* files. Match validates the content so a soft-404 or a
// catch-all page is never reported.
type SensitiveFile struct {
	ID          string
	Path        string
	Severity    string
	Title       string
	Detail      string
	Remediation string
	Match       *regexp.Regexp
}

const denyDotfiles = "Deny hidden files: location ~ /\\.(?!well-known) { deny all; } — and keep such files out of the web root."

// SensitiveFiles are the exposure checks issued in deep mode. Each is a single
// GET; only the fact of exposure is reported, never the file's content.
func SensitiveFiles() []SensitiveFile {
	return []SensitiveFile{
		{
			ID: "git-exposed", Path: "/.git/HEAD", Severity: "high",
			Title:       "Git repository is exposed (/.git/)",
			Detail:      "/.git/HEAD is served, so the repository — source code, history and any committed secrets — can be downloaded.",
			Remediation: denyDotfiles,
			Match:       regexp.MustCompile(`^(?:ref: refs/[\w./-]+|[0-9a-f]{40})\s*$`),
		},
		{
			ID: "htpasswd-exposed", Path: "/.htpasswd", Severity: "high",
			Title:       "Password file is exposed (/.htpasswd)",
			Detail:      "/.htpasswd is served: user names and password hashes can be downloaded and cracked offline. nginx does not protect .ht* files by default.",
			Remediation: "Move the file outside the web root and deny it: location ~ /\\.ht { deny all; }",
			Match:       regexp.MustCompile(`(?m)^[^:\s<>]{1,64}:(?:\$apr1\$|\$2[aby]\$|\$[156]\$|\{SHA\}|\{SSHA\}|[A-Za-z0-9./]{13}\s*$)`),
		},
		{
			ID: "htaccess-exposed", Path: "/.htaccess", Severity: "low",
			Title:       "Apache .htaccess file is served (/.htaccess)",
			Detail:      "/.htaccess is served as a plain file. nginx ignores .htaccess, so any access rules in it are NOT enforced, and its contents (rewrite rules, protected paths) are disclosed.",
			Remediation: "Translate the rules into nginx configuration and deny the file: location ~ /\\.ht { deny all; }",
			Match:       regexp.MustCompile(`(?im)^\s*(?:RewriteEngine|RewriteRule|RewriteCond|AuthType|AuthUserFile|Require\s|Deny from|Order\s+(?:allow|deny)|Options\s+[-+]?\w|<IfModule|<Files|DirectoryIndex|ErrorDocument)\b`),
		},
		{
			ID: "env-exposed", Path: "/.env", Severity: "high",
			Title:       "Environment file is exposed (/.env)",
			Detail:      "/.env is served; such files usually hold database passwords, API keys and application secrets.",
			Remediation: denyDotfiles,
			Match:       regexp.MustCompile(`(?m)\A(?:\s*#[^\n]*\n|\s*\n)*(?:export\s+)?[A-Z][A-Z0-9_]{1,63}=[^\n<]*(?:\n|\z)`),
		},
		{
			ID: "nginx-conf-exposed", Path: "/nginx.conf", Severity: "medium",
			Title:       "nginx configuration is served (/nginx.conf)",
			Detail:      "/nginx.conf is served, disclosing the server's configuration (upstreams, internal paths, access rules). This usually means the web root points at the nginx configuration directory.",
			Remediation: "Point root at the site's document directory, not at /etc/nginx or the nginx prefix.",
			Match:       regexp.MustCompile(`(?s)\b(?:worker_processes|events\s*\{).*\bhttp\s*\{|\bhttp\s*\{.*\bserver\s*\{`),
		},
	}
}

// PathInfoSuffix is appended to a static asset to test the classic
// nginx + PHP-FPM misconfiguration (a "location ~ \.php$" block passing
// "/file.png/x.php" to PHP with cgi.fix_pathinfo enabled): PHP then runs the
// static file, which echoes it back verbatim as text/html.
const PathInfoSuffix = "/qnginxscanner.php"

// ForeignHost is the Host header of the "foreign-host" raw probe. A redirect
// whose Location carries it back shows the server builds redirects from the
// client-supplied Host ($host / $http_host).
const ForeignHost = "qnginxscanner-probe.invalid"

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
//	foreign-host    (deep) a request for an unknown Host: shows whether
//	                redirects are built from the client-supplied Host.
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
			RawProbe{Name: "foreign-host", Payload: []byte("GET / HTTP/1.1\r\nHost: " + ForeignHost + "\r\n" + common)},
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
	// PathInfo is the asset re-requested with PathInfoSuffix appended.
	PathInfo *probe.Response
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
