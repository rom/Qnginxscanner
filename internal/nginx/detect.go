package nginx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/qnginxscanner/internal/probe"
)

// Input bundles everything Analyze needs about one service.
type Input struct {
	// TargetURL is the primary scheme://host:port/path that was requested.
	TargetURL string
	// Deep enables version/branch/module fingerprinting, misconfiguration
	// findings and vulnerability correlation. When false, Analyze stops at the
	// nginx yes/no verdict.
	Deep bool
	// Root is the response to the primary request. Required for HTTP services.
	Root *probe.Response
	// NotFound is the response to a guaranteed-missing path (NotFoundPath).
	NotFound *probe.Response
	// Extra holds deep-mode probe responses keyed by requested URL (an
	// "OPTIONS " prefix marks a non-GET probe).
	Extra map[string]*probe.Response
	// Raw holds the replies to the hand-built fingerprint requests.
	Raw []*probe.RawResponse
	// H2 is the HTTP/2 connection-preface fingerprint (deep mode).
	H2 *probe.H2Fingerprint
	// Alias holds the off-by-slash alias traversal checks (deep mode).
	Alias []AliasProbe
	// CRLF is the response to CRLFProbePath (deep mode).
	CRLF *probe.Response
	// Banner is the greeting of a non-HTTP service (nginx mail proxy check).
	Banner string
	// Catalog supplies vulnerability/support data. When nil, the built-in
	// default catalogue is used.
	Catalog *Catalog
}

const maxDataLen = 200

// variantRank orders how specific a product identification is, so a precise
// one (NGINX Plus from its API) replaces a generic one (nginx from a banner).
func variantRank(v string) int {
	switch v {
	case "":
		return 0
	case "nginx":
		return 1
	case "NGINX Plus":
		return 3
	default:
		return 2
	}
}

// analysis is the mutable state of one Analyze run.
type analysis struct {
	d           *Detection
	seen        map[string]bool
	modSet      map[string]bool
	protoSet    map[string]bool
	obsSeen     map[string]bool
	findSeen    map[string]bool
	versionRank int
	h2Observed  bool
	h2Refused   bool
	h3Observed  bool
	mail        bool
}

func newAnalysis() *analysis {
	return &analysis{
		d: &Detection{}, seen: map[string]bool{}, modSet: map[string]bool{},
		protoSet: map[string]bool{}, obsSeen: map[string]bool{}, findSeen: map[string]bool{},
	}
}

func (a *analysis) addEv(ev Evidence) {
	// De-duplicate by signal: the same signal seen on several probes should
	// count and display only once.
	if a.seen[ev.Signal] {
		return
	}
	a.seen[ev.Signal] = true
	if len(ev.Data) > maxDataLen {
		ev.Data = ev.Data[:maxDataLen] + "…"
	}
	if ev.Confidence == "" {
		ev.Confidence = confidenceTier(ev.Weight)
	}
	if ev.Probe == "" {
		ev.Probe = ev.Source
	}
	if ev.Where == "" || ev.How == "" {
		w, h := provenanceDefaults(ev.Signal)
		if ev.Where == "" {
			ev.Where = w
		}
		if ev.How == "" {
			ev.How = h
		}
	}
	if ev.Snippet == "" && ev.Data != "" {
		ev.Snippet = ev.Data
	}
	a.d.Evidence = append(a.d.Evidence, ev)
	a.d.Confidence += ev.Weight
}

func (a *analysis) addMod(m string) {
	if m == "" || a.modSet[m] {
		return
	}
	a.modSet[m] = true
	a.d.Modules = append(a.d.Modules, m)
}

func (a *analysis) addProto(p string) {
	if p == "" || a.protoSet[p] {
		return
	}
	a.protoSet[p] = true
	a.d.Protocols = append(a.d.Protocols, p)
}

func (a *analysis) addFinding(f Finding) {
	if a.findSeen[f.ID] {
		return
	}
	a.findSeen[f.ID] = true
	a.d.Findings = append(a.d.Findings, f)
}

func (a *analysis) setVariant(v string) {
	if variantRank(v) > variantRank(a.d.Variant) {
		a.d.Variant = v
	}
}

// setVersion records a product version observation. product is the version as
// the product reports it; the nginx core version is derived from the variant.
func (a *analysis) setVersion(variant, product, source string, rank int) {
	if product == "" {
		return
	}
	core := coreVersion(variant, product)
	shown := product
	if core == "" {
		shown = variant + " " + product
	}
	if key := shown + "\x00" + source; !a.obsSeen[key] {
		a.obsSeen[key] = true
		a.d.VersionObservations = append(a.d.VersionObservations, VersionObservation{Version: shown, Source: source, Rank: rank})
	}
	if rank > a.versionRank {
		a.versionRank = rank
		a.d.Version = core
		a.d.VersionSource = source
		a.d.ProductVersion = ""
		if core != product {
			a.d.ProductVersion = product
		}
	}
}

// coreVersion maps a product version to the nginx core version advisories are
// keyed on, or "" when the product uses its own numbering.
func coreVersion(variant, product string) string {
	switch variant {
	case "nginx", "NGINX Plus":
		return product
	case "OpenResty":
		// OpenResty X.Y.Z.N bundles nginx core X.Y.Z.
		parts := strings.Split(product, ".")
		if len(parts) >= 3 {
			return strings.Join(parts[:3], ".")
		}
		return ""
	default:
		return ""
	}
}

func canonVariant(token string) string {
	switch strings.ToLower(token) {
	case "nginx":
		return "nginx"
	case "openresty":
		return "OpenResty"
	case "tengine":
		return "Tengine"
	case "angie":
		return "Angie"
	case "freenginx":
		return "freenginx"
	default:
		return token
	}
}

// Analyze turns collected responses into an nginx Detection.
func Analyze(in Input) *Detection {
	if in.Root == nil {
		if in.Banner != "" {
			return analyzeBanner(in)
		}
		return nil
	}
	a := newAnalysis()
	d := a.d

	// --- Primary response and the guaranteed-404 ----------------------------
	a.analyzeResponse(in.Root, in.TargetURL, "GET "+in.TargetURL)
	if nf := in.NotFound; nf != nil {
		a.analyzeResponse(nf, nf.RequestURL, "GET "+nf.RequestURL)
	}

	// --- Raw-request fingerprints -------------------------------------------
	for _, raw := range in.Raw {
		a.analyzeRaw(raw)
	}

	// --- HTTP/2 fingerprint -------------------------------------------------
	a.analyzeH2(in.H2, in.TargetURL)

	// --- Deep probes --------------------------------------------------------
	for u, resp := range in.Extra {
		if resp == nil || (resp.Err != "" && resp.Status == 0) {
			continue
		}
		method, plainURL := "GET", u
		if strings.HasPrefix(u, "OPTIONS ") {
			method, plainURL = "OPTIONS", strings.TrimPrefix(u, "OPTIONS ")
		}
		a.analyzeResponse(resp, plainURL, method+" "+plainURL)
		if method == "OPTIONS" {
			allow := strings.ToUpper(resp.HeaderGet("Allow"))
			if resp.HeaderGet("Dav") != "" || strings.Contains(allow, "PROPFIND") {
				a.addMod("http_dav")
			}
			continue
		}
		a.analyzeStatusEndpoint(resp, plainURL)
	}

	// --- Protocol facts -----------------------------------------------------
	a.collectProtocols(in)

	// --- Finalise the verdict -----------------------------------------------
	if d.Confidence > 100 {
		d.Confidence = 100
	}
	d.Verdict = scoreToVerdict(d.Confidence)
	d.IsNginx = d.Confidence >= 50
	if d.IsNginx && d.Variant == "" {
		d.Variant = "nginx"
	}
	if !d.IsNginx {
		// A version or variant without a positive verdict would mislead.
		d.Variant, d.Version, d.ProductVersion, d.VersionSource = "", "", "", ""
		d.VersionObservations = nil
	}
	d.VersionHidden = d.IsNginx && d.Version == "" && d.ProductVersion == ""
	d.VersionConflict = versionsConflict(d.VersionObservations)
	if d.Version != "" {
		d.Branch = BranchKind(d.Version)
	}

	if in.Deep && d.IsNginx {
		a.misconfigFindings(in)
		a.correlate(in.Catalog)
	}

	sort.Strings(d.Modules)
	sortEvidence(d.Evidence)
	sortFindings(d.Findings)
	return d
}

// analyzeBanner assesses a non-HTTP service from its greeting: nginx's mail
// proxy announces itself with fixed default banners.
func analyzeBanner(in Input) *Detection {
	a := newAnalysis()
	d := a.d
	banner := strings.TrimSpace(in.Banner)
	for _, sig := range mailBannerSigs {
		if sig.re.MatchString(banner) {
			a.mail = true
			a.addProto("mail (" + sig.proto + ")")
			a.addMod("mail")
			a.addEv(Evidence{
				Signal: "banner.mail-" + strings.ToLower(sig.proto), Source: in.TargetURL, Weight: sig.weight,
				Detail: "greeting matches the nginx mail proxy's default " + sig.proto + " banner",
				Data:   banner, Where: "service banner", How: "regular expression", Pattern: sig.re.String(),
			})
		}
	}
	d.Verdict = scoreToVerdict(d.Confidence)
	d.IsNginx = d.Confidence >= 50
	if d.IsNginx {
		d.Variant = "nginx"
		d.VersionHidden = true
		if in.Deep {
			a.correlate(in.Catalog)
		}
	}
	return d
}

// analyzeResponse extracts header, cookie and body evidence from one response.
func (a *analysis) analyzeResponse(resp *probe.Response, source, probeDesc string) {
	if resp == nil || (resp.Err != "" && resp.Status == 0) {
		return
	}
	add := func(ev Evidence) {
		if ev.Status == 0 {
			ev.Status = resp.Status
		}
		if ev.Source == "" {
			ev.Source = source
		}
		if ev.Probe == "" {
			ev.Probe = probeDesc
		}
		a.addEv(ev)
	}

	// Server banner(s). Every value is considered: a proxy chain may add more
	// than one.
	for _, val := range resp.HeaderValues("Server") {
		a.analyzeServerHeader(val, add)
	}

	// Other header signatures.
	for _, sig := range headerSigs {
		for _, val := range resp.HeaderValues(sig.header) {
			if sig.contains != "" && !containsFold(val, sig.contains) {
				continue
			}
			how := "header present"
			if sig.contains != "" {
				how = "header substring match"
			}
			add(Evidence{
				Signal: "header." + strings.ToLower(sig.header), Weight: sig.weight, Detail: sig.detail, Data: val,
				Where: "response header '" + sig.header + "'", How: how, Pattern: sig.contains,
				Snippet: sig.header + ": " + val,
			})
			a.setVariant(sig.variant)
			a.addMod(sig.module)
			break
		}
	}
	if m := reKong.FindStringSubmatch(resp.HeaderGet("Via")); m != nil {
		a.setVersion("Kong", m[1], "Via header", 1)
	}

	// HTTP/3 advertisement.
	for _, val := range resp.HeaderValues("Alt-Svc") {
		if reAltSvcH3.MatchString(val) {
			a.h3Observed = true
		}
	}
	if strings.HasPrefix(resp.Proto, "HTTP/2") || (resp.TLS != nil && resp.TLS.ALPN == "h2") {
		a.h2Observed = true
	}
	for _, up := range resp.HeaderValues("Upgrade") {
		if containsFold(up, "h2c") {
			a.h2Observed = true
		}
	}

	// Static-file ETag in nginx's hex(mtime)-hex(size) form.
	a.analyzeETag(resp, add)

	// Cookies.
	for _, c := range resp.Cookies {
		for _, sig := range cookieSigs {
			if c.Name == sig.name || (sig.prefix && strings.HasPrefix(c.Name, sig.name)) {
				add(Evidence{
					Signal: "cookie." + strings.ToLower(sig.name), Weight: sig.weight, Detail: sig.detail, Data: c.Name,
					Where: "Set-Cookie header", How: "cookie-name match", Pattern: sig.name,
					Snippet: "Set-Cookie: " + c.Name + "=…",
				})
				a.addMod(sig.module)
			}
		}
	}

	a.analyzeBody(resp.BodyString(), add)
}

// analyzeServerHeader interprets one Server header value.
func (a *analysis) analyzeServerHeader(val string, add func(Evidence)) {
	snippet := "Server: " + val
	if m := reServer.FindStringSubmatch(val); m != nil {
		variant := canonVariant(m[1])
		detail := "Server header identifies " + variant
		weight := 70
		add(Evidence{
			Signal: "header.server", Weight: weight, Detail: detail, Data: val,
			Where: "response header 'Server'", How: "banner match", Pattern: reServer.String(), Snippet: snippet,
		})
		a.setVariant(variant)
		a.setVersion(variant, m[2], "Server header", 2)
		if m[3] != "" && a.d.Distro == "" {
			a.d.Distro = strings.TrimSpace(m[3])
		}
		if variant == "OpenResty" {
			a.addMod("lua (OpenResty)")
		}
		return
	}
	if m := reKong.FindStringSubmatch(val); m != nil {
		add(Evidence{
			Signal: "header.server-kong", Weight: 60, Detail: "Server header identifies Kong (built on OpenResty/nginx)", Data: val,
			Where: "response header 'Server'", How: "banner match", Pattern: reKong.String(), Snippet: snippet,
		})
		a.setVariant("Kong")
		a.setVersion("Kong", m[1], "Server header", 2)
		return
	}
	if m := reAPISIX.FindStringSubmatch(val); m != nil {
		add(Evidence{
			Signal: "header.server-apisix", Weight: 60, Detail: "Server header identifies Apache APISIX (built on OpenResty/nginx)", Data: val,
			Where: "response header 'Server'", How: "banner match", Pattern: reAPISIX.String(), Snippet: snippet,
		})
		a.setVariant("Apache APISIX")
		a.setVersion("Apache APISIX", m[1], "Server header", 2)
		return
	}
	if m := reServerLoose.FindStringSubmatch(val); m != nil {
		add(Evidence{
			Signal: "header.server-custom", Weight: 55, Detail: "customised Server banner names " + canonVariant(m[1]), Data: val,
			Where: "response header 'Server'", How: "banner token match", Pattern: reServerLoose.String(), Snippet: snippet,
		})
		a.setVariant(canonVariant(m[1]))
	}
}

// analyzeETag recognises nginx's static-file ETag, "hex(mtime)-hex(size)",
// verified against Last-Modified (and Content-Length when it is comparable).
// Apache's default ETag puts the size first and the mtime in microseconds, so
// a verified match is specific.
func (a *analysis) analyzeETag(resp *probe.Response, add func(Evidence)) {
	etag := resp.HeaderGet("ETag")
	m := reETag.FindStringSubmatch(etag)
	if m == nil {
		return
	}
	lm, err := http.ParseTime(resp.HeaderGet("Last-Modified"))
	if err != nil {
		return
	}
	mtime, err := strconv.ParseInt(m[2], 16, 64)
	if err != nil || mtime != lm.Unix() {
		return
	}
	weight, detail := 35, "ETag is hex(Last-Modified) + '-' + hex(size): nginx's static-file ETag format"
	if size, err := strconv.ParseInt(m[3], 16, 64); err == nil && m[1] == "" {
		if cl, err := strconv.ParseInt(resp.HeaderGet("Content-Length"), 10, 64); err == nil && cl == size {
			weight, detail = 40, "ETag is hex(Last-Modified) + '-' + hex(Content-Length): nginx's static-file ETag format"
		}
	}
	add(Evidence{
		Signal: "header.etag-format", Weight: weight, Detail: detail, Data: etag,
		Where: "response headers 'ETag' / 'Last-Modified'", How: "computed ETag comparison",
		Pattern: reETag.String(), Snippet: "ETag: " + etag + " · Last-Modified: " + resp.HeaderGet("Last-Modified"),
	})
}

// analyzeBody applies the body signatures and the error-page template check.
func (a *analysis) analyzeBody(body string, add func(Evidence)) {
	if body == "" {
		return
	}
	if m := reErrorPage.FindStringSubmatch(body); m != nil && m[1] == m[2] {
		footer := strings.TrimSpace(m[4])
		if fm := reFooterProduct.FindStringSubmatch(footer); fm != nil {
			variant := canonVariant(fm[1])
			add(Evidence{
				Signal: "body.error-page", Weight: 70,
				Detail: "built-in " + variant + " error page (exact structure, footer names the server)",
				Data:   collapseWS(m[0]), Where: "response body", How: "error-page template match",
				Pattern: "<hr><center>" + footer + "</center>", Snippet: collapseWS(m[0]), Line: 1,
			})
			a.setVariant(variant)
			a.setVersion(variant, fm[2], "error page footer", 2)
			if fm[3] != "" && a.d.Distro == "" {
				a.d.Distro = strings.TrimSpace(fm[3])
			}
			if variant == "OpenResty" {
				a.addMod("lua (OpenResty)")
			}
		} else {
			add(Evidence{
				Signal: "body.error-page-template", Weight: 45,
				Detail: "error page has nginx's exact built-in structure with a customised footer (" + strconv.Quote(footer) + ")",
				Data:   collapseWS(m[0]), Where: "response body", How: "error-page template match",
				Pattern: reErrorPage.String(), Snippet: collapseWS(m[0]), Line: 1,
			})
		}
	}
	for _, sig := range bodySigs {
		if loc := sig.re.FindStringIndex(body); loc != nil {
			snippet, line := bodyContext(body, loc[0], loc[1])
			add(Evidence{
				Signal: sig.id, Weight: sig.weight, Detail: sig.detail, Data: collapseWS(body[loc[0]:loc[1]]),
				Where: "response body", How: "regular expression", Pattern: sig.re.String(), Snippet: snippet, Line: line,
			})
			a.setVariant(sig.variant)
			a.addMod(sig.module)
		}
	}
}

// analyzeRaw interprets the reply to a hand-built request: beyond the usual
// header/body signals it sees what net/http hides — the header order and the
// exact reason phrase.
func (a *analysis) analyzeRaw(raw *probe.RawResponse) {
	if raw == nil || raw.Err != "" {
		return
	}
	source := "raw:" + raw.Name
	probeDesc := "RAW " + raw.Name + " (" + raw.Request + ")"
	a.analyzeResponse(raw.AsResponse(), source, probeDesc)

	if want, ok := nginxReasons[raw.Status]; ok && raw.Reason == want {
		a.addEv(Evidence{
			Signal: "status.reason-phrase", Source: source, Probe: probeDesc, Status: raw.Status, Weight: 30,
			Detail: fmt.Sprintf("status line uses nginx's own reason phrase for %d", raw.Status),
			Data:   raw.StatusLine, Where: "status line", How: "reason-phrase match", Pattern: want,
		})
	}
	if nginxHeaderOrder(raw.HeaderOrder) {
		a.addEv(Evidence{
			Signal: "header.order", Source: source, Probe: probeDesc, Status: raw.Status, Weight: 25,
			Detail: "response headers arrive in nginx's fixed order (Server, Date, Content-Type, …)",
			Data:   strings.Join(raw.HeaderOrder, ", "), Where: "raw response header block", How: "header-order comparison",
			Pattern: "Server, Date, Content-Type, Content-Length|Transfer-Encoding, Connection",
		})
	}
}

// nginxHeaderOrder reports whether the wire order of the response headers is
// the one nginx's header filter always emits for a self-generated response.
// (Apache sends Date before Server; IIS and most application servers put
// Server late or omit it.)
func nginxHeaderOrder(order []string) bool {
	if len(order) < 5 || order[0] != "Server" || order[1] != "Date" || order[2] != "Content-Type" {
		return false
	}
	if order[3] != "Content-Length" && order[3] != "Transfer-Encoding" {
		return false
	}
	// Self-generated (error) responses put Connection right here; static
	// files insert Last-Modified first.
	return order[4] == "Connection" || (len(order) > 5 && order[4] == "Last-Modified" && order[5] == "Connection")
}

// analyzeH2 scores the HTTP/2 opening frames. nginx announces
// INITIAL_WINDOW_SIZE=65536 and MAX_FRAME_SIZE=16777215 and then raises the
// connection window by 2147418112 — a combination no other common server uses.
func (a *analysis) analyzeH2(h *probe.H2Fingerprint, target string) {
	if h == nil || h.Err != "" {
		return
	}
	if !h.Supported {
		a.h2Refused = true
		return
	}
	a.h2Observed = true
	a.d.H2Fingerprint = h.Akamai()
	var win, frame, streams uint32
	for _, s := range h.Settings {
		switch s.ID {
		case 3:
			streams = s.Value
		case 4:
			win = s.Value
		case 5:
			frame = s.Value
		}
	}
	if win != 65536 || frame != 16777215 || h.WindowUpdate != 2147418112 {
		return
	}
	weight, detail := 40, "HTTP/2 SETTINGS and WINDOW_UPDATE match nginx's HTTP/2 implementation"
	if streams == 128 && len(h.Settings) == 3 {
		weight, detail = 45, "HTTP/2 SETTINGS and WINDOW_UPDATE match nginx's HTTP/2 defaults exactly"
	}
	a.addEv(Evidence{
		Signal: "h2.settings-fingerprint", Source: target, Probe: "HTTP/2 connection preface → " + target, Weight: weight,
		Detail: detail, Data: a.d.H2Fingerprint, Where: "HTTP/2 SETTINGS + WINDOW_UPDATE frames",
		How: "protocol fingerprint", Pattern: "4:65536;5:16777215|2147418112",
	})
}

// analyzeStatusEndpoint recognises exposed status pages and APIs.
func (a *analysis) analyzeStatusEndpoint(resp *probe.Response, u string) {
	if resp.Status != 200 {
		return
	}
	body := resp.BodyString()
	if m := reStubStatus.FindStringSubmatch(body); m != nil {
		st := &StubStatus{URL: u}
		st.Active, _ = strconv.Atoi(m[1])
		st.Accepts, _ = strconv.ParseInt(m[2], 10, 64)
		st.Handled, _ = strconv.ParseInt(m[3], 10, 64)
		st.Requests, _ = strconv.ParseInt(m[4], 10, 64)
		st.Reading, _ = strconv.Atoi(m[5])
		st.Writing, _ = strconv.Atoi(m[6])
		st.Waiting, _ = strconv.Atoi(m[7])
		if a.d.StubStatus == nil {
			a.d.StubStatus, a.d.StatusExposed, a.d.StatusURL = st, true, u
		}
		a.addMod("http_stub_status")
		a.addEv(Evidence{
			Signal: "status.stub", Source: u, Probe: "GET " + u, Status: resp.Status, Weight: 85,
			Detail: "stub_status page is publicly readable", Data: collapseWS(m[0]),
			Where: "response body", How: "regular expression", Pattern: reStubStatus.String(),
		})
		a.addFinding(Finding{
			ID: "stub-status-exposed", Severity: "low", Title: "stub_status page is publicly exposed", URL: u,
			Detail:      fmt.Sprintf("Live connection counters are readable by anyone (%d active connections, %d requests served).", st.Active, st.Requests),
			Remediation: "Restrict the stub_status location with allow/deny (e.g. allow 127.0.0.1; deny all;).",
		})
		return
	}
	if strings.Contains(body, `"build"`) && strings.Contains(body, `"version"`) {
		var info struct {
			Version string `json:"version"`
			Build   string `json:"build"`
		}
		if json.Unmarshal([]byte(body), &info) == nil && info.Version != "" && containsFold(info.Build, "nginx-plus") {
			a.setVariant("NGINX Plus")
			a.setVersion("NGINX Plus", info.Version, "NGINX Plus API", 3)
			a.addMod("http_api (NGINX Plus " + strings.TrimPrefix(info.Build, "nginx-plus-") + ")")
			a.d.StatusExposed = true
			if a.d.StatusURL == "" {
				a.d.StatusURL = u
			}
			a.addEv(Evidence{
				Signal: "api.nginx-plus", Source: u, Probe: "GET " + u, Status: resp.Status, Weight: 90,
				Detail: "NGINX Plus REST API reports version and build", Data: collapseWS(body),
				Where: "response body", How: "JSON field match", Pattern: `"build":"nginx-plus-…"`,
			})
			a.addFinding(Finding{
				ID: "plus-api-exposed", Severity: "medium", Title: "NGINX Plus API is publicly exposed", URL: u,
				Detail:      "The NGINX Plus REST API answers unauthenticated requests (build " + info.Build + "); it discloses upstreams, zones and traffic, and allows reconfiguration when write access is enabled.",
				Remediation: "Restrict the api location with allow/deny or authentication, and keep it read-only (omit write=on).",
			})
			return
		}
	}
	if m := reVTSVersion.FindStringSubmatch(body); m != nil {
		a.setVersion("nginx", m[1], "nginx-module-vts status", 3)
		a.addMod("vts (nginx-module-vts)")
		a.d.StatusExposed = true
		if a.d.StatusURL == "" {
			a.d.StatusURL = u
		}
		a.addEv(Evidence{
			Signal: "status.vts", Source: u, Probe: "GET " + u, Status: resp.Status, Weight: 85,
			Detail: "nginx-module-vts status JSON is publicly readable", Data: m[0],
			Where: "response body", How: "regular expression", Pattern: reVTSVersion.String(),
		})
		a.addFinding(Finding{
			ID: "vts-status-exposed", Severity: "low", Title: "nginx-module-vts status is publicly exposed", URL: u,
			Detail:      "Virtual-host traffic statistics (server names, upstream addresses, counters) are readable by anyone.",
			Remediation: "Restrict the vhost_traffic_status_display location with allow/deny.",
		})
	}
}

// collectProtocols records which protocols the endpoint speaks.
func (a *analysis) collectProtocols(in Input) {
	if strings.HasPrefix(in.Root.Proto, "HTTP/1") {
		a.addProto("http/1.1")
	}
	for _, raw := range in.Raw {
		if raw != nil && raw.Err == "" && strings.HasPrefix(raw.Proto, "HTTP/1") {
			a.addProto("http/1.1")
		}
	}
	if in.H2 != nil && in.H2.Err == "" && in.H2.Supported && in.H2.Cleartext {
		a.addProto("h2c")
		a.addMod("http_v2")
	} else if a.h2Observed {
		a.addProto("h2")
		a.addMod("http_v2")
	}
	if a.h3Observed {
		a.addProto("h3 (advertised)")
		a.addMod("http_v3")
	}
	if in.Root.TLS != nil {
		a.addMod("http_ssl")
		// The fetcher offers h2 via ALPN: a TLS endpoint that picked something
		// else does not offer HTTP/2 here.
		if !a.h2Observed && in.Root.TLS.ALPN != "" && in.Root.TLS.ALPN != "h2" {
			a.h2Refused = true
		}
	}
}

// facts summarises what was observed, for resolving advisory prerequisites.
func (a *analysis) facts() ObservedFacts {
	f := ObservedFacts{Modules: map[string]bool{}}
	for m := range a.modSet {
		f.Modules[strings.ToLower(strings.Fields(m)[0])] = true
	}
	switch {
	case a.h2Observed:
		f.HTTP2 = "observed"
	case a.h2Refused:
		f.HTTP2 = "contradicted"
	}
	if a.h3Observed {
		f.HTTP3 = "observed"
	}
	if a.mail {
		f.Mail = "observed"
	}
	return f
}

// misconfigFindings derives the behaviour-based findings (deep mode).
func (a *analysis) misconfigFindings(in Input) {
	d := a.d
	if d.Version != "" || d.ProductVersion != "" {
		shown := d.Version
		if shown == "" {
			shown = d.ProductVersion
		}
		a.addFinding(Finding{
			ID: "version-disclosure", Severity: "info", Title: "Server version is disclosed", URL: in.TargetURL,
			Detail:      d.Variant + " " + shown + " is announced via the " + d.VersionSource + ", which lets anyone match the server against published advisories.",
			Remediation: "Set server_tokens off; (this hides the version, it does not fix anything).",
		})
	}
	if a.seen["body.autoindex"] {
		a.addFinding(Finding{
			ID: "autoindex-enabled", Severity: "low", Title: "Directory listing is enabled (autoindex on)", URL: in.TargetURL,
			Detail:      "The server returns an nginx autoindex listing, exposing the directory's file names.",
			Remediation: "Remove autoindex on; unless the listing is intended.",
		})
	}
	for _, p := range in.Alias {
		o, t, c := p.Original, p.Traversed, p.Control
		if o == nil || t == nil || c == nil || o.Err != "" || t.Err != "" || c.Err != "" {
			continue
		}
		if o.Status != 200 || t.Status != 200 || len(o.Body) == 0 || !bytes.Equal(o.Body, t.Body) {
			continue
		}
		// A catch-all (same body for the control too) proves nothing.
		if c.Status == 200 && bytes.Equal(c.Body, o.Body) {
			continue
		}
		a.addFinding(Finding{
			ID: "alias-traversal", Severity: "high", Title: "Path traversal via misconfigured alias (off-by-slash)", URL: t.RequestURL,
			Detail: fmt.Sprintf("%s returns the same file as %s while the control path does not: the location for /%s lacks a trailing slash, so \"/%s../\" escapes one directory above the alias target and files there can be read.",
				p.Candidate.Traversed, p.Candidate.Original, p.Candidate.Segment, p.Candidate.Segment),
			Remediation: fmt.Sprintf("Give the location a trailing slash to match its alias: location /%s/ { alias …/; }", p.Candidate.Segment),
		})
	}
	if r := in.CRLF; r != nil && r.HeaderGet(CRLFProbeHeader) != "" {
		a.addFinding(Finding{
			ID: "crlf-injection", Severity: "medium", Title: "HTTP response header injection (CRLF in a redirect/header built from $uri)", URL: r.RequestURL,
			Detail:      "An encoded CR LF in the request path was decoded and copied into the response head, so the probe's own header (" + CRLFProbeHeader + ") came back as a real response header. Typical cause: return 301 https://$host$uri; or add_header/proxy_set_header using $uri or $document_uri.",
			Remediation: "Use $request_uri (not $uri/$document_uri) when building redirects or headers.",
		})
	}
}

// correlate applies the catalogue: release support status, version-based
// vulnerability leads and the NGINX2Root assessment.
func (a *analysis) correlate(cat *Catalog) {
	d := a.d
	if cat == nil {
		cat = DefaultCatalog()
	}
	facts := a.facts()
	if d.Version != "" {
		s := cat.Support(d.Variant, d.Version)
		d.EndOfLife, d.Outdated, d.EOLDetail = s.EndOfLife, s.Outdated, s.Detail
		if s.Branch != "" {
			d.Branch = s.Branch
		}
		d.Vulnerabilities = cat.Correlate(d.Variant, d.Version, facts)
		sortVulns(d.Vulnerabilities)
	}
	d.Nginx2Root = assessNginx2Root(d, facts)
}

// assessNginx2Root summarises exposure to the NGINX2Root chain.
func assessNginx2Root(d *Detection, facts ObservedFacts) *Nginx2Root {
	n := &Nginx2Root{HTTP2: orUnknown(facts.HTTP2), HTTP3: orUnknown(facts.HTTP3), Mail: orUnknown(facts.Mail)}
	surface := func() string {
		var parts []string
		switch n.HTTP2 {
		case "observed":
			parts = append(parts, "HTTP/2 is enabled on this endpoint (the precondition for CVE-2026-123007 and CVE-2026-123633)")
		case "contradicted":
			parts = append(parts, "HTTP/2 was not offered on this endpoint (other listeners may differ)")
		default:
			parts = append(parts, "HTTP/2 status on this endpoint is unknown")
		}
		if n.HTTP3 == "observed" {
			parts = append(parts, "HTTP/3 is advertised (CVE-2026-121810)")
		}
		if n.Mail == "observed" {
			parts = append(parts, "the mail proxy is reachable (CVE-2026-113425)")
		}
		return strings.Join(parts, "; ") + "."
	}
	ok, _ := correlatable(d.Variant)
	switch {
	case d.Version == "" || !ok:
		n.Status = "unknown-version"
		why := "the server hides its version"
		if !ok {
			why = d.Variant + " uses its own version numbering; check the vendor's advisory"
		}
		n.Detail = "Cannot tell whether the NGINX2Root fixes (nginx 1.31.9 / 1.30.7) are present: " + why + ". " + surface()
	default:
		for _, v := range d.Vulnerabilities {
			for _, t := range v.Tags {
				if t == TagNginx2Root {
					n.CVEs = append(n.CVEs, v.ID)
				}
			}
		}
		sort.Strings(n.CVEs)
		if len(n.CVEs) == 0 {
			n.Status = "not-affected"
			n.Detail = "nginx " + d.Version + " is outside the affected ranges of the NGINX2Root advisories (fixed in 1.31.9 / 1.30.7)."
		} else {
			n.Status = "vulnerable-version"
			n.Detail = fmt.Sprintf("nginx %s is in the affected range of %d NGINX2Root advisories (fixed in 1.31.9 / 1.30.7). %s",
				d.Version, len(n.CVEs), surface())
			if d.Distro != "" {
				n.Detail += " This is a " + d.Distro + " package: verify the package changelog, as fixes may be backported."
			}
		}
	}
	return n
}

// versionsConflict reports whether observations disagree at major.minor level.
func versionsConflict(obs []VersionObservation) bool {
	seen := map[string]bool{}
	for _, o := range obs {
		if maj, min, _, ok := parseVersion(o.Version); ok {
			seen[fmt.Sprintf("%d.%d", maj, min)] = true
		}
	}
	return len(seen) > 1
}

// bodyContext returns a collapsed context window around a body match and the
// 1-based line number where the match begins.
func bodyContext(body string, start, end int) (string, int) {
	if start < 0 {
		start = 0
	}
	if end > len(body) {
		end = len(body)
	}
	line := 1 + strings.Count(body[:start], "\n")
	lo := start - 60
	if lo < 0 {
		lo = 0
	}
	hi := end + 60
	if hi > len(body) {
		hi = len(body)
	}
	seg := collapseWS(body[lo:hi])
	if len(seg) > 220 {
		seg = seg[:220] + "…"
	}
	return seg, line
}

func collapseWS(s string) string { return strings.Join(strings.Fields(s), " ") }

// provenanceDefaults supplies a baseline where/how for a signal by prefix.
func provenanceDefaults(signal string) (where, how string) {
	switch {
	case strings.HasPrefix(signal, "header."):
		return "response header", "header match"
	case strings.HasPrefix(signal, "cookie."):
		return "Set-Cookie header", "cookie-name match"
	case strings.HasPrefix(signal, "status."), strings.HasPrefix(signal, "api."):
		return "deep-probe response", "exposed status endpoint"
	case strings.HasPrefix(signal, "h2."):
		return "HTTP/2 frames", "protocol fingerprint"
	case strings.HasPrefix(signal, "banner."):
		return "service banner", "banner match"
	case strings.HasPrefix(signal, "body."):
		return "response body", "content match"
	default:
		return "response", "heuristic"
	}
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func sortEvidence(ev []Evidence) {
	sort.SliceStable(ev, func(i, j int) bool {
		if ev[i].Weight != ev[j].Weight {
			return ev[i].Weight > ev[j].Weight
		}
		return ev[i].Signal < ev[j].Signal
	})
}

func sortVulns(vs []Vulnerability) {
	sort.SliceStable(vs, func(i, j int) bool {
		ri, rj := SeverityRank(vs[i].Severity), SeverityRank(vs[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return vs[i].ID > vs[j].ID
	})
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := SeverityRank(fs[i].Severity), SeverityRank(fs[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return fs[i].ID < fs[j].ID
	})
}
