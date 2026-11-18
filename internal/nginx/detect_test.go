package nginx

import (
	"net/http"
	"strings"
	"testing"

	"github.com/rom/qnginxscanner/internal/probe"
)

func resp(status int, headers map[string]string, body string) *probe.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &probe.Response{RequestURL: "http://h/", FinalURL: "http://h/", Status: status, Proto: "HTTP/1.1", Header: h, Body: []byte(body)}
}

func errorPage(status, footer string) string {
	return "<html>\r\n<head><title>" + status + "</title></head>\r\n<body>\r\n<center><h1>" + status +
		"</h1></center>\r\n<hr><center>" + footer + "</center>\r\n</body>\r\n</html>\r\n"
}

func hasSignal(d *Detection, sig string) bool {
	for _, e := range d.Evidence {
		if e.Signal == sig {
			return true
		}
	}
	return false
}

func hasVuln(d *Detection, id string) bool {
	for _, v := range d.Vulnerabilities {
		if v.ID == id {
			return true
		}
	}
	return false
}

func hasFinding(d *Detection, id string) bool {
	for _, f := range d.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func analyzeServer(t *testing.T, server string) *Detection {
	t.Helper()
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, map[string]string{"Server": server}, "<html></html>")})
	if d == nil {
		t.Fatal("nil detection")
	}
	return d
}

func TestAnalyzeNilRoot(t *testing.T) {
	if Analyze(Input{}) != nil {
		t.Fatal("want nil for an empty input")
	}
}

func TestServerHeader(t *testing.T) {
	cases := []struct {
		server, variant, version, product, distro string
	}{
		{"nginx", "nginx", "", "", ""},
		{"nginx/1.24.0", "nginx", "1.24.0", "", ""},
		{"nginx/1.18.0 (Ubuntu)", "nginx", "1.18.0", "", "Ubuntu"},
		{"openresty/1.25.3.1", "OpenResty", "1.25.3", "1.25.3.1", ""},
		{"Tengine/3.1.0", "Tengine", "", "3.1.0", ""},
		{"Angie/1.7.0", "Angie", "", "1.7.0", ""},
		{"freenginx/1.27.4", "freenginx", "", "1.27.4", ""},
		{"kong/3.6.1", "Kong", "", "3.6.1", ""},
		{"APISIX/3.9.0", "Apache APISIX", "", "3.9.0", ""},
		{"cloudflare-nginx", "nginx", "", "", ""},
	}
	for _, c := range cases {
		d := analyzeServer(t, c.server)
		if !d.IsNginx {
			t.Errorf("%q: not detected (confidence %d)", c.server, d.Confidence)
			continue
		}
		if d.Variant != c.variant || d.Version != c.version || d.ProductVersion != c.product || d.Distro != c.distro {
			t.Errorf("%q: got variant=%q version=%q product=%q distro=%q", c.server, d.Variant, d.Version, d.ProductVersion, d.Distro)
		}
	}
}

func TestOtherServersAreNotNginx(t *testing.T) {
	for _, s := range []string{"Apache/2.4.58 (Ubuntu)", "Microsoft-IIS/10.0", "Caddy", "cloudflare", "LiteSpeed", "nginxlike-but-not", ""} {
		d := analyzeServer(t, s)
		if d.IsNginx || d.Variant != "" || d.Version != "" || len(d.Vulnerabilities) != 0 || d.Nginx2Root != nil {
			t.Errorf("%q: false positive: %+v", s, d)
		}
	}
}

func TestErrorPageFooter(t *testing.T) {
	in := Input{
		TargetURL: "http://h/", Deep: true,
		Root:     resp(200, map[string]string{"Server": "Apache"}, "ok"), // banner rewritten by a proxy
		NotFound: resp(404, nil, errorPage("404 Not Found", "nginx/1.22.1 (Debian)")),
	}
	d := Analyze(in)
	if !d.IsNginx || d.Version != "1.22.1" || d.VersionSource != "error page footer" || d.Distro != "Debian" {
		t.Fatalf("got %+v", d)
	}
	if !hasSignal(d, "body.error-page") {
		t.Error("missing body.error-page")
	}
}

func TestErrorPageHiddenVersionAndCustomFooter(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(404, nil, errorPage("404 Not Found", "nginx"))})
	if !d.IsNginx || !d.VersionHidden || d.Version != "" {
		t.Fatalf("hidden version: %+v", d)
	}
	if d.Nginx2Root == nil || d.Nginx2Root.Status != "unknown-version" {
		t.Errorf("want unknown-version, got %+v", d.Nginx2Root)
	}
	// A rebranded footer still shows nginx's page structure, but is not enough alone.
	d = Analyze(Input{TargetURL: "http://h/", Root: resp(404, nil, errorPage("404 Not Found", "ACME edge"))})
	if !hasSignal(d, "body.error-page-template") || d.IsNginx || d.Verdict != VerdictPossible {
		t.Errorf("custom footer: verdict=%s is=%v", d.Verdict, d.IsNginx)
	}
	// A mismatching title/heading is not nginx's template.
	bad := strings.Replace(errorPage("404 Not Found", "nginx"), "<h1>404 Not Found", "<h1>500 Oops", 1)
	if d := Analyze(Input{TargetURL: "http://h/", Root: resp(404, nil, bad)}); hasSignal(d, "body.error-page") {
		t.Error("mismatched title/heading must not match")
	}
}

func TestBodySignatures(t *testing.T) {
	cases := map[string]string{
		"body.welcome-nginx":       "<html><head><title>Welcome to nginx!</title></head>",
		"body.welcome-openresty":   "<title>Welcome to OpenResty!</title>",
		"body.error-50x":           `the <a href="http://nginx.org/r/error_log">error log</a>`,
		"body.plain-http-to-https": "<center>The plain HTTP request was sent to HTTPS port</center>",
		"body.header-too-large":    "<head><title>400 Request Header Or Cookie Too Large</title></head>",
		"body.autoindex":           "<html>\r\n<head><title>Index of /pub/</title></head>\r\n<body>\r\n<h1>Index of /pub/</h1><hr><pre><a href=\"../\">../</a>\r\n",
	}
	for sig, body := range cases {
		d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, body)})
		if !hasSignal(d, sig) {
			t.Errorf("%s not matched", sig)
		}
	}
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, "<title>Welcome to OpenResty!</title>")})
	if d.Variant != "OpenResty" {
		t.Errorf("variant = %q", d.Variant)
	}
}

func TestETagFormat(t *testing.T) {
	// mtime 0x5e8c7b6a = 1586264938 = Tue, 07 Apr 2020 13:08:58 GMT; size 0x264 = 612.
	h := map[string]string{"ETag": `"5e8c7b6a-264"`, "Last-Modified": "Tue, 07 Apr 2020 13:08:58 GMT", "Content-Length": "612"}
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, h, "x")})
	if !hasSignal(d, "header.etag-format") || d.Evidence[0].Weight != 40 {
		t.Fatalf("verified ETag not matched: %+v", d.Evidence)
	}
	// Weak ETag (gzip): size is not comparable, mtime still verifies.
	h["ETag"] = `W/"5e8c7b6a-264"`
	if d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, h, "x")}); !hasSignal(d, "header.etag-format") || d.Evidence[0].Weight != 35 {
		t.Errorf("weak ETag: %+v", d.Evidence)
	}
	// Apache-style ETag (size first) must not match.
	h["ETag"] = `"264-5a2c1e0b3f4c0"`
	if d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, h, "x")}); hasSignal(d, "header.etag-format") {
		t.Error("Apache ETag matched")
	}
	// Same shape but mtime disagrees with Last-Modified.
	h["ETag"] = `"5e8c7b6b-264"`
	if d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, h, "x")}); hasSignal(d, "header.etag-format") {
		t.Error("unverified ETag matched")
	}
}

func TestRawProbeSignals(t *testing.T) {
	raw := &probe.RawResponse{
		Name: "unknown-method", Request: "QNGX / HTTP/1.1", StatusLine: "HTTP/1.1 405 Not Allowed",
		Proto: "HTTP/1.1", Status: 405, Reason: "Not Allowed",
		HeaderOrder: []string{"Server", "Date", "Content-Type", "Content-Length", "Connection"},
		Header:      http.Header{"Server": {"nginx"}},
		Body:        []byte(errorPage("405 Not Allowed", "nginx")),
	}
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, "app"), Raw: []*probe.RawResponse{raw, nil, {Name: "x", Err: "boom"}}})
	for _, sig := range []string{"status.reason-phrase", "header.order", "header.server", "body.error-page"} {
		if !hasSignal(d, sig) {
			t.Errorf("missing %s", sig)
		}
	}
	if !d.IsNginx {
		t.Error("raw evidence should confirm nginx")
	}
}

func TestHeaderOrder(t *testing.T) {
	yes := [][]string{
		{"Server", "Date", "Content-Type", "Content-Length", "Connection"},
		{"Server", "Date", "Content-Type", "Transfer-Encoding", "Connection"},
		{"Server", "Date", "Content-Type", "Content-Length", "Last-Modified", "Connection", "ETag", "Accept-Ranges"},
	}
	no := [][]string{
		{"Date", "Server", "Content-Type", "Content-Length", "Connection"},                     // Apache
		{"Server", "Date", "Content-type", "Content-Length", "Last-Modified"},                  // Python http.server
		{"Content-Type", "Server", "Date", "Content-Length"},                                   // IIS-like
		{"Server", "Date", "Content-Type", "Content-Length"},                                   // too short
		{"Server", "Date", "Content-Type", "Content-Length", "Last-Modified", "Accept-Ranges"}, // no Connection
	}
	for _, o := range yes {
		if !nginxHeaderOrder(o) {
			t.Errorf("want match: %v", o)
		}
	}
	for _, o := range no {
		if nginxHeaderOrder(o) {
			t.Errorf("want no match: %v", o)
		}
	}
}

func nginxH2() *probe.H2Fingerprint {
	return &probe.H2Fingerprint{Supported: true, ALPN: "h2", WindowUpdate: 2147418112,
		Settings: []probe.H2Setting{{ID: 3, Value: 128}, {ID: 4, Value: 65536}, {ID: 5, Value: 16777215}}}
}

func TestH2Fingerprint(t *testing.T) {
	d := Analyze(Input{TargetURL: "https://h/", Deep: true, Root: resp(200, map[string]string{"Server": "nginx/1.24.0"}, "x"), H2: nginxH2()})
	if !hasSignal(d, "h2.settings-fingerprint") || d.H2Fingerprint != "3:128;4:65536;5:16777215|2147418112" {
		t.Fatalf("fingerprint: %q %+v", d.H2Fingerprint, d.Evidence)
	}
	if d.Nginx2Root.HTTP2 != "observed" {
		t.Errorf("http2 = %s", d.Nginx2Root.HTTP2)
	}
	// Another server's SETTINGS: HTTP/2 is observed but it is not nginx evidence.
	other := &probe.H2Fingerprint{Supported: true, ALPN: "h2", WindowUpdate: 983041,
		Settings: []probe.H2Setting{{ID: 3, Value: 100}, {ID: 4, Value: 1048576}}}
	d = Analyze(Input{TargetURL: "https://h/", Root: resp(200, nil, "x"), H2: other})
	if hasSignal(d, "h2.settings-fingerprint") || d.H2Fingerprint == "" {
		t.Errorf("foreign fingerprint mis-scored: %+v", d)
	}
}

func TestStubStatusAndPlusAPI(t *testing.T) {
	stub := "Active connections: 3 \nserver accepts handled requests\n 18 18 20 \nReading: 0 Writing: 2 Waiting: 1 \n"
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, nil, "app"),
		Extra: map[string]*probe.Response{"http://h/nginx_status": resp(200, nil, stub), "http://h/x": nil}})
	if !d.IsNginx || !d.StatusExposed || d.StubStatus == nil || d.StubStatus.Active != 3 || d.StubStatus.Requests != 20 {
		t.Fatalf("stub: %+v", d)
	}
	if !hasFinding(d, "stub-status-exposed") {
		t.Error("missing finding")
	}

	api := `{"version":"1.25.3","build":"nginx-plus-r31","address":"10.0.0.1","generation":1,"pid":7}`
	d = Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, map[string]string{"Server": "nginx/1.25.3"}, "app"),
		Extra: map[string]*probe.Response{"http://h/api/9/nginx": resp(200, nil, api)}})
	if d.Variant != "NGINX Plus" || d.Version != "1.25.3" || d.VersionSource != "NGINX Plus API" || !hasFinding(d, "plus-api-exposed") {
		t.Fatalf("plus: %+v", d)
	}
	if !hasVuln(d, "CVE-2026-123007") || !strings.Contains(d.Vulnerabilities[0].MatchBasis, "NGINX Plus") {
		t.Errorf("plus correlation: %+v", d.Vulnerabilities)
	}

	vts := `{"hostName":"a","nginxVersion":"1.20.2","loadMsec":1}`
	d = Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, nil, "app"),
		Extra: map[string]*probe.Response{"http://h/status/format/json": resp(200, nil, vts)}})
	if d.Version != "1.20.2" || !hasFinding(d, "vts-status-exposed") {
		t.Errorf("vts: %+v", d)
	}
}

func TestPlusAPIFollowUp(t *testing.T) {
	if got := PlusAPIFollowUp(resp(200, nil, "[1,2,3,4,5,6,7,8,9]")); got != "/api/9/nginx" {
		t.Errorf("got %q", got)
	}
	for _, body := range []string{"", "[]", `{"a":1}`, "[2,3]", "<html>"} {
		if got := PlusAPIFollowUp(resp(200, nil, body)); got != "" {
			t.Errorf("%q → %q", body, got)
		}
	}
	if PlusAPIFollowUp(nil) != "" || PlusAPIFollowUp(resp(404, nil, "[1,2]")) != "" {
		t.Error("nil/404 must not follow up")
	}
}

func TestDavAndProtocols(t *testing.T) {
	root := resp(200, map[string]string{"Server": "nginx/1.31.9", "Alt-Svc": `h3=":443"; ma=86400`}, "x")
	root.Proto = "HTTP/2.0"
	root.TLS = &probe.TLSInfo{ALPN: "h2"}
	d := Analyze(Input{TargetURL: "https://h/", Deep: true, Root: root,
		Extra: map[string]*probe.Response{"OPTIONS https://h/": resp(200, map[string]string{"Allow": "GET, PROPFIND"}, "")}})
	want := map[string]bool{"http_dav": true, "http_v2": true, "http_v3": true, "http_ssl": true}
	for _, m := range d.Modules {
		delete(want, m)
	}
	if len(want) != 0 {
		t.Errorf("missing modules %v in %v", want, d.Modules)
	}
	if strings.Join(d.Protocols, ",") != "h2,h3 (advertised)" {
		t.Errorf("protocols = %v", d.Protocols)
	}
}

func TestAliasTraversalFinding(t *testing.T) {
	c := AliasCandidate{Segment: "static", Original: "/static/a.css", Traversed: "/static../static/a.css", Control: "/static../qnginxscanner-nx/a.css"}
	root := resp(200, map[string]string{"Server": "nginx"}, "x")
	mk := func(orig, trav, ctrl *probe.Response) *Detection {
		return Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, Alias: []AliasProbe{{Candidate: c, Original: orig, Traversed: trav, Control: ctrl}}})
	}
	if d := mk(resp(200, nil, "css"), resp(200, nil, "css"), resp(404, nil, "nf")); !hasFinding(d, "alias-traversal") {
		t.Error("vulnerable case not reported")
	}
	if d := mk(resp(200, nil, "css"), resp(404, nil, "nf"), resp(404, nil, "nf")); hasFinding(d, "alias-traversal") {
		t.Error("safe case reported")
	}
	// Catch-all server: every path returns the same body.
	if d := mk(resp(200, nil, "spa"), resp(200, nil, "spa"), resp(200, nil, "spa")); hasFinding(d, "alias-traversal") {
		t.Error("catch-all reported")
	}
	if d := mk(resp(200, nil, "css"), nil, nil); hasFinding(d, "alias-traversal") {
		t.Error("incomplete probe reported")
	}
}

func TestAliasCandidates(t *testing.T) {
	body := `<link href="/static/css/app.css?v=3"><script src="js/main.js"></script>
<img src="https://cdn.example.net/img/x.png"><img src="/static/img/y.png"><link href="/favicon.ico">
<script src="/assets/a.js"></script><script src="/media/b.js"></script><script src="/more/c.js"></script>`
	got := AliasCandidates("http://h/app/", body)
	if len(got) != maxAliasCandidates {
		t.Fatalf("got %d candidates: %+v", len(got), got)
	}
	if got[0].Original != "/static/css/app.css" || got[0].Traversed != "/static../static/css/app.css" || got[0].Control != "/static../qnginxscanner-nx/css/app.css" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Segment != "app" || got[2].Segment != "assets" {
		t.Errorf("segments = %s, %s", got[1].Segment, got[2].Segment)
	}
	if AliasCandidates("://bad", body) != nil || len(AliasCandidates("http://h/", "no assets")) != 0 {
		t.Error("want no candidates")
	}
}

func TestCRLFFinding(t *testing.T) {
	root := resp(301, map[string]string{"Server": "nginx"}, "")
	crlf := resp(301, map[string]string{CRLFProbeHeader: "crlf"}, "")
	if d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, CRLF: crlf}); !hasFinding(d, "crlf-injection") {
		t.Error("crlf not reported")
	}
	if d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, CRLF: resp(400, nil, "")}); hasFinding(d, "crlf-injection") {
		t.Error("false crlf")
	}
	// Findings need deep mode.
	if d := Analyze(Input{TargetURL: "http://h/", Root: root, CRLF: crlf}); len(d.Findings) != 0 {
		t.Error("findings in detect mode")
	}
}

func TestMailBanner(t *testing.T) {
	for banner, proto := range map[string]string{
		"+OK POP3 ready": "POP3", "+OK POP3 ready <123.456@mx>": "POP3", "* OK IMAP4 ready": "IMAP", "220 mx.example.com ESMTP ready": "SMTP",
	} {
		d := Analyze(Input{TargetURL: "h:110", Deep: true, Banner: banner})
		if d == nil || !d.IsNginx || d.Protocols[0] != "mail ("+proto+")" {
			t.Errorf("%q: %+v", banner, d)
			continue
		}
		if d.Nginx2Root == nil || d.Nginx2Root.Mail != "observed" || d.Nginx2Root.Status != "unknown-version" {
			t.Errorf("%q: nginx2root %+v", banner, d.Nginx2Root)
		}
	}
	for _, banner := range []string{"220 mx.example.com ESMTP Postfix", "* OK [CAPABILITY IMAP4rev1] Dovecot ready.", "SSH-2.0-OpenSSH_9.6"} {
		if d := Analyze(Input{TargetURL: "h:25", Banner: banner}); d == nil || d.IsNginx || len(d.Evidence) != 0 {
			t.Errorf("%q: false positive %+v", banner, d)
		}
	}
}

func TestVersionConflictAndRank(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Deep: true,
		Root:     resp(200, map[string]string{"Server": "nginx/1.24.0"}, "x"),
		NotFound: resp(404, nil, errorPage("404 Not Found", "nginx/1.18.0")),
	})
	if !d.VersionConflict || d.Version != "1.24.0" || len(d.VersionObservations) != 2 {
		t.Errorf("conflict: %+v", d)
	}
}

func TestDetectModeSkipsCorrelation(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{"Server": "nginx/1.20.0"}, "x")})
	if !d.IsNginx || d.Version != "1.20.0" || d.Branch != "stable" {
		t.Fatalf("detect: %+v", d)
	}
	if len(d.Vulnerabilities) != 0 || d.Nginx2Root != nil || d.EndOfLife {
		t.Error("detect mode must not correlate")
	}
}

func TestHeaderAndCookieSignatures(t *testing.T) {
	r := resp(200, map[string]string{"X-Kong-Proxy-Latency": "1", "X-Accel-Buffering": "no", "Via": "kong/3.4.0"}, "x")
	r.Cookies = []*http.Cookie{{Name: "INGRESSCOOKIE", Value: "v"}}
	d := Analyze(Input{TargetURL: "http://h/", Root: r})
	for _, sig := range []string{"header.x-kong-proxy-latency", "header.x-accel-buffering", "header.via", "cookie.ingresscookie"} {
		if !hasSignal(d, sig) {
			t.Errorf("missing %s", sig)
		}
	}
	if d.Variant != "Kong" || d.ProductVersion != "3.4.0" {
		t.Errorf("variant=%q product=%q", d.Variant, d.ProductVersion)
	}
}

func TestRedirectFailureStillAnalysed(t *testing.T) {
	r := resp(302, map[string]string{"Server": "nginx/1.31.9"}, "")
	r.Err = "dial tcp: connection refused"
	if d := Analyze(Input{TargetURL: "http://h/", Root: r}); !d.IsNginx {
		t.Error("a response with a status must be analysed even when following it failed")
	}
}
