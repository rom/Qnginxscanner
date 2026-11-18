package scanner

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingServer serves a handler and records every requested path.
func recordingServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, func(string) int, int) {
	t.Helper()
	var mu sync.Mutex
	paths := map[string]int{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths[r.URL.Path]++
		mu.Unlock()
		h(w, r)
	}))
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	count := func(p string) int {
		mu.Lock()
		defer mu.Unlock()
		return paths[p]
	}
	return ts, count, port
}

func deepScan(t *testing.T, port int, opts Options) *ScanResult {
	t.Helper()
	opts.Mode = ModeDeep
	opts.TLSMode = TLSOff
	opts.Ports = []int{port}
	if opts.Timeout == 0 {
		opts.Timeout = 3 * time.Second
	}
	res, err := Scan(context.Background(), []string{"127.0.0.1"}, opts)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res
}

const nginxBanner = "nginx/1.24.0"

func nginxErrorPage(status string) string {
	return "<html>\r\n<head><title>" + status + "</title></head>\r\n<body>\r\n<center><h1>" + status +
		"</h1></center>\r\n<hr><center>" + nginxBanner + "</center>\r\n</body>\r\n</html>\r\n"
}

// nginxish answers like a small nginx site: a page referencing a static
// asset, an nginx 404 page elsewhere, and whatever extra paths are given.
func nginxish(extra map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", nginxBanner)
		if body, ok := extra[r.URL.Path]; ok {
			_, _ = io.WriteString(w, body)
			return
		}
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `<html><link rel="stylesheet" href="/static/app.css"></html>`)
		case "/static/app.css":
			_, _ = io.WriteString(w, "body{}")
		default:
			w.WriteHeader(404)
			_, _ = io.WriteString(w, nginxErrorPage("404 Not Found"))
		}
	}
}

func findingIDs(svc ServiceResult) map[string]bool {
	m := map[string]bool{}
	if svc.Nginx != nil {
		for _, f := range svc.Nginx.Findings {
			m[f.ID] = true
		}
	}
	return m
}

func TestDeepProbesAndFindings(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	stub := "Active connections: 2 \nserver accepts handled requests\n 10 10 12 \nReading: 0 Writing: 1 Waiting: 1 \n"
	ts, count, port := recordingServer(t, nginxish(map[string]string{
		"/nginx_status":            stub,
		"/static../static/app.css": "body{}", // off-by-slash alias
	}))
	defer ts.Close()

	res := deepScan(t, port, Options{})
	svc := res.Targets[0].Services[0]
	if svc.Nginx == nil || !svc.Nginx.IsNginx || svc.Nginx.Version != "1.24.0" {
		t.Fatalf("nginx not detected: %+v", svc.Nginx)
	}
	for _, p := range []string{"/qnginxscanner_probe_404", "/nginx_status", "/api/", "/static/app.css", "/static../static/app.css", "/static../qnginxscanner-nx/app.css"} {
		if count(p) == 0 {
			t.Errorf("deep probe %s was not issued", p)
		}
	}
	got := findingIDs(svc)
	for _, id := range []string{"stub-status-exposed", "alias-traversal", "version-disclosure"} {
		if !got[id] {
			t.Errorf("missing finding %s (got %v)", id, got)
		}
	}
	if !svc.Nginx.EndOfLife || svc.Nginx.Nginx2Root == nil || svc.Nginx.Nginx2Root.Status != "vulnerable-version" {
		t.Errorf("lifecycle/nginx2root: eol=%v n2r=%+v", svc.Nginx.EndOfLife, svc.Nginx.Nginx2Root)
	}
	if svc.DiscoveryLimited != "" {
		t.Errorf("discovery should not be limited: %q", svc.DiscoveryLimited)
	}
	s := res.Summary
	if s.NginxConfirmed != 1 || s.Findings != len(svc.Nginx.Findings) || s.EndOfLife != 1 || s.Nginx2Root != 1 || s.Vulnerabilities == 0 {
		t.Errorf("summary: %+v", s)
	}
	if !res.Meta.RawProbes || res.Meta.CatalogAdvisories == 0 {
		t.Errorf("meta: %+v", res.Meta)
	}
}

func TestDetectModeSendsFewProbes(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts, count, port := recordingServer(t, nginxish(nil))
	defer ts.Close()
	res, err := Scan(context.Background(), []string{"127.0.0.1"}, Options{Mode: ModeDetect, TLSMode: TLSOff, Ports: []int{port}, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	svc := res.Targets[0].Services[0]
	if svc.Nginx == nil || !svc.Nginx.IsNginx {
		t.Fatalf("not detected: %+v", svc.Nginx)
	}
	if count("/qnginxscanner_probe_404") != 1 {
		t.Error("detect mode should fetch the 404 page once")
	}
	if count("/nginx_status") != 0 || count("/static/app.css") != 0 {
		t.Error("detect mode must not issue deep probes")
	}
	if len(svc.Nginx.Vulnerabilities) != 0 || len(svc.Nginx.Findings) != 0 || svc.Nginx.Nginx2Root != nil {
		t.Error("detect mode must not correlate")
	}
}

func TestPlusAPIFollowUpProbe(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts, count, port := recordingServer(t, nginxish(map[string]string{
		"/api/":        "[1,2,3,4,5,6,7,8,9]",
		"/api/9/nginx": `{"version":"1.25.3","build":"nginx-plus-r31","address":"127.0.0.1"}`,
	}))
	defer ts.Close()
	svc := deepScan(t, port, Options{}).Targets[0].Services[0]
	if count("/api/9/nginx") != 1 {
		t.Fatal("NGINX Plus API follow-up not issued")
	}
	if svc.Nginx.Variant != "NGINX Plus" || svc.Nginx.Version != "1.25.3" || !findingIDs(svc)["plus-api-exposed"] {
		t.Errorf("plus: %+v", svc.Nginx)
	}
}

func TestRequestBudgetStopsDiscovery(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts, count, port := recordingServer(t, nginxish(nil))
	defer ts.Close()
	svc := deepScan(t, port, Options{RequestBudget: 2}).Targets[0].Services[0]
	if svc.DiscoveryLimited != "budget" {
		t.Errorf("DiscoveryLimited = %q, want budget", svc.DiscoveryLimited)
	}
	if count("/nginx_status")+count("/stub_status") != 2 || count("/api/") != 0 || count("/static/app.css") != 0 {
		t.Error("probes were issued past the budget")
	}
	// Core identification still ran.
	if svc.Nginx == nil || !svc.Nginx.IsNginx || count("/qnginxscanner_probe_404") != 1 {
		t.Error("core probes must not be budgeted")
	}
}

func TestRateLimitedSkipsDiscovery(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts, count, port := recordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", nginxBanner)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(503)
		_, _ = io.WriteString(w, nginxErrorPage("503 Service Temporarily Unavailable"))
	})
	defer ts.Close()
	svc := deepScan(t, port, Options{}).Targets[0].Services[0]
	if svc.DiscoveryLimited != "rate-limited" {
		t.Errorf("DiscoveryLimited = %q", svc.DiscoveryLimited)
	}
	if count("/nginx_status") != 0 || count("/api/") != 0 {
		t.Error("optional probes issued against a throttling host")
	}
	if svc.Nginx == nil || !svc.Nginx.IsNginx {
		t.Error("the throttled reply itself still identifies nginx")
	}
}

// fakeNginx is a raw TCP server that reproduces nginx's wire behaviour for the
// fingerprint probes: header order, reason phrases, the cleartext HTTP/2
// preface and the mail-proxy style banner are byte-exact.
func fakeNginx(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	reply := func(status, body string) string {
		return "HTTP/1.1 " + status + "\r\nServer: nginx\r\nDate: Wed, 18 Nov 2026 10:00:00 GMT\r\nContent-Type: text/html\r\nContent-Length: " +
			strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
	}
	page := func(status string) string { return strings.Replace(nginxErrorPage(status), nginxBanner, "nginx", 1) }
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				br := bufio.NewReaderSize(c, 32*1024)
				first, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if strings.HasPrefix(first, "PRI * HTTP/2.0") {
					// SETTINGS{3:128,4:65536,5:16777215} + WINDOW_UPDATE(2147418112).
					_, _ = c.Write([]byte{0, 0, 18, 4, 0, 0, 0, 0, 0,
						0, 3, 0, 0, 0, 128, 0, 4, 0, 1, 0, 0, 0, 5, 0, 0xff, 0xff, 0xff,
						0, 0, 4, 8, 0, 0, 0, 0, 0, 0x7f, 0xff, 0, 0})
					_, _ = io.Copy(io.Discard, c)
					return
				}
				hasHost := false
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
					if strings.HasPrefix(strings.ToLower(line), "host:") {
						hasHost = true
					}
				}
				var out string
				switch {
				case !hasHost:
					out = reply("400 Bad Request", page("400 Bad Request"))
				case strings.HasPrefix(first, "QNGX "):
					out = reply("405 Not Allowed", page("405 Not Allowed"))
				case len(first) > 8192:
					out = reply("414 Request-URI Too Large", page("414 Request-URI Too Large"))
				case strings.HasPrefix(first, "GET / "):
					out = reply("200 OK", "<html>app</html>")
				default:
					out = reply("404 Not Found", page("404 Not Found"))
				}
				_, _ = io.WriteString(c, out)
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func signalSet(svc ServiceResult) map[string]bool {
	m := map[string]bool{}
	if svc.Nginx != nil {
		for _, e := range svc.Nginx.Evidence {
			m[e.Signal] = true
		}
	}
	return m
}

func TestRawAndH2FingerprintProbes(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	port := fakeNginx(t)
	svc := deepScan(t, port, Options{}).Targets[0].Services[0]
	got := signalSet(svc)
	for _, sig := range []string{"header.server", "body.error-page", "header.order", "status.reason-phrase", "h2.settings-fingerprint"} {
		if !got[sig] {
			t.Errorf("missing %s (got %v)", sig, got)
		}
	}
	n := svc.Nginx
	if !n.VersionHidden || n.H2Fingerprint != "3:128;4:65536;5:16777215|2147418112" {
		t.Errorf("hidden=%v h2=%q", n.VersionHidden, n.H2Fingerprint)
	}
	if n.Nginx2Root == nil || n.Nginx2Root.Status != "unknown-version" || n.Nginx2Root.HTTP2 != "observed" {
		t.Errorf("nginx2root: %+v", n.Nginx2Root)
	}
	if strings.Join(n.Protocols, ",") != "http/1.1,h2c" {
		t.Errorf("protocols: %v", n.Protocols)
	}

	// --no-raw: only well-formed requests, so the wire-level signals vanish.
	res := deepScan(t, port, Options{NoRawProbes: true})
	got = signalSet(res.Targets[0].Services[0])
	if got["header.order"] || got["status.reason-phrase"] || got["h2.settings-fingerprint"] {
		t.Errorf("raw signals present with NoRawProbes: %v", got)
	}
	if !got["header.server"] || res.Meta.RawProbes {
		t.Errorf("plain signals missing or meta wrong: %v %+v", got, res.Meta.RawProbes)
	}
}

func TestMailProxyBanner(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, "+OK POP3 ready\r\n")
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	res := deepScan(t, port, Options{GrabBanners: true, Timeout: time.Second})
	svc := res.Targets[0].Services[0]
	if svc.HTTP != nil || svc.Nginx == nil || !svc.Nginx.IsNginx || svc.Nginx.Nginx2Root.Mail != "observed" {
		t.Fatalf("mail proxy not detected: banner=%q nginx=%+v", svc.Banner, svc.Nginx)
	}
	if res.Summary.NginxLikely != 1 || res.Summary.Nginx2RootUnknown != 1 {
		t.Errorf("summary: %+v", res.Summary)
	}
	// Without --banners the port is just an open non-HTTP port.
	svc = deepScan(t, port, Options{Timeout: time.Second}).Targets[0].Services[0]
	if svc.Nginx != nil {
		t.Errorf("no banner grab requested, yet nginx assessed: %+v", svc.Nginx)
	}
}
