package web

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/qnginxscanner/internal/nginx"
	"github.com/rom/qnginxscanner/internal/scanner"
)

// runScan drives one scan through the API and drains the NDJSON stream.
func runScan(t *testing.T, base, body string) {
	t.Helper()
	resp, err := http.Post(base+"/api/scan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("scan status %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg streamMsg
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("bad NDJSON: %v", err)
		}
		if msg.Type == "error" {
			t.Fatalf("scan error: %s", msg.Error)
		}
	}
}

func getJSON(t *testing.T, url string, out interface{}) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if len(data) > 0 && out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("decode %s: %v (%s)", url, err, data)
		}
	}
	return resp.StatusCode
}

func TestOverviewAndDiff(t *testing.T) {
	target := nginxTarget()
	defer target.Close()
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := `{"targets":["` + target.URL + `"],"mode":"deep","tls":"off","security_txt":false}`
	runScan(t, srv.URL, body)
	runScan(t, srv.URL, body)

	// Overview aggregates across the two retained scans.
	var ov overview
	if code := getJSON(t, srv.URL+"/api/overview", &ov); code != 200 {
		t.Fatalf("overview status %d", code)
	}
	if ov.Stats.Scans != 2 {
		t.Errorf("stats.scans = %d, want 2", ov.Stats.Scans)
	}
	if ov.Stats.Services == 0 {
		t.Error("overview reported no services")
	}
	if ov.Stats.OldestNginx == nil || ov.Stats.OldestNginx.Version != "1.24.0" {
		t.Errorf("overview oldest nginx = %+v, want 1.24.0", ov.Stats.OldestNginx)
	}
	if len(ov.Stats.TopNetworks) == 0 {
		t.Error("overview missing top networks")
	}

	// Diff latest against itself: no changes.
	var d map[string]interface{}
	if code := getJSON(t, srv.URL+"/api/diff?a=latest&b=latest", &d); code != 200 {
		t.Fatalf("diff status %d", code)
	}
	if _, ok := d["diff"]; !ok {
		t.Errorf("diff response missing diff key: %v", d)
	}

	// Diff with a missing scan id is a clean 400.
	if code := getJSON(t, srv.URL+"/api/diff?a=latest&b=scan-does-not-exist", nil); code != 400 {
		t.Errorf("diff with bad id => %d, want 400", code)
	}
}

func TestOverviewTopServers(t *testing.T) {
	// A target that advertises nginx should show up in the web-server toplist.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		_, _ = w.Write([]byte("<title>Welcome to nginx!</title>"))
	}))
	defer target.Close()

	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	runScan(t, srv.URL, `{"targets":["`+target.URL+`"],"mode":"detect","tls":"off","security_txt":false}`)

	var ov overview
	getJSON(t, srv.URL+"/api/overview", &ov)
	found := false
	for _, e := range ov.Stats.TopServers {
		if e.Key == "nginx" && e.Count >= 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("top_servers missing nginx: %+v", ov.Stats.TopServers)
	}
}

func TestOriginCompare(t *testing.T) {
	// Edge: a plain, non-nginx page. Origin: an nginx service. Both on loopback;
	// the origin is reached by pinning the connection to its address.
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>home</title>"))
	}))
	defer edge.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		_, _ = w.Write([]byte("<title>origin</title>"))
	}))
	defer origin.Close()

	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	originAddr := strings.TrimPrefix(origin.URL, "http://") // 127.0.0.1:PORT
	body := `{"target":"` + edge.URL + `","origin":"` + originAddr + `","mode":"detect","tls":"off"}`
	resp, err := http.Post(srv.URL+"/api/origin-compare", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("origin-compare status %d: %s", resp.StatusCode, data)
	}
	var out struct {
		Host       string `json:"host"`
		OriginAddr string `json:"origin_addr"`
		Diff       struct {
			Changed []struct {
				URL           string `json:"url"`
				VerdictChange string `json:"verdict_change"`
			} `json:"changed"`
			AddedServices []string `json:"added_services"`
		} `json:"diff"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.OriginAddr != originAddr {
		t.Errorf("origin_addr = %q, want %q", out.OriginAddr, originAddr)
	}
	// The origin reveals nginx where the edge did not: a verdict change on the
	// shared URL (or, failing that, some recorded difference).
	changed := len(out.Diff.Changed) > 0
	if !changed && len(out.Diff.AddedServices) == 0 {
		t.Fatalf("expected the origin to differ from the edge: %+v", out.Diff)
	}
}

func TestVersionEndpoint(t *testing.T) {
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	var v map[string]string
	if code := getJSON(t, srv.URL+"/api/version", &v); code != 200 {
		t.Fatalf("version status %d", code)
	}
	if v["name"] == "" || v["version"] == "" {
		t.Errorf("version payload incomplete: %+v", v)
	}

	// Wrong method on a known endpoint is a clean 405, not an opaque file-server
	// response.
	resp, err := http.Post(srv.URL+"/api/version", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Errorf("POST /api/version => %d, want 405", resp.StatusCode)
	}
}

func TestScanBlockListDropsTarget(t *testing.T) {
	target := nginxTarget()
	defer target.Close()
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// Block everything via a catch-all suffix so no service is scanned.
	host := strings.TrimPrefix(target.URL, "http://")
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	body := `{"targets":["` + target.URL + `"],"mode":"detect","tls":"off","security_txt":false,"block":["` + host + `"]}`
	runScan(t, srv.URL, body)

	var ov overview
	getJSON(t, srv.URL+"/api/overview", &ov)
	// The most recent scan contributed no services (blocked), so the service
	// total should remain 0 for this fresh server.
	if ov.Stats.Services != 0 {
		t.Errorf("blocked scan still produced %d services", ov.Stats.Services)
	}
}

func TestScanStreamsServiceMessages(t *testing.T) {
	target := nginxTarget()
	defer target.Close()
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// Scan an open nginx target plus a closed port; both should stream as
	// "service" messages even though include_closed is off.
	host := strings.TrimPrefix(target.URL, "http://")
	h, portStr, _ := strings.Cut(host, ":")
	_ = portStr
	body := `{"targets":["` + h + `"],"ports":"` + portStr + `,1","mode":"detect","tls":"off","security_txt":false}`

	resp, err := http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var services, open, closed int
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg streamMsg
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("bad NDJSON: %v", err)
		}
		if msg.Type == "service" && msg.Service != nil {
			services++
			if msg.Service.PortOpen {
				open++
			} else {
				closed++
			}
		}
	}
	if services < 2 {
		t.Fatalf("expected >=2 service messages, got %d", services)
	}
	if open == 0 || closed == 0 {
		t.Errorf("expected both open (%d) and closed (%d) services streamed", open, closed)
	}
}

func TestOverviewBreakdownsAndUploadDiff(t *testing.T) {
	target := nginxTarget()
	defer target.Close()
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := `{"targets":["` + target.URL + `"],"mode":"deep","tls":"off","security_txt":false}`
	runScan(t, srv.URL, body)

	// Overview now carries severity/verdict breakdowns for the charts.
	var ov overview
	getJSON(t, srv.URL+"/api/overview", &ov)
	if ov.Stats.VerdictBreakdown["confirmed"] == 0 {
		t.Errorf("verdict_breakdown missing confirmed: %+v", ov.Stats.VerdictBreakdown)
	}
	if len(ov.Stats.SeverityBreakdown) == 0 {
		t.Errorf("severity_breakdown empty: %+v", ov.Stats.SeverityBreakdown)
	}
	// nginx-per-port breakdown is keyed by scheme/port and totals the nginx services.
	if len(ov.Stats.NginxByPort) == 0 {
		t.Errorf("nginx_by_port empty: %+v", ov.Stats.NginxByPort)
	} else {
		total := 0
		for _, n := range ov.Stats.NginxByPort {
			total += n
		}
		if total != ov.Stats.NginxServices {
			t.Errorf("nginx_by_port totals %d, want nginx_services %d (%+v)", total, ov.Stats.NginxServices, ov.Stats.NginxByPort)
		}
	}

	// Download the scan as JSON, then diff that uploaded file against the
	// retained latest scan.
	dr, err := http.Get(srv.URL + "/api/download?format=json")
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := io.ReadAll(dr.Body)
	dr.Body.Close()

	resp, err := http.Post(srv.URL+"/api/diff-upload?b=latest", "application/octet-stream", strings.NewReader(string(saved)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("diff-upload status %d", resp.StatusCode)
	}
	var d map[string]interface{}
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := d["diff"]; !ok {
		t.Errorf("diff-upload response missing diff: %s", data)
	}

	// Also accept the XML form.
	xr, _ := http.Get(srv.URL + "/api/download?format=xml")
	xdata, _ := io.ReadAll(xr.Body)
	xr.Body.Close()
	xresp, err := http.Post(srv.URL+"/api/diff-upload?b=latest", "application/xml", strings.NewReader(string(xdata)))
	if err != nil {
		t.Fatal(err)
	}
	defer xresp.Body.Close()
	if xresp.StatusCode != 200 {
		t.Fatalf("diff-upload (xml) status %d", xresp.StatusCode)
	}
}

// nginxFixtureResult builds a scan result directly from nginx.Detection
// fixtures so the overview aggregation can be asserted exactly.
func nginxFixtureResult() *scanner.ScanResult {
	svc := func(host string, port int, scheme string, d *nginx.Detection) scanner.ServiceResult {
		return scanner.ServiceResult{
			Host: host, Port: port, Scheme: scheme, PortOpen: true,
			URL:   scheme + "://" + host + ":" + strconv.Itoa(port) + "/",
			Nginx: d,
		}
	}
	chain := nginx.Vulnerability{ID: "CVE-2026-123633", Severity: "critical", Title: "UAF in HTTP/2", Tags: []string{"nginx2root"}}
	disclosure := nginx.Finding{ID: "version-disclosure", Severity: "info", Title: "Server version is disclosed"}
	return &scanner.ScanResult{
		Meta: scanner.Meta{Mode: "deep", DurationMS: 40},
		Targets: []scanner.TargetResult{{
			Host: "10.0.0.5",
			Services: []scanner.ServiceResult{
				// End-of-life, NGINX2Root-affected, with a finding and a lead.
				svc("10.0.0.5", 80, "http", &nginx.Detection{
					IsNginx: true, Verdict: nginx.VerdictConfirmed, Confidence: 100,
					Variant: "nginx", Version: "1.24.0", Branch: "legacy", EndOfLife: true,
					Nginx2Root:      &nginx.Nginx2Root{Status: "vulnerable-version", CVEs: []string{chain.ID}},
					Vulnerabilities: []nginx.Vulnerability{chain},
					Findings: []nginx.Finding{
						disclosure,
						{ID: "alias-traversal", Severity: "high", Title: "Path traversal via misconfigured alias"},
					},
				}),
				// Same version on another port: groups with the first.
				svc("10.0.0.5", 443, "https", &nginx.Detection{
					IsNginx: true, Verdict: nginx.VerdictConfirmed, Confidence: 95,
					Variant: "nginx", Version: "1.24.0", Branch: "legacy", EndOfLife: true,
					Nginx2Root:      &nginx.Nginx2Root{Status: "vulnerable-version", CVEs: []string{chain.ID}},
					Vulnerabilities: []nginx.Vulnerability{chain},
					Findings:        []nginx.Finding{disclosure},
				}),
				// Version hidden: NGINX2Root exposure unknown.
				svc("10.0.0.5", 8080, "http", &nginx.Detection{
					IsNginx: true, Verdict: nginx.VerdictLikely, Confidence: 60,
					Variant: "nginx", VersionHidden: true,
					Nginx2Root: &nginx.Nginx2Root{Status: "unknown-version"},
				}),
				// Patched derivative: not affected, supported.
				svc("10.0.0.5", 8443, "https", &nginx.Detection{
					IsNginx: true, Verdict: nginx.VerdictConfirmed, Confidence: 90,
					Variant: "OpenResty", Version: "1.31.9", ProductVersion: "1.31.9.1", Branch: "mainline",
					Nginx2Root: &nginx.Nginx2Root{Status: "not-affected"},
				}),
				// Analysed but not nginx: counted as a service only.
				svc("10.0.0.5", 9000, "http", &nginx.Detection{Verdict: nginx.VerdictNone}),
			},
		}},
	}
}

func TestOverviewNginxStats(t *testing.T) {
	s := NewServer("x")
	s.history = []historyItem{{ID: "scan-1", At: time.Now(), Result: nginxFixtureResult()}}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	var ov overview
	if code := getJSON(t, srv.URL+"/api/overview", &ov); code != 200 {
		t.Fatalf("overview status %d", code)
	}
	st := ov.Stats
	if st.Scans != 1 || st.Services != 5 {
		t.Errorf("scans/services = %d/%d, want 1/5", st.Scans, st.Services)
	}
	if st.NginxServices != 4 {
		t.Errorf("nginx_services = %d, want 4", st.NginxServices)
	}
	if st.EndOfLife != 2 {
		t.Errorf("end_of_life = %d, want 2", st.EndOfLife)
	}
	if st.Nginx2Root != 2 || st.Nginx2RootUnknown != 1 {
		t.Errorf("nginx2root/unknown = %d/%d, want 2/1", st.Nginx2Root, st.Nginx2RootUnknown)
	}
	if st.HighestSeverity != "critical" {
		t.Errorf("highest_severity = %q, want critical", st.HighestSeverity)
	}
	if st.OldestNginx == nil || st.OldestNginx.Version != "1.24.0" || st.OldestNginx.Host != "10.0.0.5" {
		t.Errorf("oldest_nginx = %+v, want 1.24.0 on 10.0.0.5", st.OldestNginx)
	}
	if st.VerdictBreakdown["confirmed"] != 3 || st.VerdictBreakdown["likely"] != 1 || st.VerdictBreakdown["none"] != 1 {
		t.Errorf("verdict_breakdown = %+v", st.VerdictBreakdown)
	}
	if st.SeverityBreakdown["critical"] != 2 {
		t.Errorf("severity_breakdown = %+v, want critical:2", st.SeverityBreakdown)
	}
	if st.NginxByPort["http/80"] != 1 || st.NginxByPort["https/443"] != 1 || len(st.NginxByPort) != 4 {
		t.Errorf("nginx_by_port = %+v", st.NginxByPort)
	}
	if len(st.TopVersions) == 0 || st.TopVersions[0].Key != "nginx 1.24.0" || st.TopVersions[0].Count != 2 {
		t.Errorf("top_versions = %+v, want nginx 1.24.0 x2 first", st.TopVersions)
	}
	if len(st.TopVulns) != 1 || st.TopVulns[0].Key != "CVE-2026-123633" || st.TopVulns[0].Count != 2 || st.TopVulns[0].Severity != "critical" {
		t.Errorf("top_vulns = %+v", st.TopVulns)
	}

	group := func(gs []tagGroup, name string) *tagGroup {
		for i := range gs {
			if gs[i].Name == name {
				return &gs[i]
			}
		}
		return nil
	}
	// Versions: one tag per product+version, most common first.
	if len(ov.Versions) != 3 {
		t.Fatalf("versions = %+v, want 3 groups", ov.Versions)
	}
	if g := ov.Versions[0]; g.Name != "nginx 1.24.0" || g.Count != 2 || len(g.Items) != 2 {
		t.Errorf("versions[0] = %+v, want nginx 1.24.0 x2", g)
	}
	if g := group(ov.Versions, "nginx (version hidden)"); g == nil || g.Count != 1 {
		t.Errorf("versions missing hidden-version group: %+v", ov.Versions)
	}
	if g := group(ov.Versions, "OpenResty 1.31.9.1"); g == nil || g.Count != 1 {
		t.Errorf("versions missing OpenResty group: %+v", ov.Versions)
	}
	// Findings: grouped by title, carrying severity and back-references.
	if len(ov.Findings) != 2 {
		t.Fatalf("findings = %+v, want 2 groups", ov.Findings)
	}
	if g := group(ov.Findings, "Server version is disclosed"); g == nil || g.Count != 2 || g.Severity != "info" {
		t.Errorf("findings disclosure group = %+v", g)
	}
	if g := group(ov.Findings, "Path traversal via misconfigured alias"); g == nil || g.Count != 1 || g.Severity != "high" ||
		g.Items[0].ScanID != "scan-1" || g.Items[0].URL != "http://10.0.0.5:80/" {
		t.Errorf("findings alias group = %+v", g)
	}
	// Vulns: grouped by advisory id.
	if len(ov.Vulns) != 1 || ov.Vulns[0].Name != "CVE-2026-123633" || ov.Vulns[0].Count != 2 || ov.Vulns[0].Severity != "critical" {
		t.Errorf("vulns = %+v", ov.Vulns)
	}
}

// TestOverviewJSONKeys pins the wire names the GUI reads.
func TestOverviewJSONKeys(t *testing.T) {
	s := NewServer("x")
	s.history = []historyItem{{ID: "scan-1", At: time.Now(), Result: nginxFixtureResult()}}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	var raw map[string]json.RawMessage
	if code := getJSON(t, srv.URL+"/api/overview", &raw); code != 200 {
		t.Fatalf("overview status %d", code)
	}
	for _, k := range []string{"stats", "versions", "findings", "vulns"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("overview missing %q", k)
		}
	}
	var stats map[string]json.RawMessage
	if err := json.Unmarshal(raw["stats"], &stats); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"scans", "services", "nginx_services", "highest_severity", "avg_scan_ms", "oldest_nginx",
		"end_of_life", "nginx2root", "nginx2root_unknown", "top_vulns", "top_versions", "top_networks", "top_servers",
		"severity_breakdown", "verdict_breakdown", "nginx_by_port"} {
		if _, ok := stats[k]; !ok {
			t.Errorf("overview stats missing %q", k)
		}
	}
}
