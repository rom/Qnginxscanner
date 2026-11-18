package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rom/qnginxscanner/internal/nginx"
	"github.com/rom/qnginxscanner/internal/scanner"
	"github.com/rom/qnginxscanner/internal/webserver"
)

func richResult() *scanner.ScanResult {
	now := time.Now()
	return &scanner.ScanResult{
		Meta: scanner.Meta{Tool: "qnginxscanner", Version: "0.1.0", Mode: "deep", StartedAt: now, FinishedAt: now},
		Targets: []scanner.TargetResult{{
			Host: "h", Addresses: []string{"203.0.113.5"}, PTR: []string{"host.example"},
			Services: []scanner.ServiceResult{{
				Host: "h", Port: 443, TLS: true, Scheme: "https", URL: "https://h/", PortOpen: true,
				HTTP:   &scanner.HTTPInfo{Status: 200, Server: "cloudflare"},
				Server: &webserver.ServerInfo{Product: "nginx", Version: "1.25.3", Modules: []string{"OpenSSL/3.0"}},
				Proxy: &webserver.ProxyInfo{
					Present: true, Concealed: true, CDN: []string{"Cloudflare"}, WAF: []string{"Cloudflare"},
					Note: "A WAF / security proxy (Cloudflare) is in front.",
				},
				Nginx: &nginx.Detection{
					IsNginx: true, Verdict: nginx.VerdictConfirmed, Confidence: 95, Variant: "nginx",
					Version: "1.18.0", VersionSource: "Server header", Branch: "legacy", Distro: "Ubuntu",
					EndOfLife: true, EOLDetail: "nginx 1.18 is a legacy branch",
					Protocols: []string{"http/1.1", "h2"}, Modules: []string{"http_ssl", "http_v2", "http_stub_status"},
					H2Fingerprint: "3:128;4:65536;5:16777215|2147418112",
					StatusExposed: true, StatusURL: "https://h/nginx_status",
					Nginx2Root: &nginx.Nginx2Root{
						Status: "vulnerable-version", CVEs: []string{"CVE-2026-123007"},
						HTTP2: "observed", HTTP3: "unknown", Mail: "unknown", Detail: "nginx 1.18.0 is in the affected range",
					},
					Findings: []nginx.Finding{{
						ID: "stub-status-exposed", Severity: "low", Title: "stub_status page is publicly exposed",
						Detail: "counters readable", URL: "https://h/nginx_status", Remediation: "allow 127.0.0.1; deny all;",
					}},
					Vulnerabilities: []nginx.Vulnerability{
						{ID: "CVE-2026-123007", Severity: "critical", Title: "Memory corruption in HTTP/2 flow control", AffectedVersions: "1.9.5-1.31.8",
							FixedVersions: "1.31.9+, 1.30.7+", MatchBasis: "version-correlation", Tags: []string{"nginx2root"}, Applicability: "observed",
							Prerequisites: []nginx.PrereqResult{{Detail: "requires HTTP/2 to be enabled", State: "observed"}}},
						{ID: "CVE-2019-9513", Severity: "low", Title: "Excessive CPU usage in HTTP/2 with priority changes", AffectedVersions: "1.9.5-1.17.2", MatchBasis: "version-correlation"},
					},
				},
			}, {
				Host: "h", Port: 22, Scheme: "http", URL: "http://h:22/", PortOpen: true,
				Banner: "SSH-2.0-OpenSSH_8.9",
			}},
		}},
		Summary: scanner.Summary{HostsScanned: 1, OpenPorts: 2, NginxConfirmed: 1, Vulnerabilities: 2},
	}
}

func TestSARIFOutput(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, richResult(), "sarif"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("version: %v", doc["version"])
	}
	s := b.String()
	for _, want := range []string{"CVE-2026-123007", "nginx-end-of-life", "nginx-stub-status-exposed", "nginx2root", "security-severity"} {
		if !strings.Contains(s, want) {
			t.Fatalf("SARIF missing %q", want)
		}
	}
}

func TestCSVOutput(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, richResult(), "csv"); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&b).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 { // header + 2 services
		t.Fatalf("want 3 rows, got %d", len(rows))
	}
	if rows[0][0] != "host" {
		t.Fatalf("header: %v", rows[0])
	}
	joined := strings.Join(rows[1], ",")
	if !strings.Contains(joined, "CVE-2026-123007") || !strings.Contains(joined, "critical") {
		t.Fatalf("row missing vuln data: %v", rows[1])
	}
}

func TestNDJSONOutput(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, richResult(), "ndjson"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 3 { // meta + 2 services
		t.Fatalf("want 3 NDJSON lines, got %d", len(lines))
	}
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &meta); err != nil || meta["type"] != "meta" {
		t.Fatalf("first line should be meta: %v", meta)
	}
}

func TestHTMLReport(t *testing.T) {
	var b bytes.Buffer
	if err := WriteReport(&b, richResult(), "html"); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.HasPrefix(s, "<!doctype html>") {
		t.Fatal("not HTML")
	}
	for _, want := range []string{"<h1>", "CVE-2026-123007", "SSH-2.0-OpenSSH_8.9", "NGINX2Root", "stub_status page is publicly exposed", "fixed in 1.31.9+, 1.30.7+", "precondition (observed)"} {
		if !strings.Contains(s, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
}

func TestProxyServerRendering(t *testing.T) {
	res := richResult()
	var txt bytes.Buffer
	if err := WriteReport(&txt, res, "text"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Reverse proxy", "Cloudflare", "nginx 1.25.3", "concealed"} {
		if !strings.Contains(txt.String(), want) {
			t.Fatalf("text report missing %q", want)
		}
	}
	var csvb bytes.Buffer
	if err := WriteOutput(&csvb, res, "csv"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(csvb.String(), "server_product") || !strings.Contains(csvb.String(), "nginx") {
		t.Fatal("CSV missing server columns")
	}
}

func TestSeverityHelpers(t *testing.T) {
	res := richResult()
	sev, rank := HighestSeverity(res)
	if sev != "critical" || rank != 4 {
		t.Fatalf("highest severity: %s/%d", sev, rank)
	}
	if !HasEOL(res) {
		t.Fatal("should detect EOL")
	}
	for _, level := range []string{"low", "medium", "high", "critical", "eol"} {
		if !FailOn(res, level) {
			t.Fatalf("FailOn(%q) should trigger", level)
		}
	}
	if FailOn(res, "bogus") {
		t.Fatal("unknown level must not trigger")
	}
	// A clean result should not trip any gate.
	clean := &scanner.ScanResult{}
	if FailOn(clean, "low") || FailOn(clean, "eol") {
		t.Fatal("clean scan must not fail gates")
	}
}

func TestDiff(t *testing.T) {
	oldRes := richResult()
	newRes := richResult()
	// Change the version and drop a vuln; add a new service.
	newRes.Targets[0].Services[0].Nginx.Version = "1.31.9"
	newRes.Targets[0].Services[0].Nginx.Vulnerabilities = []nginx.Vulnerability{
		{ID: "CVE-2024-4577", Severity: "critical"},
	}
	newRes.Targets[0].Services = append(newRes.Targets[0].Services, scanner.ServiceResult{
		Host: "h", Port: 8080, URL: "http://h:8080/", PortOpen: true,
	})

	d := Diff(oldRes, newRes)
	if d.Empty() {
		t.Fatal("expected differences")
	}
	if len(d.AddedServices) != 1 || d.AddedServices[0] != "http://h:8080/" {
		t.Fatalf("added: %v", d.AddedServices)
	}
	found := false
	for _, c := range d.Changed {
		if c.URL == "https://h/" {
			found = true
			if c.VersionChange == "" || len(c.NewVulns) == 0 || len(c.ResolvedVulns) == 0 {
				t.Fatalf("incomplete change: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("expected a change on https://h/")
	}

	var jb bytes.Buffer
	if err := WriteDiff(&jb, d, "json"); err != nil {
		t.Fatal(err)
	}
	var tb bytes.Buffer
	if err := WriteDiff(&tb, d, "text"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tb.String(), "SCAN DIFF") {
		t.Fatal("text diff missing header")
	}

	// Identical scans → empty diff.
	same := Diff(richResult(), richResult())
	if !same.Empty() {
		t.Fatal("identical scans should diff empty")
	}
}

func TestLoadScan(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, richResult(), "json"); err != nil {
		t.Fatal(err)
	}
	res, err := LoadScan(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Targets) != 1 {
		t.Fatalf("round-trip lost targets: %+v", res)
	}
	if _, err := LoadScan([]byte("not json")); err == nil {
		t.Fatal("expected parse error")
	}
}
