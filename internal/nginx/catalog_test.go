package nginx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func vulnIDs(vs []Vulnerability) map[string]Vulnerability {
	m := map[string]Vulnerability{}
	for _, v := range vs {
		m[v.ID] = v
	}
	return m
}

func TestNginx2RootRanges(t *testing.T) {
	type want struct{ h2flow, h2uaf, h3, resolver, mail bool }
	cases := map[string]want{
		"0.5.32":  {},                           // before all of them
		"0.5.33":  {mail: true},                 // mail proxy bug introduced
		"0.6.18":  {resolver: true, mail: true}, // resolver bug introduced
		"1.9.4":   {resolver: true, mail: true}, // last release without HTTP/2
		"1.9.5":   {h2flow: true, resolver: true, mail: true},
		"1.19.6":  {h2flow: true, resolver: true, mail: true},
		"1.19.7":  {h2flow: true, h2uaf: true, resolver: true, mail: true},
		"1.24.0":  {h2flow: true, h2uaf: true, resolver: true, mail: true},
		"1.25.0":  {true, true, true, true, true},
		"1.30.6":  {true, true, true, true, true}, // stable, one short of the fix
		"1.30.7":  {},                             // stable fix
		"1.30.12": {},                             // later stable
		"1.31.8":  {true, true, true, true, true}, // last vulnerable mainline
		"1.31.9":  {},                             // mainline fix
		"1.32.0":  {},                             // future branch
	}
	cat := DefaultCatalog()
	for ver, w := range cases {
		got := vulnIDs(cat.Correlate("nginx", ver))
		check := func(id string, want bool) {
			if _, ok := got[id]; ok != want {
				t.Errorf("nginx %s: %s matched=%v, want %v", ver, id, ok, want)
			}
		}
		check("CVE-2026-123007", w.h2flow)
		check("CVE-2026-123633", w.h2uaf)
		check("CVE-2026-121810", w.h3)
		check("CVE-2026-123634", w.resolver)
		check("CVE-2026-113425", w.mail)
	}
}

func TestNginx2RootCatalogueEntries(t *testing.T) {
	byID := map[string]FeedEntry{}
	for _, e := range builtinAdvisories {
		if _, dup := byID[e.ID]; dup {
			t.Errorf("duplicate advisory %s", e.ID)
		}
		byID[e.ID] = e
		if len(e.Affected) == 0 || e.Title == "" || e.Reference == "" || SeverityRank(e.Severity) == 0 {
			t.Errorf("%s: incomplete entry %+v", e.ID, e)
		}
	}
	for _, id := range Nginx2RootCVEs {
		e, ok := byID[id]
		if !ok {
			t.Fatalf("%s missing from the catalogue", id)
		}
		if len(e.Tags) != 1 || e.Tags[0] != TagNginx2Root {
			t.Errorf("%s: tags = %v", id, e.Tags)
		}
		if strings.Join(e.FixedIn, ",") != "1.31.9,1.30.7" {
			t.Errorf("%s: fixed in %v", id, e.FixedIn)
		}
	}
	if len(builtinAdvisories) < 70 {
		t.Errorf("catalogue unexpectedly small: %d", len(builtinAdvisories))
	}
}

func TestHistoricRanges(t *testing.T) {
	cat := DefaultCatalog()
	has := func(ver, id string) bool { _, ok := vulnIDs(cat.Correlate("nginx", ver))[id]; return ok }
	checks := []struct {
		ver, id string
		want    bool
	}{
		{"1.4.0", "CVE-2013-2028", true}, {"1.3.8", "CVE-2013-2028", false}, {"1.4.1", "CVE-2013-2028", false},
		{"1.20.0", "CVE-2021-23017", true}, {"1.20.1", "CVE-2021-23017", false}, {"1.21.0", "CVE-2021-23017", false},
		{"1.13.2", "CVE-2017-7529", true}, {"1.12.1", "CVE-2017-7529", false}, {"1.12.0", "CVE-2017-7529", true},
		// Two disjoint vulnerable ranges with three fixed branches.
		{"1.2.8", "CVE-2013-2070", true}, {"1.2.9", "CVE-2013-2070", false}, {"1.3.0", "CVE-2013-2070", false}, {"1.4.0", "CVE-2013-2070", true},
		// Discrete version plus a range.
		{"1.26.0", "CVE-2024-32760", true}, {"1.26.1", "CVE-2024-32760", false}, {"1.25.5", "CVE-2024-32760", true},
		{"1.25.3", "CVE-2024-24989", true}, {"1.25.2", "CVE-2024-24989", false},
		// Stable-only range.
		{"1.30.5", "CVE-2026-93479", true}, {"1.30.6", "CVE-2026-93479", false}, {"1.29.8", "CVE-2026-93479", false},
	}
	for _, c := range checks {
		if got := has(c.ver, c.id); got != c.want {
			t.Errorf("nginx %s vs %s: got %v, want %v", c.ver, c.id, got, c.want)
		}
	}
}

func TestCorrelateVariants(t *testing.T) {
	cat := DefaultCatalog()
	if len(cat.Correlate("nginx", "")) != 0 || len(cat.Correlate("nginx", "garbage")) != 0 {
		t.Error("empty/garbage versions must not correlate")
	}
	for _, v := range []string{"Tengine", "Angie", "freenginx", "Kong", "Apache APISIX"} {
		if len(cat.Correlate(v, "1.24.0")) != 0 {
			t.Errorf("%s must not be correlated against nginx.org ranges", v)
		}
	}
	or := cat.Correlate("OpenResty", "1.25.3")
	if len(or) == 0 || !strings.Contains(or[0].MatchBasis, "OpenResty") {
		t.Errorf("OpenResty: %+v", or)
	}
	if len(CorrelateVulns("nginx", "1.31.9")) != 0 {
		t.Errorf("current mainline should be clean: %+v", CorrelateVulns("nginx", "1.31.9"))
	}
}

func TestPrerequisites(t *testing.T) {
	cat := DefaultCatalog()
	get := func(f ObservedFacts, id string) Vulnerability {
		return vulnIDs(cat.Correlate("nginx", "1.25.3", f))[id]
	}

	v := get(ObservedFacts{HTTP2: "observed"}, "CVE-2026-123007")
	if v.Applicability != "observed" || v.Prerequisites[0].State != "observed" || v.FixedVersions != "1.31.9+, 1.30.7+" || v.AffectedVersions != "1.9.5-1.31.8" {
		t.Errorf("observed: %+v", v)
	}
	if v := get(ObservedFacts{HTTP2: "contradicted"}, "CVE-2026-123007"); v.Applicability != "contradicted" {
		t.Errorf("contradicted: %+v", v)
	}
	if v := get(ObservedFacts{}, "CVE-2026-123007"); v.Applicability != "" || v.Prerequisites[0].State != "unknown" {
		t.Errorf("unknown: %+v", v)
	}
	if v := get(ObservedFacts{HTTP3: "observed"}, "CVE-2026-121810"); v.Applicability != "observed" {
		t.Errorf("h3: %+v", v)
	}
	if v := get(ObservedFacts{Mail: "observed"}, "CVE-2026-113425"); v.Applicability != "observed" {
		t.Errorf("mail: %+v", v)
	}
	if v := get(ObservedFacts{Modules: map[string]bool{"http_dav": true}}, "CVE-2026-27654"); v.Applicability != "observed" {
		t.Errorf("module: %+v", v)
	}
	// Config-only conditions are context, never resolved.
	if v := get(ObservedFacts{HTTP2: "observed"}, "CVE-2026-123634"); v.Applicability != "" || v.Prerequisites[0].State != "unknown" {
		t.Errorf("config: %+v", v)
	}
	// OS prerequisite.
	win := vulnIDs(cat.Correlate("nginx", "1.3.0", ObservedFacts{OS: "linux"}))["CVE-2011-4963"]
	if win.Applicability != "contradicted" {
		t.Errorf("os: %+v", win)
	}
	if r := resolvePrereq(Prereq{Kind: "os", Want: "windows"}, ObservedFacts{OS: "Windows"}); r != "observed" {
		t.Errorf("os observed: %s", r)
	}
	if r := resolvePrereq(Prereq{Kind: "protocol", Want: "spdy"}, ObservedFacts{}); r != "unknown" {
		t.Errorf("unknown protocol: %s", r)
	}
	if d := prereqDetail(Prereq{Kind: "weird", Want: "x"}); d != "weird x" {
		t.Errorf("detail: %q", d)
	}
}

func TestSupport(t *testing.T) {
	cat := DefaultCatalog()
	cases := []struct {
		ver, branch   string
		eol, outdated bool
	}{
		{"1.31.9", "mainline", false, false},
		{"1.31.2", "mainline", false, true},
		{"1.30.7", "stable", false, false},
		{"1.30.0", "stable", false, true},
		{"1.28.3", "legacy", true, false},
		{"1.18.0", "legacy", true, false},
		{"0.7.65", "legacy", true, false},
	}
	for _, c := range cases {
		s := cat.Support("nginx", c.ver)
		if s.Branch != c.branch || s.EndOfLife != c.eol || s.Outdated != c.outdated || s.Detail == "" {
			t.Errorf("%s: %+v", c.ver, s)
		}
	}
	if s := cat.Support("Tengine", "3.1.0"); s != (Support{}) {
		t.Errorf("derivatives have no nginx lifecycle: %+v", s)
	}
	if s := cat.Support("nginx", "x"); s != (Support{}) {
		t.Errorf("garbage: %+v", s)
	}
	if BranchKind("1.24.0") != "stable" || BranchKind("1.25.1") != "mainline" || BranchKind("") != "" {
		t.Error("BranchKind")
	}
}

func TestDeepAssessment(t *testing.T) {
	d := analyzeServer(t, "nginx/1.18.0 (Ubuntu)")
	if !d.EndOfLife || d.Branch != "legacy" || d.Nginx2Root.Status != "vulnerable-version" || len(d.Nginx2Root.CVEs) != 3 {
		t.Fatalf("1.18.0: %+v / %+v", d, d.Nginx2Root)
	}
	if !strings.Contains(d.Nginx2Root.Detail, "Ubuntu") {
		t.Errorf("distro caveat missing: %s", d.Nginx2Root.Detail)
	}
	if d.Vulnerabilities[0].Severity != "critical" {
		t.Errorf("worst first: %+v", d.Vulnerabilities[0])
	}
	if !hasFinding(d, "version-disclosure") {
		t.Error("missing version-disclosure")
	}
	d = analyzeServer(t, "nginx/1.31.9")
	if d.EndOfLife || d.Outdated || d.Nginx2Root.Status != "not-affected" || len(d.Vulnerabilities) != 0 {
		t.Errorf("1.31.9: %+v / %+v", d, d.Nginx2Root)
	}
	d = analyzeServer(t, "nginx/1.30.7")
	if d.Nginx2Root.Status != "not-affected" || d.Branch != "stable" {
		t.Errorf("1.30.7: %+v", d.Nginx2Root)
	}
	d = analyzeServer(t, "Tengine/3.1.0")
	if d.Nginx2Root.Status != "unknown-version" || !strings.Contains(d.Nginx2Root.Detail, "Tengine") || len(d.Vulnerabilities) != 0 {
		t.Errorf("tengine: %+v", d.Nginx2Root)
	}
	d = analyzeServer(t, "openresty/1.21.4.3")
	if d.Nginx2Root.Status != "vulnerable-version" || d.EndOfLife {
		t.Errorf("openresty: %+v eol=%v", d.Nginx2Root, d.EndOfLife)
	}
}

func TestFeedMergeAndLoad(t *testing.T) {
	feedJSON := `{"schema":"qnginxscanner-vuln-feed/1",
	  "nginx":[{"id":"X-1","severity":"high","title":"t","note":"n","affected":[{"introduced":"1.31.0","fixed":"1.31.20"},{"branch":"1.30","lt":"1.30.9"},{"eq":"1.2.3"},{"lt":"0.1.0"},{"branch":"1.7"},{"introduced":"9.0.0"}],"fixed_in":["1.31.15"]}],
	  "supported":{"1.33":"mainline","1.32":"stable"},"latest":{"1.33":"1.33.1"}}`
	feed, err := ParseFeed([]byte(feedJSON))
	if err != nil {
		t.Fatal(err)
	}
	cat := DefaultCatalog()
	n := cat.Count()
	cat.Merge(feed)
	cat.Merge(nil)
	if cat.Count() != n+1 || len(cat.Entries()) != n+1 {
		t.Errorf("count %d → %d", n, cat.Count())
	}
	x := func(ver string) (Vulnerability, bool) {
		v, ok := vulnIDs(cat.Correlate("nginx", ver))["X-1"]
		return v, ok
	}
	if v, ok := x("1.31.12"); !ok || !strings.Contains(v.MatchBasis, "applies to: n") || !strings.Contains(v.AffectedVersions, "1.30.x < 1.30.9") {
		t.Errorf("1.31.12: %v %+v", ok, v)
	}
	for ver, want := range map[string]bool{"1.31.15": false, "1.31.20": false, "1.30.8": true, "1.30.9": false, "1.2.3": true, "1.7.4": true, "0.0.9": true} {
		if _, ok := x(ver); ok != want {
			t.Errorf("%s: got %v want %v", ver, ok, want)
		}
	}
	if s := cat.Support("nginx", "1.31.9"); !s.EndOfLife {
		t.Errorf("supported set should be replaced: %+v", s)
	}
	if s := cat.Support("nginx", "1.33.0"); s.Branch != "mainline" || !s.Outdated {
		t.Errorf("1.33.0: %+v", s)
	}
	if s := cat.Support("nginx", "1.32.4"); s.Branch != "stable" || s.Outdated || s.EndOfLife {
		t.Errorf("1.32.4: %+v", s)
	}

	if _, err := ParseFeed([]byte(`{"schema":"other/9","nginx":[]}`)); err == nil {
		t.Error("want schema error")
	}
	if _, err := ParseFeed([]byte(`{`)); err == nil {
		t.Error("want parse error")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(path, []byte(feedJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := LoadFeed(context.Background(), path, nil); err != nil || len(f.Nginx) != 1 {
		t.Errorf("file: %v %+v", err, f)
	}
	if _, err := LoadFeed(context.Background(), filepath.Join(dir, "missing.json"), nil); err == nil {
		t.Error("want read error")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/404" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(feedJSON))
	}))
	defer srv.Close()
	if f, err := LoadFeed(context.Background(), srv.URL+"/feed", nil); err != nil || len(f.Nginx) != 1 {
		t.Errorf("url: %v", err)
	}
	if _, err := LoadFeed(context.Background(), srv.URL+"/404", srv.Client()); err == nil {
		t.Error("want HTTP error")
	}
}

func TestOSVAndCSAFImport(t *testing.T) {
	osv := `[{"id":"GHSA-xxxx","aliases":["CVE-2099-0001"],"summary":"nginx bug","details":"d",
	  "affected":[{"package":{"ecosystem":"Debian","name":"nginx"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.20.0"},{"fixed":"1.20.5"}]}],"versions":["1.19.9"]},
	              {"package":{"ecosystem":"npm","name":"left-pad"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}],
	  "references":[{"type":"ADVISORY","url":"https://example.test/a"}],"database_specific":{"severity":"HIGH"}}]`
	feed, err := ParseFeed([]byte(osv))
	if err != nil {
		t.Fatal(err)
	}
	if len(feed.Nginx) != 1 || feed.Nginx[0].ID != "CVE-2099-0001" || feed.Nginx[0].Severity != "high" || feed.Nginx[0].Reference != "https://example.test/a" {
		t.Fatalf("osv: %+v", feed.Nginx)
	}
	cat := &Catalog{}
	cat.Merge(feed)
	for ver, want := range map[string]bool{"1.20.4": true, "1.20.5": false, "1.19.9": true, "1.19.8": false} {
		if got := len(cat.Correlate("nginx", ver)) == 1; got != want {
			t.Errorf("osv %s: %v", ver, got)
		}
	}

	csaf := `{"document":{"title":"adv","tracking":{"id":"ADV-1"}},
	  "product_tree":{"branches":[{"category":"vendor","name":"F5","branches":[
	     {"category":"product_name","name":"nginx","branches":[{"category":"product_version","name":"1.22.0","product":{"name":"nginx 1.22.0","product_id":"P1"}}]},
	     {"category":"product_name","name":"other","branches":[{"category":"product_version","name":"2.0.0","product":{"name":"other 2.0.0","product_id":"P2"}}]}]}]},
	  "vulnerabilities":[{"cve":"CVE-2099-0002","title":"csaf bug","scores":[{"cvss_v3":{"baseSeverity":"CRITICAL","baseScore":9.8}}],
	     "product_status":{"known_affected":["P1","P2","P404"]},"references":[{"url":"https://example.test/c"}]}]}`
	feed, err = ParseFeed([]byte(csaf))
	if err != nil {
		t.Fatal(err)
	}
	if len(feed.Nginx) != 1 || feed.Nginx[0].ID != "CVE-2099-0002" || feed.Nginx[0].Severity != "critical" || len(feed.Nginx[0].Affected) != 1 {
		t.Fatalf("csaf: %+v", feed.Nginx)
	}
	for name, want := range map[string]bool{"nginx": true, "NGINX Plus": true, "debian:nginx": true, "nginx 1.22.0": true, "pkg/nginx": true,
		"nginx-ingress": false, "ingress-nginx": false, "njs": false, "php": false, "": false} {
		if got := isNginxPackage(name); got != want {
			t.Errorf("isNginxPackage(%q) = %v", name, got)
		}
	}
}

func TestVersionHelpers(t *testing.T) {
	if compareVersion("1.9.5", "1.10.0") >= 0 || compareVersion("1.25.3.1", "1.25.3") != 0 || compareVersion("2.0.0", "1.99.99") <= 0 {
		t.Error("compareVersion")
	}
	if _, _, _, ok := parseVersion("abc"); ok {
		t.Error("parseVersion should reject non-numeric")
	}
	if maj, min, pat, ok := parseVersion("1.18"); !ok || maj != 1 || min != 18 || pat != 0 {
		t.Error("parseVersion short")
	}
	if !sameBranch("1.30.1", "1.30.9") || sameBranch("1.30.1", "1.31.1") {
		t.Error("sameBranch")
	}
	if SeverityRank("Critical") != 4 || SeverityRank("moderate") != 2 || SeverityRank("info") != 0 {
		t.Error("SeverityRank")
	}
}
