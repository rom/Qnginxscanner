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

// restoreSigs snapshots the global signature catalogues so a test that
// registers a pack does not leak into the others.
func restoreSigs(t *testing.T) {
	t.Helper()
	h, c, b := headerSigs, cookieSigs, bodySigs
	packMu.Lock()
	p := activePacks
	packMu.Unlock()
	t.Cleanup(func() {
		headerSigs, cookieSigs, bodySigs = h, c, b
		packMu.Lock()
		activePacks = p
		packMu.Unlock()
	})
}

const testPack = `{"schema":"qnginxscanner-signature-pack/1","id":"acme","version":"1.2",
 "headers":[{"header":"X-Acme-Edge","contains":"ngx","variant":"nginx","module":"acme-edge","weight":250,"detail":"ACME edge (nginx based)"}],
 "cookies":[{"name":"acme_lb_","match":"prefix","module":"acme-lb","weight":30,"detail":"ACME LB cookie"}],
 "bodies":[{"id":"body.acme-error","regex":"ACME gateway error [0-9]+","weight":40,"detail":"ACME error page"}]}`

func TestSignaturePackRegistersWorkingSignatures(t *testing.T) {
	restoreSigs(t)
	p, err := ParseSignaturePack([]byte(testPack))
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterSignaturePack(p); err != nil {
		t.Fatal(err)
	}
	if got := SignaturePacks(); len(got) == 0 || got[len(got)-1] != "acme@1.2" {
		t.Errorf("packs = %v", got)
	}
	r := resp(200, map[string]string{"X-Acme-Edge": "NGX-7"}, "oops: ACME gateway error 502")
	r.Cookies = []*http.Cookie{{Name: "acme_lb_1", Value: "x"}}
	d := Analyze(Input{TargetURL: "http://h/", Root: r})
	for _, sig := range []string{"header.x-acme-edge", "cookie.acme_lb_", "body.acme-error"} {
		if !hasSignal(d, sig) {
			t.Errorf("missing %s", sig)
		}
	}
	if !d.IsNginx || d.Confidence != 100 || d.Evidence[0].Weight != 100 {
		t.Errorf("weight must be clamped to 100: %+v", d.Evidence[0])
	}
	if strings.Join(d.Modules, ",") != "acme-edge,acme-lb" {
		t.Errorf("modules = %v", d.Modules)
	}
}

func TestSignaturePackRejectsMalformed(t *testing.T) {
	bad := map[string]string{
		"not json":      `{`,
		"wrong schema":  `{"schema":"other/1","id":"x"}`,
		"missing id":    `{"headers":[{"header":"X","weight":1}]}`,
		"empty header":  `{"id":"x","headers":[{"header":" ","weight":1}]}`,
		"empty cookie":  `{"id":"x","cookies":[{"name":"","weight":1}]}`,
		"cookie match":  `{"id":"x","cookies":[{"name":"a","match":"regex","weight":1}]}`,
		"empty body id": `{"id":"x","bodies":[{"id":"","regex":"a"}]}`,
		"empty regex":   `{"id":"x","bodies":[{"id":"b","regex":""}]}`,
		"bad regex":     `{"id":"x","bodies":[{"id":"b","regex":"("}]}`,
		"long regex":    `{"id":"x","bodies":[{"id":"b","regex":"` + strings.Repeat("a", maxRegexLen+1) + `"}]}`,
	}
	for name, doc := range bad {
		if _, err := ParseSignaturePack([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var many strings.Builder
	many.WriteString(`{"id":"x","headers":[`)
	for i := 0; i <= maxPackEntries; i++ {
		if i > 0 {
			many.WriteByte(',')
		}
		many.WriteString(`{"header":"X","weight":1}`)
	}
	many.WriteString(`]}`)
	if _, err := ParseSignaturePack([]byte(many.String())); err == nil {
		t.Error("oversized pack accepted")
	}
	if err := RegisterSignaturePack(&SignaturePack{}); err == nil {
		t.Error("empty pack registered")
	}
	if clampWeight(-5) != 0 || clampWeight(50) != 50 {
		t.Error("clampWeight")
	}
	if packLabel(&SignaturePack{ID: "a"}) != "a" {
		t.Error("packLabel without version")
	}
}

func TestLoadSignaturePackFileAndURL(t *testing.T) {
	restoreSigs(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "pack.json")
	if err := os.WriteFile(path, []byte(testPack), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := LoadSignaturePack(context.Background(), path, nil); err != nil || n != 3 {
		t.Errorf("file: n=%d err=%v", n, err)
	}
	if _, err := LoadSignaturePack(context.Background(), filepath.Join(dir, "nope.json"), nil); err == nil {
		t.Error("missing file accepted")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte(testPack))
		case "/bad":
			_, _ = w.Write([]byte(`{"id":""}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	if n, err := LoadSignaturePack(context.Background(), srv.URL+"/ok", nil); err != nil || n != 3 {
		t.Errorf("url: n=%d err=%v", n, err)
	}
	for _, p := range []string{"/bad", "/404"} {
		if _, err := LoadSignaturePack(context.Background(), srv.URL+p, srv.Client()); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}
