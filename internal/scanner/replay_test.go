package scanner

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/rom/qnginxscanner/internal/corpus"
)

// TestRecordThenReplayReproducesDetection records a live scan's detection
// inputs and shows that replaying the corpus offline reproduces the same nginx
// verdict and version — the regression-harness guarantee.
func TestRecordThenReplayReproducesDetection(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts, _, port := recordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("Set-Cookie", "INGRESSCOOKIE=secretvalue123; Path=/; HttpOnly")
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `<link href="/static/app.css">`)
		case "/static/app.css", "/static../static/app.css":
			_, _ = io.WriteString(w, "body{}")
		default:
			w.WriteHeader(404)
			_, _ = io.WriteString(w, nginxErrorPage("404 Not Found"))
		}
	})
	defer ts.Close()

	rec := corpus.NewRecorder()
	live := deepScan(t, port, Options{Corpus: rec})
	svcLive := live.Targets[0].Services[0]
	if svcLive.Nginx == nil || !svcLive.Nginx.IsNginx {
		t.Fatalf("live scan did not detect nginx: %+v", svcLive.Nginx)
	}

	c := rec.Corpus("qnginxscanner", "test")
	if len(c.Services) == 0 {
		t.Fatal("corpus recorded no services")
	}

	// The session-cookie secret must not be in the corpus; the cookie name,
	// a detection signal, must survive.
	var buf bytes.Buffer
	if err := corpus.Write(&buf, c); err != nil {
		t.Fatalf("write corpus: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte("secretvalue123")) {
		t.Error("session-cookie secret leaked into the corpus")
	}
	if !bytes.Contains(buf.Bytes(), []byte("INGRESSCOOKIE")) {
		t.Error("cookie name (a detection signal) should be kept in the corpus")
	}

	replay := Replay(c, Options{})
	if len(replay.Targets) == 0 || len(replay.Targets[0].Services) == 0 {
		t.Fatal("replay produced no services")
	}
	svcReplay := replay.Targets[0].Services[0]
	if svcReplay.Nginx == nil {
		t.Fatal("replay produced no nginx detection")
	}
	if svcReplay.Nginx.Verdict != svcLive.Nginx.Verdict {
		t.Errorf("verdict changed on replay: live %q vs replay %q", svcLive.Nginx.Verdict, svcReplay.Nginx.Verdict)
	}
	if svcReplay.Nginx.Version != svcLive.Nginx.Version {
		t.Errorf("version changed on replay: live %q vs replay %q", svcLive.Nginx.Version, svcReplay.Nginx.Version)
	}
	if got, want := findingIDs(svcReplay), findingIDs(svcLive); !want["alias-traversal"] || len(got) != len(want) || !got["alias-traversal"] {
		t.Errorf("replay findings differ: live %v vs replay %v", want, got)
	}
	if len(svcReplay.Nginx.Evidence) != len(svcLive.Nginx.Evidence) || len(svcReplay.Nginx.Vulnerabilities) != len(svcLive.Nginx.Vulnerabilities) {
		t.Errorf("replay evidence/vulns differ: %d/%d vs %d/%d", len(svcLive.Nginx.Evidence), len(svcLive.Nginx.Vulnerabilities),
			len(svcReplay.Nginx.Evidence), len(svcReplay.Nginx.Vulnerabilities))
	}
	// Replay reproduces the HTTP summary and keeps target identity.
	if svcReplay.URL != svcLive.URL || svcReplay.Port != svcLive.Port || svcReplay.Scheme != "http" {
		t.Errorf("replay target identity wrong: %+v", svcReplay)
	}
	if svcReplay.HTTP == nil || svcReplay.HTTP.Status != 200 {
		t.Errorf("replay HTTP summary missing: %+v", svcReplay.HTTP)
	}
	// Replay reflects the current catalogue in provenance.
	if replay.Meta.CatalogAdvisories == 0 {
		t.Error("replay Meta should carry catalogue counts")
	}
}

// TestReplayEmptyCorpus is a boundary check: an empty corpus replays to an
// empty-but-valid result.
func TestReplayEmptyCorpus(t *testing.T) {
	res := Replay(&corpus.Corpus{Schema: corpus.Schema}, Options{})
	if res == nil || len(res.Targets) != 0 {
		t.Fatalf("empty corpus should give an empty result: %+v", res)
	}
	if res.Summary.ServicesProbed != 0 {
		t.Errorf("summary should be zero: %+v", res.Summary)
	}
}
