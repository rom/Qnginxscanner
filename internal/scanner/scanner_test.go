package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func nginxTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Contact: mailto:security@example.test\nExpires: 2099-01-01T00:00:00Z\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		if r.URL.Path != "/" {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(nginxErrorPage("404 Not Found")))
			return
		}
		_, _ = w.Write([]byte(`<html><head><title>My Site</title></head><body>hello</body></html>`))
	})
	return httptest.NewServer(mux)
}

func TestScanDetectsNginx(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("NO_PROXY", "*")

	ts := nginxTestServer()
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := Scan(ctx, []string{ts.URL}, Options{
		Mode:        ModeDeep,
		TLSMode:     TLSOff,
		SecurityTxt: true,
		Timeout:     5 * time.Second,
		Concurrency: 10,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Targets) != 1 {
		t.Fatalf("want 1 target, got %d", len(res.Targets))
	}
	svc := res.Targets[0].Services[0]
	if svc.Nginx == nil || !svc.Nginx.IsNginx {
		t.Fatalf("expected nginx detection, got %+v", svc.Nginx)
	}
	if svc.Nginx.Version != "1.24.0" || svc.Nginx.Variant != "nginx" {
		t.Fatalf("want nginx 1.24.0, got %q %q", svc.Nginx.Variant, svc.Nginx.Version)
	}
	if svc.Server == nil || svc.Server.Product != "nginx" {
		t.Fatalf("web server identification: %+v", svc.Server)
	}
	if svc.HTTP == nil || svc.HTTP.Title != "My Site" {
		t.Fatalf("HTTP summary: %+v", svc.HTTP)
	}
	if svc.SecurityTxt == nil || !svc.SecurityTxt.Present {
		t.Fatal("expected security.txt to be found")
	}
	if res.Summary.NginxConfirmed != 1 {
		t.Fatalf("summary NginxConfirmed = %d, want 1", res.Summary.NginxConfirmed)
	}
}

func TestScanClosedPort(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 127.0.0.1 with an unlikely-open port and a short timeout.
	res, err := Scan(ctx, []string{"127.0.0.1"}, Options{
		Mode:    ModeDetect,
		Ports:   []int{1},
		Timeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// Closed ports are excluded by default, so no targets should appear.
	if len(res.Targets) != 0 {
		t.Fatalf("expected no open services, got %d", len(res.Targets))
	}
	if res.Summary.ServicesProbed != 1 {
		t.Fatalf("want 1 probed service, got %d", res.Summary.ServicesProbed)
	}
}
