package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// rawServer answers every connection with a canned byte string after reading
// the request head (or immediately when the client speaks the HTTP/2 preface).
func rawServer(t *testing.T, reply func(first string) []byte) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				br := bufio.NewReader(c)
				first, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if !strings.HasPrefix(first, "PRI ") {
					for {
						line, err := br.ReadString('\n')
						if err != nil || line == "\r\n" {
							break
						}
					}
				}
				_, _ = c.Write(reply(first))
			}(c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestRawKeepsStatusLineAndHeaderOrder(t *testing.T) {
	body := "<html>nope</html>"
	host, port := rawServer(t, func(string) []byte {
		return []byte("HTTP/1.1 405 Not Allowed\r\nServer: nginx\r\nDate: x\r\ncontent-type: text/html\r\nContent-Length: 17\r\nConnection: close\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n" + body)
	})
	rec := &recorder{}
	f := NewFetcher(FetcherConfig{Timeout: 2 * time.Second, Recorder: rec, Limiter: NewRateLimiter(1000, 10)})
	r := f.Raw(context.Background(), "unknown-method", host, port, false, []byte("QNGX / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"))
	if r.Err != "" || r.Status != 405 || r.Reason != "Not Allowed" || r.Proto != "HTTP/1.1" || r.StatusLine != "HTTP/1.1 405 Not Allowed" {
		t.Fatalf("status line: %+v", r)
	}
	if got := strings.Join(r.HeaderOrder, ","); got != "Server,Date,content-type,Content-Length,Connection,Set-Cookie,Set-Cookie" {
		t.Errorf("order = %s", got)
	}
	if r.HeaderGet("Content-Type") != "text/html" || len(r.Header.Values("Set-Cookie")) != 2 || string(r.Body) != body {
		t.Errorf("headers/body: %+v %q", r.Header, r.Body)
	}
	if r.Request != "QNGX / HTTP/1.1" || !strings.HasSuffix(r.Target, "#raw:unknown-method") {
		t.Errorf("request/target: %q %q", r.Request, r.Target)
	}
	if resp := r.AsResponse(); resp.Status != 405 || resp.HeaderGet("Server") != "nginx" {
		t.Errorf("AsResponse: %+v", resp)
	}
	if len(rec.ex) != 1 || rec.ex[0].Method != "RAW" || rec.ex[0].Status != 405 {
		t.Errorf("recorder: %+v", rec.ex)
	}
	var nilRaw *RawResponse
	if nilRaw.HeaderGet("X") != "" || nilRaw.AsResponse() != nil {
		t.Error("nil RawResponse accessors")
	}
}

type recorder struct{ ex []Exchange }

func (r *recorder) Record(e Exchange) { r.ex = append(r.ex, e) }

func TestRawHeaderlessAndErrors(t *testing.T) {
	host, port := rawServer(t, func(string) []byte { return []byte("<html>bare</html>") })
	f := NewFetcher(FetcherConfig{Timeout: 2 * time.Second})
	r := f.Raw(context.Background(), "http09", host, port, false, []byte("GET /\r\n\r\n"))
	if !r.Headerless || r.Status != 0 || string(r.Body) != "<html>bare</html>" {
		t.Errorf("headerless: %+v", r)
	}
	// Closed port.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if r := f.Raw(context.Background(), "x", "127.0.0.1", closed, false, []byte("GET / HTTP/1.1\r\n\r\n")); r.Err == "" {
		t.Error("want a dial error")
	}
	if h := f.H2(context.Background(), "127.0.0.1", closed, false); h.Err == "" || h.Supported {
		t.Errorf("H2 on closed port: %+v", h)
	}
	// Raw probes refuse to run through a proxy.
	pf := NewFetcher(FetcherConfig{Timeout: time.Second, ProxyURL: "http://127.0.0.1:1"})
	if r := pf.Raw(context.Background(), "x", host, port, false, []byte("GET / HTTP/1.1\r\n\r\n")); !strings.Contains(r.Err, "proxy") {
		t.Errorf("proxied raw probe: %+v", r)
	}
	// Long request lines are truncated in the record.
	if r := f.Raw(context.Background(), "long", host, port, false, []byte("GET /"+strings.Repeat("a", 500)+" HTTP/1.1\r\n\r\n")); len(r.Request) > 130 {
		t.Errorf("request line not truncated: %d", len(r.Request))
	}
}

func TestRawOverTLSAndResolve(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		_, _ = io.WriteString(w, "tls-ok")
	}))
	defer ts.Close()
	addr := ts.Listener.Addr().(*net.TCPAddr)
	// The logical host is pinned to the test listener, curl --resolve style.
	f := NewFetcher(FetcherConfig{Timeout: 2 * time.Second, Insecure: true,
		Resolve: []ResolveRule{{Host: "pinned.example", Port: 443, Addr: addr.String()}}})
	r := f.Raw(context.Background(), "get", "pinned.example", 443, true, []byte("GET / HTTP/1.1\r\nHost: pinned.example\r\nConnection: close\r\n\r\n"))
	if r.Err != "" || r.Status != 200 || r.HeaderGet("Server") != "nginx" {
		t.Fatalf("tls raw: %+v", r)
	}
	// Without Insecure the self-signed certificate is rejected.
	strict := NewFetcher(FetcherConfig{Timeout: 2 * time.Second, Resolve: []ResolveRule{{Host: "pinned.example", Port: 443, Addr: addr.String()}}})
	if r := strict.Raw(context.Background(), "get", "pinned.example", 443, true, []byte("GET / HTTP/1.1\r\n\r\n")); r.Err == "" {
		t.Error("certificate verification should fail")
	}
}

func TestHostHeaderValue(t *testing.T) {
	f := NewFetcher(FetcherConfig{})
	cases := []struct {
		host string
		port int
		tls  bool
		want string
	}{
		{"h", 80, false, "h"}, {"h", 443, true, "h"}, {"h", 8080, false, "h:8080"}, {"h", 80, true, "h:80"}, {"::1", 8443, true, "[::1]:8443"},
	}
	for _, c := range cases {
		if got := f.HostHeaderValue(c.host, c.port, c.tls); got != c.want {
			t.Errorf("%v → %q, want %q", c, got, c.want)
		}
	}
	if got := NewFetcher(FetcherConfig{HostHeader: "v.example"}).HostHeaderValue("h", 80, false); got != "v.example" {
		t.Errorf("override: %q", got)
	}
	if f.UserAgent() != DefaultUserAgent {
		t.Errorf("UA: %q", f.UserAgent())
	}
}

var nginxH2Frames = []byte{0, 0, 18, 4, 0, 0, 0, 0, 0,
	0, 3, 0, 0, 0, 128, 0, 4, 0, 1, 0, 0, 0, 5, 0, 0xff, 0xff, 0xff,
	0, 0, 4, 8, 0, 0, 0, 0, 0, 0x7f, 0xff, 0, 0}

func TestH2CleartextFingerprint(t *testing.T) {
	host, port := rawServer(t, func(first string) []byte {
		if strings.HasPrefix(first, "PRI * HTTP/2.0") {
			return nginxH2Frames
		}
		return []byte("HTTP/1.1 400 Bad Request\r\n\r\n")
	})
	f := NewFetcher(FetcherConfig{Timeout: 2 * time.Second})
	h := f.H2(context.Background(), host, port, false)
	if !h.Supported || !h.Cleartext || h.Akamai() != "3:128;4:65536;5:16777215|2147418112" {
		t.Fatalf("fingerprint: %+v %q", h, h.Akamai())
	}
	var nilH *H2Fingerprint
	if nilH.Akamai() != "" || (&H2Fingerprint{}).Akamai() != "" {
		t.Error("Akamai on unsupported")
	}
}

func TestH2NotSupported(t *testing.T) {
	// An HTTP/1 server answering the preface with text is not HTTP/2.
	host, port := rawServer(t, func(string) []byte { return []byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n") })
	f := NewFetcher(FetcherConfig{Timeout: 2 * time.Second})
	if h := f.H2(context.Background(), host, port, false); h.Supported || h.Err != "" {
		t.Errorf("text reply: %+v", h)
	}
	// SETTINGS followed directly by its ACK: supported, no window update.
	host, port = rawServer(t, func(string) []byte {
		return []byte{0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100, 0, 0, 0, 4, 1, 0, 0, 0, 0}
	})
	if h := f.H2(context.Background(), host, port, false); !h.Supported || h.WindowUpdate != 0 || h.Akamai() != "3:100|0" {
		t.Errorf("settings+ack: %+v", h)
	}
}

func TestH2OverTLS(t *testing.T) {
	// A TLS server that only offers http/1.1: ALPN contradicts HTTP/2.
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	ts.StartTLS()
	defer ts.Close()
	addr := ts.Listener.Addr().(*net.TCPAddr)
	f := NewFetcher(FetcherConfig{Timeout: 2 * time.Second, Insecure: true})
	if h := f.H2(context.Background(), "127.0.0.1", addr.Port, true); h.Supported {
		t.Errorf("h2 must not be reported: %+v", h)
	}
	// Go's own HTTP/2 server: supported, with its (non-nginx) settings.
	ts2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts2.EnableHTTP2 = true
	ts2.StartTLS()
	defer ts2.Close()
	addr2 := ts2.Listener.Addr().(*net.TCPAddr)
	h := f.H2(context.Background(), "127.0.0.1", addr2.Port, true)
	if !h.Supported || h.ALPN != "h2" || len(h.Settings) == 0 || h.Cleartext {
		t.Errorf("go h2: %+v", h)
	}
	if strings.HasSuffix(h.Akamai(), "|2147418112") {
		t.Errorf("Go's server must not look like nginx: %s", h.Akamai())
	}
}
