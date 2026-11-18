package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// This file holds the probes that cannot be expressed through net/http: hand
// built HTTP/1.x requests whose reply is kept verbatim (status line, header
// order), and an HTTP/2 connection-preface exchange that records the server's
// SETTINGS and WINDOW_UPDATE frames. Both are read-only fingerprinting aids.

// errRawProxied is returned when raw probes are requested through a proxy:
// they need a direct connection to observe the target's own wire behaviour.
var errRawProxied = errors.New("raw probes are skipped when a proxy is configured")

// maxRawBytes bounds how much of a raw reply is read.
const maxRawBytes = 64 * 1024

// RawResponse is the verbatim reply to a hand-built HTTP/1.x request.
type RawResponse struct {
	// Name identifies the probe (e.g. "no-host", "unknown-method").
	Name string `json:"name"`
	// Request is the first line of the request that was sent (bounded).
	Request string `json:"request,omitempty"`
	// Target is the scheme://host:port the probe was sent to.
	Target string `json:"target,omitempty"`
	// StatusLine is the raw first line of the reply.
	StatusLine string `json:"status_line,omitempty"`
	Proto      string `json:"proto,omitempty"`
	Status     int    `json:"status,omitempty"`
	// Reason is the reason phrase exactly as the server sent it.
	Reason string `json:"reason,omitempty"`
	// HeaderOrder lists the header names in wire order, original casing.
	HeaderOrder []string    `json:"header_order,omitempty"`
	Header      http.Header `json:"header,omitempty"`
	Body        []byte      `json:"body,omitempty"`
	// Headerless is true when the reply carried no status line at all
	// (an HTTP/0.9-style bare body).
	Headerless bool   `json:"headerless,omitempty"`
	Err        string `json:"error,omitempty"`
}

// HeaderGet is a nil-safe accessor for a single header value.
func (r *RawResponse) HeaderGet(key string) string {
	if r == nil || r.Header == nil {
		return ""
	}
	return r.Header.Get(key)
}

// AsResponse adapts the raw reply to the Response shape so the same header and
// body analysis can run over it.
func (r *RawResponse) AsResponse() *Response {
	if r == nil {
		return nil
	}
	return &Response{
		RequestURL: r.Target, FinalURL: r.Target, Status: r.Status, Proto: r.Proto,
		Header: r.Header, Body: r.Body, Err: r.Err,
	}
}

// dialRaw opens a direct TCP connection honouring the fetcher's resolve rules.
func (f *Fetcher) dialRaw(ctx context.Context, host string, port int) (net.Conn, error) {
	if f.proxied {
		return nil, errRawProxied
	}
	if f.limiter != nil {
		if err := f.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if repl := resolveAddr(f.resolve, addr); repl != "" {
		addr = repl
	}
	d := net.Dialer{Timeout: f.rawTimeout()}
	return d.DialContext(ctx, "tcp", addr)
}

func (f *Fetcher) rawTimeout() time.Duration {
	if f.timeout <= 0 {
		return 10 * time.Second
	}
	return f.timeout
}

func (f *Fetcher) rawTLS(ctx context.Context, conn net.Conn, host string, alpn []string) (*tls.Conn, error) {
	name := f.sni
	if name == "" {
		name = host
	}
	tc := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: f.insecure, //nolint:gosec // opt-in for self-signed scan targets
		MinVersion:         tls.VersionTLS10,
		ServerName:         name,
		NextProtos:         alpn,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tc, nil
}

// HostHeaderValue returns the Host header raw probes should send for a target:
// the configured override, else host[:port] (port omitted when it is the
// scheme default).
func (f *Fetcher) HostHeaderValue(host string, port int, useTLS bool) string {
	if f.hostHeader != "" {
		return f.hostHeader
	}
	h := host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	if (useTLS && port == 443) || (!useTLS && port == 80) {
		return h
	}
	return h + ":" + strconv.Itoa(port)
}

// UserAgent returns the User-Agent the fetcher sends.
func (f *Fetcher) UserAgent() string { return f.userAgent }

// Raw sends payload verbatim to host:port (inside TLS when useTLS is set) and
// returns the parsed-but-unnormalised reply. It never follows redirects and
// never retries. A payload should ask for "Connection: close" so the read ends
// promptly.
func (f *Fetcher) Raw(ctx context.Context, name, host string, port int, useTLS bool, payload []byte) *RawResponse {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	out := &RawResponse{Name: name, Target: scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/#raw:" + name}
	if i := bytes.IndexAny(payload, "\r\n"); i >= 0 {
		out.Request = string(payload[:i])
	} else {
		out.Request = string(payload)
	}
	if len(out.Request) > 120 {
		out.Request = out.Request[:120] + "…"
	}
	start := time.Now()
	data, err := f.rawExchange(ctx, host, port, useTLS, payload)
	if err != nil && len(data) == 0 {
		out.Err = cleanErr(err)
		f.recordRaw(out, host, port, useTLS, start)
		return out
	}
	parseRaw(out, data)
	f.recordRaw(out, host, port, useTLS, start)
	return out
}

func (f *Fetcher) rawExchange(ctx context.Context, host string, port int, useTLS bool, payload []byte) ([]byte, error) {
	conn, err := f.dialRaw(ctx, host, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(f.rawTimeout())
	_ = conn.SetDeadline(deadline)
	var rw io.ReadWriter = conn
	if useTLS {
		tc, err := f.rawTLS(ctx, conn, host, []string{"http/1.1"})
		if err != nil {
			return nil, err
		}
		rw = tc
	}
	if _, err := rw.Write(payload); err != nil {
		return nil, err
	}
	return readRawReply(rw, conn), nil
}

// readRawReply reads until EOF, the size cap, the deadline, or — once the
// header block is in — the declared Content-Length is satisfied (a server may
// keep the connection open despite "Connection: close").
func readRawReply(r io.Reader, conn net.Conn) []byte {
	var buf bytes.Buffer
	tmp := make([]byte, 8192)
	for buf.Len() < maxRawBytes {
		n, err := r.Read(tmp)
		buf.Write(tmp[:n])
		if err != nil {
			break
		}
		if rawComplete(buf.Bytes()) {
			break
		}
		// After the first bytes arrive, do not wait the full timeout for more.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
	b := buf.Bytes()
	if len(b) > maxRawBytes {
		b = b[:maxRawBytes]
	}
	return b
}

func rawComplete(b []byte) bool {
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 || !bytes.HasPrefix(b, []byte("HTTP/")) {
		return false
	}
	head := strings.ToLower(string(b[:end]))
	i := strings.Index(head, "\r\ncontent-length:")
	if i < 0 {
		return false
	}
	rest := head[i+len("\r\ncontent-length:"):]
	if j := strings.Index(rest, "\r\n"); j >= 0 {
		rest = rest[:j]
	}
	n, err := strconv.Atoi(strings.TrimSpace(rest))
	return err == nil && len(b)-(end+4) >= n
}

// parseRaw splits a raw reply into status line, ordered headers and body.
func parseRaw(out *RawResponse, data []byte) {
	if !bytes.HasPrefix(data, []byte("HTTP/")) {
		out.Headerless = true
		out.Body = data
		return
	}
	head, body := data, []byte(nil)
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		head, body = data[:i], data[i+4:]
	} else if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		head, body = data[:i], data[i+2:]
	}
	out.Body = body
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	out.StatusLine = lines[0]
	parts := strings.SplitN(lines[0], " ", 3)
	out.Proto = parts[0]
	if len(parts) > 1 {
		out.Status, _ = strconv.Atoi(parts[1])
	}
	if len(parts) > 2 {
		out.Reason = parts[2]
	}
	out.Header = http.Header{}
	for _, ln := range lines[1:] {
		i := strings.IndexByte(ln, ':')
		if i <= 0 {
			continue
		}
		name := ln[:i]
		out.HeaderOrder = append(out.HeaderOrder, name)
		out.Header.Add(textproto.CanonicalMIMEHeaderKey(name), strings.TrimSpace(ln[i+1:]))
	}
}

func (f *Fetcher) recordRaw(r *RawResponse, host string, port int, useTLS bool, ts time.Time) {
	if f.recorder == nil {
		return
	}
	f.recorder.Record(Exchange{
		Time: ts, Method: "RAW", URL: r.Target, Host: host, Port: port, TLS: useTLS,
		ReqHost: host, ReqHeaders: http.Header{"X-Raw-Request-Line": {r.Request}},
		Status: r.Status, Proto: r.Proto, RespHeaders: r.Header, RespBody: r.Body, Err: r.Err,
	})
}

// ---- HTTP/2 fingerprint -----------------------------------------------------

// H2Setting is one SETTINGS parameter in the order the server sent it.
type H2Setting struct {
	ID    uint16 `json:"id" xml:"id,attr"`
	Value uint32 `json:"value" xml:"value,attr"`
}

// H2Fingerprint records how a server opens an HTTP/2 connection.
type H2Fingerprint struct {
	// Supported is true when the server answered the client preface with a
	// SETTINGS frame (over TLS with ALPN "h2", or cleartext prior-knowledge).
	Supported bool `json:"supported"`
	// Cleartext is true for a prior-knowledge h2c exchange on a non-TLS port.
	Cleartext bool `json:"cleartext,omitempty"`
	// ALPN is the protocol the TLS handshake selected ("" for cleartext).
	ALPN         string      `json:"alpn,omitempty"`
	Settings     []H2Setting `json:"settings,omitempty" xml:"settings>setting,omitempty"`
	WindowUpdate uint32      `json:"window_update,omitempty"`
	Err          string      `json:"error,omitempty"`
}

// Akamai renders the fingerprint in the widely used "id:value;…|window" form.
func (h *H2Fingerprint) Akamai() string {
	if h == nil || !h.Supported {
		return ""
	}
	parts := make([]string, 0, len(h.Settings))
	for _, s := range h.Settings {
		parts = append(parts, fmt.Sprintf("%d:%d", s.ID, s.Value))
	}
	return strings.Join(parts, ";") + "|" + strconv.FormatUint(uint64(h.WindowUpdate), 10)
}

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	h2FrameSettings     = 0x4
	h2FrameGoAway       = 0x7
	h2FrameWindowUpdate = 0x8
)

// H2 opens a connection, sends the HTTP/2 client preface plus an empty
// SETTINGS frame, and records the server's opening SETTINGS and connection
// WINDOW_UPDATE. No request is made; the connection is closed with GOAWAY.
func (f *Fetcher) H2(ctx context.Context, host string, port int, useTLS bool) *H2Fingerprint {
	out := &H2Fingerprint{Cleartext: !useTLS}
	conn, err := f.dialRaw(ctx, host, port)
	if err != nil {
		out.Err = cleanErr(err)
		return out
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(f.rawTimeout()))
	var rw io.ReadWriter = conn
	if useTLS {
		tc, err := f.rawTLS(ctx, conn, host, []string{"h2"})
		if err != nil {
			out.Err = cleanErr(err)
			return out
		}
		out.ALPN = tc.ConnectionState().NegotiatedProtocol
		if out.ALPN != "h2" {
			return out
		}
		rw = tc
	}
	// Preface + empty SETTINGS frame.
	if _, err := rw.Write(append([]byte(h2Preface), 0, 0, 0, h2FrameSettings, 0, 0, 0, 0, 0)); err != nil {
		out.Err = cleanErr(err)
		return out
	}
	sawSettings := false
	for i := 0; i < 6; i++ {
		var hdr [9]byte
		if _, err := io.ReadFull(rw, hdr[:]); err != nil {
			break
		}
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		typ, flags := hdr[3], hdr[4]
		if length > 1<<14 {
			break // not a sane first frame: not HTTP/2
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(rw, payload); err != nil {
			break
		}
		if !sawSettings {
			// The server preface MUST start with a (non-ACK) SETTINGS frame.
			if typ != h2FrameSettings || flags&0x1 != 0 || length%6 != 0 {
				break
			}
			sawSettings = true
			out.Supported = true
			for o := 0; o+6 <= length; o += 6 {
				out.Settings = append(out.Settings, H2Setting{
					ID: binary.BigEndian.Uint16(payload[o:]), Value: binary.BigEndian.Uint32(payload[o+2:]),
				})
			}
			// Frames that follow arrive promptly or not at all.
			_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			continue
		}
		if typ == h2FrameWindowUpdate && length == 4 && binary.BigEndian.Uint32(hdr[5:])&0x7fffffff == 0 {
			out.WindowUpdate = binary.BigEndian.Uint32(payload) & 0x7fffffff
			break
		}
		if typ == h2FrameSettings && flags&0x1 != 0 {
			break // SETTINGS ACK: the server sent no connection WINDOW_UPDATE first
		}
	}
	if out.Supported {
		// GOAWAY(last-stream-id 0, NO_ERROR).
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = rw.Write([]byte{0, 0, 8, h2FrameGoAway, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	}
	return out
}
