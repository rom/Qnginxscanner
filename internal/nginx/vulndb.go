package nginx

import "strings"

// The built-in catalogue mirrors the official nginx security advisories
// (https://nginx.org/en/security_advisories.html): every entry carries the
// vendor's "Vulnerable" ranges and "Not vulnerable" (fixed) releases verbatim,
// so a stable-branch backport (e.g. 1.30.7) is honoured as well as the
// mainline fix (e.g. 1.31.9). Entries are extended with structured
// prerequisites so a lead can be qualified against what the scan observed.

const (
	advisories    = "https://nginx.org/en/security_advisories.html"
	nginx2rootURL = "https://nginx2root.com/"
	// TagNginx2Root marks the advisories that make up the NGINX2Root chain.
	TagNginx2Root = "nginx2root"
)

// Nginx2RootCVEs are the five nginx advisories of the NGINX2Root chain
// (Xint, November 2026), all fixed in nginx 1.31.9 (mainline) / 1.30.7 (stable).
var Nginx2RootCVEs = []string{
	"CVE-2026-123007", "CVE-2026-123634", "CVE-2026-123633", "CVE-2026-121810", "CVE-2026-113425",
}

// builtinSupported is the set of branches that still receive fixes, and
// builtinLatest their newest releases, as of the catalogue date (2026-11).
// Both can be overridden with --vuln-feed.
var builtinSupported = map[string]string{"1.31": "mainline", "1.30": "stable"}

var builtinLatest = map[string]string{"1.31": "1.31.9", "1.30": "1.30.7"}

type advOpt func(*FeedEntry)

func proto(p string) advOpt {
	return func(e *FeedEntry) { e.Prereqs = append(e.Prereqs, Prereq{Kind: "protocol", Want: p}) }
}

func cfg(detail string) advOpt {
	return func(e *FeedEntry) { e.Prereqs = append(e.Prereqs, Prereq{Kind: "config", Detail: detail}) }
}

func mod(name, detail string) advOpt {
	return func(e *FeedEntry) { e.Prereqs = append(e.Prereqs, Prereq{Kind: "module", Want: name, Detail: detail}) }
}

func windows() advOpt {
	return func(e *FeedEntry) { e.Prereqs = append(e.Prereqs, Prereq{Kind: "os", Want: "windows"}) }
}

func desc(d string) advOpt { return func(e *FeedEntry) { e.Description = d } }

func sev(s string) advOpt { return func(e *FeedEntry) { e.Severity = s } }

func ref(u string) advOpt { return func(e *FeedEntry) { e.Reference = u } }

func tag(t string) advOpt { return func(e *FeedEntry) { e.Tags = append(e.Tags, t) } }

// vendorSeverity maps nginx.org's rating words onto the report scale.
func vendorSeverity(s string) string {
	switch s {
	case "major":
		return "high"
	case "medium":
		return "medium"
	case "minor", "low":
		return "low"
	default:
		return "info"
	}
}

// parseVulnerable turns nginx.org's "Vulnerable:" text into range specs:
// "0.6.18-1.31.8", "1.25.0-1.25.5, 1.26.0", "nginx/Windows 0.7.52-1.3.0", "all".
func parseVulnerable(s string) []RangeSpec {
	var out []RangeSpec
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), "nginx/Windows"))
		switch {
		case part == "":
		case part == "all":
			out = append(out, RangeSpec{Introduced: "0.0.1"})
		case strings.Contains(part, "-"):
			b := strings.SplitN(part, "-", 2)
			out = append(out, RangeSpec{Introduced: strings.TrimSpace(b[0]), Last: strings.TrimSpace(b[1])})
		default:
			out = append(out, RangeSpec{Equals: part})
		}
	}
	return out
}

// parseFixed turns nginx.org's "Not vulnerable:" text ("1.31.9+, 1.30.7+",
// "none") into the per-branch fixed releases.
func parseFixed(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSuffix(strings.TrimSpace(part), "+")
		if part != "" && part != "none" {
			out = append(out, part)
		}
	}
	return out
}

func adv(id, vendorSev, title, notVulnerable, vulnerable string, opts ...advOpt) FeedEntry {
	e := FeedEntry{
		ID: id, Severity: vendorSeverity(vendorSev), Title: title,
		Reference: advisories,
		Affected:  parseVulnerable(vulnerable),
		FixedIn:   parseFixed(notVulnerable),
	}
	e.Description = title + " (nginx.org advisory, vendor severity: " + vendorSev + ")."
	for _, o := range opts {
		o(&e)
	}
	return e
}

const n2rFix = "1.31.9+, 1.30.7+"

var builtinAdvisories = []FeedEntry{
	// ---- NGINX2Root (Xint, November 2026) -------------------------------
	adv("CVE-2026-123007", "major", "Memory corruption in HTTP/2 flow control (NGINX2Root)", n2rFix, "1.9.5-1.31.8",
		sev("critical"), tag(TagNginx2Root), ref(nginx2rootURL), proto("http2"),
		desc("Integer overflow/underflow of the HTTP/2 send window leads to an out-of-bounds heap copy. An unauthenticated remote attacker can execute code as the nginx worker; reachable when HTTP/2 is enabled, even when only static files are served over TLS. Present since the first HTTP/2 release (1.9.5). Fixed in 1.31.9 / 1.30.7 (NGINX Plus 37.0.8.1 / 37.3.0.1). Rated major by nginx.org and critical (CVSS 4.0 9.2) by Xint/Wiz. Mitigation: upgrade, or disable HTTP/2 (\"http2 off;\", remove \"http2\" from listen).")),
	adv("CVE-2026-123633", "medium", "Use-after-free in HTTP/2 (NGINX2Root)", n2rFix, "1.19.7-1.31.8",
		sev("critical"), tag(TagNginx2Root), ref(nginx2rootURL), proto("http2"),
		cfg("requires requests to be proxied to an upstream (proxy_pass etc.) while free connections run low"),
		desc("An active HTTP/2 connection stays eligible for draining; opening an upstream connection can close and free the request's own HTTP/2 connection while it is still in use. Unauthenticated remote code execution when HTTP/2 is enabled on a reverse proxy. Fixed in 1.31.9 / 1.30.7 (NGINX Plus 37.0.7.1 / 37.2.0.1). Rated medium by nginx.org and critical (CVSS 4.0 9.2) by Xint/Wiz. Mitigation: upgrade, or disable HTTP/2.")),
	adv("CVE-2026-121810", "medium", "Use-after-free in HTTP/3 (NGINX2Root)", n2rFix, "1.25.0-1.31.8",
		sev("high"), tag(TagNginx2Root), ref(nginx2rootURL), proto("http3"),
		cfg("requires requests to be proxied to an upstream"),
		desc("The parent QUIC connection becomes eligible for draining during stream creation and can be closed while one of its HTTP/3 requests is still running. Part of the NGINX2Root chain (Xint rates it RCE-capable; nginx.org: medium). Fixed in 1.31.9 / 1.30.7. Mitigation: upgrade, or remove quic listeners / \"http3 off;\" and the Alt-Svc header.")),
	adv("CVE-2026-123634", "medium", "Use-after-free during response processing in resolver (NGINX2Root)", n2rFix, "0.6.18-1.31.8",
		sev("high"), tag(TagNginx2Root), ref(nginx2rootURL),
		cfg("requires a \"resolver\" with a request-derived upstream name (e.g. proxy_pass http://$host) reached through subrequests (mirror, SSI)"),
		desc("A resolver handler can free another resolver context on the waiting list which the loop then keeps using. Part of the NGINX2Root chain (Xint rates it RCE-capable; nginx.org: medium). Not mitigated by disabling HTTP/2. Fixed in 1.31.9 / 1.30.7.")),
	adv("CVE-2026-113425", "major", "Use-after-free in mail proxy module (NGINX2Root)", n2rFix, "0.5.33-1.31.8",
		tag(TagNginx2Root), ref(nginx2rootURL), proto("mail"),
		cfg("requires \"proxy on\" together with auth_http"),
		desc("Closing the client connection frees its mail session while the auth_http connection still references it. Part of the NGINX2Root chain. Fixed in 1.31.9 / 1.30.7. Mitigation: upgrade, or bind/firewall mail listeners (25, 110, 143, 465, 587, 993, 995).")),

	// ---- 2026 -----------------------------------------------------------
	adv("CVE-2026-118899", "major", "Infinite loop while reading client request body over TLS 1.3", n2rFix, "1.13.0-1.31.8", cfg("requires TLS 1.3")),
	adv("CVE-2026-120993", "minor", "NULL pointer dereference when using PROXY protocol version 2", "1.31.9+", "1.31.4-1.31.8", cfg("requires a listener with proxy_protocol")),
	adv("CVE-2026-125283", "minor", "Buffer overflow when using alias with try_files", n2rFix, "0.9.6-1.31.8", cfg("requires alias combined with try_files")),
	adv("CVE-2026-120967", "medium", "SNI bypass when using client certificate validation in stream", n2rFix, "1.25.5-1.31.8", cfg("requires the stream module with ssl_verify_client")),
	adv("CVE-2026-123640", "minor", "Insufficient validation in stream ssl_preread module", n2rFix, "1.15.2-1.31.8", cfg("requires the stream module with ssl_preread")),
	adv("CVE-2026-15176", "medium", "Buffer overflow when using alias with rewrite", "1.31.7+, 1.30.6+", "0.1.29-1.31.6", cfg("requires alias combined with rewrite")),
	adv("CVE-2026-93479", "medium", "Buffer overflow in script evaluation", "1.31.7+, 1.30.6+", "1.31.2-1.31.6, 1.30.0-1.30.5"),
	adv("CVE-2026-95101", "medium", "Request body injection in HTTP/3", "1.31.7+, 1.30.6+", "1.25.0-1.31.6", proto("http3")),
	adv("CVE-2026-97629", "medium", "Session forgery when using TLS session tickets", "1.31.7+, 1.30.6+", "1.23.2-1.31.6", cfg("requires TLS session tickets")),
	adv("CVE-2026-97205", "medium", "Use-after-free when using asynchronous file I/O (AIO)", "1.31.7+, 1.30.6+", "0.8.11-1.31.6", cfg("requires \"aio\"")),
	adv("CVE-2026-90439", "medium", "Buffer overflow when using ngx_http_v3_module", "1.31.6+, 1.30.5+", "1.29.2-1.31.5", proto("http3")),
	adv("CVE-2026-42533", "major", "Buffer overflow when using map and regex", "1.31.3+, 1.30.4+", "0.9.6-1.31.2", cfg("requires a map with regular expressions")),
	adv("CVE-2026-60005", "medium", "Memory disclosure when using ngx_http_slice_module", "1.31.3+, 1.30.4+", "1.15.8-1.31.2", cfg("requires the slice directive")),
	adv("CVE-2026-56434", "medium", "Use-after-free when using ngx_http_ssi_module", "1.31.3+, 1.30.4+", "0.8.11-1.31.2", cfg("requires \"ssi on\"")),
	adv("CVE-2026-42530", "major", "Use-after-free in HTTP/3", "1.31.2+", "1.31.0-1.31.1", proto("http3")),
	adv("CVE-2026-42055", "medium", "Buffer overflow in the ngx_http_proxy_v2_module and ngx_http_grpc_module", "1.31.2+, 1.30.3+", "1.13.10-1.31.1", cfg("requires grpc_pass or proxy_http_version 2 with ignore_invalid_headers off and very large header buffers")),
	adv("CVE-2026-48142", "low", "Buffer overread in the ngx_http_charset_module", "1.31.2+, 1.30.3+", "0.3.50-1.31.1", cfg("requires charset conversion (charset/source_charset)")),
	adv("CVE-2026-9256", "medium", "Buffer overflow in the ngx_http_rewrite_module", "1.31.1+, 1.30.2+", "0.1.17-1.31.0", cfg("requires specific rewrite/if/set usage")),
	adv("CVE-2026-42926", "medium", "HTTP/2 request injection in the ngx_http_proxy_module", "1.31.0+, 1.30.1+", "1.29.4-1.30.0", cfg("requires proxy_http_version 2")),
	adv("CVE-2026-42945", "medium", "Buffer overflow in the ngx_http_rewrite_module", "1.31.0+, 1.30.1+", "0.6.27-1.30.0", cfg("requires specific rewrite usage")),
	adv("CVE-2026-42946", "medium", "Buffer overread in the ngx_http_scgi_module and ngx_http_uwsgi_module", "1.31.0+, 1.30.1+", "0.8.42-1.30.0", cfg("requires scgi_pass or uwsgi_pass")),
	adv("CVE-2026-42934", "low", "Buffer overread in the ngx_http_charset_module", "1.31.0+, 1.30.1+", "0.3.50-1.30.0", cfg("requires charset conversion (charset/source_charset)")),
	adv("CVE-2026-40460", "medium", "HTTP/3 address spoofing", "1.31.0+, 1.30.1+", "1.25.0-1.30.0", proto("http3")),
	adv("CVE-2026-40701", "medium", "Resolver use-after-free in OCSP", "1.31.0+, 1.30.1+", "1.19.0-1.30.0", cfg("requires ssl_ocsp / ssl_stapling with a resolver")),
	adv("CVE-2026-27654", "medium", "Buffer overflow in ngx_http_dav_module", "1.29.7+, 1.28.3+", "0.5.13-1.29.6", mod("http_dav", "requires the WebDAV module (dav_methods COPY/MOVE)")),
	adv("CVE-2026-27784", "medium", "Buffer overflow in the ngx_http_mp4_module", "1.29.7+, 1.28.3+", "1.1.19-1.29.6", cfg("requires the mp4 directive")),
	adv("CVE-2026-32647", "medium", "Buffer overflow in the ngx_http_mp4_module", "1.29.7+, 1.28.3+", "1.1.19-1.29.6", cfg("requires the mp4 directive")),
	adv("CVE-2026-27651", "low", "NULL pointer dereference while using CRAM-MD5 or APOP", "1.29.7+, 1.28.3+", "0.5.15-1.29.6", proto("mail")),
	adv("CVE-2026-28753", "medium", "Injection in auth_http and XCLIENT", "1.29.7+, 1.28.3+", "0.6.27-1.29.6", proto("mail")),
	adv("CVE-2026-28755", "medium", "OCSP result bypass in stream", "1.29.7+, 1.28.3+", "1.27.2-1.29.6", cfg("requires the stream module with ssl_ocsp")),
	adv("CVE-2026-1642", "medium", "SSL upstream injection", "1.29.5+, 1.28.2+", "1.3.0-1.29.4", cfg("requires proxying to TLS upstreams")),

	// ---- 2024–2025 ------------------------------------------------------
	adv("CVE-2025-53859", "low", "Buffer overread in the ngx_mail_smtp_module", "1.29.1+", "0.7.22-1.29.0", proto("mail")),
	adv("CVE-2025-23419", "medium", "SSL session reuse vulnerability", "1.27.4+, 1.26.3+", "1.11.4-1.27.3", cfg("requires name-based virtual hosts with client certificate authentication and shared TLS session resumption")),
	adv("CVE-2024-7347", "low", "Buffer overread in the ngx_http_mp4_module", "1.27.1+, 1.26.2+", "1.5.13-1.27.0", cfg("requires the mp4 directive")),
	adv("CVE-2024-32760", "medium", "Buffer overwrite in HTTP/3", "1.27.0+, 1.26.1+", "1.25.0-1.25.5, 1.26.0", proto("http3")),
	adv("CVE-2024-31079", "medium", "Stack overflow and use-after-free in HTTP/3", "1.27.0+, 1.26.1+", "1.25.0-1.25.5, 1.26.0", proto("http3")),
	adv("CVE-2024-35200", "medium", "NULL pointer dereference in HTTP/3", "1.27.0+, 1.26.1+", "1.25.0-1.25.5, 1.26.0", proto("http3")),
	adv("CVE-2024-34161", "medium", "Memory disclosure in HTTP/3", "1.27.0+, 1.26.1+", "1.25.0-1.25.5, 1.26.0", proto("http3")),
	adv("CVE-2024-24989", "major", "NULL pointer dereference in HTTP/3", "1.25.4+", "1.25.3", proto("http3")),
	adv("CVE-2024-24990", "major", "Use-after-free in HTTP/3", "1.25.4+", "1.25.0-1.25.3", proto("http3")),

	// ---- 2016–2022 ------------------------------------------------------
	adv("CVE-2022-41741", "medium", "Memory corruption in the ngx_http_mp4_module", "1.23.2+, 1.22.1+", "1.1.3-1.23.1, 1.0.7-1.0.15", cfg("requires the mp4 directive")),
	adv("CVE-2022-41742", "medium", "Memory disclosure in the ngx_http_mp4_module", "1.23.2+, 1.22.1+", "1.1.3-1.23.1, 1.0.7-1.0.15", cfg("requires the mp4 directive")),
	adv("CVE-2021-23017", "medium", "1-byte memory overwrite in resolver", "1.21.0+, 1.20.1+", "0.6.18-1.20.0", sev("high"), cfg("requires the \"resolver\" directive"),
		desc("Off-by-one in the resolver while processing a DNS response allows a 1-byte heap overwrite by an attacker able to forge UDP replies from the DNS server; may lead to worker crash or code execution. Applies only when \"resolver\" is configured (nginx.org severity: medium; NVD: high).")),
	adv("CVE-2019-9511", "medium", "Excessive CPU usage in HTTP/2 with small window updates", "1.17.3+, 1.16.1+", "1.9.5-1.17.2", proto("http2")),
	adv("CVE-2019-9513", "low", "Excessive CPU usage in HTTP/2 with priority changes", "1.17.3+, 1.16.1+", "1.9.5-1.17.2", proto("http2")),
	adv("CVE-2019-9516", "low", "Excessive memory usage in HTTP/2 with zero length headers", "1.17.3+, 1.16.1+", "1.9.5-1.17.2", proto("http2")),
	adv("CVE-2018-16843", "low", "Excessive memory usage in HTTP/2", "1.15.6+, 1.14.1+", "1.9.5-1.15.5", proto("http2")),
	adv("CVE-2018-16844", "low", "Excessive CPU usage in HTTP/2", "1.15.6+, 1.14.1+", "1.9.5-1.15.5", proto("http2")),
	adv("CVE-2018-16845", "medium", "Memory disclosure in the ngx_http_mp4_module", "1.15.6+, 1.14.1+", "1.1.3-1.15.5, 1.0.7-1.0.15", cfg("requires the mp4 directive")),
	adv("CVE-2017-7529", "medium", "Integer overflow in the range filter", "1.13.3+, 1.12.1+", "0.5.6-1.13.2", sev("high"), cfg("memory disclosure needs the proxy cache; otherwise limited impact"),
		desc("A specially crafted Range header triggers an integer overflow in the range filter, which can leak cache-file headers (potentially sensitive memory/backend addresses) when responses are served from the proxy cache (nginx.org severity: medium; NVD: high).")),
	adv("CVE-2016-4450", "medium", "NULL pointer dereference while writing client request body", "1.11.1+, 1.10.1+", "1.3.9-1.11.0"),
	adv("CVE-2016-0742", "medium", "Invalid pointer dereference in resolver", "1.9.10+, 1.8.1+", "0.6.18-1.9.9", cfg("requires the \"resolver\" directive")),
	adv("CVE-2016-0746", "medium", "Use-after-free during CNAME response processing in resolver", "1.9.10+, 1.8.1+", "0.6.18-1.9.9", cfg("requires the \"resolver\" directive")),
	adv("CVE-2016-0747", "medium", "Insufficient limits of CNAME resolution in resolver", "1.9.10+, 1.8.1+", "0.6.18-1.9.9", cfg("requires the \"resolver\" directive")),

	// ---- 2009–2014 ------------------------------------------------------
	adv("CVE-2014-3616", "medium", "SSL session reuse vulnerability", "1.7.5+, 1.6.2+", "0.5.6-1.7.4", cfg("requires a shared TLS session cache/ticket key across server blocks")),
	adv("CVE-2014-3556", "medium", "STARTTLS command injection", "1.7.4+, 1.6.1+", "1.5.6-1.7.3", proto("mail")),
	adv("CVE-2014-0133", "major", "SPDY heap buffer overflow", "1.5.12+, 1.4.7+", "1.3.15-1.5.11", cfg("requires SPDY to be enabled")),
	adv("CVE-2014-0088", "major", "SPDY memory corruption", "1.5.11+", "1.5.10", cfg("requires SPDY to be enabled")),
	adv("CVE-2013-4547", "medium", "Request line parsing vulnerability", "1.5.7+, 1.4.4+", "0.8.41-1.5.6", sev("high"),
		desc("An unescaped space in the request URI lets an attacker bypass location-based access restrictions or have a file handled by the wrong handler (e.g. executing an uploaded file as PHP via \"file.jpg \\0.php\") (nginx.org severity: medium; NVD: high).")),
	adv("CVE-2013-2070", "medium", "Memory disclosure with specially crafted HTTP backend responses", "1.5.0+, 1.4.1+, 1.2.9+", "1.1.4-1.2.8, 1.3.9-1.4.0", cfg("requires proxy_pass to an untrusted upstream")),
	adv("CVE-2013-2028", "major", "Stack-based buffer overflow with specially crafted request", "1.5.0+, 1.4.1+", "1.3.9-1.4.0", sev("critical"),
		desc("A chunked Transfer-Encoding request with a huge chunk size overflows a stack buffer in the worker process: unauthenticated remote code execution (public exploits exist).")),
	adv("CVE-2011-4963", "medium", "Vulnerabilities with Windows directory aliases", "1.3.1+, 1.2.1+", "nginx/Windows 0.7.52-1.3.0", windows()),
	adv("CVE-2012-2089", "major", "Buffer overflow in the ngx_http_mp4_module", "1.1.19+, 1.0.15+", "1.1.3-1.1.18, 1.0.7-1.0.14", cfg("requires the mp4 directive")),
	adv("CVE-2012-1180", "major", "Memory disclosure with specially crafted backend responses", "1.1.17+, 1.0.14+", "0.1.0-1.1.16", cfg("requires proxying to an upstream")),
	adv("CVE-2011-4315", "medium", "Buffer overflow in resolver", "1.1.8+, 1.0.10+", "0.6.18-1.1.7", cfg("requires the \"resolver\" directive")),
	adv("CVE-2010-2266", "major", "Vulnerabilities with invalid UTF-8 sequence on Windows", "0.8.41+, 0.7.67+", "nginx/Windows 0.7.52-0.8.40", windows()),
	adv("CVE-2010-2263", "major", "Vulnerabilities with Windows file default stream", "0.8.40+, 0.7.66+", "nginx/Windows 0.7.52-0.8.39", windows()),
	adv("CORE-2010-0121", "major", "Vulnerabilities with Windows 8.3 filename pseudonyms", "0.8.33+, 0.7.65+", "nginx/Windows 0.7.52-0.8.32", windows()),
	adv("CVE-2009-3555", "major", "The renegotiation vulnerability in SSL protocol", "0.8.23+, 0.7.64+", "0.1.0-0.8.22", cfg("requires TLS")),
	adv("CVE-2009-3898", "minor", "Directory traversal vulnerability", "0.8.17+, 0.7.63+", "0.1.0-0.8.16", mod("http_dav", "requires the WebDAV module (COPY/MOVE)")),
	adv("CVE-2009-2629", "major", "Buffer underflow vulnerability", "0.8.15+, 0.7.62+, 0.6.39+, 0.5.38+", "0.1.0-0.8.14", sev("critical"),
		desc("A crafted request URI causes a heap buffer underflow in ngx_http_parse_complex_uri: remote code execution in the worker process.")),
	adv("CVE-2009-3896", "major", "Null pointer dereference vulnerability", "0.8.14+, 0.7.62+, 0.6.39+, 0.5.38+", "0.1.0-0.8.13"),
}
