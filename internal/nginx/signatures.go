package nginx

import "regexp"

var (
	// reServer parses the Server banner of nginx and its direct derivatives:
	// "nginx", "nginx/1.24.0", "nginx/1.18.0 (Ubuntu)", "openresty/1.25.3.1",
	// "Tengine/3.1.0", "Angie/1.7.0", "freenginx/1.27.4".
	reServer = regexp.MustCompile(`(?i)^\s*(nginx|openresty|tengine|angie|freenginx)(?:/(\d+(?:\.\d+){1,3})[^\s(]*)?(?:\s*\(([^)]*)\))?\s*$`)
	// reServerLoose finds an nginx-family token inside a customised banner
	// ("cloudflare-nginx", "nginx-rc/1.25.3.2", "yunjiasu-nginx").
	reServerLoose = regexp.MustCompile(`(?i)\b(nginx|openresty|tengine)\b`)
	reKong        = regexp.MustCompile(`(?i)\bkong/(\d+(?:\.\d+){1,3})`)
	reAPISIX      = regexp.MustCompile(`(?i)\bapisix(?:/(\d+(?:\.\d+){1,3}))?`)

	// reErrorPage matches nginx's built-in error page byte structure. Groups:
	// 1 title, 2 heading, 3 optional explanation line (497-style), 4 footer.
	reErrorPage = regexp.MustCompile(`^<html>\r?\n<head><title>(\d{3} [^<]+)</title></head>\r?\n<body(?: bgcolor="white")?>\r?\n<center><h1>(\d{3} [^<]+)</h1></center>\r?\n(?:<center>([^<]+)</center>\r?\n)?<hr><center>([^<]*)</center>\r?\n</body>\r?\n</html>`)
	// reFooterProduct parses the error-page footer ("nginx/1.24.0", "openresty").
	reFooterProduct = regexp.MustCompile(`(?i)^(nginx|openresty|tengine|angie|freenginx)(?:/(\d+(?:\.\d+){1,3}))?(?:\s*\(([^)]*)\))?\s*$`)

	// reStubStatus matches the ngx_http_stub_status_module output.
	reStubStatus = regexp.MustCompile(`Active connections:\s*(\d+)\s*\n\s*server accepts handled requests\s*\n\s*(\d+)\s+(\d+)\s+(\d+)\s*\n\s*Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)`)
	// rePlusAPIRoot matches the NGINX Plus REST API version list ("[1,2,…,9]").
	rePlusAPIRoot = regexp.MustCompile(`^\s*\[\s*1(?:\s*,\s*\d+){0,20}\s*\]\s*$`)
	// reETag matches nginx's static-file ETag: "hex(mtime)-hex(size)".
	reETag = regexp.MustCompile(`^(W/)?"([0-9a-f]{6,10})-([0-9a-f]{1,12})"$`)
	// reAltSvcH3 finds an HTTP/3 advertisement in Alt-Svc.
	reAltSvcH3 = regexp.MustCompile(`(?i)\bh3(?:-\d+)?\s*=`)
	// reVTSVersion finds the nginx version in nginx-module-vts JSON output.
	reVTSVersion = regexp.MustCompile(`"nginxVersion"\s*:\s*"(\d+\.\d+\.\d+)"`)
)

// nginxReasons are HTTP reason phrases nginx spells differently from the RFC
// text other servers use ("405 Method Not Allowed", "414 URI Too Long", …).
var nginxReasons = map[int]string{
	405: "Not Allowed",
	408: "Request Time-out",
	414: "Request-URI Too Large",
	504: "Gateway Time-out",
}

// headerSig matches a response header, optionally by substring.
type headerSig struct {
	header   string
	contains string // case-insensitive substring; "" means "present at all"
	variant  string // product the header implies ("" = nginx family in general)
	module   string // module/feature the header reveals
	weight   int
	detail   string
}

var headerSigs = []headerSig{
	{"X-Accel-Buffering", "", "", "", 20, "nginx X-Accel control header leaked to the client"},
	{"X-Accel-Redirect", "", "", "", 20, "nginx X-Accel control header leaked to the client"},
	{"X-Accel-Expires", "", "", "", 20, "nginx X-Accel control header leaked to the client"},
	{"X-Accel-Limit-Rate", "", "", "", 20, "nginx X-Accel control header leaked to the client"},
	{"X-Accel-Charset", "", "", "", 20, "nginx X-Accel control header leaked to the client"},
	{"X-Nginx-Cache", "", "", "http_proxy cache", 30, "nginx cache status header"},
	{"X-Nginx-Cache-Status", "", "", "http_proxy cache", 30, "nginx cache status header"},
	{"X-NginX-Proxy", "", "", "", 30, "X-NginX-Proxy header (set by common nginx reverse-proxy configs)"},
	{"X-Nginx-Upstream", "", "", "", 30, "nginx upstream header"},
	{"X-Proxy-Cache", "", "", "http_proxy cache", 15, "cache status header in the form nginx configurations conventionally add ($upstream_cache_status)"},
	{"X-Cache-Status", "", "", "http_proxy cache", 15, "cache status header in the form nginx configurations conventionally add ($upstream_cache_status)"},
	{"X-FastCGI-Cache", "", "", "http_fastcgi cache", 20, "nginx FastCGI cache status header"},
	{"X-Page-Speed", "", "", "ngx_pagespeed", 40, "ngx_pagespeed header (the nginx build of PageSpeed; Apache's sends X-Mod-Pagespeed)"},
	{"X-Kong-Upstream-Latency", "", "Kong", "", 55, "Kong gateway header (Kong is built on OpenResty/nginx)"},
	{"X-Kong-Proxy-Latency", "", "Kong", "", 55, "Kong gateway header (Kong is built on OpenResty/nginx)"},
	{"X-Kong-Response-Latency", "", "Kong", "", 55, "Kong gateway header (Kong is built on OpenResty/nginx)"},
	{"Via", "kong/", "Kong", "", 50, "Via names the Kong gateway (built on OpenResty/nginx)"},
	{"X-APISIX-Upstream-Status", "", "Apache APISIX", "", 55, "Apache APISIX header (APISIX is built on OpenResty/nginx)"},
}

// cookieSig maps a cookie name to the nginx-related technology it implies.
type cookieSig struct {
	name   string
	prefix bool
	module string
	weight int
	detail string
}

var cookieSigs = []cookieSig{
	{"INGRESSCOOKIE", false, "ingress-nginx", 30, "ingress-nginx session-affinity cookie (default name)"},
}

// bodySig matches distinctive content in a response body.
type bodySig struct {
	id      string
	re      *regexp.Regexp
	variant string
	module  string
	weight  int
	detail  string
}

var bodySigs = []bodySig{
	{"body.welcome-nginx", regexp.MustCompile(`(?i)<title>Welcome to nginx( on [^<!]+)?!?</title>`), "", "", 60, "nginx default welcome page"},
	{"body.welcome-thanks", regexp.MustCompile(`Thank you for using nginx\.`), "", "", 45, "nginx default welcome page text"},
	{"body.welcome-testpage", regexp.MustCompile(`(?i)Test Page for the (?:HTTP Server|Nginx HTTP Server) on|This page is used to test the proper operation of the\s+<strong>nginx</strong>`), "", "", 55, "distribution nginx test page"},
	{"body.welcome-openresty", regexp.MustCompile(`(?i)<title>Welcome to OpenResty!</title>`), "OpenResty", "", 60, "OpenResty default welcome page"},
	{"body.welcome-tengine", regexp.MustCompile(`(?i)<title>Welcome to tengine!</title>`), "Tengine", "", 60, "Tengine default welcome page"},
	{"body.welcome-angie", regexp.MustCompile(`(?i)<title>Welcome to Angie!</title>`), "Angie", "", 60, "Angie default welcome page"},
	{"body.error-50x", regexp.MustCompile(`nginx\.org/r/error_log`), "", "", 55, "nginx default 50x.html error page"},
	{"body.plain-http-to-https", regexp.MustCompile(`The plain HTTP request was sent to HTTPS port`), "", "http_ssl", 60, "nginx-specific reply to cleartext HTTP on a TLS port (status 497)"},
	{"body.ssl-cert-error", regexp.MustCompile(`<center>(?:The SSL certificate error|No required SSL certificate was sent)</center>`), "", "http_ssl", 50, "nginx-specific client-certificate error page (status 495/496)"},
	{"body.header-too-large", regexp.MustCompile(`<title>400 Request Header Or Cookie Too Large</title>`), "", "", 50, "nginx-specific 'Request Header Or Cookie Too Large' page (status 494)"},
	{"body.tengine-error", regexp.MustCompile(`(?is)Sorry for the inconvenience\.<br\s*/?>\s*Please report this message and include the following information to us.*Powered by Tengine`), "Tengine", "", 65, "Tengine default error page"},
	{"body.autoindex", regexp.MustCompile(`^<html>\r?\n<head><title>Index of [^<]*</title></head>\r?\n<body(?: bgcolor="white")?>\r?\n<h1>Index of [^<]*</h1><hr><pre><a href="\.\./">\.\./</a>`), "", "http_autoindex", 55, "nginx autoindex directory listing (exact page structure)"},
	{"body.ingress-default-backend", regexp.MustCompile(`^default backend - 404\s*$`), "", "ingress-nginx", 35, "ingress-nginx default backend response"},
}

// mailBannerSigs are the default greetings of nginx's mail proxy.
var mailBannerSigs = []struct {
	re     *regexp.Regexp
	proto  string
	weight int
}{
	{regexp.MustCompile(`^\+OK POP3 ready(?: <[^>]+>)?$`), "POP3", 55},
	{regexp.MustCompile(`^\* OK IMAP4 ready$`), "IMAP", 55},
	{regexp.MustCompile(`^220 \S+ ESMTP ready$`), "SMTP", 50},
}
