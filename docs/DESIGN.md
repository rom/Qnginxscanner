# qnginxscanner — Design

This document describes the architecture of `qnginxscanner`, the nginx
detection heuristics it uses, the scoring model, the vulnerability catalogue,
and the data schema shared by all output formats.

## Goals and non-goals

**Goals**

- Decide, with auditable evidence, whether a network service is nginx or an
  nginx derivative (OpenResty, Tengine, Angie, freenginx, NGINX Plus, Kong,
  Apache APISIX) — including when the `Server` banner is hidden or rewritten.
- Fingerprint the version, release branch, protocols and modules; flag common
  misconfigurations from observed behaviour; correlate known version-based
  vulnerabilities, with a dedicated assessment for the NGINX2Root chain.
- Surface any published `security.txt`, and say when a CDN/WAF/reverse proxy
  conceals the origin.
- Accept flexible targets and ports, emit multiple machine formats, and render
  human reports — from both a CLI and a web GUI.
- Build anywhere with **no external dependencies**.

**Non-goals**

- No exploitation, authentication bypass, fuzzing or write operations. The
  tool never sends traffic meant to trigger a memory-safety bug; vulnerability
  results are version correlation, not proof of exploitability.
- No brute force and no content discovery beyond a fixed, short probe list.

## Package layout

```
cmd/qnginxscanner    CLI entrypoint: flags, config merge, output/report wiring,
                     shell completions generated from the live flag set
internal/
  version            build metadata (overridable via -ldflags)
  target             target spec parsing/expansion (URL, IP, CIDR, range, wildcard)
  portspec           port spec parsing (single, list, range)
  probe              low-level network I/O: TCP connect checks, bounded HTTP(S)
                     fetches with manual redirect following, banner grabbing,
                     rate limiter, SOCKS5 client; raw.go holds the hand-built
                     HTTP/1.x requests and the HTTP/2 preface fingerprint;
                     a Recorder hook feeds exchanges to the audit trail
  pcap               dependency-free libpcap writer: reconstructs HTTP exchanges
                     as raw-IPv4 TCP conversations with valid checksums
  corpus             sanitised record/replay fixture of a scan's detection inputs
                     (leaf: depends only on probe); drives offline replay
  nginx              nginx detection, fingerprinting, findings and vulnerability
                     correlation (the core):
                       types.go        Detection model, verdict bands
                       detect.go       Analyze: signals, weights, findings,
                                       NGINX2Root assessment
                       signatures.go   banner/error-page/body/header/cookie/
                                       mail-banner signature catalogues
                       probes.go       probe definitions (404 path, status
                                       paths, raw probes, alias + CRLF checks)
                       catalog.go      vulnerability/lifecycle catalogue, feed
                                       schema and loader, prerequisite resolution
                       vulndb.go       built-in advisories (nginx.org mirror)
                       feeds_import.go OSV and CSAF importers
                       sigpack.go      runtime-loadable signature packs
                       version.go      version parsing and comparison
  securitytxt        RFC 9116 security.txt discovery and parsing
  webserver          generic web-server identification + reverse-proxy/CDN/WAF/LB
                     detection (independent of the nginx verdict)
  dnsenum            subdomain discovery for "*.domain" via Certificate Transparency
  scanner            orchestration: expand → connect → probe → analyse → aggregate;
                     a host-level scheduler (HostConcurrency) over a global
                     service-concurrency pool; enrich.go (DNS, jitter, per-host
                     gate), filter.go (allow/block), checkpoint.go (resume),
                     audit.go (PCAP + decision log), replay.go (rebuild a
                     ScanResult from a recorded corpus), result.go (schema)
  report             rendering: text, JSON, XML, CSV, SARIF, NDJSON, RTF, PDF,
                     HTML; diff; --fail-on gating
  config             YAML-subset parser and typed configuration
  web                embedded single-page GUI + JSON API over the scanner
```

Dependencies flow one way: `scanner` imports `probe`, `nginx`, `securitytxt`,
`target`, `portspec`, `webserver`, `dnsenum`, `corpus` and `pcap`; `report` and
`web` import `scanner`; `cmd` wires it all together. `nginx` depends only on
`probe` (for the response types). There are no import cycles.

## Pipeline

```
targets ──► target.Expand / dnsenum ──► allow/block filter ──► endpoints
                                              │
                                   for each endpoint × port
                                              ▼
                                   probe.CheckPort (TCP connect)
                                              │ open
                                              ▼
                          GET root (scheme per --tls / URL / port)
                              │                         │ no HTTP reply
                              │                         ▼
                              │              --banners: GrabBanner ──► nginx.Analyze
                              ▼                                        (mail proxy)
          GET guaranteed-404 · security.txt · raw probes (no-host, plain-on-tls)
                              │
       deep mode (default):   ▼
          OPTIONS · raw probes (foreign-host, unknown-method, long-uri) · HTTP/2 preface
          status paths · CRLF check · sensitive files · alias + path-info checks
                                                      (optional ones budgeted)
                              │
              ┌───────────────┴────────────────┐
              ▼                                ▼
      nginx.Analyze(Input)            webserver.Analyze
   verdict, version, findings,     server product, proxy/CDN/WAF
   leads, NGINX2Root, lifecycle
              └───────────────┬────────────────┘
                              ▼
                    scanner.ServiceResult
                              ▼
             aggregate by host ─► ScanResult ─► report.*
```

The scanner collects responses; `nginx.Analyze` is a pure function of its
`Input` (root response, 404 response, raw replies, HTTP/2 fingerprint, deep
probe responses, alias, path-info and CRLF check responses, or a banner). This
is what
makes offline replay possible: a recorded `Input` reproduces the same
`Detection`.

Two levels of concurrency apply: `--host-concurrency` bounds how many distinct
hosts are worked at once and `--concurrency` bounds service probes across all
of them; `--per-host-concurrency` gates probes per host. Redirects are followed
manually so headers and cookies from every hop are available; response bodies
are read up to a byte cap (512 KiB by default), raw replies up to 64 KiB.

**Scheme selection.** In `auto` TLS mode the port's usual scheme is tried
first, then the other. A cleartext `400` whose body says the port expects TLS
(nginx's status 497 page) makes the scan continue over HTTPS; the cleartext
reply is passed to detection as a `plain-on-tls` raw observation, so the
dedicated raw probe is not sent again.

**DNS wildcards.** A `*.example.com` target is expanded before scanning by the
`dnsenum` package, which queries Certificate Transparency (crt.sh) for names
issued under the domain, normalises and de-duplicates them, and optionally
filters to names that resolve.

**Progress.** `scanner.Options.OnProgress` receives one event per enumeration
step and one per completed service (a monotonic `done`/`total` counter, the
host/port, open state, nginx verdict and version). `OnService` and
`OnHostResolved` stream complete service results and DNS data. The CLI renders
progress as an in-place counter or, with `--verbose`, a line per service; the
web server forwards the events to the browser as NDJSON.

## Probes

The probe list is defined in `internal/nginx/probes.go` so that detection and
the scanner agree on what is collected. All probes are read-only. `deep` is
the default mode (`Options.withDefaults`, the CLI flag, the web form and the
web API for an omitted or unknown `mode`); `detect` is the opt-in subset marked
"both" below.

| Probe | Mode | Kind | What it yields |
| --- | --- | --- | --- |
| `GET <path>` | both | HTTP | banner, headers, ETag, cookies, body, ALPN |
| `GET /qnginxscanner_probe_404` | both | HTTP | the server's own error page; also the baseline for proxy/WAF analysis |
| `no-host` | both | raw | `GET / HTTP/1.1` without `Host`: the front server must answer 400 itself |
| `plain-on-tls` | both, TLS only | raw | cleartext HTTP to the TLS port: nginx's 497 page |
| security.txt | both | HTTP | `/.well-known/security.txt`, `/security.txt` |
| `OPTIONS /` | deep | HTTP | WebDAV indicators |
| `unknown-method` | deep | raw | `QNGX / HTTP/1.1`: `405 Not Allowed` |
| `long-uri` | deep | raw | 9000-byte URI: `414 Request-URI Too Large` |
| `foreign-host` | deep | raw | `GET /` with `Host: qnginxscanner-probe.invalid`: a redirect whose `Location` carries that host shows redirects built from `$host`/`$http_host` |
| HTTP/2 preface | deep | raw | server `SETTINGS` + `WINDOW_UPDATE`; no request |
| status paths (9) | deep, optional | HTTP | `stub_status`, NGINX Plus API (+ one follow-up), nginx-module-vts, Prometheus metrics (`/metrics`) |
| CRLF check | deep, optional | HTTP | `GET /%0D%0AX-Qnginxscanner-Probe:%20crlf` |
| sensitive files (5) | deep, optional | HTTP | `/.git/HEAD`, `/.htpasswd`, `/.htaccess`, `/.env`, `/nginx.conf`; content validated, never reported |
| alias checks (≤ 3 × 4 requests) | deep, optional | HTTP | off-by-slash `alias` traversal; the fourth request (`<asset>/qnginxscanner.php`) is the PHP path-info check |
| banner grab | both, `--banners`, non-HTTP ports | TCP | mail proxy greeting |

**Why raw probes.** Go's `net/http` normalises what it receives: header order
is lost and reason phrases are not reliably preserved, and it cannot send a
request without `Host` or with an unknown method line of our choosing over a
connection we control. `probe.Fetcher.Raw` writes a hand-built HTTP/1.x request
to a direct connection and keeps the reply verbatim (status line, header names
in wire order, body). The `no-host` probe has a second purpose: when nginx is a
pure reverse proxy and hides its banner, normal responses come from the
upstream, but a request that violates HTTP/1.1 is rejected by nginx itself with
its own error page.

**HTTP/2 fingerprint.** `probe.Fetcher.H2` opens a connection (TLS with ALPN
`h2`, or cleartext prior knowledge), sends the client preface and an empty
`SETTINGS` frame, reads the server's `SETTINGS` and the first connection-level
`WINDOW_UPDATE`, then sends `GOAWAY`. No stream is opened. The result is
rendered Akamai-style as `id:value;…|window`.

**Opt-outs.** `--no-raw` (`Options.NoRawProbes`) disables the raw requests and
the HTTP/2 preface; `Meta.RawProbes` records the setting so a diff can
attribute a change to it. Raw probes need a direct connection and return an
error when a proxy is configured, which detection ignores. Optional deep probes
are counted against `--request-budget` and skipped entirely when the root or
404 response is `429`/`503`; `ServiceResult.DiscoveryLimited` records `budget`
or `rate-limited`. An alias candidate is only started when four requests
remain in the budget.

**Safety of the active checks.** The CRLF probe asks for a path whose
decoded form ends in CR LF plus a header line; a vulnerable configuration
echoes that header in its own response and nothing else is affected. The alias
check takes static assets the page already links to and re-requests them as
`/<seg>../<seg>/<file>`: with `location /seg { alias …/seg/; }` this resolves
to the very same public file, which proves the traversal without reading
anything private. A control request (`/<seg>../qnginxscanner-nx/<file>`) and a
byte-for-byte body comparison exclude catch-all sites. The path-info check
re-requests the same public asset as `<asset>/qnginxscanner.php`
(`PathInfoSuffix`): when a `location ~ \.php$` block hands that to PHP-FPM
with `cgi.fix_pathinfo` enabled, PHP runs the static file and echoes it back —
the same bytes, now `text/html` — which proves the misconfiguration without
uploading or executing anything. The sensitive-file checks (`SensitiveFiles`)
are single `GET`s whose body must match the file's format (a regular
expression per file), so a soft-404 is not reported; only the fact of exposure
goes into the finding, never the content. The `foreign-host` raw probe sends a
reserved `.invalid` host name and only looks at the `Location` of its own
reply.

## Detection model

Detection is **evidence-based and additive**. Each matched signal contributes a
weight; the confidence is the capped sum (0–100), mapped to a verdict band
(`confirmed` ≥ 70, `likely` ≥ 50, `possible` ≥ 25, else `none`). A service is
reported as nginx at confidence ≥ 50. Every signal is retained as an `Evidence`
record (signal id, source, detail, raw data, weight, tier, and provenance:
where/how/pattern/snippet/line/probe/status), and each distinct signal id is
counted once however many probes showed it. When the verdict is negative, any
variant or version gathered along the way is cleared so the result cannot
mislead.

### Signals

Weights are chosen so that one definitive signal confirms on its own, while
circumstantial signals must corroborate each other.

**Banner** — `Server` header (all values are considered; a proxy chain may add
more than one):

| Signal | Weight | Match |
| --- | --- | --- |
| `header.server` | 70 | `nginx`, `openresty`, `tengine`, `angie`, `freenginx`, optional `/version`, optional `(packaging)` |
| `header.server-kong` / `-apisix` | 60 | `kong/x.y.z`, `apisix[/x.y.z]` |
| `header.server-custom` | 55 | an nginx-family token inside a customised banner |

**Error pages and default content** — response bodies of every HTTP and raw
probe:

| Signal | Weight | Match |
| --- | --- | --- |
| `body.error-page` | 70 | the built-in error page, matched as an anchored byte structure (`<html>`, `<head><title>NNN Reason</title></head>`, `<body>`, `<center><h1>…</h1></center>`, optional explanation line, `<hr><center>FOOTER</center>`) with title equal to heading and a footer naming the product; version and packaging hint are parsed from the footer |
| `body.error-page-template` | 45 | the same structure with a footer that names no known product |
| `body.welcome-nginx`, `-openresty`, `-tengine`, `-angie` | 60 | default welcome page titles |
| `body.welcome-testpage` / `body.welcome-thanks` | 55 / 45 | distribution test pages; "Thank you for using nginx." |
| `body.error-50x` | 55 | default `50x.html` (`nginx.org/r/error_log`) |
| `body.autoindex` | 55 | autoindex listing, exact page structure |
| `body.plain-http-to-https` | 60 | status 497 message |
| `body.ssl-cert-error` | 50 | status 495/496 pages |
| `body.header-too-large` | 50 | status 494 page |
| `body.tengine-error` | 65 | Tengine's default error page |
| `body.ingress-default-backend` | 35 | `default backend - 404` |

**Protocol behaviour**

| Signal | Weight | Match |
| --- | --- | --- |
| `header.etag-format` | 35 / 40 | `ETag` of the form `"hex-hex"` whose first part equals `Last-Modified` as a Unix time in hex; 40 when the second part also equals `Content-Length`. Apache's default ETag differs (size first, mtime in microseconds), so a verified match is specific |
| `header.order` | 25 | raw reply whose headers start `Server, Date, Content-Type, Content-Length\|Transfer-Encoding` followed by `Connection` (or `Last-Modified, Connection` for static files). Apache sends `Date` before `Server`; most application servers put `Server` late or omit it |
| `status.reason-phrase` | 30 | raw status line with nginx's wording: `405 Not Allowed`, `408 Request Time-out`, `414 Request-URI Too Large`, `504 Gateway Time-out` |
| `h2.settings-fingerprint` | 40 / 45 | `INITIAL_WINDOW_SIZE=65536`, `MAX_FRAME_SIZE=16777215` and a connection `WINDOW_UPDATE` of 2147418112; 45 when the fingerprint is exactly nginx's default `3:128;4:65536;5:16777215\|2147418112` |

**Status endpoints** (deep mode, HTTP 200 only)

| Signal | Weight | Match |
| --- | --- | --- |
| `status.stub` | 85 | `stub_status` output; counters are parsed |
| `api.nginx-plus` | 90 | NGINX Plus API object with `version` and a `build` starting `nginx-plus` |
| `status.vts` | 85 | nginx-module-vts JSON with `nginxVersion` |
| `status.metrics` | 60 | Prometheus metrics of nginx-prometheus-exporter, ingress-nginx (`nginx_ingress_controller_*`) or the vts exporter at `/metrics` |

**Headers and cookies**

| Signal | Weight | Match |
| --- | --- | --- |
| `header.x-accel-*` | 20 | `X-Accel-Buffering`, `-Redirect`, `-Expires`, `-Limit-Rate`, `-Charset` |
| `header.x-nginx-cache`, `-cache-status`, `x-nginx-proxy`, `x-nginx-upstream` | 30 | nginx-named headers |
| `header.x-proxy-cache`, `x-cache-status` / `x-fastcgi-cache` | 15 / 20 | conventional `$upstream_cache_status` headers |
| `header.x-page-speed` | 40 | ngx_pagespeed |
| `header.x-kong-*`, `header.via` (`kong/`), `header.x-apisix-upstream-status` | 50–55 | Kong, APISIX |
| `cookie.ingresscookie` | 30 | ingress-nginx affinity cookie |

**Mail proxy** (banner of a non-HTTP port, `--banners`)

| Signal | Weight | Match |
| --- | --- | --- |
| `banner.mail-pop3` / `-imap` | 55 | `+OK POP3 ready`, `* OK IMAP4 ready` |
| `banner.mail-smtp` | 50 | `220 <host> ESMTP ready` |

Signature packs (`sigpack.go`) append header, cookie and body matchers to the
same catalogues at start-up; they are validated as a whole, size-bounded and
weight-clamped, and their `id@version` is recorded in `Meta.SignaturePacks`.

### Variant and version

- **Variant** is ranked by specificity: NGINX Plus (from its API) over a named
  derivative over plain `nginx`. A positive verdict with no variant defaults to
  `nginx`.
- **Version** observations are ranked by source: NGINX Plus API and
  nginx-module-vts (3) over the `Server` header and error-page footer (2) over
  a Kong `Via` header (1). Every observation is kept with its source;
  `version_conflict` is set when they disagree at major.minor level.
- **Core version**: advisories are keyed on the nginx core. nginx and NGINX
  Plus report it directly; OpenResty `X.Y.Z.N` bundles core `X.Y.Z`; Tengine,
  Angie, freenginx, Kong and APISIX use their own numbering, so no core version
  is derived (`version` stays empty, `product_version` holds theirs).
- **Packaging hint**: the parenthesised banner suffix (`Ubuntu`, `Debian`, …)
  is stored as `distro`.
- **Protocols**: `http/1.1`; `h2` (negotiated via ALPN, or an `Upgrade: h2c`
  advertisement) or `h2c` (prior-knowledge preface accepted on a cleartext
  port); `h3 (advertised)` from `Alt-Svc`; `mail (…)` from a banner.
- **Modules**: only what was observed — `http_ssl` (TLS), `http_v2`, `http_v3`,
  `http_stub_status`, `http_autoindex`, `http_dav` (from `OPTIONS`), cache
  headers, `ngx_pagespeed`, `ingress-nginx` (plus `ingress-nginx <version>`
  when its metrics disclose the controller version), `lua (OpenResty)`, `vts`,
  the NGINX Plus API, `mail`.

### Findings

Findings are derived in deep mode from observed behaviour, not from the
version: `stub-status-exposed` (low), `plus-api-exposed` (medium),
`vts-status-exposed` (low), `metrics-exposed` (low), `version-disclosure`
(info), `default-page` (info, a stock welcome page), `autoindex-enabled`
(low), `alias-traversal` (high), `crlf-injection` (medium), `php-pathinfo`
(high, static files handed to PHP-FPM), `host-header-redirect` (low, from the
`foreign-host` raw probe) and the exposed-file findings `git-exposed` (high),
`htpasswd-exposed` (high), `env-exposed` (high), `nginx-conf-exposed` (medium)
and `htaccess-exposed` (low; nginx ignores `.htaccess`, so its rules are not
enforced, and nginx has no default protection for `.ht*` or dotfiles). Each
carries a detail, a URL and a remediation hint, and is de-duplicated by id.

## Vulnerability catalogue

The data is a **catalogue of `FeedEntry` records** (`catalog.go`, `vulndb.go`).
The built-in set mirrors https://nginx.org/en/security_advisories.html — 77
advisories from 2009 to 2026 — entered with the vendor's own text: the
"Vulnerable" ranges become `RangeSpec`s (`introduced`/`last` inclusive bounds,
or `eq`), and "Not vulnerable: 1.31.9+, 1.30.7+" becomes `fixed_in`.

**Matching.** A version matches an entry when any affected range matches,
unless it is on the same major.minor as a `fixed_in` release and at or above
it. That exception is how a stable-branch backport is expressed: 1.30.7 lies
inside "0.6.18–1.31.8" numerically but is not affected. Versions compare as
major.minor.patch.

**Severity.** nginx.org's "major", "medium" and "minor" map to high, medium and
low. A few entries are raised where code execution is documented (for example
CVE-2026-123007, CVE-2013-2028); their description states both ratings.

**Prerequisites.** An entry may carry structured conditions, resolved against
`ObservedFacts` gathered during the scan:

| Kind | `want` | Resolution |
| --- | --- | --- |
| `protocol` | `http2`, `http3`, `mail` | HTTP/2: observed when negotiated, advertised or fingerprinted; contradicted when the preface was refused or TLS ALPN chose something else. HTTP/3: observed from `Alt-Svc`. Mail: observed from a banner. Otherwise unknown |
| `os` | `windows` | the scan does not determine the OS: unknown |
| `module` | module name | observed when in the module list; never contradicted |
| `config` | — | not observable remotely: always unknown, displayed as context |

A lead's `applicability` is `contradicted` if any prerequisite is, else
`observed` if any is, else empty. Leads are never dropped on this basis.

**Which products are correlated.** nginx; OpenResty (through its core, with a
caveat in `match_basis`); NGINX Plus (through the reported core version, with a
pointer to the F5 advisory). Products with their own numbering are skipped.

**Lifecycle.** `Catalog.Support` classifies a plain-nginx version against the
supported-branch set (built-in: 1.31 mainline, 1.30 stable; latest 1.31.9 and
1.30.7): unsupported branches are `legacy` and end-of-life, a supported branch
behind its latest release is `outdated`.

**Feeds.** `--vuln-feed` loads files or URLs and `Merge`s them: entries are
appended, `supported` replaces the branch set, `latest` overrides per branch.
`ParseFeed` sniffs the JSON and accepts the native `qnginxscanner-vuln-feed/1`
schema, OSV records (single or array) and CSAF 2.0; `feeds_import.go` maps the
latter two into `FeedEntry`, keeping only nginx packages. The merged catalogue
is used by live scans, by replay and, in `--web` mode, by every GUI scan and
by origin-compare (`web.Server.SetCatalog`).

### NGINX2Root assessment

The five advisories of the chain (CVE-2026-123007, CVE-2026-123633,
CVE-2026-121810, CVE-2026-123634, CVE-2026-113425; fixed in 1.31.9 / 1.30.7)
are ordinary catalogue entries tagged `nginx2root`. After correlation,
`assessNginx2Root` summarises them per service:

- no core version, or a product that is not correlated → `unknown-version`;
- at least one correlated lead carries the tag → `vulnerable-version`, with the
  matching CVE ids;
- otherwise → `not-affected`.

It also copies the HTTP/2, HTTP/3 and mail observations and composes a detail
sentence, adding a backport caveat when a packaging hint was seen. The status
deliberately does not depend on the protocol observations: they describe one
endpoint, and the resolver advisory needs neither HTTP/2 nor HTTP/3.

This is a **version-based** assessment. The tool does not attempt to trigger
the bugs, so it can neither confirm exploitability nor verify a mitigation, and
a server that hides its version cannot be assessed at all. Fixed NGINX Plus
releases (37.0.7.1 / 37.2.0.1 and 37.0.8.1 / 37.3.0.1) are taken from the Wiz
analysis; the F5 article K000164058 could not be retrieved automatically.
Sources: nginx.org, https://nginx2root.com/,
https://xint.io/blog/nginx2root-remote-code-execution,
https://wiz.io/blog/nginx-http2-rce-vulnerabilities.

## Web server, reverse proxy, CDN and WAF

Independently of the nginx verdict, the `webserver` package analyses the root
response plus the 404, `OPTIONS` and status-path responses to:

- **Identify the web server** — product, version, OS hint and server-level
  modules — from `Server` banners, module/runtime headers, the `DAV` header and
  error-page signatures (nginx/Apache/IIS/LiteSpeed/…). If a `Server` value is
  a CDN token the origin product is reported as concealed.
- **Detect a front layer** — CDN, WAF, cache or load balancer — from
  distinctive headers, cookies and block/challenge page bodies. Any front layer
  sets `concealed`, with a note on what that implies.

Every proxy/server observation carries a numeric confidence and a
low/medium/high tier. This matters for interpreting an nginx verdict: an
nginx-based CDN edge is nginx, but its version and findings describe the edge,
not the origin behind it.

## Enrichment, politeness and resume

A global token-bucket limiter in the probe layer caps requests per second (raw
probes included); per-host concurrency and jitter are enforced in the scanner;
transient failures are retried with backoff. Hosts are optionally resolved
(forward + reverse DNS). A checkpoint file records each completed service as
NDJSON so an interrupted scan resumes by skipping finished work. HTTP requests
can carry custom headers, Basic/Bearer/cookie auth and a Host override, be
pinned to an address (`--resolve`, `--sni`), and route through an http(s) or
SOCKS5 proxy (a minimal dependency-free SOCKS5 client). Raw probes carry only
`Host`, `User-Agent`, `Accept` and `Connection`.

## Audit trail: PCAP capture and session log

The `Fetcher` exposes a `Recorder` interface that receives every HTTP
request/response `Exchange` (across redirect hops too) and every raw probe. The
scanner's `audit.go` fans each exchange out to the optional outputs:

- **PCAP** (`--pcap`): the sink reconstructs the wire bytes of the request and
  response and hands them to the `pcap` package, which synthesises a complete
  TCP conversation — handshake, PSH/ACK data segments chunked at a 1460-byte
  MSS, FIN teardown — with correct sequence numbers and valid IPv4/TCP
  checksums. Link type is `RAW` (IPv4); non-IP hosts map to stable `10/8`
  addresses. It is a faithful record of what was requested and returned
  (plaintext, even for TLS targets), not a timing-accurate wire capture. Raw
  probes appear with the method `RAW` and their request line rather than their
  exact bytes; the HTTP/2 preface exchange, connect checks and banner grabs are
  not recorded.
- **Session log** (`--log`): a plain-text journal. Each exchange is logged as
  it happens; then, per service, a `DECISION` block states the web server, any
  reverse proxy, the nginx verdict, version, lifecycle and protocols, walks the
  evidence highest-weight-first with its provenance, and lists the findings and
  the NGINX2Root assessment.

Write failures are best-effort and never abort a scan.

## Record and replay

With `--record-corpus`, the scanner snapshots each service's `nginx.Input` into
a `corpus.Service` (root, 404, deep probe responses, raw replies, HTTP/2
fingerprint, alias, path-info and CRLF responses, or the banner). Cookie values and
credential headers are redacted; bodies are kept byte-exact (base64), which the
alias comparison requires. `scanner.Replay` rebuilds the `Input`s and calls
`nginx.Analyze`, using the current build's catalogue, feeds and signature
packs. Port state, security.txt and web-server/proxy identification are not
part of the corpus.

## Data schema

All formats serialise the same `ScanResult`:

```
ScanResult
├─ meta      { tool, version, mode, started_at, finished_at, duration_ms, ports[],
│              tls_mode, timeout_ms, follow, insecure, auth, pinned, allow_block,
│              raw_probes, catalog_advisories, signature_packs[] }
├─ targets[] { host, inputs[], addresses[], ptr[], services[] }
│    └─ service { host, port, tls, scheme, url, port_open, error, banner,
│                 duration_ms, checked_at, discovery_limited,
│                 http   { url, final_url, status, proto, server, powered_by,
│                          title, content_type, redirects, tls{…}, headers{},
│                          http2, alpn, h2c },
│                 server { product, version, os, modules[], evidence[] },
│                 proxy  { present, concealed, cdn[], waf[], caches[],
│                          load_balancers[], note, evidence[] },
│                 nginx  { is_nginx, verdict, confidence,
│                          variant, version, product_version, version_source,
│                          version_hidden, branch, outdated, end_of_life,
│                          eol_detail, distro,
│                          version_observations[]{version,source,rank},
│                          version_conflict,
│                          protocols[], modules[], h2_fingerprint,
│                          status_exposed, status_url,
│                          stub_status{url,active,accepts,handled,requests,
│                                      reading,writing,waiting},
│                          nginx2root{status,cves[],http2,http3,mail,detail},
│                          evidence[]{signal,source,detail,data,weight,
│                              confidence,where,how,pattern,snippet,line,
│                              probe,status},
│                          findings[]{id,severity,title,detail,url,remediation},
│                          vulnerabilities[]{id,severity,title,
│                              affected_versions,fixed_versions,description,
│                              reference,match_basis,tags[],
│                              prerequisites[]{detail,state},applicability} },
│                 security_txt { present, url, signed, contact[], expires, … } }
└─ summary   { hosts_scanned, services_probed, open_ports, http_services,
               nginx_confirmed, nginx_likely, nginx_possible,
               vulnerabilities, findings, end_of_life,
               nginx2root, nginx2root_unknown,
               security_txt, behind_proxy, waf_protected }
```

`nginx` is present on every service that answered HTTP (with verdict `none`
when nothing matched) and on a non-HTTP service whose banner matched. The
`nginx2root`, `findings`, `vulnerabilities` and lifecycle fields are filled in
deep mode only. Empty fields are omitted from JSON.

JSON and XML emit this directly (XML is rooted at `<scan>`; maps are omitted as
XML cannot represent them). CSV flattens one row per service; SARIF 2.1.0
exposes vulnerability leads, findings, end-of-life branches and NGINX2Root
exposure as results with rules; NDJSON streams one object per service. Text,
RTF, PDF and HTML are produced from a single intermediate **document model**
(`internal/report/doc.go`) of headings, key/value rows, bullets and rules, so
the human formats stay consistent. `report.Diff` compares two results
(coverage-aware, with provenance notes derived from `meta`), and
`report.FailOn` powers the `--fail-on` gates: severity (leads and findings),
`eol` and `nginx2root`.

## Self-contained RTF, PDF and HTML

To avoid third-party dependencies, the writers are implemented directly (HTML
is rendered from the same document model with inline CSS):

- **RTF** — emits an `{\rtf1 …}` document with bold headings, sized text and
  bullet paragraphs; control characters are escaped and non-ASCII is encoded as
  `\uN?`.
- **PDF** — a minimal PDF 1.4 generator (`internal/report/pdfwriter.go`): pages
  of left-aligned text in the standard Helvetica / Helvetica-Bold fonts (no
  embedding), with word wrapping, pagination, horizontal rules and a correct
  cross-reference table and trailer.

## Configuration

`internal/config` includes a deliberately small YAML-subset parser (comments,
space-indented nested maps, scalar key/values, block lists of scalars, quoted
scalars; tabs rejected; no flow syntax such as `[]`). It is sufficient for the
documented schema and keeps the tool dependency-free. Booleans are parsed as
pointers so the CLI can tell "unset in config" from "explicitly false" when
merging flag precedence.

## Security considerations

- The tool only reads; it never submits forms, uploads, or attempts
  exploitation. The active misconfiguration checks (CRLF, alias, path-info)
  are constructed so that a positive result discloses nothing beyond what was
  already public, and the content of an exposed sensitive file is validated
  but never stored in the result.
- The raw probes are syntactically unusual on purpose and may be logged or
  counted by the target's defences; `--no-raw` exists for environments where
  only well-formed HTTP is acceptable.
- The web GUI binds to localhost by default, supports HTTP Basic auth, and
  size-caps request bodies. A scan started from the GUI runs until it finishes
  or the client cancels or disconnects. The API answers cross-origin requests,
  so do not expose the GUI to untrusted networks without `--web-auth`.
- Response bodies are read up to a byte cap to bound memory; signature-pack
  regular expressions are RE2 (linear time) and length-bounded.
- Target expansion is capped per spec to prevent accidental massive sweeps.
- Subdomain enumeration reads only public Certificate Transparency data; it
  does not brute-force DNS or probe the target during discovery.
- External feeds and packs are read only from the locations the operator
  names and are validated before use; remote fetches are size-limited.
