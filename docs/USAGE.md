# qnginxscanner — Usage

`qnginxscanner` decides whether network services are served by nginx (or an
nginx derivative), collects the evidence behind each verdict, and — in deep
mode — fingerprints the version, flags misconfigurations and correlates known
vulnerabilities, including the NGINX2Root chain. It runs as a one-shot CLI or
as a local web GUI.

> **Authorised use only.** Only scan hosts and networks you own or are
> explicitly permitted to test.

## Contents

- [Synopsis](#synopsis)
- [Targets](#targets)
- [Ports](#ports)
- [TLS](#tls)
- [Scan depth](#scan-depth-detect-vs-deep)
- [What is sent to targets](#what-is-sent-to-targets)
- [Interpreting results](#interpreting-results)
- [Findings](#findings)
- [Vulnerability leads](#vulnerability-leads)
- [NGINX2Root](#nginx2root)
- [Release lifecycle](#release-lifecycle)
- [Mail proxy](#mail-proxy)
- [Output formats](#output-formats)
- [Report formats](#report-formats)
- [Progress and verbosity](#progress-and-verbosity)
- [Configuration file](#configuration-file)
- [Web GUI](#web-gui)
- [Authentication & request shaping](#authentication--request-shaping)
- [Connection pinning](#connection-pinning-ip--host--sni)
- [Politeness & rate limiting](#politeness--rate-limiting)
- [Enrichment](#enrichment)
- [Vulnerability feeds](#vulnerability-feeds)
- [Signature packs](#signature-packs)
- [Shell completions](#shell-completions)
- [Diffing scans](#diffing-scans)
- [Resume](#resume)
- [Audit trail (PCAP and session log)](#audit-trail-pcap-and-session-log)
- [Record & replay](#record--replay-offline-regression-harness)
- [Exit status](#exit-status)
- [Examples](#examples)

## Synopsis

```
qnginxscanner [options] <target> [target ...]
qnginxscanner --web [--listen host:port]
qnginxscanner --config scan.yaml
```

Run `qnginxscanner --help` for the full flag list. Flags may be written with
one or two dashes and may appear before, between or after targets.

## Targets

Targets are given as positional arguments (or in the config file / web form).
Each target may be any of:

| Form | Example |
| --- | --- |
| URL | `https://example.com/app/` |
| IPv4 literal | `203.0.113.10` |
| IPv6 literal | `2001:db8::1` or `[2001:db8::1]` |
| IPv4 CIDR | `10.0.0.0/24` |
| IPv6 CIDR | `2001:db8::/120` |
| Dashed range (last octet) | `192.168.1.10-20` |
| Dashed range (full) | `10.0.0.1-10.0.0.50`, `2001:db8::1-2001:db8::ff` |
| Wildcard | `192.168.1.*`, `10.0.*.*`, `2001:db8::*` (IPv6 trailing group) |
| DNS wildcard | `*.example.com` |
| Hostname | `example.com` |

Targets may also be read from a file or stdin with `--targets-file FILE`
(alias `-iL`), one per line; blank lines and `#` comments are ignored. Use `-`
to read from stdin. File targets are added to any given on the command line.

When a target is a **URL**, its scheme, port and path are honoured: that exact
endpoint is scanned (and `--ports` is ignored for it). All other target forms
are scanned across the selected port set.

A **DNS wildcard** (`*.example.com`) is expanded by querying Certificate
Transparency logs (crt.sh) for names issued under the domain; the discovered
hosts are then scanned across the selected ports. Quote it in a shell
(`'*.example.com'`) so the shell does not glob it. Disable this with
`--no-dns-enum`; `--verify-subdomains` keeps only names that resolve. If the
lookup fails (e.g. the CT service is unreachable), the spec is skipped with a
progress message and the rest of the scan continues.

A single spec is capped at `--max-hosts` (default 65 536) expanded hosts to
guard against an accidental huge range.

`--allow PATTERN` and `--block PATTERN` (both repeatable) filter the expanded
targets: a pattern is an exact host/IP, a CIDR block, or a `*.domain` /
`.domain` suffix. With an allow list only matching hosts are scanned; the block
list then drops matching hosts.

## Ports

`--ports` accepts single ports, comma-separated lists, inclusive ranges, and
any mixture:

```
--ports 80
--ports 80,443,8080
--ports 8000-8100
--ports 80,443,8000-8010,9000
```

With no `--ports`, a built-in common-web-port set is used:
`80, 443, 8000, 8008, 8080, 8443, 8888, 3000, 5000, 9000`.

Mail ports are not in the default set; name them explicitly to look for the
nginx mail proxy (see [Mail proxy](#mail-proxy)).

## TLS

`--tls` controls whether services are probed over HTTPS:

- `auto` (default) — infer from the port (443/8443/9443/4443/10443 ⇒ HTTPS),
  and fall back to the other scheme if the first attempt yields no HTTP
  response. A cleartext reply saying the port expects TLS (nginx's "The plain
  HTTP request was sent to HTTPS port") makes the scan switch to HTTPS and is
  kept as evidence.
- `on` — force HTTPS.
- `off` — force HTTP.

A URL target's own scheme always wins. Use `--insecure` to probe hosts with
self-signed or otherwise invalid certificates.

## Scan depth: detect vs deep

- `--mode detect` (default) — decide **whether** each service is nginx and
  record the evidence. A handful of requests per service.
- `--mode deep` — additionally fingerprint the **product and version**, the
  **release branch**, the **protocols** on the endpoint and observed
  **modules**; check for **misconfigurations** ([findings](#findings)); and
  correlate **known vulnerabilities** from the version, including the
  [NGINX2Root](#nginx2root) assessment and the
  [release lifecycle](#release-lifecycle) status.

Detect mode already reports a version when the server announces one; findings,
vulnerability leads, the lifecycle status and the NGINX2Root assessment exist
only in deep mode.

## What is sent to targets

Every probe is read-only: nothing is submitted, nothing is brute-forced, and no
request is designed to crash or corrupt the server.

**Both modes**, for each open port:

| Probe | Purpose |
| --- | --- |
| TCP connect | is the port open? |
| `GET <path>` (default `/`), following redirects | banner, headers, ETag, cookies, body |
| `GET /qnginxscanner_probe_404` | the server's own 404 page (nginx's built-in error page identifies it and shows the version when `server_tokens` is on) |
| raw `no-host`: `GET / HTTP/1.1` without a `Host` header | the front server must answer 400 itself, so the reply is its own error page even when every normal request is proxied elsewhere; also shows the wire order of headers |
| raw `plain-on-tls` (TLS services only): cleartext HTTP to the TLS port | nginx answers with its distinctive "plain HTTP request was sent to HTTPS port" page |
| `GET /.well-known/security.txt`, `/security.txt` | RFC 9116 contact data (`--security-txt=false` disables) |

**Deep mode** adds:

| Probe | Purpose |
| --- | --- |
| `OPTIONS /` | WebDAV (`Dav` header, `PROPFIND` in `Allow`) and server identification |
| raw `unknown-method`: `QNGX / HTTP/1.1` | nginx's static handler replies `405 Not Allowed` |
| raw `long-uri`: a 9000-byte request URI | above nginx's default 8k header buffer: `414 Request-URI Too Large` |
| HTTP/2 connection preface + empty `SETTINGS` frame | reads the server's opening `SETTINGS` and `WINDOW_UPDATE`; no request is made and the connection is closed with `GOAWAY`. Over TLS it offers ALPN `h2`; on a cleartext port it tries prior-knowledge h2c |
| `GET` `/nginx_status`, `/stub_status`, `/basic_status`, `/nginx-status`, `/status`, `/server-status`, `/api/`, `/status/format/json` | exposed `stub_status`, NGINX Plus API, nginx-module-vts. If `/api/` is the NGINX Plus API version list, `/api/<n>/nginx` is fetched for version and build |
| `GET /%0D%0AX-Qnginxscanner-Probe:%20crlf` | CRLF header-injection check; only affects its own response |
| alias off-by-slash check | for up to three static assets linked from the page (one per first path segment): the asset, the same asset via `/<seg>../<seg>/<file>`, and a control path `/<seg>../qnginxscanner-nx/<file>` that must not resolve. It only re-reads a file that is already public |

With `--banners`, an open port that does not speak HTTP is read for a greeting;
if none arrives, a bare CRLF is sent once to prompt one.

Controls:

- `--no-raw` removes the raw requests and the HTTP/2 preface, so only
  well-formed HTTP requests are sent. It costs evidence: header order, reason
  phrases and the HTTP/2 fingerprint are only visible to those probes, and
  without the HTTP/2 preface the HTTP/2 status of a cleartext port stays
  unknown.
- Raw probes and the HTTP/2 preface need a direct connection and are **skipped
  automatically when `--proxy` is set**.
- `--request-budget N` caps the optional deep probes per service (status
  paths, the CRLF check, the alias checks); 0 means no cap. The `OPTIONS`
  request, the raw probes and the HTTP/2 preface always run in deep mode.
- A host that answers the first requests with `429` or `503` gets none of the
  optional deep probes.
- When optional probing stops early, the service's `discovery_limited` field
  says why: `budget` or `rate-limited`.

All requests carry a `User-Agent` naming the tool (override with
`--user-agent`). The malformed raw requests may show up in the server's error
log or be counted by a WAF or IDS.

## Interpreting results

Each service gets a **verdict** derived from a weighted confidence score
(0–100, the capped sum of the matched signals' weights):

| Verdict | Score | Meaning |
| --- | --- | --- |
| `confirmed` | ≥ 70 | strong, usually unambiguous nginx evidence |
| `likely` | 50–69 | corroborating signals without a definitive one |
| `possible` | 25–49 | weak or circumstantial signals |
| `none` | < 25 | no meaningful nginx evidence |

A service counts as nginx (`is_nginx`) from `likely` upward. Each distinct
signal is counted once, however many probes showed it.

### Detection signals

| Signal id | Weight | What it is |
| --- | --- | --- |
| `header.server` | 70 | `Server` banner naming nginx, OpenResty, Tengine, Angie or freenginx (version and packaging hint parsed) |
| `header.server-kong`, `header.server-apisix` | 60 | `Server` banner naming Kong or Apache APISIX (both built on OpenResty/nginx) |
| `header.server-custom` | 55 | a customised banner containing an nginx-family token (`cloudflare-nginx`, …) |
| `body.error-page` | 70 | nginx's built-in error page, byte-exact structure, footer naming the product (and version) |
| `body.error-page-template` | 45 | the same exact structure with a customised footer |
| `body.welcome-*` | 45–60 | default welcome pages (nginx, OpenResty, Tengine, Angie, distribution test pages) |
| `body.error-50x` | 55 | the default `50x.html` |
| `body.autoindex` | 55 | an nginx autoindex listing (exact page structure) |
| `body.plain-http-to-https` | 60 | "The plain HTTP request was sent to HTTPS port" (status 497) |
| `body.ssl-cert-error`, `body.header-too-large` | 50 | the 495/496 client-certificate pages; "Request Header Or Cookie Too Large" (494) |
| `body.tengine-error` | 65 | Tengine's default error page |
| `body.ingress-default-backend` | 35 | ingress-nginx default backend reply |
| `header.etag-format` | 35–40 | static-file `ETag` equal to `hex(mtime)-hex(size)`, verified against `Last-Modified` (40 when the size also equals `Content-Length`) |
| `header.order` | 25 | response headers in nginx's fixed wire order: `Server, Date, Content-Type, Content-Length` or `Transfer-Encoding`, `Connection` (raw probes only) |
| `status.reason-phrase` | 30 | nginx's own reason phrases: `405 Not Allowed`, `408 Request Time-out`, `414 Request-URI Too Large`, `504 Gateway Time-out` (raw probes only) |
| `h2.settings-fingerprint` | 40–45 | HTTP/2 opening frames `4:65536;5:16777215` + `WINDOW_UPDATE 2147418112`; 45 when the full default fingerprint `3:128;4:65536;5:16777215\|2147418112` matches |
| `status.stub`, `status.vts` | 85 | readable `stub_status` page; nginx-module-vts status JSON |
| `api.nginx-plus` | 90 | NGINX Plus REST API reporting version and build |
| `header.x-accel-*` | 20 | `X-Accel-*` control headers leaked to the client |
| `header.x-nginx-*`, cache-status headers | 15–30 | `X-Nginx-Cache`, `X-NginX-Proxy`, `X-Proxy-Cache`, `X-Cache-Status`, `X-FastCGI-Cache`, … |
| `header.x-page-speed` | 40 | ngx_pagespeed |
| `header.x-kong-*`, `header.via` (Kong), `header.x-apisix-upstream-status` | 50–55 | Kong / APISIX gateway headers |
| `cookie.ingresscookie` | 30 | ingress-nginx session-affinity cookie `INGRESSCOOKIE` |
| `banner.mail-pop3`, `-imap`, `-smtp` | 50–55 | mail proxy default greetings (with `--banners`) |

Every evidence item carries its weight, a confidence tier (low/medium/high) and
full provenance — *where* it was found, *how* it matched, the literal matcher,
the matched snippet (with the body line number where applicable), the exact
probe (method + URL, or the raw probe's name) and its HTTP status — so a
verdict can be audited down to the byte. The same reasoning is written to the
`--log` session log.

### What deep mode reports about an nginx service

- **Product** (`variant`): nginx, OpenResty, Tengine, Angie, freenginx,
  NGINX Plus, Kong or Apache APISIX.
- **Version** (`version`): the nginx core version, which is what advisories are
  keyed on. For OpenResty the core is the first three components of its version
  (`openresty/1.25.3.1` ⇒ core 1.25.3) and the full product version is kept in
  `product_version`. Tengine, Angie, freenginx, Kong and APISIX use their own
  numbering: their version is shown as `product_version` and no core version is
  derived.
- **Version hidden** (`version_hidden`): nginx was identified but discloses no
  version (`server_tokens off`).
- **Version observations**: every version seen, with its source. A *version
  conflict* is flagged when sources disagree at major.minor level (several
  backends, a cache, or a proxy chain).
- **Packaging hint** (`distro`): the parenthesised part of the banner, e.g.
  `Ubuntu`. Distribution builds may backport fixes without changing the
  version.
- **Release branch**, **outdated**, **end of life** — see
  [Release lifecycle](#release-lifecycle).
- **Protocols**: `http/1.1`, `h2`, `h2c`, `h3 (advertised)` (from `Alt-Svc`;
  no QUIC connection is made), `mail (POP3|IMAP|SMTP)`.
- **Modules / features** whose presence was observed, for example `http_ssl`,
  `http_v2`, `http_v3`, `http_stub_status`, `http_autoindex`, `http_dav`,
  `http_proxy cache`, `ngx_pagespeed`, `ingress-nginx`, `lua (OpenResty)`,
  `mail`. Absence from the list is not evidence that a module is missing.
- **HTTP/2 fingerprint** (`h2_fingerprint`) in the `id:value;…|window` form.
- **Status endpoint** and the parsed `stub_status` counters when exposed.

## Findings

Findings are observed directly on the service (deep mode), independent of the
version:

| ID | Severity | Trigger |
| --- | --- | --- |
| `alias-traversal` | high | `/<seg>../<seg>/<file>` returns byte-for-byte the same content as the public `/<seg>/<file>` while the control path does not: `location /seg` without a trailing slash combined with `alias`, which lets `/seg../` escape one directory above the alias target |
| `crlf-injection` | medium | the probe's own header came back as a real response header: an encoded CR LF in the path was decoded and copied into the response head (typically `return 301 https://$host$uri;`) |
| `plus-api-exposed` | medium | the NGINX Plus REST API answers unauthenticated requests |
| `stub-status-exposed` | low | a `stub_status` page is publicly readable |
| `vts-status-exposed` | low | nginx-module-vts status JSON is publicly readable |
| `autoindex-enabled` | low | the scanned page is an nginx directory listing |
| `version-disclosure` | info | the server announces its version |

Each finding has a detail text, the URL it was observed at and a remediation
hint. The alias check proves the traversal by re-reading a file that is already
public; it never requests anything else through the traversal. A site that
returns the same body for every path (a catch-all) is not reported.

## Vulnerability leads

Deep mode correlates the detected nginx core version against the built-in
catalogue, which mirrors the official
[nginx security advisories](https://nginx.org/en/security_advisories.html):
77 advisories from 2009 to 2026, each with the vendor's "Vulnerable" ranges and
"Not vulnerable" (fixed) releases. A stable-branch backport is honoured: a
version on the same branch as a fixed release and at or above it is not
reported even when it lies inside the affected range.

Leads are **qualified, never dropped**. An advisory may carry prerequisites,
each resolved against the scan's own evidence:

| Kind | Examples | Resolution |
| --- | --- | --- |
| protocol | HTTP/2, HTTP/3, mail proxy | *observed* when the endpoint negotiated or advertised it; HTTP/2 is *contradicted* when the endpoint did not offer it; otherwise *unknown* |
| OS | nginx on Windows | not determined by the scan, so *unknown* |
| module | WebDAV (`http_dav`) | *observed* when seen; never contradicted, because absence is not proof |
| config | "requires the `resolver` directive", "requires the mp4 directive" | cannot be seen remotely: always *unknown*, shown as context |

A lead's `applicability` is `contradicted` (shown as "likely N/A here") if any
prerequisite is contradicted, `observed` if one is observed, otherwise empty.
This qualifies the lead — it is not an assertion that the service is safe: the
observation is about one endpoint, and other listeners of the same server may
differ.

Further rules:

- **Severity** uses the scale critical/high/medium/low/info. nginx.org's
  "major" maps to high, "medium" to medium and "minor" to low; a few entries
  are rated higher where remote code execution is documented, and their
  description says so.
- **Distribution packages**: for a banner such as `nginx/1.18.0 (Ubuntu)` the
  leads are still reported, and the report notes that fixes may have been
  backported without a version change. Check the package changelog.
- **OpenResty** is correlated through its bundled nginx core; the lead's
  `match_basis` says that the fix ships with an OpenResty release.
- **NGINX Plus** is keyed on the nginx core version it reports; check the F5
  advisory for the fixed Plus release.
- **Tengine, Angie, freenginx, Kong, Apache APISIX** use their own version
  numbers and are not correlated.
- No version, no leads: a server with `server_tokens off` gets none.

Leads indicate issues that *affect that version*. They are not confirmed by
exploitation; verify against the live configuration before acting.

## NGINX2Root

[NGINX2Root](https://nginx2root.com/) (Xint, November 2026) is a chain of five
nginx memory-safety vulnerabilities. All are fixed in nginx **1.31.9**
(mainline) and **1.30.7** (stable).

| CVE | Issue | Affected | Precondition |
| --- | --- | --- | --- |
| CVE-2026-123007 | HTTP/2 flow-control memory corruption | 1.9.5–1.31.8 | HTTP/2 enabled |
| CVE-2026-123633 | HTTP/2 use-after-free | 1.19.7–1.31.8 | HTTP/2 enabled; requests proxied to an upstream |
| CVE-2026-121810 | HTTP/3 use-after-free | 1.25.0–1.31.8 | HTTP/3 enabled; requests proxied to an upstream |
| CVE-2026-123634 | resolver use-after-free | 0.6.18–1.31.8 | `resolver` with a request-derived upstream name, reached through subrequests |
| CVE-2026-113425 | mail proxy use-after-free | 0.5.33–1.31.8 | mail proxy with `proxy on` and `auth_http` |

In deep mode each nginx service carries an `nginx2root` object:

| Field | Values |
| --- | --- |
| `status` | `vulnerable-version` — the version is in the affected range of at least one of the five advisories; `not-affected` — the version is outside all five ranges; `unknown-version` — the version is hidden, or the product uses its own numbering |
| `cves` | the chain advisories whose range matched |
| `http2`, `http3`, `mail` | `observed`, `contradicted` or `unknown` on this endpoint |
| `detail` | a sentence explaining the above |

The text report prints it as an `NGINX2Root` line per service, the summary
counts affected services and services with a hidden version separately
(`nginx2root`, `nginx2root_unknown`), the CSV has an `nginx2root` column, SARIF
has an `nginx2root` rule, and the CLI prints a warning line on stderr when any
service is affected.

Gate a pipeline on it:

```sh
qnginxscanner --mode deep --fail-on nginx2root --targets-file hosts.txt
echo $?    # 2 when any service is vulnerable-version
```

**Limits**

- The assessment is **version-based**. The tool does not attempt to trigger
  any of the bugs and cannot confirm exploitability or the effect of a
  mitigation such as disabling HTTP/2.
- A **hidden version cannot be assessed**. `unknown-version` does not trip
  `--fail-on nginx2root`; look at `nginx2root_unknown`.
- `status` does not depend on the protocol observations. A server on an
  affected version stays `vulnerable-version` when HTTP/2 was not offered on
  the scanned endpoint: other listeners may differ, and the resolver advisory
  does not need HTTP/2.
- Distribution packages may carry backported fixes under an unchanged version
  number; the detail text says so when a packaging hint was seen.
- HTTP/3 is recognised only from an `Alt-Svc` advertisement. The mail surface
  is seen only on a scanned mail port with `--banners`.
- NGINX Plus: the fixed releases are 37.0.7.1 / 37.2.0.1 and 37.0.8.1 /
  37.3.0.1 according to the Wiz analysis. The F5 article K000164058 could not
  be retrieved automatically when the catalogue was compiled (the page needs
  JavaScript); NGINX Plus users should consult it directly.

Sources: [nginx.org advisories](https://nginx.org/en/security_advisories.html),
the [Xint write-up](https://xint.io/blog/nginx2root-remote-code-execution), the
[Wiz analysis](https://wiz.io/blog/nginx-http2-rce-vulnerabilities).

## Release lifecycle

nginx maintains two branches at a time: the current **mainline** and the
current **stable**. The built-in data (November 2026) is:

| Branch | Kind | Latest release |
| --- | --- | --- |
| 1.31 | mainline | 1.31.9 |
| 1.30 | stable | 1.30.7 |

For plain nginx with a known version, deep mode reports:

- `branch`: `mainline`, `stable`, or `legacy` for every other branch;
- `end_of_life: true` for a legacy branch, which no longer receives fixes;
- `outdated: true` for a supported branch behind its latest release.

`--fail-on eol` exits 2 when any service is end-of-life. A vulnerability feed
can replace the supported set and the latest releases (see below). The
lifecycle is evaluated for plain nginx only, not for derivatives.

## Mail proxy

nginx's mail proxy (POP3/IMAP/SMTP) is recognised by its default greetings:
`+OK POP3 ready`, `* OK IMAP4 ready` and `220 <host> ESMTP ready`. Enable
banner grabbing and name the ports:

```sh
qnginxscanner --mode deep --banners --ports 25,110,143,80,443 mail.example.com
```

One greeting is worth 50–55 points, so a mail port is reported as `likely`
nginx. The greeting carries no version, so such a service has
`version_hidden: true` and, in deep mode, an NGINX2Root status of
`unknown-version` with `mail: observed`. Only cleartext greetings are read
(implicit-TLS ports 465/993/995 are not decoded), and a customised greeting is
not recognised.

## Output formats

`--format` selects the machine-readable scan output, written to stdout or to
`--out FILE`:

- `text` (default) — the same layout as the text report.
- `json` — a structured document (see [`DESIGN.md`](DESIGN.md) for the schema).
- `xml` — the same data as XML, rooted at `<scan>`.
- `csv` — one row per service, for spreadsheets and quick triage (includes
  verdict, variant, version, end-of-life, protocols, NGINX2Root status, finding
  ids, vulnerability ids and the highest severity).
- `sarif` — SARIF 2.1.0, for CI and security-tooling ingestion: one result per
  vulnerability lead, finding, end-of-life branch and NGINX2Root-affected
  service.
- `ndjson` — one JSON object per service (a leading meta line), for streaming.

If `--out` ends in `.json`, `.xml` or `.txt` the format is inferred from the
extension (unless `--format` is given explicitly).

`--oA BASE` writes every machine output plus an HTML report at once:
`BASE.json`, `BASE.xml`, `BASE.csv`, `BASE.sarif`, `BASE.txt` and `BASE.html`.

## Report formats

A report is a human-readable write-up (summary, per-host sections, verdict,
NGINX2Root status, findings, evidence, vulnerability leads, security.txt).
Produce one with `--report` and/or `--report-out`:

- `--report text` — write to stdout (or to `--report-out`).
- `--report rtf --report-out report.rtf` — Rich Text, opens in Word/LibreOffice.
- `--report pdf --report-out report.pdf` — PDF.
- `--report html --report-out report.html` — self-contained HTML.

`rtf`, `pdf` and `html` require `--report-out`. If only `--report-out` is
given, a `.pdf` or `.rtf` extension selects that format and anything else is
written as text — pass `--report html` explicitly for HTML.

The scan output (`--format`) and the report (`--report`) are independent — you
can request both in one run.

## Progress and verbosity

By default qnginxscanner shows live progress on **stderr** (so it never mixes
with machine output on stdout):

- On a terminal, a single counter line is redrawn in place:
  `scanning… 128/2560 (open 12, nginx 4)`.
- When stderr is redirected, the counter is emitted as occasional full lines
  instead.
- Subdomain-enumeration steps are printed as `[*] …` lines.

`--verbose` (or `-v`) replaces the counter with one line per service — open
ports, nginx verdicts and versions, and closed/filtered ports — plus the
enumeration steps:

```
[*] enumerating subdomains for example.com via certificate transparency…
[*] found 37 host(s) for example.com
[+] www.example.com:443 open http nginx=confirmed 1.24.0
[+] api.example.com:80 open http
[-] legacy.example.com:80 closed/filtered
```

`--quiet` (or `-q`) suppresses progress. A one-line summary is always printed
to stderr when the scan finishes, followed by a warning line when any service
runs an NGINX2Root-affected version.

## Configuration file

`--config FILE` loads settings from a small YAML file. Every scan option —
politeness (including `host_concurrency`), enrichment, `no_raw`, auth/headers
(a list or a map), vulnerability feeds, signature packs, allow/block lists,
`fail_on`, the audit trail (`pcap`/`log`) and `web.auth` — is settable from the
config. `--oA`, `--diff`, `--record-corpus`, `--replay-corpus` and
`--completion` are command-line only. See
[`../config.example.yaml`](../config.example.yaml) for the annotated schema.
Precedence, highest first:

1. Explicit command-line flags.
2. Values in the config file.
3. Built-in defaults.

Positional CLI targets override the config's `targets` list. Allow/block lists,
vulnerability feeds and signature packs from the config are combined with any
given on the command line.

The parser is a deliberately small YAML subset: comments, space-indented nested
maps, scalar values and block lists of scalars. Flow syntax (`[]`, `{}`) is not
supported — leave a list key without a value to keep it empty.

## Web GUI

```
qnginxscanner --web                       # http://127.0.0.1:8088/
qnginxscanner --web --listen 0.0.0.0:9000 # bind elsewhere (use with care)
```

The GUI offers a form (targets, ports, depth, TLS, timeout, concurrency, host
concurrency, request budget and toggles for redirects, security.txt, TLS
verification, closed ports, DNS resolution and banner grabbing), shows a
progress bar and live feed while scanning (with a **Cancel** button that aborts
the run), renders per-service result cards with evidence, and keeps the last
25 scans in memory with their own download links. Downloads cover JSON, XML,
CSV, SARIF, text, HTML, RTF and PDF, named uniquely with the scan's timestamp.
The history lives in the server process and is lost when it stops.

The targets box supports loading lists from local files (read in the browser),
an **Allow / block lists** section filters the target list, and **Connection
overrides** pin `host:port` to an address or override the TLS SNI.

The GUI has four views:

- **Scan** — configure and run a scan, watch results stream in, and browse the
  previous-scan history. If a scan errors or is cancelled, whatever was
  collected so far stays on screen.
- **Compare** — diff any two retained scans, or load a saved scan file (JSON
  or XML) as the baseline. An **Origin check** scans a target through its
  public edge and again pinned to an operator-supplied origin address, then
  shows the difference.
- **Statistics** — figures aggregated across the retained scans: verdict and
  severity breakdowns, top vulnerabilities, versions, web servers and
  networks, nginx by port, end-of-life and NGINX2Root counts.
- **Info** — an explorer that groups scanned services by detected version, by
  finding and by vulnerability.

Protect the GUI with `--web-auth user:pass` (HTTP Basic auth). It is bound to
localhost by default; exposing it to a network makes a scan trigger available
to anyone who can reach it, so do so only on trusted networks and with auth.

A `--signature-pack` given at start-up applies to every scan the GUI runs.
`--vuln-feed` is **not** applied in web mode: GUI scans use the built-in
catalogue.

### HTTP API

The GUI is backed by a small JSON API you can script against:

- `POST /api/scan` — body is a JSON object: `targets` (array) or
  `targets_text`, `ports`, `mode`, `tls`, `timeout_seconds`, `concurrency`,
  `follow_redirects`, `insecure`, `security_txt`, `include_closed`,
  `no_dns_enum`, `resolve_dns`, `banners`, `no_raw`, `host_concurrency`,
  `request_budget`, `allow`, `block`, `resolve`, `sni`. The response is a
  stream of newline-delimited JSON (`application/x-ndjson`): `progress`,
  `host` and `service` lines as the scan runs, then a final
  `{"type":"result","result":{…}}` (or `{"type":"error","error":"…"}`).
- `GET /api/download?format=json|xml|csv|sarif|text|html|rtf|pdf[&scan=<id>]` —
  renders the most recent scan result, or a specific one by `scan` id.
- `GET /api/history` — lists retained scans (newest first) with summaries and
  ids.
- `GET /api/diff?a=<id>&b=<id>` — the structured difference of two retained
  scans. `POST /api/diff-upload?b=<id>` diffs an uploaded JSON/XML scan (the
  baseline) against a retained one.
- `GET /api/overview` — the aggregated statistics and groupings.
- `POST /api/origin-compare` — body `{target, origin, ports, mode, tls,
  insecure, security_txt}`; runs the edge-versus-origin comparison.
- `GET /api/version` — the tool version.

## Authentication & request shaping

To scan services behind auth or virtual hosts:

- `--header "Name: value"` — add a request header (repeatable).
- `--cookie "sid=…"` — send a Cookie header.
- `--bearer TOKEN` — send `Authorization: Bearer TOKEN`.
- `--basic user:pass` — HTTP Basic auth.
- `--vhost HOST` — override the Host header on the initial request (name-based
  virtual hosts on a shared IP). It is not carried across redirects. The raw
  probes send the same Host value.
- `--proxy URL` — route HTTP requests through an `http(s)://` or
  `socks5://[user:pass@]host:port` proxy. The raw probes and the HTTP/2
  preface are skipped, and the TCP connect check and banner grab still connect
  directly.

Cookies and Basic/Bearer credentials are scoped to the original target host:
they are not re-sent if a redirect leads to a different host. The raw probes
carry no credentials or extra headers.

## Connection pinning (IP / Host / SNI)

Control the connection target independently of the URL — useful for reaching an
origin that sits behind a CDN:

- `--resolve HOST:PORT:ADDR` — dial `ADDR` whenever a request would go to
  `HOST:PORT`, like `curl --resolve`. The URL host is preserved for the Host
  header and TLS SNI, so a correct origin certificate still verifies.
  Repeatable. The raw probes honour it too.
- `--sni NAME` — override the TLS SNI server name, independent of the Host
  header. A name that does not match the presented certificate fails
  verification unless `--insecure` is set.

Example — compare a CDN-fronted site against its origin:

    qnginxscanner --mode deep example.com                       # public edge
    qnginxscanner --mode deep --resolve example.com:443:203.0.113.10 \
                --sni example.com example.com                 # origin

## Politeness & rate limiting

- `--rate N` — cap outbound requests to N per second across the whole scan.
- `--concurrency N` — cap total in-flight service probes (default 50).
- `--per-host-concurrency N` — at most N concurrent service probes against one
  host.
- `--host-concurrency N` — at most N distinct hosts worked at once (0 = no
  host cap).
- `--jitter DUR` — sleep a random time up to DUR before each service probe.
- `--retries N` — retry transient network failures N times with backoff.
- `--request-budget N` — cap the optional deep probes per service.

Combine them to sweep large target sets politely — e.g.
`--host-concurrency 10 --per-host-concurrency 2 --rate 20`.

## Enrichment

- `--resolve-dns` — record forward addresses and reverse (PTR) names per host.
- `--banners` — for open ports that do not speak HTTP, read a short service
  banner (SSH/FTP/SMTP announce themselves) so the port is labelled. This is
  also what detects the nginx [mail proxy](#mail-proxy).

Every HTTP service is also checked, independently of the nginx verdict, for a
**web server** (product/version/OS hint/modules — Apache, IIS, LiteSpeed,
Caddy, … as well as nginx) and for a **reverse proxy / CDN / WAF / load
balancer** in front. When a front layer is found the result is flagged as
*concealed* — the real origin reply may be hidden, cached, filtered or
challenged — with a note explaining the implication. This is useful context
for an nginx verdict: a CDN whose edge is nginx-based is correctly reported as
nginx, but that says nothing about the origin behind it.

## Vulnerability feeds

Merge extra data into the built-in catalogue with `--vuln-feed FILE|URL`
(repeatable; config key `vuln_feeds`). Three formats are auto-detected:

- the native `qnginxscanner-vuln-feed/1` schema (see
  [`vuln-feed.example.json`](vuln-feed.example.json)),
- **OSV** records (a single object or a JSON array),
- **CSAF 2.0** advisories.

From OSV and CSAF documents only records about nginx itself are kept (package
or product names such as `nginx`, `nginx-core`, `nginx plus`); advisories for
other packages in the same document are ignored.

The native schema:

```json
{
  "schema": "qnginxscanner-vuln-feed/1",
  "nginx": [
    {
      "id": "EXAMPLE-2026-0001",
      "severity": "high",
      "title": "…",
      "description": "…",
      "reference": "https://…",
      "note": "…",
      "affected": [ { "introduced": "99.1.0", "last": "99.3.4" } ],
      "fixed_in": ["99.3.5", "99.2.9"],
      "tags": ["example"],
      "prereqs": [ { "kind": "protocol", "want": "http2" } ]
    }
  ],
  "supported": { "1.31": "mainline", "1.30": "stable" },
  "latest":    { "1.31": "1.31.9", "1.30": "1.30.7" }
}
```

- `nginx` entries are **appended** to the built-in catalogue.
- `affected` is a list of ranges; a version matches the entry when any range
  matches. Within a range every populated bound must hold: `branch` pins a
  major.minor, `introduced` is an inclusive lower bound, `last` an inclusive
  upper bound, `fixed` and `lt` exclusive upper bounds, `eq` an exact version.
- `fixed_in` lists per-branch fixed releases: a version on the same major.minor
  as one of them and at or above it is not affected.
- `prereqs` entries have a `kind` (`protocol`, `os`, `module`, `config`), a
  `want` (`http2` | `http3` | `mail`, an OS token such as `windows`, or a
  module name) and an optional `detail` text.
- `tags` are free-form labels shown with the lead. The NGINX2Root assessment
  counts the leads tagged `nginx2root`.
- `supported`, when present, **replaces** the built-in set of maintained
  branches (values `mainline` or `stable`); `latest` overrides the newest
  release per branch. Use them when new nginx branches are released.

A feed with an unknown `schema` value is rejected and the scan does not start.
Feeds apply to live scans and to `--replay-corpus`, not to the web GUI.

## Signature packs

The built-in detection catalogues (response-header, cookie-name and
response-body matchers) can be extended at run time with a **signature pack** —
a versioned JSON document of the `qnginxscanner-signature-pack/1` schema (see
[`signature-pack.example.json`](signature-pack.example.json)):

    qnginxscanner --mode deep --signature-pack my-edge.json example.com

`--signature-pack FILE|URL` is repeatable (config key `signature_packs`). A pack
has an `id`, an optional `version`, and any of three matcher lists:

- `headers` — `{header, contains?, variant?, module?, weight, detail?}`;
  `contains` is a case-insensitive substring (omit it to match the header's mere
  presence).
- `cookies` — `{name, match?, module?, weight, detail?}`; `match` is `exact`
  (default) or `prefix`.
- `bodies` — `{id, regex, variant?, module?, weight, detail?}`; `regex` is a
  Go/RE2 regular expression and `id` becomes the evidence signal id.

`weight` is added to the nginx confidence score when the matcher fires,
`variant` names the nginx-based product the match implies, and `module` adds an
entry to the service's modules list. A pack adds no requests; it only looks at
responses the scan collects anyway. Since a match raises the nginx score, only
add signals that really imply nginx or an nginx-based product.

Packs are **bounded and validated** on load: an unknown schema, a missing `id`,
an unparseable or over-length (> 512-byte) body regex, an unknown cookie `match`
kind, or more than 500 entries in a category rejects the whole pack rather than
loading it partially. Weights are clamped to 0–100, and RE2 runs in linear time
(no catastrophic backtracking). The active packs (`id@version`) are recorded in
the scan's provenance metadata, so a [diff](#diffing-scans) attributes a
detection change to a loaded pack rather than to the target. A pack passed to
`--web` at start-up applies to every scan the GUI runs.

## Shell completions

`--completion bash|zsh|fish` prints a completion script generated from the live
flag set:

```sh
# bash
source <(qnginxscanner --completion bash)
# zsh (into a directory on $fpath)
qnginxscanner --completion zsh > ~/.zfunc/_qnginxscanner
# fish
qnginxscanner --completion fish > ~/.config/fish/completions/qnginxscanner.fish
```

## Diffing scans

`--diff baseline.json` compares the current scan against a previously saved
JSON result and prints what changed (new/gone services, version and verdict
changes, new/resolved vulnerability leads and findings). `--diff-format` is
`text` (default) or `json`. With `--diff`, scan output is written only to an
explicit `--out`.

The diff is **coverage-aware**: an endpoint that the newer scan did not actually
re-check — a timeout, a WAF challenge, an auth requirement, or a host/port it
never covered — is reported as *not reassessed*, and findings that are merely
absent there are **not** claimed as resolved. A finding only counts as resolved
when its endpoint responded (or was reassessed and found closed). The diff also
emits **provenance notes** when the two scans were run under different settings
(mode, ports, TLS, timeout, auth, connection pinning, raw probes on/off,
vulnerability-catalogue size, signature packs), so a result change caused by
the scanner's configuration is not mistaken for a change on the server.

## Resume

`--resume FILE` records each completed service to FILE as it finishes. Re-run
the same command with the same `--resume FILE` to skip already-scanned
services and continue — useful for large or interrupted sweeps.

## Audit trail (PCAP and session log)

For engagements that must be fully auditable, two optional outputs record
exactly what the tool did and why.

`--pcap FILE` writes a **libpcap capture** of every HTTP exchange the scan
performs. Each request/response is reconstructed as a complete TCP conversation
(SYN / SYN-ACK / ACK handshake, PSH/ACK data segments, graceful teardown) with
valid IPv4/TCP checksums, so the file opens directly in Wireshark, tcpdump or
tshark:

```sh
qnginxscanner --mode deep --pcap scan.pcap example.com
tcpdump -nr scan.pcap        # or: wireshark scan.pcap
```

The capture is a reconstruction, not a wire tap: it holds the plaintext HTTP
that was exchanged (for TLS targets too), packet timing is approximate and the
link type is `RAW` (IPv4). Hostnames that are not IP literals are mapped to
stable addresses in `10.0.0.0/8` so the capture stays valid. Raw probes are
recorded as exchanges with the method `RAW` and their request line, not as the
exact bytes sent; the HTTP/2 preface exchange, TCP connect checks and banner
grabs are not recorded.

`--log FILE` writes a **human-readable session log**. It records each request
and its response status as they happen, then, per service, a `DECISION` block
that states the web server, any reverse proxy, the nginx verdict, version,
lifecycle and protocols, and — evidence by evidence — *where* each signal was
found, *how* it matched, the probe that produced it, the literal matcher and
the matched snippet, followed by the findings and the NGINX2Root assessment:

```
DECISION  192.0.2.10:8080  http://192.0.2.10:8080/
  web server: nginx 1.24.0
  nginx verdict: CONFIRMED (confidence 100/100)
  version: 1.24.0 — learned via Server header
  lifecycle: END OF LIFE — nginx 1.24 is a legacy branch that no longer receives fixes (supported: 1.31 mainline, 1.30 stable)
  protocols: http/1.1
  reasoning — 6 evidence item(s), highest-weighted first:
    • [high w70] body.error-page — built-in nginx error page (exact structure, footer names the server)
        where: response body
        how:   error-page template match
        probe: GET http://192.0.2.10:8080/qnginxscanner_probe_404
        http status: 404
        matcher: <hr><center>nginx/1.24.0 (Ubuntu)</center>
        body line: 1
        match: <html> <head><title>404 Not Found</title></head> … </html>
    • [medium w30] status.reason-phrase — status line uses nginx's own reason phrase for 405
        where: status line
        how:   reason-phrase match
        probe: RAW unknown-method (QNGX / HTTP/1.1)
        http status: 405
        matcher: Not Allowed
        match: HTTP/1.1 405 Not Allowed
  finding [low] stub_status page is publicly exposed — …
  NGINX2Root: vulnerable-version — nginx 1.24.0 is in the affected range of 4 NGINX2Root advisories (fixed in 1.31.9 / 1.30.7). …
```

Both flags can be combined, and work with any scan mode and target type.

## Record & replay (offline regression harness)

A scan can be captured once and replayed many times with no network, so a real
target becomes a repeatable test case:

```sh
qnginxscanner --mode deep --record-corpus site.corpus.json example.com   # capture
qnginxscanner --replay-corpus site.corpus.json --format json             # re-run offline
```

`--record-corpus FILE` writes a JSON **corpus** (schema
`qnginxscanner-replay-corpus/1`) holding, per service, the exact inputs that
were fed to analysis: the root response, the guaranteed-404, the raw probe
replies, the HTTP/2 fingerprint, every deep probe response, the alias and CRLF
check responses, or the banner of a non-HTTP service. `--replay-corpus FILE`
loads it and runs those inputs back through the detection pipeline — no
network, no targets — emitting a scan result as a live run would, so the nginx
verdict, version, evidence, findings, vulnerability leads and NGINX2Root
assessment are reproduced. It honours `--vuln-feed`, `--signature-pack`,
`--format`/`--report`, `--diff` and `--fail-on`, so you can confirm that a
catalogue or signature change behaves as expected against a fixed input.

The corpus is **sanitised on capture**: `Set-Cookie` values, parsed cookie
values and credential headers (`Authorization`, `Proxy-Authorization`,
`X-Api-Key`, `X-Auth-Token`) are redacted, while the cookie *names* that
detection keys on are kept. Response bodies are stored verbatim — they are the
fingerprinting material — and round-trip byte-exact (base64), which the alias
check needs; review a corpus before sharing it. Replay reproduces the nginx
detection and the HTTP summary; network-only facets of a live scan (port state,
security.txt, web-server/reverse-proxy identification) are not part of the
corpus.

## Exit status

- `0` — the scan completed (regardless of what was found).
- `1` — a fatal error (bad target/port spec, unreadable config/feed/pack, I/O
  error).
- `2` — the scan completed but a `--fail-on` gate matched.

`--fail-on LEVEL` makes the process exit `2` when the result meets a threshold:

| Level | Fires when |
| --- | --- |
| `low`, `medium`, `high`, `critical` | any vulnerability lead **or finding** is at least that severe |
| `eol` | any nginx service is on an end-of-life branch |
| `nginx2root` | any nginx service has the NGINX2Root status `vulnerable-version` |

Output and reports are still written. The gates rely on deep-mode data, so use
them with `--mode deep`; in detect mode there are no leads, findings, lifecycle
status or NGINX2Root assessment and no gate can fire. The severity gates
consider every lead, including those whose prerequisites are unknown or
contradicted.

```sh
qnginxscanner --mode deep --fail-on high --format sarif --out scan.sarif example.com || echo "gate matched or error"
```

## Examples

```sh
# Minimal: is it nginx?
qnginxscanner example.com

# Deep scan with a PDF report
qnginxscanner --mode deep --report-out audit.pdf https://example.com

# NGINX2Root gate over a host list
qnginxscanner --mode deep --fail-on nginx2root --targets-file hosts.txt

# Subnet sweep, HTTPS only, JSON to file
qnginxscanner --tls on --format json --out results.json 10.0.0.0/24

# Specific ports and a range, text report to stdout
qnginxscanner --ports 80,443,8000-8010 --report text example.com

# Mail proxy and web ports on one host
qnginxscanner --mode deep --banners --ports 25,110,143,80,443 mail.example.com

# IPv6 host, deep, ignore cert errors
qnginxscanner --mode deep --insecure https://[2001:db8::1]:8443/

# Well-formed HTTP only, rate-limited
qnginxscanner --mode deep --no-raw --rate 5 example.com

# Drive everything from a config file
qnginxscanner --config scan.yaml

# Full audit trail: PCAP capture + decision log
qnginxscanner --mode deep --pcap scan.pcap --log scan.log example.com

# Web GUI
qnginxscanner --web
```
