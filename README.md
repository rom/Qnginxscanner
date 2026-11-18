# qnginxscanner

A command-line and web tool, written in Go, that decides — with auditable
evidence — whether a network service is **nginx** (or an nginx derivative:
OpenResty, Tengine, Angie, freenginx, NGINX Plus, Kong, Apache APISIX),
fingerprints its **version, release branch, protocols and modules**, flags
common **misconfigurations**, and correlates **known vulnerabilities**,
including the **NGINX2Root** chain.

It is a read-only fingerprinting and reporting tool: it reads banners, headers,
error pages and protocol behaviour and reasons about them. It **never exploits
anything** and never tries to trigger a memory-safety bug.

> **Authorised use only.** Scan only hosts and networks you own or have
> explicit permission to test. Port scanning and service fingerprinting may be
> regulated where you operate.

## Features

- **nginx detection from many independent signals**, so a hidden or rewritten
  `Server` header does not defeat it: the `Server` banner; the built-in
  error-page template (exact byte structure, footer with product and version);
  default welcome, `50x.html` and autoindex pages; nginx-only messages ("The
  plain HTTP request was sent to HTTPS port", the 494/495/496 pages); the
  static-file `ETag` format `hex(mtime)-hex(size)`, verified against
  `Last-Modified` and `Content-Length`; the wire order of response headers;
  nginx-only reason phrases (`405 Not Allowed`, `414 Request-URI Too Large`,
  …); the HTTP/2 `SETTINGS` + `WINDOW_UPDATE` fingerprint; `stub_status`, the
  NGINX Plus API and nginx-module-vts; `X-Accel-*`, cache-status, Kong and
  APISIX headers; the ingress-nginx `INGRESSCOOKIE`; and the mail proxy's
  default POP3/IMAP/SMTP greetings.
- **Weighted, explainable verdicts**: every signal is an evidence item with a
  weight and full provenance (where it was found, how it matched, the matcher,
  the matched snippet, the exact probe and its HTTP status). Weights add up to
  a 0–100 confidence: `confirmed` ≥ 70, `likely` ≥ 50, `possible` ≥ 25.
- **Deep mode** fingerprints the product and version (including the nginx core
  inside OpenResty), the release branch (mainline / stable / legacy), a
  distribution packaging hint (`nginx/1.18.0 (Ubuntu)`), the protocols on the
  endpoint (HTTP/1.1, h2, h2c, advertised h3, mail) and observed modules.
- **Behaviour-based findings** (deep mode): `stub-status-exposed`,
  `plus-api-exposed`, `vts-status-exposed`, `version-disclosure`,
  `autoindex-enabled`, `alias-traversal` (off-by-slash `alias`) and
  `crlf-injection` (`$uri` copied into a response header) — each with a
  remediation hint.
- **Vulnerability leads** (deep mode): the complete
  [nginx.org security advisory list](https://nginx.org/en/security_advisories.html)
  (77 advisories, 2009–2026) with the vendor's "vulnerable" ranges and
  per-branch fixed releases. Each lead is qualified by its prerequisites —
  HTTP/2, HTTP/3, mail proxy, Windows, a module, or a configuration-only
  condition — resolved against what the scan saw as *observed*,
  *contradicted* or *unknown*.
- **NGINX2Root assessment** per service, and a CI gate:
  `--fail-on nginx2root`. See [below](#nginx2root-detection).
- **Release lifecycle**: only the current mainline (1.31) and stable (1.30)
  branches are supported; anything else is reported end-of-life, and a
  supported branch behind its latest release is reported outdated.
- **Web server / reverse proxy / CDN / WAF identification** for every HTTP
  service, so you know when a front layer conceals the origin.
- **`security.txt`** (RFC 9116) discovery and parsing.
- **Flexible targets**: URLs, hostnames, IPv4/IPv6, CIDR, ranges, wildcards,
  `*.example.com` (subdomains via Certificate Transparency), target files.
- **Outputs**: text, JSON, XML, CSV, SARIF 2.1.0, NDJSON; reports as text,
  RTF, PDF and HTML; scan **diffing**; `--fail-on` exit-code gating.
- **Operational controls**: rate limit, per-host and host concurrency, jitter,
  retries, request budget, proxy (HTTP/SOCKS5), `--resolve`/`--sni` pinning,
  auth headers, allow/block lists, resume checkpoints.
- **Audit trail**: a PCAP of every HTTP exchange and a session log that
  explains each decision; offline **record & replay** of a scan.
- **Extensible data**: external vulnerability feeds (native JSON, OSV, CSAF)
  and detection-signature packs.
- **Web GUI** (`--web`) with live results, history, compare and statistics.
- **No external dependencies**: Go standard library only.

## Install / build

Requires Go 1.24 or newer. There are no third-party modules.

```sh
git clone https://github.com/rom/qnginxscanner
cd qnginxscanner
make build            # produces bin/qnginxscanner
make test             # run the test suite
sudo make install     # optional: binary + man page under /usr/local
```

Without `make`: `go build -o bin/qnginxscanner ./cmd/qnginxscanner`.

## Quick start

```sh
# Is it nginx? (detect mode: a handful of requests per service)
qnginxscanner example.com

# Deep scan: version, branch, protocols, misconfigurations, vulnerability leads
qnginxscanner --mode deep --ports 80,443,8080 example.com

# CI gate: exit 2 if any service runs an NGINX2Root-affected version
qnginxscanner --mode deep --fail-on nginx2root --targets-file hosts.txt

# Mail proxy: non-HTTP ports are identified from their greeting with --banners
qnginxscanner --mode deep --banners --ports 25,110,143,80,443 mail.example.com

# JSON to a file, plus a PDF report
qnginxscanner --mode deep --format json --out scan.json --report-out report.pdf 10.0.0.0/28

# Only well-formed HTTP requests (no raw / HTTP/2-preface fingerprint probes)
qnginxscanner --mode deep --no-raw example.com

# Web GUI on http://127.0.0.1:8088/
qnginxscanner --web
```

Run `qnginxscanner --help` for every flag; [`docs/USAGE.md`](docs/USAGE.md) is
the full manual and [`docs/DESIGN.md`](docs/DESIGN.md) describes the detection
model and data schema.

## NGINX2Root detection

[NGINX2Root](https://nginx2root.com/) is a set of five nginx memory-safety
vulnerabilities published by Xint in November 2026. All five are fixed in
**nginx 1.31.9 (mainline)** and **1.30.7 (stable)**.

| CVE | Component | Affected nginx | Needs |
| --- | --- | --- | --- |
| CVE-2026-123007 | HTTP/2 flow control — memory corruption | 1.9.5 – 1.31.8 | HTTP/2 enabled |
| CVE-2026-123633 | HTTP/2 — use-after-free | 1.19.7 – 1.31.8 | HTTP/2 enabled, proxying to an upstream |
| CVE-2026-121810 | HTTP/3 — use-after-free | 1.25.0 – 1.31.8 | HTTP/3 (QUIC) enabled, proxying to an upstream |
| CVE-2026-123634 | resolver — use-after-free | 0.6.18 – 1.31.8 | `resolver` with a request-derived upstream name |
| CVE-2026-113425 | mail proxy — use-after-free | 0.5.33 – 1.31.8 | mail proxy with `auth_http` |

In deep mode every nginx service gets an `nginx2root` assessment:

- **`vulnerable-version`** — the detected version is inside the affected range
  of at least one of the five advisories. The matching CVEs are listed.
- **`not-affected`** — the detected version carries the fixes.
- **`unknown-version`** — nginx was identified but hides its version
  (`server_tokens off`), or the product (Tengine, Angie, freenginx, Kong,
  APISIX) uses its own version numbering. The tool cannot tell either way.

The assessment also records whether the attack surface was seen **on that
endpoint**: `http2`, `http3` and `mail` are each `observed`, `contradicted` or
`unknown`. The same qualification appears on the individual vulnerability
leads (for example "precondition (contradicted): requires HTTP/2 to be
enabled").

`--fail-on nginx2root` exits with status 2 when any service is
`vulnerable-version`; the scan summary counts affected services and, separately,
services whose version is hidden.

**Limits — read these before relying on the result:**

- Detection is **version-based**. The tool does not send the malformed HTTP/2,
  HTTP/3, DNS or mail traffic that would trigger the bugs, so it cannot confirm
  that a given server is exploitable, nor that a mitigation is effective.
- A **hidden version cannot be assessed**. `unknown-version` is not "safe", and
  `--fail-on nginx2root` does not fire on it — check `nginx2root_unknown` in the
  summary.
- **Distribution packages** (for example `nginx/1.24.0 (Ubuntu)`) may carry
  backported fixes without changing the version string. The tool still reports
  the lead and says so; verify against the package changelog.
- The protocol observations describe the scanned endpoint only. HTTP/2 not
  being offered on one port says nothing about other listeners, and the status
  stays `vulnerable-version` because the resolver advisory does not depend on
  HTTP/2. HTTP/3 is recognised only from an `Alt-Svc` advertisement; no QUIC
  connection is made.
- **OpenResty** is assessed through its bundled nginx core (the first three
  version components). **NGINX Plus** is assessed through the nginx
  core version it reports (in its banner or its API), not through its Plus
  release number; fixed Plus releases are 37.0.7.1 / 37.2.0.1 and
  37.0.8.1 / 37.3.0.1 according to the Wiz analysis. The F5 article K000164058
  could not be retrieved automatically when the catalogue was compiled (the
  page requires JavaScript), so NGINX Plus users should consult it directly.

Sources: the [nginx.org advisories](https://nginx.org/en/security_advisories.html),
the [Xint write-up](https://xint.io/blog/nginx2root-remote-code-execution) and
the [Wiz analysis](https://wiz.io/blog/nginx-http2-rce-vulnerabilities).

## What is sent to targets

Every probe is read-only. Nothing is submitted, nothing is brute-forced, and no
request is designed to crash or corrupt the server.

**Detect mode**, per open port:

- a TCP connect check;
- `GET` of the target path (default `/`), following redirects;
- `GET /qnginxscanner_probe_404`, a guaranteed-missing path, to obtain the
  server's own error page;
- a raw `no-host` request: `GET / HTTP/1.1` without a `Host` header, which the
  front server must answer itself with a 400;
- on TLS services, a raw `plain-on-tls` request: cleartext HTTP sent to the TLS
  port;
- `GET /.well-known/security.txt` and `/security.txt` (disable with
  `--security-txt=false`).

**Deep mode** adds:

- `OPTIONS /`;
- two more raw requests: an unknown method (`QNGX / HTTP/1.1`) and a 9000-byte
  request URI;
- the HTTP/2 connection preface with an empty `SETTINGS` frame, to read the
  server's opening frames; no HTTP/2 request is made and the connection is
  closed with `GOAWAY`;
- `GET` of eight status paths: `/nginx_status`, `/stub_status`,
  `/basic_status`, `/nginx-status`, `/status`, `/server-status`, `/api/`,
  `/status/format/json` (plus `/api/<n>/nginx` when `/api/` is the NGINX Plus
  API);
- the CRLF check: `GET /%0D%0AX-Qnginxscanner-Probe:%20crlf`, which only
  affects its own response;
- the alias off-by-slash check, for up to three static assets the home page
  already links to: the asset itself, the same asset via
  `/<seg>../<seg>/<file>`, and a control path that must not resolve. It only
  ever re-reads a file that is already public.

With `--banners`, open ports that do not speak HTTP are read for a greeting
(after a short wait, a bare CRLF is sent to prompt one).

`--no-raw` removes the raw requests and the HTTP/2 preface, leaving only
well-formed HTTP requests. Raw probes are also skipped automatically when
`--proxy` is set. `--request-budget N` caps the optional deep probes (status
paths, CRLF check, alias checks), and a host answering 429/503 skips them.

Requests carry a `User-Agent` that names the tool, so they are easy to find in
access logs. The malformed raw requests may be logged as errors or counted by a
WAF or IDS.

## Output formats

- **Scan output** (`--format`, `--out`): `text` (default), `json`, `xml`,
  `csv`, `sarif`, `ndjson`.
- **Report** (`--report`, `--report-out`): `text`, `rtf`, `pdf`, `html`.
- `--oA BASE` writes `BASE.json`, `.xml`, `.csv`, `.sarif`, `.txt` and an HTML
  report `BASE.html` in one go.
- `--diff baseline.json` compares a scan with an earlier JSON result.
- `--pcap FILE` and `--log FILE` write the audit trail.

Exit status: `0` scan completed, `1` fatal error, `2` a `--fail-on` gate
matched (`low`, `medium`, `high`, `critical`, `eol` or `nginx2root`).

## Limitations

- Vulnerability leads are derived from the **version string**, not from
  exploitation. Many advisories need a specific module or directive that cannot
  be seen from outside; these prerequisites are listed as `unknown`.
- With `server_tokens off` there is no version, hence no vulnerability
  correlation, lifecycle status or NGINX2Root verdict for that service.
- Tengine, Angie, freenginx, Kong and Apache APISIX are detected but use their
  own version numbers and are **not** correlated against nginx advisories.
- A CDN, WAF or other reverse proxy in front may answer instead of the origin;
  the result then describes the front layer. Such services are flagged, and
  `--resolve` can pin the scan to an origin address.
- An nginx reverse proxy that passes through every response of its upstream
  and hides its banner gives few signals in a normal request; the raw probes
  exist for this case, so `--no-raw` and `--proxy` reduce detection there.
- The mail proxy is recognised only by its default greetings; a customised
  greeting is not detected.
- The lifecycle data (supported branches 1.31 / 1.30 and their latest
  releases) reflects November 2026. Override it with a `--vuln-feed` when newer
  branches appear.

## Lineage and licence

qnginxscanner is derived from
[qphpscanner](https://github.com/rom/qphpscanner), a PHP service detector by
the same author (released under the MIT licence). The
scanning framework — target expansion, probing, reports, audit trail, web GUI —
comes from that project; the detection engine, probes and vulnerability
catalogue were rewritten for nginx.

This repository is licensed under the **GNU General Public License v3.0** — see
[LICENSE](LICENSE).
