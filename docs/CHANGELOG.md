# Changelog

All notable changes to **qnginxscanner** are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-18

Initial release. qnginxscanner is derived from
[qphpscanner](https://github.com/rom/qphpscanner) by the same author: the
scanning framework is inherited, and the detection engine, probes and
vulnerability catalogue are new and specific to nginx. The history of
qphpscanner is not repeated here.

### Added

- **nginx detection** for nginx and its derivatives (OpenResty, Tengine, Angie,
  freenginx, NGINX Plus, Kong, Apache APISIX) from additive, weighted signals
  with verdict bands `confirmed` (≥ 70), `likely` (≥ 50) and `possible` (≥ 25):
  - the `Server` banner, including customised banners that keep an nginx token;
  - the built-in error-page template (exact byte structure; product, version
    and packaging hint from the footer);
  - default welcome, `50x.html` and autoindex pages;
  - nginx-specific messages: "The plain HTTP request was sent to HTTPS port"
    and the 494/495/496 pages;
  - the static-file `ETag` format `hex(mtime)-hex(size)`, verified against
    `Last-Modified` and `Content-Length`;
  - the wire order of response headers and nginx-only reason phrases
    (`405 Not Allowed`, `408 Request Time-out`, `414 Request-URI Too Large`,
    `504 Gateway Time-out`);
  - the HTTP/2 `SETTINGS` + `WINDOW_UPDATE` fingerprint
    `3:128;4:65536;5:16777215|2147418112`;
  - exposed `stub_status`, NGINX Plus API and nginx-module-vts endpoints, and
    Prometheus metrics of nginx-prometheus-exporter, ingress-nginx or the vts
    exporter at `/metrics` (signal `status.metrics`; the ingress-nginx
    controller version is listed under modules when disclosed);
  - `X-Accel-*`, cache-status, ngx_pagespeed, Kong and APISIX headers, and the
    ingress-nginx `INGRESSCOOKIE`;
  - the mail proxy's default POP3/IMAP/SMTP greetings (with `--banners`).
- **Raw probes**: hand-built HTTP/1.x requests whose replies are kept verbatim
  (`no-host`, `plain-on-tls`, and in deep mode `unknown-method`, `long-uri`
  and `foreign-host`), plus an HTTP/2 connection-preface fingerprint. `--no-raw`
  (config `no_raw`) restricts a scan to well-formed HTTP requests; raw probes
  are skipped automatically behind `--proxy`.
- **Scan depth**: `deep` is the default everywhere — the CLI `--mode`, the
  configuration file, the web GUI's form, and the web API when `mode` is
  omitted or unknown. `--mode detect` is the opt-in lighter mode that only
  decides whether a service is nginx, with a handful of requests per service.
- **Deep-mode fingerprinting**: product and nginx core version (OpenResty is
  mapped to its bundled core), version observations with conflict detection,
  packaging hint, protocols (`http/1.1`, `h2`, `h2c`, advertised `h3`, mail)
  and observed modules.
- **Behaviour-based findings**: `stub-status-exposed`, `plus-api-exposed`,
  `vts-status-exposed`, `version-disclosure`, `autoindex-enabled`,
  `alias-traversal` (off-by-slash `alias`, proven by re-reading an
  already-public asset) and `crlf-injection`, each with a remediation hint.
  Further findings, all from read-only `GET`s:
  - exposed files that nginx serves unless the configuration denies them
    (unlike Apache it does not protect `.ht*` files or dotfiles by default):
    `git-exposed` (high, `/.git/HEAD`), `htpasswd-exposed` (high,
    `/.htpasswd`), `env-exposed` (high, `/.env`), `nginx-conf-exposed`
    (medium, `/nginx.conf`) and `htaccess-exposed` (low, `/.htaccess`; nginx
    ignores `.htaccess`, so its rules are not enforced). The content is
    validated but never copied into the report;
  - `php-pathinfo` (high): the nginx + PHP-FPM path-info misconfiguration — a
    public static asset re-requested as `<asset>/qnginxscanner.php` comes back
    with the same bytes as `text/html`, i.e. static files are handed to PHP
    and an uploaded file could execute as code;
  - `host-header-redirect` (low): the `foreign-host` raw probe
    (`Host: qnginxscanner-probe.invalid`) is answered by a redirect whose
    `Location` carries that host (redirects built from `$host`/`$http_host`);
  - `metrics-exposed` (low): nginx Prometheus metrics readable at `/metrics`;
  - `default-page` (info): the stock welcome page is served.
- **Vulnerability catalogue** mirroring the nginx.org security advisories (77
  entries, 2009–2026) with the vendor's vulnerable ranges and per-branch fixed
  releases, so stable-branch backports are honoured. Each lead is qualified by
  prerequisites (HTTP/2, HTTP/3, mail proxy, Windows, modules,
  configuration-only conditions) resolved as observed / contradicted /
  unknown. Distribution packages are flagged as possibly carrying backported
  fixes rather than hidden.
- **NGINX2Root assessment** (CVE-2026-123007, CVE-2026-123633,
  CVE-2026-121810, CVE-2026-123634, CVE-2026-113425; fixed in nginx 1.31.9 and
  1.30.7): a per-service status `vulnerable-version`, `not-affected` or
  `unknown-version`, with the HTTP/2, HTTP/3 and mail observations for that
  endpoint; summary counters `nginx2root` and `nginx2root_unknown`; a CSV
  column and a SARIF rule; and the gate `--fail-on nginx2root`. The assessment
  is version-based: the tool does not attempt to trigger the bugs.
- **Release lifecycle**: branches other than the current mainline (1.31) and
  stable (1.30) are reported end-of-life (`legacy`); a supported branch behind
  its latest release is reported `outdated`. `--fail-on eol` gates on it.
- **Vulnerability feeds** (`--vuln-feed`): the native
  `qnginxscanner-vuln-feed/1` schema (`nginx`, `supported`, `latest`), OSV and
  CSAF 2.0; only nginx packages are imported from the latter two. Feeds also
  apply in `--web` mode: they are merged into the catalogue used by every GUI
  scan and by origin-compare.
- **Signature packs** (`--signature-pack`, schema
  `qnginxscanner-signature-pack/1`) with header, cookie and body matchers that
  can name a `variant` and a `module`.
- Inherited from qphpscanner and adapted: flexible target and port specs,
  Certificate Transparency subdomain enumeration, TLS handling, politeness
  controls (rate, concurrency levels, jitter, retries, request budget), request
  shaping (headers, auth, vhost, proxy, `--resolve`, `--sni`), allow/block
  lists, web-server and reverse-proxy/CDN/WAF identification, `security.txt`
  parsing, output formats (text, JSON, XML, CSV, SARIF, NDJSON), reports
  (text, RTF, PDF, HTML), coverage-aware scan diffing with provenance notes,
  resume checkpoints, the PCAP and session-log audit trail, offline corpus
  record and replay, YAML configuration, shell completions and the web GUI.
- **Release automation**: tagged releases are built by a GitHub Actions
  workflow (`.github/workflows/release.yml`), which on a `v*` tag runs
  `make check`, then `make release`, and publishes the archives and
  `SHA256SUMS` as a GitHub release.

### Removed (relative to qphpscanner)

- All detection logic, probes and catalogue data specific to qphpscanner's
  target technology, together with the command-line flags and configuration
  keys that only served them (the icon-hash catalogue and the dependency-file
  inventory).

### Changed (relative to qphpscanner)

- Licence: GPL-3.0 (qphpscanner is MIT).
- The JSON/XML result carries an `nginx` object per service and nginx-specific
  summary counters; results are not interchangeable with qphpscanner's.
