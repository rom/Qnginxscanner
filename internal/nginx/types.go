// Package nginx contains the heuristics that decide whether a service is
// served by nginx (or an nginx derivative such as OpenResty, Tengine, Angie or
// NGINX Plus), and — in deep mode — fingerprints its version, release branch,
// enabled protocols/modules, common misconfigurations, and correlates known
// version-based vulnerabilities (including the NGINX2Root chain).
//
// Everything this package does is fingerprinting and evidence collection: it
// reads banners, headers, error pages and protocol behaviour and reasons about
// them. It does not attempt to exploit anything.
package nginx

// Verdict is a coarse, human-facing classification derived from Confidence.
type Verdict string

const (
	VerdictConfirmed Verdict = "confirmed"
	VerdictLikely    Verdict = "likely"
	VerdictPossible  Verdict = "possible"
	VerdictNone      Verdict = "none"
)

// Evidence is a single observation that contributed to the verdict.
type Evidence struct {
	// Signal is a stable, machine-friendly identifier, e.g.
	// "header.server" or "body.error-page".
	Signal string `json:"signal"`
	// Source names where the observation came from (a URL or probe name).
	Source string `json:"source"`
	// Detail is a human readable explanation.
	Detail string `json:"detail"`
	// Data is the raw matched snippet (bounded), useful as proof in reports.
	Data string `json:"data,omitempty"`
	// Weight is this signal's contribution to the confidence score.
	Weight int `json:"weight"`
	// Confidence is a human tier (low/medium/high) derived from Weight.
	Confidence string `json:"confidence"`

	// --- Provenance metadata (where / how / what) ---
	Where   string `json:"where,omitempty"`
	How     string `json:"how,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Snippet string `json:"snippet,omitempty"`
	Line    int    `json:"line,omitempty"`
	// Probe is the request (method + URL, or raw probe name) whose response
	// produced the match.
	Probe string `json:"probe,omitempty"`
	// Status is the HTTP response code of the probe that produced the match
	// (0 when the evidence did not come from an HTTP response).
	Status int `json:"status,omitempty"`
}

// confidenceTier maps a signal weight to a low/medium/high label.
func confidenceTier(weight int) string {
	switch {
	case weight >= 60:
		return "high"
	case weight >= 30:
		return "medium"
	default:
		return "low"
	}
}

// Vulnerability is a known issue correlated purely from the detected version.
// It is an informational lead, not a confirmed, exploited finding.
type Vulnerability struct {
	ID               string `json:"id"`
	Severity         string `json:"severity"`
	Title            string `json:"title"`
	AffectedVersions string `json:"affected_versions"`
	// FixedVersions lists the releases that carry the fix (e.g. "1.31.9+, 1.30.7+").
	FixedVersions string `json:"fixed_versions,omitempty"`
	Description   string `json:"description"`
	Reference     string `json:"reference,omitempty"`
	// MatchBasis explains how the correlation was made.
	MatchBasis string `json:"match_basis"`
	// Tags group related advisories (e.g. "nginx2root").
	Tags []string `json:"tags,omitempty" xml:"tags>tag,omitempty"`
	// Prerequisites qualifies the lead by resolving each structured condition
	// (required protocol/OS/module/config) against what the scan observed.
	Prerequisites []PrereqResult `json:"prerequisites,omitempty" xml:"prerequisites>prerequisite,omitempty"`
	// Applicability summarises the prerequisites: "observed" (conditions hold),
	// "contradicted" (evidence a condition does NOT hold on this endpoint), or
	// "" (no structured prerequisites, or all unknown: a plain lead).
	Applicability string `json:"applicability,omitempty"`
}

// PrereqResult is one resolved prerequisite for a vulnerability lead.
type PrereqResult struct {
	Detail string `json:"detail"`
	State  string `json:"state"` // observed | contradicted | unknown
}

// VersionObservation is one version value seen during detection, with where it
// came from.
type VersionObservation struct {
	Version string `json:"version" xml:"version"`
	Source  string `json:"source" xml:"source"`
	Rank    int    `json:"rank,omitempty" xml:"rank,omitempty"`
}

// Finding is a non-CVE issue observed directly on the service: an exposure or
// a misconfiguration (exposed stub_status, alias traversal, header injection…).
// Unlike a Vulnerability it is based on observed behaviour, not on the version.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	URL      string `json:"url,omitempty"`
	// Remediation is a short configuration hint.
	Remediation string `json:"remediation,omitempty"`
}

// StubStatus holds the counters of an exposed stub_status page.
type StubStatus struct {
	URL      string `json:"url"`
	Active   int    `json:"active"`
	Accepts  int64  `json:"accepts"`
	Handled  int64  `json:"handled"`
	Requests int64  `json:"requests"`
	Reading  int    `json:"reading"`
	Writing  int    `json:"writing"`
	Waiting  int    `json:"waiting"`
}

// Nginx2Root summarises exposure to the NGINX2Root vulnerability chain
// (CVE-2026-123007, CVE-2026-123634, CVE-2026-123633, CVE-2026-121810,
// CVE-2026-113425; fixed in nginx 1.31.9 / 1.30.7).
type Nginx2Root struct {
	// Status is "vulnerable-version" (the detected version is in an affected
	// range), "not-affected" (the detected version carries the fixes) or
	// "unknown-version" (nginx detected but its version is hidden).
	Status string `json:"status"`
	// CVEs lists the chain advisories whose version range matched.
	CVEs []string `json:"cves,omitempty" xml:"cves>cve,omitempty"`
	// HTTP2, HTTP3 and Mail record whether the attack surface each advisory
	// needs was seen on this endpoint: observed | contradicted | unknown.
	HTTP2  string `json:"http2"`
	HTTP3  string `json:"http3"`
	Mail   string `json:"mail"`
	Detail string `json:"detail"`
}

// Detection is the full nginx assessment of one service.
type Detection struct {
	IsNginx    bool    `json:"is_nginx"`
	Verdict    Verdict `json:"verdict"`
	Confidence int     `json:"confidence"` // 0-100

	// Variant is the product: nginx, OpenResty, Tengine, Angie, freenginx,
	// NGINX Plus, Kong, Apache APISIX, ...
	Variant string `json:"variant,omitempty"`
	// Version is the nginx core version (what advisories are keyed on).
	Version string `json:"version,omitempty"`
	// ProductVersion is the derivative's own version when it differs from the
	// nginx core version (e.g. OpenResty 1.25.3.1, Tengine 3.1.0).
	ProductVersion string `json:"product_version,omitempty"`
	VersionSource  string `json:"version_source,omitempty"`
	// VersionHidden is true when nginx was identified but discloses no version
	// (server_tokens off).
	VersionHidden bool `json:"version_hidden,omitempty"`
	// Branch is the release line of Version: "mainline", "stable" or "legacy".
	Branch string `json:"branch,omitempty"`
	// Outdated is set when Version is on a supported branch but behind its
	// latest release.
	Outdated  bool   `json:"outdated,omitempty"`
	EndOfLife bool   `json:"end_of_life,omitempty"`
	EOLDetail string `json:"eol_detail,omitempty"`
	// Distro is the packaging hint from the Server banner, e.g. "Ubuntu".
	// Distribution builds may backport fixes without changing the version.
	Distro string `json:"distro,omitempty"`

	VersionObservations []VersionObservation `json:"version_observations,omitempty" xml:"version_observations>observation,omitempty"`
	VersionConflict     bool                 `json:"version_conflict,omitempty" xml:"version_conflict,omitempty"`

	// Protocols lists the protocols seen on this endpoint (http/1.1, h2, h2c,
	// "h3 (advertised)", mail).
	Protocols []string `json:"protocols,omitempty" xml:"protocols>protocol,omitempty"`
	// Modules lists nginx modules/features whose presence was observed.
	Modules []string `json:"modules,omitempty" xml:"modules>module,omitempty"`
	// H2Fingerprint is the HTTP/2 SETTINGS/WINDOW_UPDATE fingerprint
	// (Akamai-style "id:value;…|window") when one was collected.
	H2Fingerprint string `json:"h2_fingerprint,omitempty"`

	StatusExposed bool        `json:"status_exposed,omitempty"`
	StatusURL     string      `json:"status_url,omitempty"`
	StubStatus    *StubStatus `json:"stub_status,omitempty" xml:"stub_status,omitempty"`

	Nginx2Root *Nginx2Root `json:"nginx2root,omitempty" xml:"nginx2root,omitempty"`

	Evidence        []Evidence      `json:"evidence,omitempty" xml:"evidence>item,omitempty"`
	Findings        []Finding       `json:"findings,omitempty" xml:"findings>finding,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty" xml:"vulnerabilities>vulnerability,omitempty"`
}

// scoreToVerdict maps a confidence score to a verdict band.
func scoreToVerdict(score int) Verdict {
	switch {
	case score >= 70:
		return VerdictConfirmed
	case score >= 50:
		return VerdictLikely
	case score >= 25:
		return VerdictPossible
	default:
		return VerdictNone
	}
}
