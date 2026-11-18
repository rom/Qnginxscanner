package nginx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// FeedSchema is the schema identifier external feeds should declare.
const FeedSchema = "qnginxscanner-vuln-feed/1"

// RangeSpec describes an affected version range. A version matches when every
// populated bound is satisfied:
//
//	Branch      restricts to a single major.minor (e.g. "1.30")
//	Introduced  version >= Introduced
//	Last        version <= Last      (inclusive upper bound, nginx.org style)
//	Fixed       version <  Fixed
//	LessThan    version <  LessThan  (alias for an open-ended upper bound)
//	Equals      version == Equals
//
// At least one bound must be set for the range to match anything.
type RangeSpec struct {
	Branch     string `json:"branch,omitempty"`
	Introduced string `json:"introduced,omitempty"`
	Last       string `json:"last,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	LessThan   string `json:"lt,omitempty"`
	Equals     string `json:"eq,omitempty"`
}

func (r RangeSpec) empty() bool {
	return r == RangeSpec{}
}

func (r RangeSpec) matches(v string) bool {
	if r.empty() {
		return false
	}
	if r.Equals != "" {
		return compareVersion(v, r.Equals) == 0
	}
	if r.Branch != "" && !sameBranch(v, r.Branch+".0") {
		return false
	}
	if r.Introduced != "" && compareVersion(v, r.Introduced) < 0 {
		return false
	}
	if r.Last != "" && compareVersion(v, r.Last) > 0 {
		return false
	}
	if r.Fixed != "" && compareVersion(v, r.Fixed) >= 0 {
		return false
	}
	if r.LessThan != "" && compareVersion(v, r.LessThan) >= 0 {
		return false
	}
	return true
}

// FeedEntry is one catalogue entry (a CVE or advisory) plus its affected ranges.
type FeedEntry struct {
	ID          string      `json:"id"`
	Severity    string      `json:"severity"`
	Title       string      `json:"title"`
	Description string      `json:"description,omitempty"`
	Reference   string      `json:"reference,omitempty"`
	Note        string      `json:"note,omitempty"`
	Affected    []RangeSpec `json:"affected"`
	// FixedIn lists per-branch fixed releases (nginx.org's "Not vulnerable:
	// 1.31.9+, 1.30.7+"). A version on the same major.minor as one of these and
	// at or above it is not affected, even when inside an Affected range — this
	// is how a stable-branch backport is expressed.
	FixedIn []string `json:"fixed_in,omitempty"`
	// Tags group related advisories (e.g. "nginx2root").
	Tags []string `json:"tags,omitempty"`
	// Prereqs are structured applicability conditions resolved against the
	// scan's observed evidence (optional; absent ⇒ a plain version-range lead).
	Prereqs []Prereq `json:"prereqs,omitempty"`
}

// Prereq is a structured applicability condition for a lead.
//
//	Kind "protocol": Want is http2, http3 or mail — resolved from what the
//	                 endpoint negotiated/advertised.
//	Kind "os":       Want is an OS token (windows).
//	Kind "module":   Want is a module name; observed when the scan saw it,
//	                 never contradicted (absence is not proof).
//	Kind "config":   a configuration condition that cannot be observed
//	                 remotely; always "unknown", shown as context (Detail).
type Prereq struct {
	Kind   string `json:"kind"`
	Want   string `json:"want,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// ObservedFacts is the evidence a scan gathered, used to resolve prerequisites.
// Protocol states are "observed", "contradicted" or "" (unknown).
type ObservedFacts struct {
	HTTP2   string
	HTTP3   string
	Mail    string
	OS      string
	Modules map[string]bool
}

func (e FeedEntry) matches(v string) bool {
	for _, f := range e.FixedIn {
		if sameBranch(v, f) && compareVersion(v, f) >= 0 {
			return false
		}
	}
	for _, r := range e.Affected {
		if r.matches(v) {
			return true
		}
	}
	return false
}

// VulnFeed is the on-disk / remote JSON format for external vulnerability data.
type VulnFeed struct {
	Schema    string      `json:"schema"`
	Generated string      `json:"generated,omitempty"`
	Nginx     []FeedEntry `json:"nginx,omitempty"`
	// Supported maps each release branch that still receives fixes to its kind
	// ("mainline" or "stable"). When present it REPLACES the built-in set.
	Supported map[string]string `json:"supported,omitempty"`
	// Latest maps a branch to its newest release (overrides by branch).
	Latest map[string]string `json:"latest,omitempty"`
}

// Catalog holds the active vulnerability and support data: the built-in
// curated set, merged with any external feeds.
type Catalog struct {
	entries   []FeedEntry
	supported map[string]string
	latest    map[string]string
}

// DefaultCatalog returns a fresh catalog built from the curated built-in data.
func DefaultCatalog() *Catalog {
	c := &Catalog{
		entries:   append([]FeedEntry(nil), builtinAdvisories...),
		supported: map[string]string{},
		latest:    map[string]string{},
	}
	for k, v := range builtinSupported {
		c.supported[k] = v
	}
	for k, v := range builtinLatest {
		c.latest[k] = v
	}
	return c
}

// Merge folds an external feed into the catalog (appending entries, replacing
// the supported-branch set when given, and overriding latest releases).
func (c *Catalog) Merge(f *VulnFeed) {
	if f == nil {
		return
	}
	c.entries = append(c.entries, f.Nginx...)
	if len(f.Supported) > 0 {
		c.supported = map[string]string{}
		for k, v := range f.Supported {
			c.supported[k] = v
		}
	}
	if c.latest == nil {
		c.latest = map[string]string{}
	}
	for k, v := range f.Latest {
		c.latest[k] = v
	}
}

// Count reports how many advisories the catalog holds.
func (c *Catalog) Count() int { return len(c.entries) }

// Entries returns a copy of the catalogue entries (for listing/UI).
func (c *Catalog) Entries() []FeedEntry { return append([]FeedEntry(nil), c.entries...) }

// correlatable reports whether nginx.org advisories can be keyed on this
// variant's core version, plus a caveat to attach to each lead.
func correlatable(variant string) (bool, string) {
	switch variant {
	case "", "nginx":
		return true, ""
	case "OpenResty":
		return true, "OpenResty bundles this nginx core; the fix ships with an OpenResty release"
	case "NGINX Plus":
		return true, "NGINX Plus: keyed on the reported nginx core version; check the F5 advisory for the fixed Plus release"
	default:
		return false, ""
	}
}

// Correlate returns leads for the detected nginx core version. Derivatives
// with their own numbering (Tengine, Angie, freenginx, …) are skipped. The
// optional facts argument supplies observed evidence for resolving
// prerequisites; omitting it leaves prerequisites "unknown".
func (c *Catalog) Correlate(variant, version string, facts ...ObservedFacts) []Vulnerability {
	if version == "" {
		return nil
	}
	ok, caveat := correlatable(variant)
	if !ok {
		return nil
	}
	if _, _, _, ok := parseVersion(version); !ok {
		return nil
	}
	f := ObservedFacts{}
	if len(facts) > 0 {
		f = facts[0]
	}
	basis := "version-correlation"
	if caveat != "" {
		basis += " (" + caveat + ")"
	}
	return matchEntries(c.entries, version, basis, f)
}

func matchEntries(entries []FeedEntry, version, basisKind string, facts ObservedFacts) []Vulnerability {
	var out []Vulnerability
	for _, e := range entries {
		if !e.matches(version) {
			continue
		}
		basis := basisKind
		if e.Note != "" {
			basis += "; applies to: " + e.Note
		}
		v := Vulnerability{
			ID:               e.ID,
			Severity:         e.Severity,
			Title:            e.Title,
			AffectedVersions: affectedSummary(e.Affected),
			FixedVersions:    fixedSummary(e.FixedIn),
			Description:      e.Description,
			Reference:        e.Reference,
			MatchBasis:       basis,
			Tags:             append([]string(nil), e.Tags...),
		}
		v.Prerequisites, v.Applicability = resolvePrereqs(e.Prereqs, facts)
		out = append(out, v)
	}
	return out
}

// resolvePrereqs resolves each prerequisite against the observed facts and
// summarises applicability: any contradicted ⇒ "contradicted"; else any
// observed ⇒ "observed"; else "" (plain lead).
func resolvePrereqs(prereqs []Prereq, facts ObservedFacts) ([]PrereqResult, string) {
	if len(prereqs) == 0 {
		return nil, ""
	}
	results := make([]PrereqResult, 0, len(prereqs))
	anyContradicted, anyObserved := false, false
	for _, p := range prereqs {
		state := resolvePrereq(p, facts)
		switch state {
		case "contradicted":
			anyContradicted = true
		case "observed":
			anyObserved = true
		}
		results = append(results, PrereqResult{Detail: prereqDetail(p), State: state})
	}
	switch {
	case anyContradicted:
		return results, "contradicted"
	case anyObserved:
		return results, "observed"
	default:
		return results, ""
	}
}

func prereqDetail(p Prereq) string {
	if p.Detail != "" {
		return p.Detail
	}
	switch p.Kind {
	case "protocol":
		switch strings.ToLower(p.Want) {
		case "http2":
			return "requires HTTP/2 to be enabled"
		case "http3":
			return "requires HTTP/3 (QUIC) to be enabled"
		case "mail":
			return "requires the mail proxy (IMAP/POP3/SMTP)"
		}
		return "requires " + p.Want
	case "os":
		return "requires nginx on " + p.Want
	case "module":
		return "requires the " + p.Want + " module"
	default:
		return strings.TrimSpace(p.Kind + " " + p.Want)
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func resolvePrereq(p Prereq, facts ObservedFacts) string {
	switch p.Kind {
	case "protocol":
		switch strings.ToLower(p.Want) {
		case "http2":
			return orUnknown(facts.HTTP2)
		case "http3":
			return orUnknown(facts.HTTP3)
		case "mail":
			return orUnknown(facts.Mail)
		}
		return "unknown"
	case "os":
		if facts.OS == "" {
			return "unknown"
		}
		if strings.EqualFold(facts.OS, p.Want) {
			return "observed"
		}
		return "contradicted"
	case "module":
		// Absence is not proof, so a missing module is unknown, never contradicted.
		if facts.Modules[strings.ToLower(p.Want)] {
			return "observed"
		}
		return "unknown"
	default:
		return "unknown"
	}
}

// BranchKind classifies a version's release line by nginx's numbering rule:
// an even minor is a stable branch, an odd minor is mainline.
func BranchKind(version string) string {
	_, min, _, ok := parseVersion(version)
	if !ok {
		return ""
	}
	if min%2 == 0 {
		return "stable"
	}
	return "mainline"
}

// Support describes where a version sits in the nginx release lifecycle.
type Support struct {
	Branch    string // "mainline", "stable" or "legacy"
	EndOfLife bool
	Outdated  bool
	Detail    string
}

// Support evaluates a version against the supported-branch set. nginx only
// maintains the current mainline and the current stable branch; every older
// branch is legacy and receives no fixes.
func (c *Catalog) Support(variant, version string) Support {
	if variant != "" && variant != "nginx" {
		return Support{}
	}
	maj, min, _, ok := parseVersion(version)
	if !ok {
		return Support{}
	}
	branch := fmt.Sprintf("%d.%d", maj, min)
	kind, supported := c.supported[branch]
	if !supported {
		return Support{
			Branch: "legacy", EndOfLife: true,
			Detail: fmt.Sprintf("nginx %s is a legacy branch that no longer receives fixes (supported: %s)", branch, c.supportedSummary()),
		}
	}
	s := Support{Branch: kind}
	latest := c.latest[branch]
	switch {
	case latest != "" && compareVersion(version, latest) < 0:
		s.Outdated = true
		s.Detail = fmt.Sprintf("nginx %s is on the supported %s branch but behind its latest release %s", version, kind, latest)
	case latest != "":
		s.Detail = fmt.Sprintf("nginx %s is current for the supported %s branch", version, kind)
	default:
		s.Detail = fmt.Sprintf("nginx %s is on the supported %s branch", branch, kind)
	}
	return s
}

func (c *Catalog) supportedSummary() string {
	parts := make([]string, 0, len(c.supported))
	for b, k := range c.supported {
		parts = append(parts, b+" "+k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(parts)))
	return strings.Join(parts, ", ")
}

func affectedSummary(ranges []RangeSpec) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		switch {
		case r.Equals != "":
			parts = append(parts, r.Equals)
		case r.Introduced != "" && r.Last != "":
			parts = append(parts, r.Introduced+"-"+r.Last)
		case r.Last != "":
			parts = append(parts, "<= "+r.Last)
		case r.Branch != "" && r.LessThan != "":
			parts = append(parts, r.Branch+".x < "+r.LessThan)
		case r.Branch != "" && r.Fixed != "":
			parts = append(parts, r.Branch+".x < "+r.Fixed)
		case r.Introduced != "" && r.Fixed != "":
			parts = append(parts, r.Introduced+" – "+r.Fixed)
		case r.LessThan != "":
			parts = append(parts, "< "+r.LessThan)
		case r.Fixed != "":
			parts = append(parts, "< "+r.Fixed)
		case r.Branch != "":
			parts = append(parts, r.Branch+".x")
		case r.Introduced != "":
			parts = append(parts, ">= "+r.Introduced)
		}
	}
	return strings.Join(parts, ", ")
}

func fixedSummary(fixed []string) string {
	parts := make([]string, 0, len(fixed))
	for _, f := range fixed {
		parts = append(parts, f+"+")
	}
	return strings.Join(parts, ", ")
}

// ParseFeed decodes feed JSON, auto-detecting the native qnginxscanner schema,
// the OSV format (single record or array) and CSAF 2.0 advisories.
func ParseFeed(data []byte) (*VulnFeed, error) {
	switch detectFeedFormat(data) {
	case feedOSV:
		return convertOSV(data)
	case feedCSAF:
		return convertCSAF(data)
	default:
		var f VulnFeed
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse vuln feed: %w", err)
		}
		if f.Schema != "" && f.Schema != FeedSchema {
			return nil, fmt.Errorf("unsupported vuln feed schema %q (want %q, or an OSV/CSAF document)", f.Schema, FeedSchema)
		}
		return &f, nil
	}
}

// LoadFeed reads a feed from a local file path or an http(s) URL.
func LoadFeed(ctx context.Context, src string, client *http.Client) (*VulnFeed, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		if client == nil {
			client = &http.Client{Timeout: 30 * time.Second}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch vuln feed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch vuln feed: HTTP %d", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if err != nil {
			return nil, err
		}
		return ParseFeed(data)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return nil, fmt.Errorf("read vuln feed: %w", err)
	}
	return ParseFeed(data)
}

// SeverityRank maps a severity string to a comparable rank (higher = worse).
func SeverityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium", "moderate":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
