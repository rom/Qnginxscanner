package report

import (
	"encoding/json"
	"io"

	"github.com/rom/qnginxscanner/internal/nginx"
	"github.com/rom/qnginxscanner/internal/scanner"
	"github.com/rom/qnginxscanner/internal/version"
)

// Minimal SARIF 2.1.0 model (static analysis results interchange format), so
// results can be ingested by CI and security tooling.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifText           `json:"shortDescription"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties"`
}

type sarifRuleProperties struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifText              `json:"message"`
	Locations  []sarifLocation        `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func writeSARIF(w io.Writer, res *scanner.ScanResult) error {
	rules := map[string]sarifRule{}
	var results []sarifResult

	addRule := func(id, name, desc, helpURI, severity string, tags []string) {
		if _, ok := rules[id]; ok {
			return
		}
		rules[id] = sarifRule{
			ID: id, Name: name,
			ShortDescription: sarifText{Text: desc},
			HelpURI:          helpURI,
			Properties:       sarifRuleProperties{SecuritySeverity: securityScore(severity), Tags: tags},
		}
	}

	for _, t := range res.Targets {
		for _, s := range t.Services {
			if s.Nginx == nil {
				continue
			}
			loc := []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifact{URI: s.URL}}}}

			for _, v := range s.Nginx.Vulnerabilities {
				addRule(v.ID, v.Title, v.Title, v.Reference, v.Severity, []string{"security", "vulnerability"})
				results = append(results, sarifResult{
					RuleID:    v.ID,
					Level:     sarifLevel(v.Severity),
					Message:   sarifText{Text: v.ID + ": " + v.Title + " (" + v.AffectedVersions + ")"},
					Locations: loc,
					Properties: map[string]interface{}{
						"severity": v.Severity, "host": s.Host, "port": s.Port,
						"nginx_version": s.Nginx.Version, "match_basis": v.MatchBasis,
					},
				})
			}

			for _, f := range s.Nginx.Findings {
				addRule("nginx-"+f.ID, f.Title, f.Title, "", f.Severity, []string{"security", "misconfiguration"})
				floc := loc
				if f.URL != "" {
					floc = []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifact{URI: f.URL}}}}
				}
				results = append(results, sarifResult{
					RuleID: "nginx-" + f.ID, Level: sarifLevel(f.Severity),
					Message:   sarifText{Text: f.Title + ": " + f.Detail},
					Locations: floc,
					Properties: map[string]interface{}{
						"severity": f.Severity, "host": s.Host, "port": s.Port, "remediation": f.Remediation,
					},
				})
			}

			if s.Nginx.EndOfLife {
				addRule("nginx-end-of-life", "nginx branch end of life", "The detected nginx release branch no longer receives fixes", "https://nginx.org/en/download.html", "high", []string{"security", "maintenance"})
				results = append(results, sarifResult{
					RuleID: "nginx-end-of-life", Level: "warning",
					Message:    sarifText{Text: s.Nginx.EOLDetail},
					Locations:  loc,
					Properties: map[string]interface{}{"host": s.Host, "port": s.Port, "nginx_version": s.Nginx.Version},
				})
			}
			if n := s.Nginx.Nginx2Root; n != nil && n.Status == "vulnerable-version" {
				addRule("nginx2root", "NGINX2Root vulnerable version", "The detected nginx version is in the affected range of the NGINX2Root advisories", "https://nginx2root.com/", "critical", []string{"security", "vulnerability"})
				results = append(results, sarifResult{
					RuleID: "nginx2root", Level: "error",
					Message:   sarifText{Text: n.Detail},
					Locations: loc,
					Properties: map[string]interface{}{
						"host": s.Host, "port": s.Port, "nginx_version": s.Nginx.Version,
						"cves": n.CVEs, "http2": n.HTTP2, "http3": n.HTTP3,
					},
				})
			}
		}
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	if results == nil {
		results = []sarifResult{}
	}

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: version.Name, Version: res.Meta.Version,
				InformationURI: "https://github.com/rom/qnginxscanner",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func sarifLevel(severity string) string {
	switch nginx.SeverityRank(severity) {
	case 4, 3:
		return "error"
	case 2:
		return "warning"
	default:
		return "note"
	}
}

func securityScore(severity string) string {
	switch nginx.SeverityRank(severity) {
	case 4:
		return "9.0"
	case 3:
		return "7.5"
	case 2:
		return "5.0"
	case 1:
		return "3.0"
	default:
		return ""
	}
}
