package audit

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteText prints a human-readable report and returns the number of findings.
func WriteText(w io.Writer, findings []Finding, ig *Ignore) int {
	if ig.Empty() {
		fmt.Fprintln(w, "note: no .dockerignore found — every path below is currently in the build context.")
		fmt.Fprintln(w)
	}
	if len(findings) == 0 {
		fmt.Fprintln(w, "OK: no unignored files matched an audit rule.")
		return 0
	}
	var danger int
	for _, f := range findings {
		if f.Severity == Danger {
			danger++
		}
		fmt.Fprintf(w, "  [%s] %s\n", f.Severity, f.Path)
		fmt.Fprintf(w, "         %s (add `%s` to .dockerignore)\n", f.Why, f.Rule)
	}
	fmt.Fprintf(w, "\n%d file(s) should be ignored (%d dangerous).\n", len(findings), danger)
	return len(findings)
}

// jsonReport is the -json output shape.
type jsonReport struct {
	HasDockerignore bool      `json:"has_dockerignore"`
	Count           int       `json:"count"`
	DangerCount     int       `json:"danger_count"`
	Findings        []Finding `json:"findings"`
}

// MarshalJSON gives Finding stable snake_case keys with a string severity.
func (f Finding) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Path     string `json:"path"`
		Rule     string `json:"rule"`
		Why      string `json:"why"`
		Severity string `json:"severity"`
	}{f.Path, f.Rule, f.Why, f.Severity.String()})
}

// WriteJSON prints machine-readable output and returns the finding count.
func WriteJSON(w io.Writer, findings []Finding, ig *Ignore) int {
	var danger int
	for _, f := range findings {
		if f.Severity == Danger {
			danger++
		}
	}
	rep := jsonReport{
		HasDockerignore: !ig.Empty(),
		Count:           len(findings),
		DangerCount:     danger,
		Findings:        findings,
	}
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
	return len(findings)
}
