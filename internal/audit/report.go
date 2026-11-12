package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// displayPath marks directory findings with a trailing slash.
func displayPath(f Finding) string {
	if f.Dir {
		return f.Path + "/"
	}
	return f.Path
}

// humanBytes formats n with decimal units (1 MB = 1,000,000 bytes), the way
// Docker reports the context it transfers.
func humanBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTP"[exp])
}

// groupDigits writes n with thousands separators: 12431 -> "12,431".
func groupDigits(n int) string {
	if n < 0 {
		return "-" + groupDigits(-n)
	}
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return groupDigits(n) + " " + one
	}
	return groupDigits(n) + " " + many
}

// WriteText prints a human-readable report and returns the number of findings.
// size is optional and adds the context size comparison.
func WriteText(w io.Writer, findings []Finding, ig *Ignore, size *SizeReport) int {
	if ig.Empty() {
		fmt.Fprintln(w, "note: no .dockerignore found — every path below is currently in the build context.")
		fmt.Fprintln(w)
	}
	if len(findings) == 0 {
		fmt.Fprintln(w, "OK: no unignored files matched an audit rule.")
	} else {
		var danger int
		for _, f := range findings {
			if f.Severity == Danger {
				danger++
			}
			if f.Dir {
				fmt.Fprintf(w, "  [%s] %s (%s, %s)\n", f.Severity, displayPath(f), plural(f.Files, "file", "files"), humanBytes(f.Bytes))
			} else {
				fmt.Fprintf(w, "  [%s] %s\n", f.Severity, f.Path)
			}
			fmt.Fprintf(w, "         %s (add `%s` to .dockerignore)\n", f.Why, f.Rule)
		}
		fmt.Fprintf(w, "\n%d path(s) should be ignored (%d dangerous).\n", len(findings), danger)
	}
	if size != nil {
		writeSizeText(w, size)
	}
	return len(findings)
}

func writeSizeText(w io.Writer, s *SizeReport) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Build context: %s in %s now, %s in %s with the suggested patterns.\n",
		humanBytes(s.Before.Bytes), plural(s.Before.Files, "file", "files"),
		humanBytes(s.After.Bytes), plural(s.After.Files, "file", "files"))
	top := s.topDirs()
	if len(top) == 0 {
		return
	}
	fmt.Fprintln(w, "Largest top-level directories now:")
	for _, d := range top {
		fmt.Fprintf(w, "  %10s  %s (%s)\n", humanBytes(d.Bytes), d.Path+"/", plural(d.Files, "file", "files"))
	}
}

// jsonReport is the -json output shape.
type jsonReport struct {
	HasDockerignore bool      `json:"has_dockerignore"`
	Count           int       `json:"count"`
	DangerCount     int       `json:"danger_count"`
	Findings        []Finding `json:"findings"`
	Size            *jsonSize `json:"size,omitempty"`
}

// jsonSize is the "size" object that -size adds to -json output.
type jsonSize struct {
	Before  Usage         `json:"before"`
	After   Usage         `json:"after"`
	TopDirs []jsonDirSize `json:"top_dirs"`
}

type jsonDirSize struct {
	Path  string `json:"path"`
	Files int    `json:"files"`
	Bytes int64  `json:"bytes"`
}

// MarshalJSON gives Finding stable snake_case keys with a string severity.
// Directory paths end in "/".
func (f Finding) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Path     string `json:"path"`
		Rule     string `json:"rule"`
		Why      string `json:"why"`
		Severity string `json:"severity"`
		Files    int    `json:"files"`
		Bytes    int64  `json:"bytes"`
	}{displayPath(f), f.Rule, f.Why, f.Severity.String(), f.Files, f.Bytes})
}

// WriteJSON prints machine-readable output and returns the finding count.
// size is optional and adds the "size" object.
func WriteJSON(w io.Writer, findings []Finding, ig *Ignore, size *SizeReport) int {
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
	if size != nil {
		js := &jsonSize{Before: size.Before.Usage, After: size.After.Usage, TopDirs: []jsonDirSize{}}
		for _, d := range size.topDirs() {
			js.TopDirs = append(js.TopDirs, jsonDirSize{Path: d.Path + "/", Files: d.Files, Bytes: d.Bytes})
		}
		rep.Size = js
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
	return len(findings)
}
