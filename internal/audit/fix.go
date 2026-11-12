package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FixHeader is the comment line above the patterns that -fix writes.
const FixHeader = "# added by dockerignore-audit"

// Fix is a planned change to .dockerignore: the suggested patterns that are
// not in the file yet, inserted as one block.
type Fix struct {
	// Path is the .dockerignore file; Exists is false when it has to be created.
	Path   string
	Exists bool
	Old    []byte
	New    []byte
	// Added lists the inserted patterns in report order.
	Added []string
	// Kept lists findings left alone because a "!" line re-includes them.
	Kept []Kept

	// at and lines locate the inserted block, for Diff.
	at       int
	lines    []string
	inserted []string
}

// Kept is a finding whose path the user re-included with a "!" line.
type Kept struct {
	Path     string
	Rule     string
	Negation string
}

// PlanFix computes the .dockerignore change that adds the suggestions of
// findings. ig must be the Ignore that Audit returned for dir.
//
// Existing lines are never reordered or rewritten. The block goes at the end
// of the file, or right before the first "!" line when there is one: Docker
// lets the last matching line win, so a pattern appended after a "!" line
// would override that re-include. Placed before it, the new patterns exclude
// every finding (nothing matched those before) while every existing "!" line
// keeps working. If a previous run left a FixHeader block above the first "!"
// line, new patterns extend that block instead of starting another one.
// Findings that a "!" line re-includes are reported in Kept, not excluded.
func PlanFix(dir string, findings []Finding, ig *Ignore) (*Fix, error) {
	fx := &Fix{Path: filepath.Join(dir, ".dockerignore"), Exists: true}
	old, err := os.ReadFile(fx.Path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		fx.Exists = false
	}
	fx.Old = old

	lines := strings.SplitAfter(string(old), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	seen := map[string]bool{}
	for i := range lines {
		seen[strings.TrimSpace(lineText(lines, i))] = true
	}
	for _, f := range findings {
		if neg, ok := ig.reincludedBy(f.Path); ok {
			fx.Kept = append(fx.Kept, Kept{Path: displayPath(f), Rule: f.Rule, Negation: neg})
			continue
		}
		if seen[f.Rule] {
			continue
		}
		seen[f.Rule] = true
		fx.Added = append(fx.Added, f.Rule)
	}
	fx.lines = lines
	if len(fx.Added) == 0 {
		fx.New = old
		return fx, nil
	}

	eol := "\n"
	if strings.Contains(string(old), "\r\n") {
		eol = "\r\n"
	}
	firstNeg := len(lines)
	header := -1
	for i := range lines {
		t := lineText(lines, i)
		if strings.HasPrefix(t, "#") {
			if header < 0 && strings.TrimRight(t, " \t\r") == FixHeader {
				header = i
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(t), "!") {
			firstNeg = i
			break
		}
	}
	var ins []string
	at := firstNeg
	if header >= 0 && header < firstNeg {
		at = header + 1
		for at < firstNeg && !blank(lineText(lines, at)) && !strings.HasPrefix(lineText(lines, at), "#") {
			at++
		}
		ins = append(ins, fx.Added...)
	} else {
		if at > 0 && !blank(lineText(lines, at-1)) {
			ins = append(ins, "")
		}
		ins = append(ins, FixHeader)
		ins = append(ins, fx.Added...)
		if at < len(lines) && !blank(lineText(lines, at)) {
			ins = append(ins, "")
		}
	}

	var b strings.Builder
	for i, l := range lines[:at] {
		b.WriteString(l)
		if i == len(lines)-1 && !strings.HasSuffix(l, "\n") {
			b.WriteString(eol)
		}
	}
	for _, l := range ins {
		b.WriteString(l + eol)
	}
	for _, l := range lines[at:] {
		b.WriteString(l)
	}
	fx.New = []byte(b.String())
	fx.at = at
	fx.inserted = ins
	return fx, nil
}

// lineText returns line i without its line ending, and without the UTF-8 BOM
// on the first line, which Docker also strips.
func lineText(lines []string, i int) string {
	t := strings.TrimRight(lines[i], "\r\n")
	if i == 0 {
		t = strings.TrimPrefix(t, "\ufeff")
	}
	return t
}

func blank(s string) bool { return strings.TrimSpace(s) == "" }

// Changed reports whether applying the fix would modify .dockerignore.
func (fx *Fix) Changed() bool { return len(fx.Added) > 0 }

// Apply writes the planned content, creating .dockerignore if needed.
func (fx *Fix) Apply() error {
	if !fx.Changed() {
		return nil
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(fx.Path); err == nil {
		mode = st.Mode().Perm()
	}
	return os.WriteFile(fx.Path, fx.New, mode)
}

// Diff returns the change as a unified diff with three lines of context, or
// "" when nothing would change.
func (fx *Fix) Diff() string {
	if !fx.Changed() {
		return ""
	}
	const ctx = 3
	start := max(fx.at-ctx, 0)
	end := min(fx.at+ctx, len(fx.lines))
	var b strings.Builder
	if fx.Exists {
		b.WriteString("--- a/.dockerignore\n")
	} else {
		b.WriteString("--- /dev/null\n")
	}
	b.WriteString("+++ b/.dockerignore\n")
	oldN := end - start
	newN := oldN + len(fx.inserted)
	oldStart, newStart := start+1, start+1
	if oldN == 0 {
		oldStart = start
	}
	fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", oldStart, oldN, newStart, newN)
	for i := start; i < fx.at; i++ {
		b.WriteString(" " + lineText(fx.lines, i) + "\n")
	}
	for _, l := range fx.inserted {
		b.WriteString("+" + l + "\n")
	}
	for i := fx.at; i < end; i++ {
		b.WriteString(" " + lineText(fx.lines, i) + "\n")
	}
	return b.String()
}
