package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readIgnore(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".dockerignore"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// planAndApply runs Audit, PlanFix and Apply, then audits again.
func planAndApply(t *testing.T, dir string) (*Fix, []Finding) {
	t.Helper()
	findings, ig, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	fx, err := PlanFix(dir, findings, ig)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.Apply(); err != nil {
		t.Fatal(err)
	}
	after, _, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	return fx, after
}

func TestFixCreatesDockerignore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.pem", "x")
	writeFile(t, dir, "certs/b.pem", "x")
	writeFile(t, dir, "certs/c.pem", "x")
	writeFile(t, dir, "web/node_modules/x/i.js", "x")
	writeFile(t, dir, "api/node_modules/y/i.js", "x")
	fx, after := planAndApply(t, dir)
	if fx.Exists {
		t.Error("Exists must be false for a missing .dockerignore")
	}
	want := FixHeader + "\n**/*.pem\n**/node_modules\n"
	if got := readIgnore(t, dir); got != want {
		t.Errorf(".dockerignore:\n%s\nwant:\n%s", got, want)
	}
	if len(after) != 0 {
		t.Errorf("audit after -fix must be clean, got %+v", after)
	}
}

func TestFixKeepsExistingLinesAndSkipsKnownPatterns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app/.env", "x")
	writeFile(t, dir, "app.log", "x")
	writeFile(t, dir, ".dockerignore", "# mine\n**/*.log\n.env\n")
	// app.log is not a finding: "**/*.log" covers it. ".env" is anchored to
	// the root, so app/.env is a finding and "**/.env" gets added.
	fx, after := planAndApply(t, dir)
	want := "# mine\n**/*.log\n.env\n\n" + FixHeader + "\n**/.env\n"
	if got := readIgnore(t, dir); got != want {
		t.Errorf(".dockerignore:\n%q\nwant:\n%q", got, want)
	}
	if len(fx.Added) != 1 || len(after) != 0 {
		t.Errorf("added=%v after=%+v", fx.Added, after)
	}
}

func TestFixInsertsBeforeFirstNegation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "secrets/public.pem", "x")
	writeFile(t, dir, "secrets/private.key", "x")
	writeFile(t, dir, "certs/tls.pem", "x")
	writeFile(t, dir, "keep.key", "x")
	writeFile(t, dir, ".dockerignore", "secrets\n!secrets/public.pem\n*.key\n!keep.key\n")
	fx, after := planAndApply(t, dir)
	got := readIgnore(t, dir)
	wantFile := "secrets\n\n" + FixHeader + "\n**/*.pem\n\n!secrets/public.pem\n*.key\n!keep.key\n"
	if got != wantFile {
		t.Errorf(".dockerignore:\n%q\nwant:\n%q", got, wantFile)
	}
	// Both re-included files stay in the context and are reported as kept.
	kept := map[string]string{}
	for _, k := range fx.Kept {
		kept[k.Path] = k.Negation
	}
	if kept["secrets/public.pem"] != "!secrets/public.pem" || kept["keep.key"] != "!keep.key" {
		t.Errorf("kept = %+v", fx.Kept)
	}
	if len(fx.Added) != 1 || fx.Added[0] != "**/*.pem" {
		t.Errorf("added = %v", fx.Added)
	}
	left := findingSet(after)
	if len(after) != 2 || left["secrets/public.pem"].Path == "" || left["keep.key"].Path == "" {
		t.Errorf("after -fix only the re-included files may remain, got %v", keys(left))
	}
}

func TestFixExtendsPreviousBlock(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.pem", "x")
	writeFile(t, dir, "logs/a.log", "x")
	writeFile(t, dir, ".dockerignore", "dist\n\n"+FixHeader+"\n**/*.key\n\n# mine\n!dist/keep\n")
	planAndApply(t, dir)
	want := "dist\n\n" + FixHeader + "\n**/*.key\n**/*.pem\n**/*.log\n\n# mine\n!dist/keep\n"
	if got := readIgnore(t, dir); got != want {
		t.Errorf(".dockerignore:\n%q\nwant:\n%q", got, want)
	}
}

func TestFixPreservesCRLFAndMissingNewline(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.pem", "x")
	writeFile(t, dir, ".dockerignore", "\ufeffdist\r\nbuild")
	planAndApply(t, dir)
	want := "\ufeffdist\r\nbuild\r\n\r\n" + FixHeader + "\r\n**/*.pem\r\n"
	if got := readIgnore(t, dir); got != want {
		t.Errorf(".dockerignore:\n%q\nwant:\n%q", got, want)
	}
}

func TestFixNothingToAdd(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keep.pem", "x")
	writeFile(t, dir, ".dockerignore", "*.pem\n!keep.pem\n")
	findings, ig, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	fx, err := PlanFix(dir, findings, ig)
	if err != nil {
		t.Fatal(err)
	}
	if fx.Changed() || fx.Diff() != "" || string(fx.New) != string(fx.Old) {
		t.Errorf("a re-included finding must not change the file: %+v", fx)
	}
	if err := fx.Apply(); err != nil {
		t.Fatal(err)
	}
	if got := readIgnore(t, dir); got != "*.pem\n!keep.pem\n" {
		t.Errorf("file changed: %q", got)
	}
}

func TestFixDiff(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.pem", "x")
	findings, ig, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	fx, err := PlanFix(dir, findings, ig)
	if err != nil {
		t.Fatal(err)
	}
	want := "--- /dev/null\n+++ b/.dockerignore\n@@ -0,0 +1,2 @@\n+" + FixHeader + "\n+**/*.pem\n"
	if got := fx.Diff(); got != want {
		t.Errorf("diff for a new file:\n%s\nwant:\n%s", got, want)
	}
	if _, err := os.Stat(filepath.Join(dir, ".dockerignore")); !os.IsNotExist(err) {
		t.Error("PlanFix and Diff must not write the file")
	}

	writeFile(t, dir, ".dockerignore", "one\ntwo\nthree\nfour\n!five\nsix\nseven\neight\nnine\n")
	findings, ig, err = Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fx, err = PlanFix(dir, findings, ig); err != nil {
		t.Fatal(err)
	}
	want = strings.Join([]string{
		"--- a/.dockerignore",
		"+++ b/.dockerignore",
		"@@ -2,6 +2,10 @@",
		" two",
		" three",
		" four",
		"+",
		"+" + FixHeader,
		"+**/*.pem",
		"+",
		" !five",
		" six",
		" seven",
		"",
	}, "\n")
	if got := fx.Diff(); got != want {
		t.Errorf("diff for an existing file:\n%s\nwant:\n%s", got, want)
	}
}
