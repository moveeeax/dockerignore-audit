package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func findingSet(f []Finding) map[string]Finding {
	m := make(map[string]Finding, len(f))
	for _, x := range f {
		m[x.Path] = x
	}
	return m
}

func TestFlagsSecretsAndBloat(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main")
	writeFile(t, dir, "server.pem", "-----BEGIN PRIVATE KEY-----")
	writeFile(t, dir, ".env", "SECRET=1")
	writeFile(t, dir, "node_modules/left-pad/index.js", "module.exports=0")
	writeFile(t, dir, ".git/config", "[core]")

	findings, ig, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ig.Empty() {
		t.Fatal("expected empty ignore (no .dockerignore)")
	}
	got := findingSet(findings)
	for _, want := range []string{"server.pem", ".env", "node_modules/left-pad/index.js", ".git/config"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected finding for %q, got %v", want, keys(got))
		}
	}
	if _, ok := got["main.go"]; ok {
		t.Error("main.go should not be flagged")
	}
	if got["server.pem"].Severity != Danger || got[".env"].Severity != Danger {
		t.Error("pem/.env must be danger severity")
	}
}

func TestRespectsDockerignore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "server.pem", "x")
	writeFile(t, dir, "node_modules/x/i.js", "x")
	writeFile(t, dir, ".dockerignore", "*.pem\nnode_modules\n")

	findings, ig, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ig.Empty() {
		t.Fatal("ignore should not be empty")
	}
	if len(findings) != 0 {
		t.Errorf("everything is ignored, expected 0 findings, got %v", keys(findingSet(findings)))
	}
}

func TestNegationReincludes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keep.pem", "x")
	writeFile(t, dir, ".dockerignore", "*.pem\n!keep.pem\n")
	findings, _, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingSet(findings)["keep.pem"]; !ok {
		t.Error("keep.pem was re-included by ! and should be flagged")
	}
}

func TestSortDangerFirst(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.log", "x")
	writeFile(t, dir, "z.pem", "x")
	findings, _, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 2 || findings[0].Severity != Danger {
		t.Fatalf("danger should sort first, got %+v", findings)
	}
}

func TestJSONShape(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "id_rsa", "x")
	findings, ig, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	n := WriteJSON(&buf, findings, ig)
	if n != 1 {
		t.Fatalf("want 1 finding, got %d", n)
	}
	out := buf.String()
	for _, sub := range []string{`"has_dockerignore": false`, `"danger_count": 1`, `"severity": "danger"`, `"id_rsa"`} {
		if !bytes.Contains([]byte(out), []byte(sub)) {
			t.Errorf("json missing %q; got:\n%s", sub, out)
		}
	}
}

func TestTextOKWhenClean(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main")
	writeFile(t, dir, ".dockerignore", "# nothing to ignore\n")
	findings, ig, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	n := WriteText(&buf, findings, ig)
	if n != 0 || !bytes.Contains(buf.Bytes(), []byte("OK:")) {
		t.Errorf("expected clean OK report, got n=%d out=%s", n, buf.String())
	}
}

func keys(m map[string]Finding) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}
