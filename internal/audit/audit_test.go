package audit

import (
	"bytes"
	"encoding/json"
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
	for _, want := range []string{"server.pem", ".env", "node_modules", ".git"} {
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
	if !got["node_modules"].Dir || !got[".git"].Dir {
		t.Error("node_modules and .git must be reported as directories")
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
	n := WriteJSON(&buf, findings, ig, nil)
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
	n := WriteText(&buf, findings, ig, nil)
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

func mustIgnore(t *testing.T, lines ...string) *Ignore {
	t.Helper()
	ig := &Ignore{}
	for _, l := range lines {
		if err := ig.add(l); err != nil {
			t.Fatal(err)
		}
	}
	return ig
}

// Cases follow the .dockerignore section of the Docker docs
// (https://docs.docker.com/build/concepts/context/#dockerignore-files) and
// moby/patternmatcher, which Docker uses to evaluate the file.
func TestIgnoredDockerSemantics(t *testing.T) {
	cases := []struct {
		patterns []string
		path     string
		want     bool
	}{
		// Patterns are anchored to the context root.
		{[]string{"*.pem"}, "server.pem", true},
		{[]string{"*.pem"}, "config/tls.pem", false},
		{[]string{".env"}, ".env", true},
		{[]string{".env"}, "app/.env", false},
		{[]string{"node_modules"}, "node_modules/x/i.js", true},
		{[]string{"node_modules"}, "web/node_modules/x/i.js", false},
		// "**" matches any number of directories, including zero.
		{[]string{"**/*.pem"}, "server.pem", true},
		{[]string{"**/*.pem"}, "config/tls/tls.pem", true},
		{[]string{"**/node_modules"}, "web/node_modules/x/i.js", true},
		{[]string{"**/.env"}, "app/.env", true},
		{[]string{"secrets/**"}, "secrets/a/b.key", true},
		{[]string{"a/**/b.key"}, "a/b.key", true},
		{[]string{"a/**/b.key"}, "a/x/y/b.key", true},
		// Leading and trailing slashes are disregarded.
		{[]string{"/foo/bar/"}, "foo/bar", true},
		{[]string{"/foo/bar/"}, "foo/bar/baz.txt", true},
		{[]string{"foo/bar"}, "x/foo/bar", false},
		// "*" and "?" never cross a "/".
		{[]string{"*/temp*"}, "somedir/temporary.txt", true},
		{[]string{"*/temp*"}, "temporary.txt", false},
		{[]string{"*/*/temp*"}, "somedir/subdir/temporary.txt", true},
		{[]string{"temp?"}, "tempa", true},
		{[]string{"temp?"}, "dir/tempa", false},
		{[]string{"*"}, "dir/file", true}, // parent dir "dir" matches
		// Negation: last matching line wins; only root-level README.md re-included.
		{[]string{"*.md", "!README.md"}, "README.md", false},
		{[]string{"*.md", "!README.md"}, "CHANGES.md", true},
		{[]string{"*.md", "!README.md"}, "docs/README.md", false},
		{[]string{"secrets", "!secrets/public.pem"}, "secrets/public.pem", false},
		{[]string{"secrets", "!secrets/public.pem"}, "secrets/private.pem", true},
		// "." is ignored for historical reasons; "#" is a comment only in column 1.
		{[]string{"."}, "main.go", false},
		{[]string{"[ab].key"}, "a.key", true},
		// Non-ASCII names are matched rune by rune.
		{[]string{"café.pem"}, "café.pem", true},
		{[]string{"данные"}, "данные/x", true},
		{[]string{"*.pem", "!café.pem"}, "café.pem", false},
		{[]string{"дан?ые"}, "данные", true},
		{[]string{"[дж]анные"}, "данные", true},
		{[]string{"**/секрет.key"}, "a/секрет.key", true},
		{[]string{"[ab].key"}, "c.key", false},
		{[]string{"file.with+meta(chars)"}, "file.with+meta(chars)", true},
		{[]string{"file.with+meta(chars)"}, "fileXwith+meta(chars)", false},
	}
	for _, c := range cases {
		ig := mustIgnore(t, c.patterns...)
		if got := ig.Ignored(c.path); got != c.want {
			t.Errorf("patterns %q, path %q: Ignored=%v, want %v", c.patterns, c.path, got, c.want)
		}
	}
}

func TestBareGlobDoesNotHideNestedSecrets(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config/tls.pem", "x")
	writeFile(t, dir, "app/.env", "SECRET=1")
	writeFile(t, dir, ".dockerignore", "*.pem\n.env\n")
	findings, _, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := findingSet(findings)
	for _, want := range []string{"config/tls.pem", "app/.env"} {
		if f, ok := got[want]; !ok || f.Severity != Danger {
			t.Errorf("Docker still sends %q with root-anchored patterns; want a danger finding, got %v", want, keys(got))
		}
	}
}

func TestCommentOnlyInColumnOne(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "server.pem", "x")
	writeFile(t, dir, ".dockerignore", "# *.pem\n")
	findings, _, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingSet(findings)["server.pem"]; !ok {
		t.Error("a commented-out pattern must not exclude anything")
	}
}

// Every suggested pattern must actually remove its finding when added.
func TestSuggestionsExcludeTheFinding(t *testing.T) {
	dir := t.TempDir()
	for _, rel := range []string{
		"config/tls.pem", "deep/a/b.key", "home/.ssh/id_ed25519", "svc/.env.local",
		"certs/client.pfx", "aws/credentials", "sub/.npmrc", "lib/.git/HEAD",
		"web/node_modules/x/i.js", "go/vendor/m/m.go", "logs/app.log",
		"svc/Dockerfile.dev", "py/__pycache__/m.cpython.pyc", "py/m.pyc",
		"infra/.terraform/p", "infra/terraform.tfstate", "assets/.DS_Store",
	} {
		writeFile(t, dir, rel, "x")
	}
	findings, _, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 17 {
		t.Fatalf("want 17 findings, got %d: %v", len(findings), keys(findingSet(findings)))
	}
	for _, f := range findings {
		ig := mustIgnore(t, f.Rule)
		if !ig.Ignored(f.Path) {
			t.Errorf("suggested pattern %q does not exclude %q", f.Rule, f.Path)
		}
	}
}

func TestCollapsesDirectoryFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "web/node_modules/a/index.js", "12345")
	writeFile(t, dir, "web/node_modules/a/node_modules/b/index.js", "123")
	writeFile(t, dir, "web/node_modules/a/README.md", "1")
	writeFile(t, dir, "web/node_modules/a/test/fixture.pem", "pem")
	writeFile(t, dir, "web/node_modules/a/app.log", "log")
	writeFile(t, dir, ".dockerignore", "web/node_modules/**/*.md\n")
	findings, _, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want the directory and the key inside it, got %+v", findings)
	}
	got := findingSet(findings)
	nm, ok := got["web/node_modules"]
	if !ok || !nm.Dir || nm.Rule != "**/node_modules" || nm.Severity != Warn {
		t.Fatalf("want one warn finding for web/node_modules, got %+v", findings)
	}
	// README.md is excluded; the other four files total 5+3+3+3 bytes.
	if nm.Files != 4 || nm.Bytes != 14 {
		t.Errorf("web/node_modules: files=%d bytes=%d, want 4 and 14", nm.Files, nm.Bytes)
	}
	if pem := got["web/node_modules/a/test/fixture.pem"]; pem.Severity != Danger || pem.Files != 1 || pem.Bytes != 3 {
		t.Errorf("a key inside a collapsed directory must stay a danger finding, got %+v", pem)
	}
}

func TestDirectoryFullyIgnoredBelowIsNotReported(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "vendor/m/m.go", "x")
	writeFile(t, dir, ".dockerignore", "vendor/**\n")
	findings, _, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("nothing under vendor/ reaches the builder, got %+v", findings)
	}
}

func TestNegationInsideIgnoredDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "node_modules/keep.js", "x")
	writeFile(t, dir, "node_modules/drop.js", "x")
	writeFile(t, dir, ".dockerignore", "node_modules\n!node_modules/keep.js\n")
	findings, _, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Path != "node_modules/keep.js" || findings[0].Dir {
		t.Errorf("only the re-included file reaches the builder, got %+v", findings)
	}
}

func TestDirectoryTextAndJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "node_modules/a.js", "1234")
	writeFile(t, dir, "node_modules/b.js", "1234")
	writeFile(t, dir, "id_rsa", "12")
	findings, ig, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	var txt bytes.Buffer
	WriteText(&txt, findings, ig, nil)
	if !bytes.Contains(txt.Bytes(), []byte("[warn] node_modules/ (2 files, 8 B)")) {
		t.Errorf("text report missing collapsed line:\n%s", txt.String())
	}
	var js bytes.Buffer
	WriteJSON(&js, findings, ig, nil)
	var rep struct {
		Findings []struct {
			Path  string `json:"path"`
			Files int    `json:"files"`
			Bytes int64  `json:"bytes"`
		} `json:"findings"`
		Size *json.RawMessage `json:"size"`
	}
	if err := json.Unmarshal(js.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 2 || rep.Findings[0].Path != "id_rsa" || rep.Findings[0].Files != 1 || rep.Findings[0].Bytes != 2 ||
		rep.Findings[1].Path != "node_modules/" || rep.Findings[1].Files != 2 || rep.Findings[1].Bytes != 8 {
		t.Errorf("unexpected JSON findings: %s", js.String())
	}
	if rep.Size != nil {
		t.Error("size must be omitted without -size")
	}
}

func TestHumanBytesAndDigits(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 999: "999 B", 1000: "1.0 kB", 184_200_000: "184.2 MB", 2_500_000_000: "2.5 GB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 12431: "12,431", 1234567: "1,234,567"} {
		if got := groupDigits(n); got != want {
			t.Errorf("groupDigits(%d) = %q, want %q", n, got, want)
		}
	}
}
