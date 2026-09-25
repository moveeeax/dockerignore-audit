// Package audit inspects a directory's Docker build context and reports files
// that should almost certainly be excluded via .dockerignore but are not.
package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Severity classifies how much a finding matters.
type Severity int

const (
	// Warn: bloats the build context or leaks source history, but not a secret.
	Warn Severity = iota
	// Danger: a credential or key that must never enter an image layer.
	Danger
)

func (s Severity) String() string {
	if s == Danger {
		return "danger"
	}
	return "warn"
}

// Rule describes one thing worth keeping out of the build context.
type Rule struct {
	// Name is the .dockerignore pattern that would exclude it.
	Name string
	// Why explains the risk in one line.
	Why      string
	Severity Severity
	// match reports whether a repo-relative path (slash-separated) triggers the rule.
	match func(rel string) bool
}

// Finding is a concrete path that matched a rule and is not already ignored.
type Finding struct {
	Path     string
	Rule     string
	Why      string
	Severity Severity
}

func base(rel string) string { return filepath.Base(rel) }

func hasSegment(rel, seg string) bool {
	for _, p := range strings.Split(rel, "/") {
		if p == seg {
			return true
		}
	}
	return false
}

func hasExt(rel string, exts ...string) bool {
	b := strings.ToLower(base(rel))
	for _, e := range exts {
		if strings.HasSuffix(b, e) {
			return true
		}
	}
	return false
}

// Rules is the default rule set, ordered most-severe first.
var Rules = []Rule{
	{"*.pem", "private key or certificate — never ship in an image layer", Danger,
		func(r string) bool { return hasExt(r, ".pem") }},
	{"*.key", "private key material", Danger,
		func(r string) bool { return hasExt(r, ".key") }},
	{"id_rsa", "SSH private key", Danger,
		func(r string) bool {
			b := base(r)
			return b == "id_rsa" || b == "id_dsa" || b == "id_ecdsa" || b == "id_ed25519"
		}},
	{".env", "environment file with secrets/config", Danger,
		func(r string) bool { b := base(r); return b == ".env" || strings.HasPrefix(b, ".env.") }},
	{"*.p12", "PKCS#12 keystore", Danger,
		func(r string) bool { return hasExt(r, ".p12", ".pfx") }},
	{"credentials", "cloud/CLI credentials file", Danger,
		func(r string) bool { b := base(r); return b == "credentials" || b == ".netrc" || b == ".npmrc" }},
	{".git", "full source history bloats context and can leak old secrets", Warn,
		func(r string) bool { return hasSegment(r, ".git") }},
	{"node_modules", "reinstalled in the image; huge, slow context upload", Warn,
		func(r string) bool { return hasSegment(r, "node_modules") }},
	{"vendor", "vendored deps usually restored during build", Warn,
		func(r string) bool { return hasSegment(r, "vendor") }},
	{"*.log", "log noise in the context", Warn,
		func(r string) bool { return hasExt(r, ".log") }},
	{"Dockerfile", "the Dockerfile does not belong inside the image it builds", Warn,
		func(r string) bool { b := base(r); return b == "Dockerfile" || strings.HasPrefix(b, "Dockerfile.") }},
	{"__pycache__", "compiled Python cache", Warn,
		func(r string) bool { return hasSegment(r, "__pycache__") || hasExt(r, ".pyc") }},
	{".terraform", "provider plugins / local terraform cache", Warn,
		func(r string) bool { return hasSegment(r, ".terraform") || hasExt(r, ".tfstate") }},
	{".DS_Store", "macOS metadata", Warn,
		func(r string) bool { return base(r) == ".DS_Store" }},
}

// Ignore holds parsed .dockerignore patterns for prefix/segment matching.
// This is a pragmatic subset of Docker's rules: it covers the exact-name,
// leading-directory, and "**/name" cases that matter for auditing, not the
// full pattern grammar (negation with ! is honored).
type Ignore struct {
	patterns []ignorePat
}

type ignorePat struct {
	raw    string
	negate bool
}

// LoadIgnore reads .dockerignore from dir. A missing file yields an empty set.
func LoadIgnore(dir string) (*Ignore, error) {
	ig := &Ignore{}
	f, err := os.Open(filepath.Join(dir, ".dockerignore"))
	if err != nil {
		if os.IsNotExist(err) {
			return ig, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := ignorePat{raw: line}
		if strings.HasPrefix(line, "!") {
			p.negate = true
			p.raw = strings.TrimPrefix(line, "!")
		}
		p.raw = strings.TrimPrefix(p.raw, "./")
		p.raw = strings.TrimSuffix(p.raw, "/")
		ig.patterns = append(ig.patterns, p)
	}
	return ig, sc.Err()
}

// Empty reports whether no patterns were loaded (missing or blank file).
func (ig *Ignore) Empty() bool { return len(ig.patterns) == 0 }

// Ignored reports whether a repo-relative slash path is excluded from the
// build context. Later matching patterns win, so a trailing "!keep" re-includes.
func (ig *Ignore) Ignored(rel string) bool {
	ignored := false
	for _, p := range ig.patterns {
		if patMatch(p.raw, rel) {
			ignored = !p.negate
		}
	}
	return ignored
}

func patMatch(pat, rel string) bool {
	pat = strings.TrimPrefix(pat, "**/")
	// Exact path.
	if pat == rel {
		return true
	}
	// Leading-directory match: "node_modules" excludes "node_modules/x/y".
	if strings.HasPrefix(rel, pat+"/") {
		return true
	}
	// Any path segment equals the pattern (covers "**/.git" behavior).
	if !strings.ContainsAny(pat, "/*?[") && hasSegment(rel, pat) {
		return true
	}
	// Glob on the basename ("*.pem").
	if strings.ContainsAny(pat, "*?[") {
		if ok, _ := filepath.Match(pat, base(rel)); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, rel); ok {
			return true
		}
	}
	return false
}

// Audit walks dir and returns findings for context files that match a rule and
// are not already excluded by .dockerignore. Findings are sorted most-severe first.
func Audit(dir string) ([]Finding, *Ignore, error) {
	ig, err := LoadIgnore(dir)
	if err != nil {
		return nil, nil, err
	}
	var out []Finding
	err = filepath.Walk(dir, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == ".dockerignore" {
			return nil
		}
		if ig.Ignored(rel) {
			return nil
		}
		for _, ru := range Rules {
			if ru.match(rel) {
				out = append(out, Finding{Path: rel, Rule: ru.Name, Why: ru.Why, Severity: ru.Severity})
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sortFindings(out)
	return out, ig, nil
}

func sortFindings(f []Finding) {
	// insertion sort: danger before warn, then by path — small n, stable, no deps
	for i := 1; i < len(f); i++ {
		for j := i; j > 0; j-- {
			a, b := f[j-1], f[j]
			less := a.Severity > b.Severity || (a.Severity == b.Severity && a.Path <= b.Path)
			if less {
				break
			}
			f[j-1], f[j] = f[j], f[j-1]
		}
	}
}
