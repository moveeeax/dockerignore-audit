// Package audit inspects a directory's Docker build context and reports files
// that should almost certainly be excluded via .dockerignore but are not.
package audit

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
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
	// Name is the .dockerignore pattern that would exclude it at any depth.
	Name string
	// Why explains the risk in one line.
	Why      string
	Severity Severity
	// match reports whether a repo-relative path (slash-separated) triggers the rule.
	match func(rel string) bool
	// suggest, when set, returns a pattern tailored to the matched path for
	// rules that cover several names (id_rsa/id_ed25519, .env/.env.local, ...).
	suggest func(rel string) string
}

// Suggestion returns the .dockerignore pattern to recommend for rel.
func (r Rule) Suggestion(rel string) string {
	if r.suggest != nil {
		return r.suggest(rel)
	}
	return r.Name
}

// Finding is a concrete path that matched a rule and is not already ignored.
type Finding struct {
	Path string
	// Rule is the .dockerignore pattern that would exclude Path.
	Rule     string
	Why      string
	Severity Severity
}

func base(rel string) string { return path.Base(rel) }

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

// anyName suggests "**/<basename>", which Docker matches at every depth.
func anyName(rel string) string { return "**/" + base(rel) }

// anyExt suggests "**/*<ext>" using the file's own extension.
func anyExt(rel string) string { return "**/*" + path.Ext(base(rel)) }

// Rules is the default rule set, ordered most-severe first.
//
// Docker anchors .dockerignore patterns to the root of the build context:
// "*.pem" excludes only top-level .pem files, so every suggestion uses the
// "**/" prefix, which matches any number of directories including zero.
var Rules = []Rule{
	{"**/*.pem", "private key or certificate — never ship in an image layer", Danger,
		func(r string) bool { return hasExt(r, ".pem") }, nil},
	{"**/*.key", "private key material", Danger,
		func(r string) bool { return hasExt(r, ".key") }, nil},
	{"**/id_rsa", "SSH private key", Danger,
		func(r string) bool {
			b := base(r)
			return b == "id_rsa" || b == "id_dsa" || b == "id_ecdsa" || b == "id_ed25519"
		}, anyName},
	{"**/.env", "environment file with secrets/config", Danger,
		func(r string) bool { b := base(r); return b == ".env" || strings.HasPrefix(b, ".env.") }, anyName},
	{"**/*.p12", "PKCS#12 keystore", Danger,
		func(r string) bool { return hasExt(r, ".p12", ".pfx") }, anyExt},
	{"**/credentials", "cloud/CLI credentials file", Danger,
		func(r string) bool { b := base(r); return b == "credentials" || b == ".netrc" || b == ".npmrc" }, anyName},
	{"**/.git", "full source history bloats context and can leak old secrets", Warn,
		func(r string) bool { return hasSegment(r, ".git") }, nil},
	{"**/node_modules", "reinstalled in the image; huge, slow context upload", Warn,
		func(r string) bool { return hasSegment(r, "node_modules") }, nil},
	{"**/vendor", "vendored deps usually restored during build", Warn,
		func(r string) bool { return hasSegment(r, "vendor") }, nil},
	{"**/*.log", "log noise in the context", Warn,
		func(r string) bool { return hasExt(r, ".log") }, nil},
	{"**/Dockerfile", "the Dockerfile does not belong inside the image it builds", Warn,
		func(r string) bool { b := base(r); return b == "Dockerfile" || strings.HasPrefix(b, "Dockerfile.") }, anyName},
	{"**/__pycache__", "compiled Python cache", Warn,
		func(r string) bool { return hasSegment(r, "__pycache__") || hasExt(r, ".pyc") },
		func(r string) string {
			if hasSegment(r, "__pycache__") {
				return "**/__pycache__"
			}
			return "**/*.pyc"
		}},
	{"**/.terraform", "provider plugins / local terraform cache", Warn,
		func(r string) bool { return hasSegment(r, ".terraform") || hasExt(r, ".tfstate") },
		func(r string) string {
			if hasSegment(r, ".terraform") {
				return "**/.terraform"
			}
			return "**/*.tfstate"
		}},
	{"**/.DS_Store", "macOS metadata", Warn,
		func(r string) bool { return base(r) == ".DS_Store" }, nil},
}

// Ignore holds parsed .dockerignore patterns.
//
// Matching follows Docker's semantics (moby/patternmatcher, which BuildKit and
// the Docker CLI use): patterns are anchored to the root of the build context,
// "*" and "?" never cross a "/", "**" matches any number of directories
// including zero, a pattern that matches a parent directory excludes
// everything below it, and the last matching line wins, so "!keep" re-includes.
type Ignore struct {
	patterns []ignorePat
}

type ignorePat struct {
	raw    string
	negate bool
	re     *regexp.Regexp
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
	first := true
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if first {
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}
		// Docker treats "#" as a comment only in column 1.
		if strings.HasPrefix(line, "#") {
			continue
		}
		if err := ig.add(line); err != nil {
			return nil, err
		}
	}
	return ig, sc.Err()
}

// add parses one .dockerignore line the way Docker does: trim whitespace,
// split off "!", clean the path and drop a leading "/".
func (ig *Ignore) add(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	p := ignorePat{}
	if line[0] == '!' {
		p.negate = true
		line = strings.TrimSpace(line[1:])
		if line == "" {
			return fmt.Errorf(".dockerignore: illegal exclusion pattern %q", "!")
		}
	}
	line = path.Clean(filepath.ToSlash(line))
	if len(line) > 1 && line[0] == '/' {
		line = line[1:]
	}
	// For historical reasons Docker ignores the pattern ".".
	if line == "." {
		return nil
	}
	re, err := compilePattern(line)
	if err != nil {
		return fmt.Errorf(".dockerignore: bad pattern %q: %w", line, err)
	}
	p.raw = line
	p.re = re
	ig.patterns = append(ig.patterns, p)
	return nil
}

// compilePattern translates a cleaned .dockerignore pattern into an anchored
// regular expression with Docker's wildcard rules.
func compilePattern(pat string) (*regexp.Regexp, error) {
	if _, err := path.Match(pat, "."); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("^")
	inClass := false
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		switch {
		case inClass:
			if c == ']' {
				inClass = false
			}
			if c == '\\' && i+1 < len(pat) {
				i++
				b.WriteString(regexp.QuoteMeta(pat[i : i+1]))
				continue
			}
			b.WriteByte(c)
		case c == '[':
			inClass = true
			b.WriteByte(c)
		case c == '*' && i+1 < len(pat) && pat[i+1] == '*':
			i++
			if i+1 < len(pat) && pat[i+1] == '/' {
				i++
			}
			if i+1 == len(pat) {
				b.WriteString(".*")
			} else {
				b.WriteString("(.*/)?")
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		case c == '\\' && i+1 < len(pat):
			i++
			b.WriteString(regexp.QuoteMeta(pat[i : i+1]))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// Empty reports whether no patterns were loaded (missing or blank file).
func (ig *Ignore) Empty() bool { return len(ig.patterns) == 0 }

// Ignored reports whether a repo-relative slash path is excluded from the
// build context. A pattern applies when it matches the path itself or one of
// its parent directories; later matching patterns win.
func (ig *Ignore) Ignored(rel string) bool {
	ignored := false
	for _, p := range ig.patterns {
		if p.negate != ignored {
			continue
		}
		if p.matches(rel) {
			ignored = !p.negate
		}
	}
	return ignored
}

func (p ignorePat) matches(rel string) bool {
	if p.re.MatchString(rel) {
		return true
	}
	for i := 0; i < len(rel); i++ {
		if rel[i] == '/' && p.re.MatchString(rel[:i]) {
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
	err = filepath.Walk(dir, func(fp string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, fp)
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
				out = append(out, Finding{Path: rel, Rule: ru.Suggestion(rel), Why: ru.Why, Severity: ru.Severity})
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
