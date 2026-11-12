// Package audit inspects a directory's Docker build context and reports files
// that should almost certainly be excluded via .dockerignore but are not.
package audit

import (
	"bufio"
	"fmt"
	"io"
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
	// dir, when set, is a directory name the rule covers as a whole: a
	// directory with this name is reported once instead of file by file.
	dir string
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
	// Path is slash-separated and relative to the context root.
	Path string
	// Dir is set when Path is a directory reported as a whole.
	Dir bool
	// Rule is the .dockerignore pattern that would exclude Path.
	Rule     string
	Why      string
	Severity Severity
	// Files and Bytes count what Path adds to the build context today: 1 and
	// the file size for a file, the unignored files below it for a directory.
	Files int
	Bytes int64
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
		func(r string) bool { return hasExt(r, ".pem") }, nil, ""},
	{"**/*.key", "private key material", Danger,
		func(r string) bool { return hasExt(r, ".key") }, nil, ""},
	{"**/id_rsa", "SSH private key", Danger,
		func(r string) bool {
			b := base(r)
			return b == "id_rsa" || b == "id_dsa" || b == "id_ecdsa" || b == "id_ed25519"
		}, anyName, ""},
	{"**/.env", "environment file with secrets/config", Danger,
		func(r string) bool { b := base(r); return b == ".env" || strings.HasPrefix(b, ".env.") }, anyName, ""},
	{"**/*.p12", "PKCS#12 keystore", Danger,
		func(r string) bool { return hasExt(r, ".p12", ".pfx") }, anyExt, ""},
	{"**/credentials", "cloud/CLI credentials file", Danger,
		func(r string) bool { b := base(r); return b == "credentials" || b == ".netrc" || b == ".npmrc" }, anyName, ""},
	{"**/.git", "full source history bloats context and can leak old secrets", Warn,
		func(r string) bool { return hasSegment(r, ".git") }, nil, ".git"},
	{"**/node_modules", "reinstalled in the image; huge, slow context upload", Warn,
		func(r string) bool { return hasSegment(r, "node_modules") }, nil, "node_modules"},
	{"**/vendor", "vendored deps usually restored during build", Warn,
		func(r string) bool { return hasSegment(r, "vendor") }, nil, "vendor"},
	{"**/*.log", "log noise in the context", Warn,
		func(r string) bool { return hasExt(r, ".log") }, nil, ""},
	{"**/Dockerfile", "the Dockerfile does not belong inside the image it builds", Warn,
		func(r string) bool { b := base(r); return b == "Dockerfile" || strings.HasPrefix(b, "Dockerfile.") }, anyName, ""},
	{"**/__pycache__", "compiled Python cache", Warn,
		func(r string) bool { return hasSegment(r, "__pycache__") || hasExt(r, ".pyc") },
		func(r string) string {
			if hasSegment(r, "__pycache__") {
				return "**/__pycache__"
			}
			return "**/*.pyc"
		}, "__pycache__"},
	{"**/.terraform", "provider plugins / local terraform cache", Warn,
		func(r string) bool { return hasSegment(r, ".terraform") || hasExt(r, ".tfstate") },
		func(r string) string {
			if hasSegment(r, ".terraform") {
				return "**/.terraform"
			}
			return "**/*.tfstate"
		}, ".terraform"},
	{"**/.DS_Store", "macOS metadata", Warn,
		func(r string) bool { return base(r) == ".DS_Store" }, nil, ""},
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
	return ParseIgnore(f)
}

// ParseIgnore reads .dockerignore content from r.
func ParseIgnore(r io.Reader) (*Ignore, error) {
	ig := &Ignore{}
	first := true
	sc := bufio.NewScanner(r)
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
	// Walk runes, not bytes: a multi-byte UTF-8 character must be quoted as
	// one unit or non-ASCII patterns never match.
	rs := []rune(pat)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case inClass:
			if c == ']' {
				inClass = false
			}
			if c == '\\' && i+1 < len(rs) {
				i++
				b.WriteString(regexp.QuoteMeta(string(rs[i])))
				continue
			}
			b.WriteRune(c)
		case c == '[':
			inClass = true
			b.WriteRune(c)
		case c == '*' && i+1 < len(rs) && rs[i+1] == '*':
			i++
			if i+1 < len(rs) && rs[i+1] == '/' {
				i++
			}
			if i+1 == len(rs) {
				b.WriteString(".*")
			} else {
				b.WriteString("(.*/)?")
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		case c == '\\' && i+1 < len(rs):
			i++
			b.WriteString(regexp.QuoteMeta(string(rs[i])))
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

// hasNegation reports whether any "!" pattern exists. Without one, nothing
// below an excluded directory can come back, so the walk can skip it.
func (ig *Ignore) hasNegation() bool {
	for _, p := range ig.patterns {
		if p.negate {
			return true
		}
	}
	return false
}

// reincludedBy returns the "!" line that re-includes rel when the last
// pattern matching rel is a negation, i.e. the user kept rel on purpose.
func (ig *Ignore) reincludedBy(rel string) (string, bool) {
	var last *ignorePat
	for i := range ig.patterns {
		if ig.patterns[i].matches(rel) {
			last = &ig.patterns[i]
		}
	}
	if last == nil || !last.negate {
		return "", false
	}
	return "!" + last.raw, true
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

// walkContext walks start, which is dir or a directory below it, and calls fn
// for every directory and file that Docker would send from the build context
// rooted at dir. rel is slash-separated and relative to dir. fn may return
// filepath.SkipDir for a directory. Excluded directories are skipped unless a
// "!" pattern could re-include something below them.
func walkContext(dir, start string, ig *Ignore, fn func(rel string, info os.FileInfo) error) error {
	negations := ig.hasNegation()
	return filepath.Walk(start, func(fp string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(dir, fp)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if ig.Ignored(rel) {
			if info.IsDir() && !negations {
				return filepath.SkipDir
			}
			return nil
		}
		return fn(rel, info)
	})
}

// Audit walks dir and returns findings for context paths that match a rule and
// are not already excluded by .dockerignore. Findings are sorted most-severe first.
//
// A directory covered by a directory rule (node_modules, .git, ...) yields one
// finding with the count and size of the files below it, and its files are
// not reported one by one. Secrets found inside it still get their own danger
// findings, so -danger-only keeps failing on them.
func Audit(dir string) ([]Finding, *Ignore, error) {
	ig, err := LoadIgnore(dir)
	if err != nil {
		return nil, nil, err
	}
	var out []Finding
	err = walkContext(dir, dir, ig, func(rel string, info os.FileInfo) error {
		if info.IsDir() {
			for _, ru := range Rules {
				if ru.dir == "" || ru.dir != base(rel) {
					continue
				}
				d := Finding{Path: rel, Dir: true, Rule: ru.Suggestion(rel), Why: ru.Why, Severity: ru.Severity}
				var secrets []Finding
				err := walkContext(dir, filepath.Join(dir, filepath.FromSlash(rel)), ig, func(sub string, si os.FileInfo) error {
					if si.IsDir() {
						return nil
					}
					d.Files++
					d.Bytes += si.Size()
					if f, ok := dangerFinding(sub, si); ok {
						secrets = append(secrets, f)
					}
					return nil
				})
				if err != nil {
					return err
				}
				if d.Files > 0 {
					out = append(out, d)
				}
				out = append(out, secrets...)
				return filepath.SkipDir
			}
			return nil
		}
		if rel == ".dockerignore" {
			return nil
		}
		for _, ru := range Rules {
			if ru.match(rel) {
				out = append(out, Finding{Path: rel, Rule: ru.Suggestion(rel), Why: ru.Why, Severity: ru.Severity, Files: 1, Bytes: info.Size()})
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

// dangerFinding checks a file inside a collapsed directory against the danger
// rules only. Rules lists them first, so the scan stops at the first warning.
func dangerFinding(rel string, info os.FileInfo) (Finding, bool) {
	for _, ru := range Rules {
		if ru.Severity != Danger {
			break
		}
		if ru.match(rel) {
			return Finding{Path: rel, Rule: ru.Suggestion(rel), Why: ru.Why, Severity: ru.Severity, Files: 1, Bytes: info.Size()}, true
		}
	}
	return Finding{}, false
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
