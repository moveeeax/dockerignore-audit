// Command dockerignore-audit reports files in a Docker build context that
// should be excluded via .dockerignore but are not — secrets, keys, .git,
// dependency dirs, and other bloat. It exits non-zero when findings exist so
// it can gate a CI pipeline.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/moveeeax/dockerignore-audit/internal/audit"
)

// version is set at build time with -ldflags "-X main.version=<tag>".
// When it is empty, the module version recorded by "go install ...@vX.Y.Z"
// is used instead.
var version = ""

func resolveVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func main() {
	path := flag.String("path", ".", "build-context directory to audit")
	asJSON := flag.Bool("json", false, "emit JSON instead of text")
	dangerOnly := flag.Bool("danger-only", false, "exit non-zero only for dangerous (secret) findings")
	fix := flag.Bool("fix", false, "add the suggested patterns to .dockerignore, then audit again")
	dryRun := flag.Bool("dry-run", false, "with -fix: print the .dockerignore diff and change nothing")
	size := flag.Bool("size", false, "report build-context size now and with the suggested patterns")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(resolveVersion())
		return
	}
	if *dryRun && !*fix {
		fail(errors.New("-dry-run requires -fix"))
	}
	if *dryRun && *asJSON {
		fail(errors.New("-dry-run prints a diff and cannot be combined with -json"))
	}

	findings, ig, err := audit.Audit(*path)
	if err != nil {
		fail(err)
	}

	var plan *audit.Fix
	if *fix || *size {
		if plan, err = audit.PlanFix(*path, findings, ig); err != nil {
			fail(err)
		}
	}

	if *fix {
		for _, k := range plan.Kept {
			fmt.Fprintf(os.Stderr, "kept: %s is re-included by `%s` in .dockerignore; not adding `%s`\n", k.Path, k.Negation, k.Rule)
		}
		if *dryRun {
			fmt.Print(plan.Diff())
			os.Exit(exitCode(findings, *dangerOnly))
		}
	}

	var sz *audit.SizeReport
	if *size {
		if sz, err = audit.MeasureSize(*path, ig, plan); err != nil {
			fail(err)
		}
	}

	if *fix {
		if err := plan.Apply(); err != nil {
			fail(err)
		}
		if plan.Changed() {
			fmt.Fprintf(os.Stderr, "fix: added %d pattern(s) to %s\n", len(plan.Added), plan.Path)
		} else {
			fmt.Fprintln(os.Stderr, "fix: nothing to add to .dockerignore")
		}
		// Audit again so the report shows the result, not the plan.
		if findings, ig, err = audit.Audit(*path); err != nil {
			fail(err)
		}
	}

	if *asJSON {
		audit.WriteJSON(os.Stdout, findings, ig, sz)
	} else {
		audit.WriteText(os.Stdout, findings, ig, sz)
	}
	os.Exit(exitCode(findings, *dangerOnly))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}

// exitCode is 1 when there are findings (only dangerous ones with
// dangerOnly), else 0.
func exitCode(findings []audit.Finding, dangerOnly bool) int {
	for _, f := range findings {
		if !dangerOnly || f.Severity == audit.Danger {
			return 1
		}
	}
	return 0
}
