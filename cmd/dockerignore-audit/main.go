// Command dockerignore-audit reports files in a Docker build context that
// should be excluded via .dockerignore but are not — secrets, keys, .git,
// dependency dirs, and other bloat. It exits non-zero when findings exist so
// it can gate a CI pipeline.
package main

import (
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
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(resolveVersion())
		return
	}

	findings, ig, err := audit.Audit(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	if *asJSON {
		audit.WriteJSON(os.Stdout, findings, ig)
	} else {
		audit.WriteText(os.Stdout, findings, ig)
	}

	var danger int
	for _, f := range findings {
		if f.Severity == audit.Danger {
			danger++
		}
	}
	if *dangerOnly {
		if danger > 0 {
			os.Exit(1)
		}
		return
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
}
