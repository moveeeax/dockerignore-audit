# dockerignore-audit

A tiny, zero-dependency linter that finds files sitting in your Docker **build context** that should be excluded by `.dockerignore` — secrets and keys, `.git`, dependency directories, build junk — and **exits non-zero** so it can gate CI.

When you run `docker build`, everything in the context directory (minus what `.dockerignore` excludes) is sent to the daemon and can end up in an image layer. A stray `.env`, `id_rsa`, or `*.pem` is a real leak. A missing `.dockerignore` also means your whole `.git` history and `node_modules` get uploaded on every build. This tool catches both.

## Install

```sh
go install github.com/moveeeax/dockerignore-audit/cmd/dockerignore-audit@latest
```

Or build from source:

```sh
git clone https://github.com/moveeeax/dockerignore-audit
cd dockerignore-audit
make build   # -> dist/dockerignore-audit
```

## Usage

```sh
dockerignore-audit -path .
```

```
  [danger] config/tls.pem
         private key or certificate — never ship in an image layer (add `**/*.pem` to .dockerignore)
  [warn] node_modules/left-pad/index.js
         reinstalled in the image; huge, slow context upload (add `**/node_modules` to .dockerignore)

2 file(s) should be ignored (1 dangerous).
```

### Flags

| Flag | Meaning |
|------|---------|
| `-path <dir>` | Build-context directory to audit (default `.`) |
| `-json` | Emit JSON instead of text |
| `-danger-only` | Exit non-zero only for **dangerous** (secret/key) findings; still prints warnings |
| `-version` | Print version (set via `-ldflags "-X main.version=..."`, or the module version when installed with `go install ...@vX.Y.Z`) |

Exit code is `1` when there are findings (or, with `-danger-only`, when there are dangerous ones), `0` when clean, `2` on error.

## What it flags

**Dangerous** (secrets — should never enter a layer): `*.pem`, `*.key`, `*.p12`/`*.pfx`, `id_rsa` and friends, `.env` / `.env.*`, `credentials` / `.netrc` / `.npmrc`.

**Warnings** (bloat / hygiene): `.git`, `node_modules`, `vendor`, `*.log`, `Dockerfile*`, `__pycache__` / `*.pyc`, `.terraform` / `*.tfstate`, `.DS_Store`.

Anything already excluded by your `.dockerignore` is not reported. Patterns are evaluated with Docker's own rules ([docs](https://docs.docker.com/build/concepts/context/#dockerignore-files), [moby/patternmatcher](https://github.com/moby/patternmatcher)): they are anchored to the root of the build context, `*` and `?` stay within one path segment, `**` matches any number of directories, excluding a directory excludes everything under it, and the last matching line wins, so `!` re-includes.

That anchoring is the trap this tool catches: `*.pem` or `.env` in `.dockerignore` only exclude top-level files, so `config/tls.pem` or `app/.env` still reach the builder. Suggestions therefore use the `**/` form (`**/*.pem`, `**/.env`), which matches at any depth.

## In CI

```yaml
- uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
  with:
    go-version: '1.27'
- name: Install dockerignore-audit
  run: go install github.com/moveeeax/dockerignore-audit/cmd/dockerignore-audit@latest
- name: Audit build context
  run: dockerignore-audit -path .
```

`go install` puts the binary in `$(go env GOPATH)/bin`, which `actions/setup-go` adds to `PATH`. Replace `@latest` with a tag to pin the version.

Fail fast before you build. Use `-danger-only` if you want a strict secrets gate without failing on bloat.

## Why no YAML/pattern library

`.dockerignore` is line-oriented and the risky patterns are simple. Keeping the whole thing standard-library means the tool that tells you to shrink your supply-chain surface doesn't add to it. Go 1.26 or newer, no dependencies.

## License

MIT
