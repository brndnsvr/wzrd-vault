# Contributing to wzrd-vault

Thank you for your interest in contributing. This document covers how to build,
test, lint, and submit changes.

## Building from Source

```
git clone https://github.com/brndnsvr/wzrd-vault.git
cd wzrd-vault
make build
```

The binary is written to `bin/wzrd-vault`. Version metadata is injected at
build time via `-ldflags`; a local build will report `dev` for the version
unless a git tag is present.

You can also install the binary to `~/.local/bin`:

```
make install
```

## Running Tests

Run the full unit test suite (all packages, race detector enabled):

```
make test
```

Run integration tests. These build the binary and exercise it end-to-end, so
they require a working Go toolchain and a writable temp directory:

```
make test-integration
```

Or invoke go directly:

```
go test -tags=integration ./cmd/ -race -count=1 -timeout=120s
```

Generate a coverage report:

```
make coverage
```

## Running the Linter

```
make lint
```

This runs `golangci-lint run` with the project's configuration. You can also
invoke golangci-lint directly:

```
golangci-lint run
```

Install golangci-lint if it is not already available:

```
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

## Code Style

- **Formatter**: `gofumpt`. Format all files before committing.
- **Linter**: `golangci-lint` with the project's `.golangci.yml` (or the
  linter's defaults if no config file exists).
- **Doc comments**: All exported types, functions, constants, and variables must
  have a doc comment. Use standard Go doc comment style (begin with the name of
  the identifier).
- **Error handling**: Return errors explicitly; do not panic except in `main`
  for truly unrecoverable conditions.
- **Tests**: Table-driven tests are preferred for unit tests. New packages
  should have corresponding `_test.go` files.

## Submitting a Pull Request

1. Fork the repository and create a feature branch from `main`.
2. Make your changes. Add or update tests as appropriate.
3. Ensure `make test` and `go test -tags=integration ./cmd/` pass locally.
4. Ensure `make lint` passes with no errors.
5. Open a pull request against `main`. Describe what the change does and why.
6. Keep each PR focused on a single concern. Large changes are easier to review
   when split into a series of smaller PRs.

## Commit Message Style

- Use the imperative mood in the subject line: "Add flag", "Fix crash", not
  "Added flag" or "Fixes crash".
- Keep the subject line concise (50–72 characters).
- If additional context is needed, add a blank line after the subject followed
  by a body paragraph.
- Do not reference issue numbers in the subject; put them in the body if needed.

Examples of good commit messages:

```
Add --expires flag with duration and absolute date support

Validate path segments to reject traversal and uppercase characters
```

## Security-Sensitive Changes

Changes that touch encryption, key handling, passphrase derivation, secret
storage, or any code path where user credentials are processed require extra
care. Before submitting such a change, read `SECURITY.md` for the project's
disclosure policy. If you have found a security vulnerability, please follow
the responsible disclosure process described there rather than opening a public
issue.
