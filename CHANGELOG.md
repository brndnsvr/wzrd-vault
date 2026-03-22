# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.1] - 2026-03-21

### Fixed
- Dotenv export now escapes `$`, backtick, and `\r` in double-quoted values (prevents shell injection when sourced)
- `WZVAULT_PASSPHRASE_FD` stripped from editor subprocess environment (was only stripping `AGE_KEY`)
- SQLite deadlock when importing with `MaxOpenConns(1)` — `ExistsTx` now runs within the import transaction
- `ParseExpiry` hoisted out of filter loop in `list --expiring` (was re-parsing + re-calling `time.Now()` per entry)
- `init --force` now logs warnings when old file removal fails instead of silently continuing

### Changed
- SQLite hardened: `busy_timeout=5000`, `MaxOpenConns(1)`, `umask(0077)` for WAL/SHM sidecar files
- Database file pre-created at `0600` before `sql.Open` (eliminates TOCTOU permission window)
- `schema_version` table uses singleton pattern with `CHECK(id = 1)`
- Import is now transactional — partial failures roll back the entire batch
- Delete confirmation prompts use `/dev/tty` (consistent with set command)
- `--prefix-strip` auto-appends trailing `/` if missing
- Public-key newline stripping standardized to `strings.TrimSpace` across all commands
- `migrate()` commit error now wrapped with context
- Store `doc.go` updated to document WAL mode, busy timeout, and permission strategy

### Added
- `ExistsTx` method on store for transaction-aware existence checks
- `SetTx` method on store for transactional batch inserts
- `Begin` method on store for explicit transaction control
- `make test-integration` Makefile target
- Integration test for dotenv export escaping of `$` and backtick characters
- Advisory expiry behavior documented in README security model, `get` help text, and `list` help text
- `init` help text documents `--force` file removal behavior
- `edit` help text documents environment sanitization
- CONTRIBUTING.md references `make test-integration`

## [0.2.0] - 2026-03-20

### Fixed
- `os.Exit` calls inside command handlers now use `ExitError` type to preserve deferred cleanup (SQLite WAL/SHM files no longer left behind)
- `secureDelete` uses in-place overwrite + fsync instead of truncate-then-write
- `secureTmpDir` falls back to `~/Library/Caches/wzrd-vault` on macOS instead of disk-backed `/tmp`
- `SecretsMatch` uses constant-time comparison (`crypto/subtle.ConstantTimeCompare`)
- `ReadPassphraseFromFD` no longer leaks the file descriptor
- `--force` reinit now deletes old database and identity files before recreating
- Signal handler in `edit` uses `sync.Once` to prevent race conditions; adds SIGHUP/SIGQUIT
- Editor priority corrected to VISUAL before EDITOR (POSIX compliance)
- `WZVAULT_AGE_KEY` stripped from editor subprocess environment
- Export dotenv format now quotes values containing special characters (`$`, spaces, newlines)
- Export dotenv/shell formats stream output instead of accumulating all decrypted plaintext in memory

### Changed
- Database file permissions explicitly set to 0600 after creation
- Schema migration wrapped in transaction for crash safety
- `store.Exists` returns `(bool, error)` instead of silently swallowing query errors
- Removed redundant SQLite index on primary key column
- Added `gosec` linter to CI configuration
- Extracted shared `requireStore` helper to reduce code duplication across commands

## [0.1.0] - 2026-03-20

### Added
- Core commands: `init`, `set`, `get`, `list`, `delete`, `version`
- age X25519 encryption with scrypt-protected private keys
- SQLite storage with schema versioning
- Secrets read from stdin only — never from command-line arguments
- Interactive terminal prompts with echo disabled for secret entry
- Passphrase prompt on stderr for clean piping (`get | other-command`)
- `export` command with dotenv, JSON, and shell formats
- `import` command with dotenv and JSON parsing, auto-detection
- `edit` command with secure temp file handling and signal cleanup
- `--expires` flag with duration support (h/d/w/m/y) and absolute dates
- `--tag` and `--note` metadata flags on `set`
- `--json` output on `list` and `version`
- `--expired` and `--expiring` filters on `list`
- `WZVAULT_AGE_KEY` env var for CI/automation (bypasses passphrase)
- `WZVAULT_PASSPHRASE_FD` for session-style passphrase caching
- Shell completion for bash, zsh, fish, and powershell
- Path validation (lowercase, hierarchical, no traversal)
- Prefix-based listing and deletion
- CI with GitHub Actions (ubuntu + macos, Go 1.22 + 1.23)
- GoReleaser configuration for cross-platform releases

[Unreleased]: https://github.com/brndnsvr/wzrd-vault/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/brndnsvr/wzrd-vault/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/brndnsvr/wzrd-vault/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/brndnsvr/wzrd-vault/releases/tag/v0.1.0
