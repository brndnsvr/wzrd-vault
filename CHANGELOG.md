# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/brndnsvr/wzrd-vault/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/brndnsvr/wzrd-vault/releases/tag/v0.1.0
