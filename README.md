# wzrd-vault

**Local-first secrets manager that never leaks secrets to process arguments.**

[![CI](https://github.com/brndnsvr/wzrd-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/brndnsvr/wzrd-vault/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/brndnsvr/wzrd-vault)](https://goreportcard.com/report/github.com/brndnsvr/wzrd-vault)
[![Latest Release](https://img.shields.io/github/v/release/brndnsvr/wzrd-vault)](https://github.com/brndnsvr/wzrd-vault/releases)
[![License](https://img.shields.io/github/license/brndnsvr/wzrd-vault)](LICENSE)

---

## The Problem

Most tools that accept secrets do so through command-line arguments: `mysql -pPassword`, `curl -u user:pass`, `docker run -e SECRET=value`. This is a serious security flaw. Every argument passed to a process is visible to every user on the same system — anyone running `ps aux` or reading `/proc/PID/cmdline` can see your credentials in plain text. This is not a hypothetical: automated credential harvesters running as background jobs on shared systems continuously loop over the process table, capturing anything that looks like a password or API key.

The `/proc/PID/cmdline` interface on Linux is world-readable by default. Even on macOS, process argument lists are accessible to unprivileged users through `ps`. A secret passed as an argument exists in plaintext in kernel memory for the entire duration of the process, and may be captured by any monitoring agent, log aggregator, or curious coworker with shell access.

The harvester pattern is simple and widely deployed: a loop reads every process's argument list, applies patterns to identify credential-shaped strings, and ships them off. The window of exposure is small — the fraction of a second a command runs — but harvesters run continuously and collect thousands of candidates per hour on busy systems. Passwords, tokens, API keys, and connection strings passed as arguments are routinely harvested this way.

## The Fix

wzrd-vault eliminates argument-based exposure by design. Secrets are **written via stdin** (pipe or interactive prompt with echo disabled) and **retrieved via stdout** (suitable for `$()` substitution or pipe). No secret ever appears in a process argument list.

At rest, secrets are encrypted individually using [age](https://age-encryption.org) X25519 asymmetric encryption and stored in a local SQLite database. The age private key is itself encrypted with your passphrase using age's scrypt-based recipient, so compromising the database file without the passphrase yields only ciphertext. Secret paths and metadata (tags, notes, expiry) are stored unencrypted for fast listing without requiring a passphrase.

## Installation

### Homebrew (once tap is available)

```sh
brew install brndnsvr/tap/wzrd-vault
```

### Go install

```sh
go install github.com/brndnsvr/wzrd-vault@latest
```

### Binary download

Pre-built binaries for Linux (amd64, arm64) and macOS (amd64, arm64) are available on the [Releases page](https://github.com/brndnsvr/wzrd-vault/releases).

### Build from source

```sh
git clone https://github.com/brndnsvr/wzrd-vault.git
cd wzrd-vault
make build
```

The binary is written to `bin/wzrd-vault`. Copy it anywhere on your `$PATH`.

---

## Quick Start

```sh
# Initialize a new vault (generates age keypair, creates SQLite database)
wzrd-vault init

# Store a secret via pipe
echo "ghp_myPersonalAccessToken" | wzrd-vault set dev/github/pat

# Store a secret interactively (echo disabled, confirmation prompt)
wzrd-vault set personal/wifi/password

# Retrieve a secret
wzrd-vault get dev/github/pat

# List all stored paths (no passphrase required)
wzrd-vault list
```

---

## Usage

### Initialize the vault

```sh
wzrd-vault init
```

Creates `~/.config/wzrd-vault/` containing:
- `identity.age` — passphrase-encrypted age private key
- `identity.pub` — age public key (printed to stdout on init)
- `stash.db` — SQLite database
- `config.toml` — default configuration stub

The passphrase is collected interactively with echo disabled. It is never accepted as a command-line argument.

Use `--force` to reinitialize an existing vault (destroys all stored secrets).

---

### Store a secret

**Pipe from another command:**

```sh
echo "my-api-key" | wzrd-vault set dev/github/pat
cat ~/.ssh/id_ed25519 | wzrd-vault set work/ssh/private_key
op read "op://vault/item/field" | wzrd-vault set work/item/field
```

**Interactive prompt (echo disabled, value confirmed):**

```sh
wzrd-vault set personal/wifi/password
```

**With metadata:**

```sh
# Add tags (key=value pairs)
echo "s3cr3t" | wzrd-vault set dev/db/password \
  --tag env=production \
  --tag service=postgres \
  --note "Rotated after 2025 audit"

# Set an expiry
echo "token123" | wzrd-vault set ci/deploy/token --expires 90d
```

Supported expiry formats: `90d`, `24h`, `12w`, `6m`, `1y`, or a date like `2026-12-31`.

**Overwrite an existing secret:**

```sh
echo "new-value" | wzrd-vault set dev/github/pat --force
```

Without `--force`, wzrd-vault prompts for confirmation before overwriting.

---

### Retrieve a secret

**Pipe into a command (no trailing newline by default):**

```sh
curl -H "Authorization: Bearer $(wzrd-vault get dev/github/pat)" \
  https://api.github.com/user
```

**With trailing newline for terminal readability:**

```sh
wzrd-vault get dev/github/pat --newline
# or
wzrd-vault get dev/github/pat -n
```

**Assign to a variable:**

```sh
DB_PASS=$(wzrd-vault get prod/db/password)
```

The passphrase prompt goes to stderr, so stdout remains clean for piping.

---

### Manage secrets

**List all paths (no passphrase required):**

```sh
wzrd-vault list
```

**Filter by prefix:**

```sh
wzrd-vault list work/
wzrd-vault list dev/github/
```

**JSON output (includes metadata, timestamps, expiry):**

```sh
wzrd-vault list --json
wzrd-vault list work/ --json
```

**Show expired secrets:**

```sh
wzrd-vault list --expired
```

**Show secrets expiring within a window:**

```sh
wzrd-vault list --expiring 30d
wzrd-vault list --expiring 7d
```

**Delete a single secret (prompts for confirmation):**

```sh
wzrd-vault delete dev/github/pat
```

**Delete without confirmation:**

```sh
wzrd-vault delete dev/github/pat --force
```

**Delete all secrets under a prefix:**

```sh
wzrd-vault delete work/legacy/ --prefix
wzrd-vault delete work/legacy/ --prefix --force
```

---

### Import secrets

Import secrets from a `.env` file or JSON object piped to stdin. No passphrase is needed — import only encrypts.

**From a dotenv file:**

```sh
cat .env | wzrd-vault import
cat .env | wzrd-vault import --prefix dev/myapp
```

Dotenv rules: `KEY=VALUE` lines are imported. Lines starting with `#` and blank lines are ignored. Keys are lowercased with underscores converted to slashes for path construction. Surrounding double or single quotes are stripped from values.

**From a JSON file:**

```sh
cat secrets.json | wzrd-vault import --format json
```

JSON format: a flat object mapping path strings to string values.

```json
{
  "dev/github/pat": "ghp_token",
  "dev/db/password": "s3cret"
}
```

**Format auto-detection:** if the first non-whitespace character is `{` or `[`, the input is treated as JSON. Otherwise, it is parsed as dotenv.

**Dry run (preview without storing):**

```sh
cat .env | wzrd-vault import --dry-run
```

**Overwrite existing secrets:**

```sh
cat .env | wzrd-vault import --force
```

Without `--force`, existing secrets are skipped and reported.

---

### Export secrets

Decrypt and export secrets for use in scripts or environment files.

**Default dotenv format:**

```sh
wzrd-vault export
wzrd-vault export work/
```

Output: `WORK_TACACS_KEY=value`

**Shell export format (safe quoting, suitable for eval):**

```sh
wzrd-vault export work/ --format shell
eval "$(wzrd-vault export work/ --prefix-strip work/ --format shell)"
```

Output: `export TACACS_KEY='value'`

**JSON format:**

```sh
wzrd-vault export --format json
wzrd-vault export dev/ --format json > dev-secrets.json
```

Output: `{"dev/github/pat": "value", ...}`

**Strip a path prefix when converting to env var names:**

```sh
# Secrets at work/tacacs/key → TACACS_KEY (not WORK_TACACS_KEY)
wzrd-vault export work/ --prefix-strip work/ --format dotenv
```

---

### Edit a secret in your editor

```sh
wzrd-vault edit dev/github/pat
```

wzrd-vault decrypts the secret, opens it in your editor (`$EDITOR`, `$VISUAL`, or `vi`), then re-encrypts and stores the updated value. If the content is unchanged, no write occurs.

The plaintext is written to a temporary file in a RAM-backed directory when available (`$XDG_RUNTIME_DIR`, `/dev/shm`). The file is securely wiped (overwritten with zeros and unlinked) on exit, even if interrupted by `SIGINT` or `SIGTERM`.

---

## Passphrase Caching

wzrd-vault resolves the private key using the first method that succeeds:

### 1. `WZVAULT_AGE_KEY` — raw private key from environment

```sh
export WZVAULT_AGE_KEY="AGE-SECRET-KEY-1..."
wzrd-vault get dev/github/pat   # no prompt
```

This is suitable for CI/CD environments where the key is injected as a secret. The key is read from the environment, not from a command-line argument.

### 2. `WZVAULT_PASSPHRASE_FD` — passphrase from a file descriptor

```sh
# Read passphrase from fd 3 (opened from a secret file or pipe)
WZVAULT_PASSPHRASE_FD=3 wzrd-vault get dev/github/pat 3< <(echo "my-passphrase")
```

wzrd-vault reads the passphrase from the given file descriptor, decrypts `identity.age`, and proceeds. This allows passphrase injection without environment variable exposure.

### 3. Interactive prompt

If neither environment variable is set, wzrd-vault prompts for your passphrase via the terminal (`/dev/tty`). The prompt goes to stderr so stdout remains usable for piping.

```sh
wzrd-vault get dev/github/pat
# Passphrase: (typed, not echoed)
```

---

## Shell Completion

Generate and install completion scripts for your shell:

**Bash:**

```sh
wzrd-vault completion bash > /etc/bash_completion.d/wzrd-vault
```

Or for a user-level install:

```sh
wzrd-vault completion bash > ~/.local/share/bash-completion/completions/wzrd-vault
```

**Zsh:**

```sh
wzrd-vault completion zsh > "${fpath[1]}/_wzrd-vault"
```

**Fish:**

```sh
wzrd-vault completion fish > ~/.config/fish/completions/wzrd-vault.fish
```

**PowerShell:**

```sh
wzrd-vault completion powershell > wzrd-vault.ps1
```

---

## Security Model

### How encryption works

Each secret value is encrypted individually using [age](https://age-encryption.org) X25519 asymmetric encryption. The public key (`identity.pub`) is used for encryption; no passphrase is required to store a secret. The private key (`identity.age`) is encrypted at rest using age's scrypt-based passphrase recipient with a work factor of 18 (high cost). Decryption requires both the encrypted private key file and your passphrase.

### What is encrypted vs. not

| Data | Encrypted |
|------|-----------|
| Secret values (ciphertext) | Yes — age X25519 |
| Private key (`identity.age`) | Yes — age scrypt passphrase |
| Secret paths | No |
| Metadata (tags, notes, expiry) | No |
| Timestamps | No |

Secret paths, metadata, and timestamps are stored in plaintext in the SQLite database. This enables fast listing and filtering without requiring the passphrase. If the paths themselves are sensitive, be aware they are visible to anyone with read access to `stash.db`.

### Threat model

wzrd-vault protects your secrets against:

- **Other users on the same system** — arguments never appear in `/proc/PID/cmdline` or `ps` output
- **Process-argument harvesters** — secrets are never in argument lists
- **Casual database exposure** — reading `stash.db` without the passphrase yields only ciphertext
- **Backup exposure** — the database can be safely backed up; values are encrypted at rest

wzrd-vault does **not** protect against:

- **Root or sudo access** — a privileged process can read memory, key files, and `/dev/tty`
- **A compromised user account** — if your shell session is compromised, so is your vault
- **Malware with user-level access** — keyloggers can capture your passphrase at the prompt
- **Physical access to an unlocked session**

wzrd-vault is designed for single-user local use on a machine you control. It is not a multi-user secrets manager or a substitute for a hardware security module.

### Expiry behavior

Secret expiry (`--expires` on `set`) is **advisory only**. Expired secrets remain accessible via `get` and `export`. Use `wzrd-vault list --expired` to find secrets past their expiry date for manual rotation. Enforcement on read is not currently implemented.

---

## Configuration

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WZVAULT_DB` | Path to the SQLite database file | `~/.config/wzrd-vault/stash.db` |
| `WZVAULT_AGE_KEY` | Raw age private key (`AGE-SECRET-KEY-1...`) — bypasses passphrase prompt | (not set) |
| `WZVAULT_PASSPHRASE_FD` | File descriptor number to read the passphrase from | (not set) |

`XDG_CONFIG_HOME` is respected: if set, the configuration directory is `$XDG_CONFIG_HOME/wzrd-vault` instead of `~/.config/wzrd-vault`.

### Config file

`~/.config/wzrd-vault/config.toml` is created on `wzrd-vault init` with a commented-out stub. See `config.example.toml` for all options:

```toml
# Database location (default: ~/.config/wzrd-vault/stash.db)
# db = "~/.config/wzrd-vault/stash.db"

# Preferred editor for `wzrd-vault edit` (overrides $EDITOR/$VISUAL)
# editor = "vi"

# Default expiration for new secrets (optional)
# Accepts durations (90d, 24h, 12w, 6m, 1y) or dates (2026-12-31)
# default_expires = "365d"
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (I/O failure, wrong passphrase, invalid arguments, etc.) |
| `2` | Conflict (user aborted an overwrite prompt) |
| `3` | Not found (secret path does not exist) |

---

## Roadmap

- Agent daemon for passphrase caching with a configurable TTL (no repeated prompts)
- Multi-recipient support (shared vault readable by multiple age identities)
- Sync backends (S3, git, rsync) for cross-machine vault replication
- MCP server for IDE and AI agent integration
- Audit log (append-only record of all read and write operations)
- Key rotation (re-encrypt all secrets under a new keypair)

---

## Contributing

Contributions, bug reports, and feature requests are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT — see [LICENSE](LICENSE).
