# wzrd-vault Security Audit Report

**Audit Date:** 2026-03-21
**Version Audited:** v0.2.0 (commit 66b4868)
**Scope:** Full source code review of all Go source, tests, CI/CD, and build configuration
**Auditor:** Post-release security audit following prior fix cycle

---

## Executive Summary

wzrd-vault is a well-architected local-first secrets manager that delivers on its
core security promise: secrets never appear in process arguments. The prior audit
cycle addressed critical issues (ExitError pattern, secureDelete, constant-time
comparison, signal handling, DB permissions, FD leak, export escaping), and all
those fixes are confirmed present and correctly implemented.

This follow-up audit identified **no critical or high-severity vulnerabilities**.
The remaining findings are medium, low, and informational items that represent
defense-in-depth improvements rather than exploitable weaknesses.

**Summary of Findings:**

| Severity | Count |
|----------|-------|
| CRITICAL | 0     |
| HIGH     | 0     |
| MEDIUM   | 3     |
| LOW      | 5     |
| INFO     | 8     |

---

## Prior Fix Verification

All fixes from the prior audit are confirmed present and correctly implemented:

| Fix | Status | Verification |
|-----|--------|-------------|
| ExitError pattern (no os.Exit in commands) | PASS | `main.go:20-26` handles ExitError; only `edit.go:91` calls os.Exit in signal handler (acceptable) |
| secureDelete in-place overwrite + fsync | PASS | `edit.go:182-203` overwrites with zeros, fsyncs, then removes |
| secureTmpDir macOS fallback | PASS | `edit.go:161-165` uses `~/Library/Caches/wzrd-vault` before os.TempDir() |
| Constant-time comparison | PASS | `cli.go:111` uses `subtle.ConstantTimeCompare` |
| Signal handler sync.Once + SIGHUP/SIGQUIT | PASS | `edit.go:79-93` uses sync.Once, handles SIGINT/SIGTERM/SIGHUP/SIGQUIT |
| DB permissions 0600 | PASS | `store.go:96` calls `os.Chmod(dbPath, 0o600)` after Open |
| FD leak fix (ReadPassphraseFromFD) | PASS | `cli.go:99` defers f.Close() |
| Export escaping (special chars) | PASS | `export.go:128-135` (dotenv), `export.go:103-112` (shell) handle quoting |
| WZVAULT_AGE_KEY stripped from editor | PASS | `edit.go:115` calls filterEnv |
| VISUAL before EDITOR | PASS | `edit.go:172-178` checks VISUAL first |
| Schema migration in transaction | PASS | `store.go:123-135` wraps in tx with rollback |
| store.Exists returns (bool, error) | PASS | `store.go:242-249` returns both values |
| gosec linter enabled | PASS | `.golangci.yml:6` includes gosec |
| Identity/pubkey permissions (0600/0644) | PASS | `init.go:67` (0600), `init.go:72` (0644) |
| Config dir permissions 0700 | PASS | `init.go:43` uses 0700 |

---

## Findings

### MEDIUM Findings

#### M-1: Dotenv export does not escape `$` in double-quoted values

**File:** `cmd/export.go:128-132`
**Severity:** MEDIUM

**Description:** When the dotenv format quotes a value with double quotes, it
escapes backslashes (`\`), double quotes (`"`), and newlines, but does not escape
dollar signs (`$`). Many dotenv parsers and shells will interpret `$VAR` or
`${VAR}` within double-quoted values as variable expansion, potentially causing
silent data corruption when the exported file is consumed.

**Impact:** A secret containing `$HOME` or `$PATH` would be silently expanded
when the dotenv file is sourced by a shell or parsed by a library that performs
variable interpolation in double-quoted values. This is a data integrity issue,
not a confidentiality issue.

**Code:**
```go
escaped := strings.ReplaceAll(value, `\`, `\\`)
escaped = strings.ReplaceAll(escaped, `"`, `\"`)
escaped = strings.ReplaceAll(escaped, "\n", `\n`)
fmt.Printf("%s=\"%s\"\n", envVar, escaped)
```

**Recommendation:** Add `$` escaping for the dotenv double-quoted path:
```go
escaped = strings.ReplaceAll(escaped, "$", `\$`)
```
Alternatively, consider using single quotes for dotenv values that contain `$`
but not newlines, since single quotes suppress all expansion.

---

#### M-2: WAL/SHM sidecar files may have looser permissions than the database

**File:** `internal/store/store.go:79,96`
**Severity:** MEDIUM

**Description:** The database file is explicitly `chmod 0600` after creation at
line 96. However, SQLite WAL mode creates two sidecar files (`stash.db-wal` and
`stash.db-shm`) that inherit the process umask rather than the database file's
permissions. On a system with a permissive umask (e.g., 0022), these files would
be world-readable and could contain recently-written ciphertext pages.

**Impact:** While the data in WAL/SHM files is ciphertext (not plaintext), an
attacker with read access to these files could extract encrypted secret blobs
without needing access to the main database file. This weakens the defense-in-
depth posture.

**Recommendation:** Either set the process umask before opening the database
(e.g., `syscall.Umask(0077)` early in the command run), or explicitly chmod the
WAL/SHM files after opening. Alternatively, document that the user's umask should
be restrictive. The simplest fix is a targeted umask set before `sql.Open`:
```go
oldMask := syscall.Umask(0077)
db, err := sql.Open("sqlite", dbPath)
syscall.Umask(oldMask)
```

---

#### M-3: Expired secrets are still decryptable

**File:** `cmd/get.go:44-71`, `internal/store/store.go:192-238`
**Severity:** MEDIUM

**Description:** The `expires_at` field is stored in the database and can be
filtered via `list --expired`, but the `get` command does not check whether a
secret has expired before decrypting and returning it. The `export` command also
does not skip expired secrets. Expiry is advisory only.

**Impact:** If a user sets an expiry intending the secret to become inaccessible
after that date, the expectation is not enforced. This is a design decision but
should be explicitly documented or enforced.

**Recommendation:** Either:
1. Add an expiry check in `Get()` or the `get` command handler that returns a
   clear error for expired secrets (with a `--allow-expired` override flag), or
2. Clearly document in the README and command help that `expires_at` is advisory
   metadata only and does not restrict access.

---

### LOW Findings

#### L-1: Plaintext secret remains in Go memory after use

**File:** `cmd/get.go:60-70`, `cmd/edit.go:58,100,130`, `cmd/export.go:83-101`
**Severity:** LOW

**Description:** Decrypted plaintext is held in Go byte slices and strings that
are not explicitly zeroed after use. Go's garbage collector does not guarantee
timely zeroing of freed memory, and strings are immutable (cannot be zeroed at
all). The plaintext may persist in process memory, swap, or core dumps.

**Impact:** An attacker with access to the process memory, swap partition, or
core dump files could potentially recover plaintext secrets. This is inherent to
Go's memory model and is a known limitation of virtually all Go-based secret
management tools.

**Recommendation:** This is a known limitation of Go's runtime. Mitigations:
- Document this limitation for security-conscious users
- Use `debug.SetGCPercent` or runtime.GC() after handling secrets to encourage
  earlier collection (not guaranteed)
- For the edit command, the byte slice `plaintext` could be zeroed with
  `clear(plaintext)` before the function returns (Go 1.21+)
- Consider `RLIMIT_CORE = 0` to prevent core dumps containing secrets

---

#### L-2: config.example.toml documents `db` path with tilde expansion

**File:** `config.example.toml:4`
**Severity:** LOW

**Description:** The example configuration contains `db = "~/.config/wzrd-vault/stash.db"`
using tilde notation. The application uses `os.Getenv("WZVAULT_DB")` for the DB
path (not a TOML config parser), so if a user set a TOML config file with tilde
paths, it would not be expanded. However, the config.toml file is currently
not parsed at all -- only env vars are used.

**Impact:** User confusion. The example implies TOML config parsing is supported,
but `config.Load()` only reads environment variables. No functional security
impact.

**Recommendation:** Either implement TOML config file parsing or clarify in the
example file and documentation that configuration is environment-variable-only
and the TOML file is a placeholder for future support.

---

#### L-3: No input size limit on stdin reads

**File:** `internal/cli/cli.go:25-26`, `cmd/import.go:57`
**Severity:** LOW

**Description:** `ReadSecretFromPipe` calls `io.ReadAll(r)` without any size
limit. The `import` command also uses `io.ReadAll(os.Stdin)`. A malicious or
accidental pipe of a very large file could cause excessive memory allocation.

**Impact:** Denial of service through memory exhaustion. Since this is a local
CLI tool, the attack surface is limited to the local user.

**Recommendation:** Add a size limit using `io.LimitReader`:
```go
const maxSecretSize = 1 << 20 // 1 MiB
data, err := io.ReadAll(io.LimitReader(r, maxSecretSize+1))
if len(data) > maxSecretSize {
    return "", fmt.Errorf("input exceeds maximum size of %d bytes", maxSecretSize)
}
```

---

#### L-4: Codecov action used without token or checksum verification

**File:** `.github/workflows/ci.yml:32-34`
**Severity:** LOW

**Description:** The `codecov/codecov-action@v4` is used without specifying a
Codecov token and without pinning to a specific commit SHA. The v4 action
typically requires a token for private repos but may work without one for public
repos. Using a version tag (`v4`) instead of a commit SHA means a compromised
action tag could inject code into CI.

**Impact:** Supply chain risk in CI. A compromised Codecov action could exfiltrate
the coverage report (which does not contain secrets) or the GITHUB_TOKEN
(read-only per the permissions block).

**Recommendation:**
1. Pin the action to a specific commit SHA:
   `uses: codecov/codecov-action@<full-sha>`
2. Add a `token: ${{ secrets.CODECOV_TOKEN }}` if available
3. Consider whether the coverage upload is necessary for a public repo

---

#### L-5: GitHub Actions not pinned to commit SHAs

**File:** `.github/workflows/ci.yml:19-26`, `.github/workflows/release.yml:13-20`
**Severity:** LOW

**Description:** All GitHub Actions (`actions/checkout@v4`, `actions/setup-go@v5`,
`golangci/golangci-lint-action@v6`, `goreleaser/goreleaser-action@v6`,
`codecov/codecov-action@v4`) are referenced by version tags rather than commit
SHAs. While major version tags are generally maintained by reputable publishers,
they can be force-pushed to point to different commits.

**Impact:** Supply chain risk. A compromised tag could inject arbitrary code into
CI/CD. The release workflow has `contents: write` permission, making it a higher
value target.

**Recommendation:** Pin all actions to full commit SHAs. The version tag can be
kept as a comment for readability:
```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4
```

---

### INFORMATIONAL Findings

#### I-1: Secret paths stored unencrypted (by design)

**File:** `internal/store/store.go:14-21`
**Severity:** INFO

**Description:** Secret paths, metadata (tags, notes), and timestamps are stored
as plaintext in the SQLite database. Only the secret values (ciphertext column)
are encrypted. This is a documented design decision that enables path listing
and prefix operations without requiring a passphrase.

**Impact:** An attacker who gains read access to the database file can see the
organizational structure and names of all stored secrets (e.g.,
`work/production/database/password`), which may itself be sensitive information.

**Recommendation:** This is clearly documented in the README. Consider mentioning
it prominently in the `init` command output or a first-use notice. No code
change needed.

---

#### I-2: WZVAULT_AGE_KEY visible in /proc/PID/environ

**File:** `internal/config/config.go:46`, `cmd/get.go:80-83`
**Severity:** INFO

**Description:** When using `WZVAULT_AGE_KEY` for CI/automation, the raw private
key is stored in an environment variable, which is readable via
`/proc/PID/environ` on Linux by the same user (and root). This is a known
tradeoff for CI/automation use cases.

**Impact:** Any process running as the same user can read the private key from
the environment. This is documented and is the standard tradeoff for
environment-based secret injection in CI.

**Recommendation:** Already documented. Consider adding a note in the README
recommending that CI environments use short-lived keys or `WZVAULT_PASSPHRASE_FD`
with process substitution for better isolation.

---

#### I-3: Shell format export uses $'...' ANSI-C quoting for multiline values

**File:** `cmd/export.go:103-108`
**Severity:** INFO

**Description:** The shell export format uses `$'...'` ANSI-C quoting for values
containing newlines or carriage returns. This syntax is supported by bash, zsh,
and ksh but is not POSIX sh compliant. Values without newlines use standard
single quotes with `'\''` escaping, which is safe.

**Impact:** The `$'...'` syntax will fail in strict POSIX sh environments (dash,
busybox ash). Single-line values work everywhere.

**Recommendation:** Document that the shell format requires bash/zsh for
multiline values, or offer a POSIX-compatible alternative (e.g., using printf).

---

#### I-4: Edit command temp file name contains predictable prefix

**File:** `cmd/edit.go:72`
**Severity:** INFO

**Description:** Temp files are created with the prefix `wzrd-vault-edit-*` via
`os.CreateTemp`. The `os.CreateTemp` function generates a random suffix, so the
filename itself is not predictable enough for symlink attacks. However, the
prefix does advertise that the file is a wzrd-vault secret.

**Impact:** No direct security impact. `os.CreateTemp` uses `O_CREATE|O_EXCL`
atomically, preventing symlink/TOCTOU attacks. The file is created with 0600
permissions and cleaned up with secureDelete.

**Recommendation:** No change needed. The implementation is correct.

---

#### I-5: Go module requires go 1.25.0

**File:** `go.mod:3`
**Severity:** INFO

**Description:** The `go.mod` file specifies `go 1.25.0`. The CI matrix tests
against Go 1.25 and 1.26. All direct dependencies (`filippo.io/age v1.3.1`,
`modernc.org/sqlite v1.47.0`, `golang.org/x/term v0.41.0`, `golang.org/x/crypto
v0.45.0`) are recent versions with no known published CVEs at the time of this
audit.

**Impact:** Dependencies are current. No known vulnerabilities found.

**Recommendation:** Continue running `govulncheck` periodically via CI or
Dependabot/Renovate for automated vulnerability monitoring.

---

#### I-6: Integration tests use WZVAULT_AGE_KEY with test keys only

**File:** `cmd/integration_test.go:73`
**Severity:** INFO

**Description:** Integration tests inject `WZVAULT_AGE_KEY` via the test
environment, which is appropriate. The keys are freshly generated per test and
never committed. The test structure properly isolates each test in its own
temp directory.

**Impact:** No security concern. Test isolation is well implemented.

**Recommendation:** No change needed.

---

#### I-7: Build strips debug info and symbols

**File:** `Makefile:4`, `.goreleaser.yml:20-21`
**Severity:** INFO

**Description:** Both the Makefile and GoReleaser configuration use `-s -w`
ldflags to strip debug information and symbol tables from release binaries.
This is good practice -- it reduces binary size and makes reverse engineering
marginally harder.

**Impact:** Positive security measure already in place.

**Recommendation:** No change needed.

---

#### I-8: CI permissions properly scoped

**File:** `.github/workflows/ci.yml:8-9`, `.github/workflows/release.yml:6-7`
**Severity:** INFO

**Description:** The CI workflow uses `contents: read` (minimum required). The
release workflow uses `contents: write` (required for creating GitHub releases).
Both follow the principle of least privilege for their respective purposes.

The release workflow also uses a separate `TAP_TOKEN` secret for the Homebrew
tap dispatch, which correctly avoids overloading the GITHUB_TOKEN's permissions.

**Impact:** CI/CD permissions are well-scoped.

**Recommendation:** No change needed.

---

## Architecture Security Assessment

### Core Promise: No Secrets in Process Arguments

**Verdict: FULLY ENFORCED**

The core security guarantee is implemented correctly through multiple layers:

1. **Set command** (`cmd/set.go:41-47`): `cobra.MinimumNArgs(1)` accepts the
   path argument, but if a user passes a second positional argument (likely the
   secret), it returns a clear error explaining why this is dangerous.

2. **All secret input** flows through `cli.ReadSecretFromPipe` (pipe) or
   `cli.ReadSecretInteractive` (tty with echo disabled). Neither mechanism
   exposes the secret value in process arguments or environment variables.

3. **Get command output** goes to stdout only. Prompts and errors go to stderr.
   This enables safe piping patterns like `$(wzrd-vault get path)`.

### Encryption Design

**Verdict: SOUND**

- **Algorithm:** age X25519 (Curve25519 + ChaCha20-Poly1305) -- modern, audited,
  no known weaknesses.
- **Key protection:** Private key encrypted with age scrypt recipient at work
  factor 18 (~262144 iterations). This is above the default work factor and
  provides strong brute-force resistance.
- **Per-secret encryption:** Each secret is independently encrypted with the
  X25519 public key, providing ciphertext independence (compromising one
  ciphertext reveals nothing about others).
- **No key reuse issues:** Each `age.Encrypt` call generates a fresh ephemeral
  key internally.

### SQL Injection Prevention

**Verdict: FULLY MITIGATED**

All SQL queries use parameterized statements (`?` placeholders). The `LIKE`
queries in `List` and `DeletePrefix` properly escape `%`, `_`, and `\` via the
`escapeLike` function with a declared `ESCAPE '\'` clause. No string
concatenation of user input into SQL.

### Path Traversal Prevention

**Verdict: FULLY MITIGATED**

`ValidatePath` in `internal/store/path.go` enforces:
- Lowercase alphanumeric, slashes, underscores, dots, hyphens only
- No `..` components
- No double slashes
- No leading/trailing slashes
- Each component must start with alphanumeric
- Minimum 2 characters

The regex `^[a-z0-9][a-z0-9/_.\-]*[a-z0-9]$` prevents any path traversal
character injection. Validation is called at the store layer (`Set`), ensuring
all code paths are covered.

### Error Message Safety

**Verdict: PASS**

Error messages reference paths, file locations, and error types but never include
secret values, passphrases, or private key material. The `%w` wrapping pattern
passes through library errors which may include age-level error descriptions
(e.g., "wrong passphrase") but not the passphrase itself.

---

## Public Repository Readiness

| Check | Status |
|-------|--------|
| No hardcoded secrets in source | PASS |
| No hardcoded file paths | PASS |
| No credentials in test files | PASS -- test keys are generated at runtime |
| .gitignore covers sensitive patterns | PASS -- `*.db`, `*.age`, `*.pub`, `.env` |
| No personal information in source | PASS |
| License file present | PASS (MIT) |
| CI secrets use GitHub Secrets | PASS (`GITHUB_TOKEN`, `TAP_TOKEN`) |

---

## Recommendations Summary

### Priority Actions (Medium)

1. **M-1:** Escape `$` in dotenv double-quoted export values to prevent variable
   expansion
2. **M-2:** Set restrictive umask before SQLite database open to protect WAL/SHM
   sidecar files
3. **M-3:** Either enforce or clearly document that secret expiry is advisory only

### Hardening Improvements (Low)

4. **L-1:** Zero plaintext byte slices after use where possible (Go limitation)
5. **L-2:** Clarify config file support status
6. **L-3:** Add size limits to stdin reads to prevent memory exhaustion
7. **L-4/L-5:** Pin GitHub Actions to commit SHAs for supply chain security

---

## Conclusion

wzrd-vault demonstrates strong security engineering for a local-first secrets
manager. The core design decisions -- stdin-only secret input, age X25519
encryption, scrypt key protection, parameterized SQL, strict path validation --
are all correctly implemented. The prior audit fixes are fully in place and
working as intended.

The remaining findings are defense-in-depth improvements that do not represent
exploitable vulnerabilities in the tool's threat model (local-first,
single-user). The most impactful improvement would be the dotenv `$` escaping
fix (M-1), as it could cause silent data corruption in a realistic usage
scenario.
