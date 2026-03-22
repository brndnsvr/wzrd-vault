# Code Review Report — wzrd-vault

**Date:** 2026-03-21
**Reviewer:** Senior Engineer (AI-assisted)
**Scope:** Full source review after prior hardening round
**Commit:** 66b4868 (v0.1.0)

---

## Summary

**Overall assessment: APPROVED WITH NOTES**

The codebase is in solid shape. The prior hardening round addressed the major structural concerns — secret argument leakage, process-argument security, deferred cleanup, exit-code discipline, and signal handling in `edit`. The architecture is clean, the package boundaries are appropriate, and the test suite provides good coverage of the core store and crypto layers.

Three findings warrant attention before the next release: a shell-injection risk in `dotenv` export when the output is `source`d, `WZVAULT_PASSPHRASE_FD` being inherited by the editor subprocess, and `ParseExpiry` being called inside a hot loop. Everything else is either a low-priority nit or a positive note.

---

## Findings

### High Severity (Should Fix Before Next Release)

**[H1] `cmd/export.go:128-132` — dotenv format does not escape `$` or backticks in double-quoted values**

When `needsQuoting` returns `true` for a value containing `$` or `` ` ``, the dotenv escaping path uses double quotes but only escapes `\`, `"`, and `\n`. Dollar signs and backticks are passed through unmodified, producing output like:

```
MY_VAR="$(id)"
```

If a user `source`s this output in bash (a very common dotenv workflow), the shell expands `$(...)` and executes the embedded command. This is a credential-controlled injection — an attacker who can write a secret value can achieve code execution when the vault owner sources the export.

The `shell` format correctly avoids this by using single-quote escaping (`'\''`) or `$'...'` syntax, both of which suppress dollar-sign and backtick expansion. The `dotenv` format should either:

- Use single-quote quoting (same as `shell` format, which would be fully equivalent for dotenv use), or
- Escape `$` as `\$` and backtick as `` \` `` in the double-quote path.

Additionally, `\r` is detected by `needsQuoting` but not escaped in the double-quote path (only `\n` is escaped), leaving a bare carriage return in the output that could corrupt the dotenv file on some parsers.

---

**[H2] `cmd/edit.go:115` — `WZVAULT_PASSPHRASE_FD` is not filtered from the editor subprocess environment**

```go
editorCmd.Env = filterEnv(os.Environ(), "WZVAULT_AGE_KEY")
```

`filterEnv` removes only `WZVAULT_AGE_KEY`. If `WZVAULT_PASSPHRASE_FD` is set, the editor process inherits the file-descriptor reference. At the time the editor launches the passphrase FD has already been consumed by `resolvePrivateKey` (line 54), so the editor cannot re-read it — but the FD number itself leaks into the child's environment, which is at minimum a confusion risk and could be exploited if the editor opens its own subprocesses that inherit the descriptor.

Fix: filter both variables:

```go
editorCmd.Env = filterEnv(filterEnv(os.Environ(), "WZVAULT_AGE_KEY"), "WZVAULT_PASSPHRASE_FD")
```

---

### Medium Severity (Should Fix)

**[M1] `cmd/list.go:66` — `ParseExpiry` called inside the filtering loop**

```go
for _, e := range entries {
    ...
    if listExpiring != "" {
        threshold, err := duration.ParseExpiry(listExpiring)  // called N times
```

`duration.ParseExpiry` re-parses the expiry string and calls `time.Now()` on every iteration. With a large vault this produces slightly different `threshold` values per entry (because `time.Now()` advances) and does unnecessary work. The threshold should be computed once before the loop. The `now` variable already exists in scope (line 55) but is not passed to `ParseExpiryAt`, so using it directly would also make the filtering deterministic across a single run:

```go
var threshold time.Time
if listExpiring != "" {
    threshold, err = duration.ParseExpiryAt(listExpiring, now)
    if err != nil {
        return err
    }
}
for _, e := range entries {
    ...
    if listExpiring != "" && e.ExpiresAt.After(now) && e.ExpiresAt.Before(threshold) {
```

---

**[M2] `cmd/export.go:149-152` — `--prefix-strip` without trailing slash produces invalid env var names**

`pathToEnvVar` calls `strings.TrimPrefix` verbatim. If the user passes `--prefix-strip work` (without the trailing slash) and the path is `work/key`, the result is `/key` which becomes `_KEY` after replacing `/` with `_` — an env var name starting with an underscore and missing the expected prefix separator.

The help text and examples correctly show `--prefix-strip work/` with the trailing slash, but there is no validation or normalization of the flag value. At minimum the documentation should be explicit about the requirement; ideally the code should warn or auto-normalize:

```go
if exportPrefixStrip != "" && !strings.HasSuffix(exportPrefixStrip, "/") {
    // warn or append "/"
}
```

---

**[M3] `internal/store/store.go:73,96` — TOCTOU window between database creation and `Chmod`**

`sql.Open` creates the SQLite file (with umask-derived permissions, typically 0644 on a 0022-umask system). `os.Chmod(dbPath, 0o600)` is called only after `migrate()` completes — leaving the database world-readable for the duration of schema creation. On a shared multi-user system, another process could observe the newly-created database file and read its contents during this window.

The cleanest fix is to pre-create the file with the desired permissions before `sql.Open`:

```go
f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0o600)
if err != nil {
    return nil, fmt.Errorf("creating database file %q: %w", dbPath, err)
}
_ = f.Close()
// Now sql.Open will open the already-existing file at 0600
```

---

**[M4] `internal/store/store.go:23-25` — `schema_version` table has no uniqueness constraint**

```sql
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
```

The table has no `PRIMARY KEY` or `UNIQUE` constraint. The migration inserts exactly one row and the code queries with `LIMIT 1`, so this cannot corrupt itself in normal operation. However, if a future migration path or external tool inserts a second row, `SchemaVersion()` would silently return whichever row the DB engine happens to return first. A simple fix is `PRIMARY KEY(version)` or replacing the table design with a single-row sentinel:

```sql
CREATE TABLE IF NOT EXISTS schema_version (
    id      INTEGER PRIMARY KEY CHECK(id = 1),
    version INTEGER NOT NULL
);
```

---

**[M5] `cmd/init.go:37-39` — `--force` silently swallows `os.Remove` errors**

```go
_ = os.Remove(cfg.DBPath)
_ = os.Remove(cfg.IdentityPath)
_ = os.Remove(cfg.PublicKeyPath)
```

If any of these fail (e.g., the database is locked by another process, or a permission issue), `init --force` continues silently. The user receives no indication that the old file is still present, and the subsequent `store.Open` may open the old database rather than creating a fresh one. The errors should at least be logged to stderr as warnings.

---

### Low Severity (Consider)

**[L1] `internal/store/path.go:12,16` — Path components may end with `.` or `-`**

`pathPattern` requires the overall path to start and end with `[a-z0-9]`, but `componentPattern` only checks that each slash-delimited component *starts* with `[a-z0-9]`. As a result, intermediate components like `ab.` or `a-` are accepted — for example, `ab./cd` passes `ValidatePath`. This is harmless (the path is stored correctly and validation prevents actual dangerous patterns), but it's cosmetically inconsistent with the documented constraint that components must "start and end with alphanumeric."

Fix: update `componentPattern` to anchor both start and end, or add a per-component end check.

**[L2] `cmd/delete.go:55,83` — confirmation prompt reads from `os.Stdin` rather than `/dev/tty`**

`set.go` correctly opens `/dev/tty` for its overwrite confirmation because stdin may be a pipe. `delete.go` reads from `os.Stdin` directly. In the `delete` use case stdin is rarely piped, but the inconsistency means that in a scripted context (`some-cmd | wzrd-vault delete path`) the prompt silently reads from the pipe and returns false, aborting without explanation. Using `/dev/tty` (with a fallback requiring `--force` if `/dev/tty` is unavailable) would be consistent with `set.go`'s approach.

**[L3] `cmd/import.go:179-199` — inline comments in dotenv values are not stripped**

`parseDotenv` ignores lines that *begin* with `#` but does not strip inline comments. A line like `KEY=value # production key` is stored as `value # production key`. Many dotenv parsers strip inline comments. The current behavior is consistent with the documented spec (`Lines starting with '#' are ignored`) and will not produce incorrect imports for standard dotenv files, but users who hand-edit dotenv files with inline comments will be surprised.

**[L4] `cmd/set.go:62-65` vs `cmd/import.go:128` vs `cmd/edit.go:68` — inconsistent public-key newline stripping**

`set.go` manually strips exactly one trailing `\n` via a length check. `import.go` and `edit.go` use `strings.TrimRight(..., "\n")` which strips all trailing newlines. In practice the public-key file always has exactly one trailing newline (written by `init`), so this makes no functional difference, but the inconsistency is a maintenance hazard. Standardize on `strings.TrimSpace` or `strings.TrimRight`.

**[L5] `Makefile` — no `integration` target**

CI runs integration tests with `-tags=integration` but the Makefile has no equivalent target. Developers must know to run `go test -tags=integration ./cmd/ -race -count=1 -timeout=120s` manually. Adding a `test-integration` phony target improves discoverability.

**[L6] `cmd/list.go:78-85` — empty-list on filtered result goes to stderr with no exit-code signal**

When `--expired` or `--expiring` is set and no entries match, the command exits 0 with a stderr message. Scripts checking `wzrd-vault list --expired` for automation (e.g., alerting on expired secrets) cannot distinguish "no expired secrets" from "vault is empty" without parsing stderr. Consider exit code 1 (or a dedicated code) when filters produce an empty result.

**[L7] `.github/workflows/ci.yml:16` — CI matrix includes Go 1.26 which has not yet been released**

The matrix tests against `['1.25', '1.26']`. Go 1.26 has not been released as of March 2026. The CI step will fail when `actions/setup-go` cannot find version 1.26 until it ships. Either remove 1.26 from the matrix now and add it when released, or use `allow-failure` for the 1.26 matrix leg.

---

### Nitpicks (Consider)

- **`internal/store/store.go:357` — `escapeLike` is 0% covered** because path validation prevents `%`, `_`, and `\` in paths, making the escape logic unreachable in practice. Either add a test with a directly-crafted prefix containing those characters, or add a comment noting the function is defensive dead-code.

- **`cmd/import.go:220-222` — `detectFormat` treats a JSON array (`[...]`) as JSON** but `parseJSON` unmarshal target is `map[string]string`, so an array input will fail with a confusing `json` decode error rather than a helpful message. The error propagation chain (`parsing JSON input: cannot unmarshal array...`) is readable but a pre-check for array input with a tailored message would be friendlier.

- **`cmd/export.go` — export in `shell` and `dotenv` formats does N individual `store.Get` calls** (one per entry, already loaded by `list`). This is intentional since `List` omits ciphertext to avoid bulk-loading encrypted blobs, but the design means a full export of 100 secrets makes 101 DB queries. A future `GetMany` or a batch-decrypt approach would scale better, though it's not a concern at current vault sizes.

- **`internal/store/store.go:73` — `sql.Open` driver string is `"sqlite"` (lowercase)** — this works fine with `modernc.org/sqlite` but differs from the `"sqlite3"` convention used with `mattn/go-sqlite3`. A comment noting the driver name matches the `modernc` registration would help future maintainers who might expect the standard name.

- **`cmd/errors.go` — `ExitError.Error()` returns `Message`, which may be empty** — when `Message` is `""` and the error bubbles up through cobra's error handling chain, `errors.As` correctly recovers the code, but calling `.Error()` on such an error returns an empty string. This is handled in `main.go` with the `if exitErr.Message != ""` guard, but it's worth a comment explaining the intentional empty-message case.

---

### Positive Notes

- **Secret never touches process arguments.** The design enforces stdin-only secret input throughout — `set`, `edit`, `import`, and `init` all use `ReadSecretInteractive` or pipe-reading, and the error message when extra args are passed is specifically educational about `/proc/PID/cmdline`.

- **The `edit` command's temp-file handling is well-executed.** `sync.Once` for cleanup, `secureDelete` with zero-overwrite and fsync, signal catching for SIGINT/SIGTERM/SIGHUP/SIGQUIT, filtering `WZVAULT_AGE_KEY` from the editor environment, and preference for `/dev/shm` and `XDG_RUNTIME_DIR` are all correct and thoughtfully layered.

- **ExitError and deferred cleanup are properly coordinated.** Commands return errors rather than calling `os.Exit` directly, ensuring `defer s.Close()` runs before the process exits. The `ExitError` pattern in `main.go` is clean and the distinction between exit codes 1, 2, and 3 is documented and tested.

- **The `store.Set` upsert correctly preserves `created_at`.** The `ON CONFLICT DO UPDATE SET` clause does not include `created_at`, so the original creation timestamp survives overwrites. The comment in the function correctly documents this invariant.

- **Path validation is layered and thorough.** The combination of `pathPattern` (overall shape), double-slash check, `..` component check, and `componentPattern` (per-segment start anchor) catches all practically dangerous inputs, and the test suite covers 15 invalid cases including Unicode, leading dash, and path traversal.

- **`requireStore` provides actionable errors.** Rather than a raw `os.Stat` error, the user gets `run "wzrd-vault init" to create it` — consistent across all commands that need the store.

- **`WZVAULT_AGE_KEY` / `WZVAULT_PASSPHRASE_FD` auth hierarchy is clear and tested.** The three-level fallback in `resolvePrivateKey` (raw key env → passphrase-fd → interactive prompt) is well-ordered and all three paths are exercised in integration tests.

- **WAL mode and foreign keys are enabled at open time.** `PRAGMA journal_mode=WAL` improves read concurrency; `PRAGMA foreign_keys=ON` is good hygiene even though the schema has no foreign keys today.

- **The `scrypt` work factor of 18** (2^18 = 262,144 iterations) for identity encryption is above the age default and provides meaningful resistance to offline passphrase cracking.

- **Integration tests build and exercise the real binary.** Testing via `exec.Command` against a compiled binary catches issues that unit tests with injected dependencies cannot — including actual argument parsing, exit codes, and env-var propagation.

- **Dependencies are minimal and well-chosen.** `filippo.io/age` for encryption, `modernc.org/sqlite` for a CGo-free SQLite, `spf13/cobra` for CLI, `golang.org/x/term` for terminal detection. No dependency does what another one already does.

---

## Security Review

| Area | Status | Notes |
|---|---|---|
| Secret argument leakage | PASS | Enforced at API level; set/edit/import all use stdin |
| Encryption at rest | PASS | age X25519 for values; age scrypt (WF=18) for identity |
| Temp file confidentiality | PASS | RAM-backed dir preferred; zero-overwrite on cleanup |
| Process env leakage | PARTIAL | WZVAULT_AGE_KEY filtered from editor; PASSPHRASE_FD not (H2) |
| Shell injection via export | FAIL | dotenv double-quote path does not escape $ or backtick (H1) |
| Path traversal | PASS | ValidatePath rejects `..`, leading slash, double slash |
| DB file permissions | PARTIAL | Chmod to 0600 applied but after a TOCTOU window (M3) |
| Public key exposure | PASS | Intentionally 0644; comment in init.go explains rationale |
| Passphrase echo prevention | PASS | term.ReadPassword used consistently |
| LIKE injection | PASS | escapeLike correctly handles %, _, \ in prefixes |

---

## Edge Cases

| Edge case | Handling |
|---|---|
| Empty passphrase at `init` | Rejected with error: `passphrase cannot be empty` |
| Empty secret value at `set` | Rejected: `secret value is empty` |
| `get` on expired secret | Returned without warning — no expiry enforcement on read |
| `export` with `--prefix-strip` missing trailing slash | Produces env var with leading `_` (M2) |
| `import` with JSON array input | Detected as JSON, fails with unmarshal error (nitpick) |
| `import --dry-run` with missing public key | Succeeds (dry-run exits before public key read) |
| `delete` with piped stdin | Prompt silently returns false, aborts safely (L2) |
| `list --expired --expiring 30d` together | Correct union semantics; expired items handled first via `continue` |
| `init --force` with locked DB | Remove silently fails, may leave old DB in place (M5) |
| `edit` interrupted by signal during zero-overwrite | Handled via sync.Once; signal goroutine calls cleanup before exit |
| Path component ending with `.` or `-` (e.g., `ab./cd`) | Accepted by ValidatePath — componentPattern only anchors start (L1) |

---

## Recommendation

Approve after addressing H1 (dotenv injection) and H2 (passphrase FD leakage to editor). H1 in particular could be reached in a realistic threat model where secrets are exported and sourced into shell scripts.

The medium findings (M1-M5) are clean-up work that should ship in the next patch. The low findings are improvements worth tracking but not blocking.

The foundation is solid: the crypto is correct, the architecture is clean, and the security-sensitive code paths (secret input, editor temp files, key resolution) are all handled with appropriate care.

