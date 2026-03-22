# Database Review — wzrd-vault

**Date:** 2026-03-21
**Reviewer:** Database Review Agent
**Scope:** `internal/store/store.go`, `cmd/{set,get,list,delete,export,import,edit}.go`

---

## Summary

The database layer is well-structured for a single-user CLI secrets manager. Schema design is clean, queries are fully parameterized, and the connection lifecycle is handled correctly in every command. The issues found are low-to-medium severity: a few missing indexes, two N+1 query patterns in `export`, a TOCTOU race in `delete` and `set`, an unbounded `schema_version` table, a missing `busy_timeout` pragma, and several minor robustness gaps. Nothing rises to the level of data loss or SQL injection risk.

---

## 1. Schema Design

**File:** `internal/store/store.go`, constant `schemaSQL`

### What is good

- `path TEXT PRIMARY KEY` is correct. SQLite creates a B-tree index on the primary key automatically; point lookups in `Get`, `Exists`, and `Delete` all use it efficiently.
- `ciphertext BLOB NOT NULL` — correct type; enforces that an empty ciphertext can never be stored.
- `created_at` and `updated_at` both have `NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))`. The defaults use UTC explicitly, which prevents local-timezone drift.
- `expires_at TEXT` is nullable, which is the right choice when most secrets have no expiry.
- The partial index `idx_secrets_expires ON secrets(expires_at) WHERE expires_at IS NOT NULL` is exactly right for expiry scans — it stays small even when most rows have `NULL`.

### Issues

**S1 — Missing index on `(updated_at)` and `(created_at)` for future audit queries (low priority now, worth noting)**

Currently there are no ordering indexes beyond `path`. Because `ORDER BY path ASC` is already served by the primary key, this is not a current problem. However, if time-based filtering is ever added to `list`, a full table scan will result. Acceptable for the current feature set; flag for later.

**S2 — `schema_version` has no primary key and no UNIQUE constraint**

```sql
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
```

Nothing prevents the table from accumulating multiple rows. `SchemaVersion()` uses `LIMIT 1`, which masks the problem but relies on insertion order rather than a constraint. A duplicate row can appear if `migrate()` is called twice against the same database (unlikely in practice but theoretically possible in tests).

Recommended fix:

```sql
CREATE TABLE IF NOT EXISTS schema_version (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);
```

The `CHECK (id = 1)` singleton pattern ensures exactly one row can ever exist.

**S3 — `metadata` column has no length or format constraint**

`metadata TEXT` accepts arbitrary text. The application always writes valid JSON, but the database itself does not enforce this. If a bug or external tool writes a malformed JSON string, the `json.Unmarshal` call in `list.go` silently discards the error (`_ = json.Unmarshal(...)`), resulting in `null` metadata in JSON output with no diagnostic. This is acceptable for a single-user tool but worth documenting.

**S4 — Timestamps stored as TEXT, not INTEGER**

SQLite's recommended approach for timestamps is either Unix epoch integers or ISO-8601 text. The current ISO-8601 format (`strftime('%Y-%m-%dT%H:%M:%SZ', 'now')`) is correct and sorts lexicographically, so `ORDER BY created_at` would work. The Go side uses `time.RFC3339` for formatting and parsing, which is compatible. This is fine as-is.

---

## 2. Query Safety

All queries use `?` placeholders — there is no string interpolation of user data into SQL anywhere. SQL injection is not possible.

### `Set` — UPSERT

The `INSERT ... ON CONFLICT(path) DO UPDATE` pattern is correct and atomic. The deliberate exclusion of `created_at` from the `DO UPDATE` clause correctly preserves the original creation time on overwrite.

### `Get`

Selects all columns explicitly (no `SELECT *`). Returns `NotFoundError` on `sql.ErrNoRows`. Time parsing errors are propagated clearly. No issues.

### `List`

**Q1 — LIKE prefix scan has no index support**

```sql
WHERE path LIKE ? ESCAPE '\'
```

SQLite can use the primary key B-tree for `LIKE prefix%` patterns only when the column is `TEXT` with the default `BINARY` affinity and the pattern does not start with a wildcard. `path TEXT PRIMARY KEY` meets these conditions, so SQLite will use a range scan on the primary key index (`path >= prefix AND path < prefix_successor`) internally — this is a SQLite optimizer behavior that does apply here. The `escapeLike` function correctly handles `%`, `_`, and `\` in the prefix, preventing accidental wildcard expansion. No issues.

**Q2 — Expiry filtering is done in Go, not SQL**

In `list.go`, `--expired` and `--expiring` filtering is applied after fetching all entries from the database. For a small personal vault this is fine. At scale, a `WHERE expires_at < ?` clause would be more efficient, but this is not a problem in practice.

### `Delete` and `DeletePrefix`

Both use parameterized queries and check `RowsAffected()` correctly. `DeletePrefix` uses the same `escapeLike` guard as `List`. No issues with the queries themselves.

### `Exists`

Uses `COUNT(*)` against the primary key. Functionally correct. A marginally more efficient alternative is `SELECT 1 FROM secrets WHERE path = ? LIMIT 1`, which stops scanning after the first match, but with a primary key lookup there is only ever one row examined — the difference is immaterial.

### `SchemaVersion`

```sql
SELECT version FROM schema_version LIMIT 1
```

Relies on `LIMIT 1` to tolerate multiple rows (see S2 above). Correct but fragile.

---

## 3. Index Strategy

| Index | Type | Used by | Assessment |
|---|---|---|---|
| `secrets(path)` — implicit PK | B-tree | `Get`, `Exists`, `Delete`, `Set` | Correct |
| `idx_secrets_expires` — partial | B-tree, filtered | Expiry scans | Well-designed |

No over-indexing is present. The schema is appropriately lean for a single-writer SQLite database.

**I1 — No index on `path` prefix scans beyond the PK**

As noted, the SQLite optimizer uses the PK B-tree for `LIKE prefix%` — this is adequate. No additional index is needed.

---

## 4. Migration Approach

### What is good

- First-run detection queries `sqlite_master` before attempting DDL — correct approach.
- The initial schema application and version insert happen inside a single transaction, so a crash mid-migration leaves the database in a clean state.
- The version check is strict: any version other than 1 returns an actionable error.

### Issues

**M1 — Migration does not acquire an exclusive lock before checking `sqlite_master`**

The check-then-create sequence is:

```
SELECT COUNT(*) FROM sqlite_master ...   -- step 1
BEGIN; CREATE TABLE ...; INSERT ...      -- step 2
```

Between step 1 and step 2 another process (or test goroutine) could create the schema, causing `CREATE TABLE IF NOT EXISTS` to silently succeed while the subsequent `INSERT INTO schema_version` creates a duplicate row. For a single-user CLI this is extremely unlikely, but wrapping the entire migration in `BEGIN EXCLUSIVE` would eliminate the race:

```go
tx, err := s.db.Begin()  // upgrade: use BeginTx with sql.LevelSerializable
```

SQLite only supports one writer at a time, so `BEGIN IMMEDIATE` or `BEGIN EXCLUSIVE` is the correct primitive here.

**M2 — No upgrade path beyond version 1**

The current code does not provide a mechanism to apply incremental migrations when `version > 1`. The error message tells the user to upgrade, but there is no migration runner for future schema changes. This is acceptable for v0.1 but should be addressed before a breaking schema change is shipped.

---

## 5. Connection Handling

### What is good

- Every command opens with `store.Open(...)` and closes with `defer func() { _ = s.Close() }()`. The close error is intentionally discarded (acceptable for a deferred close in a short-lived CLI process).
- WAL mode is enabled immediately after `Open`, before any schema work.
- `foreign_keys=ON` is set — correct.
- File permissions are set to `0600` after `Open`, enforcing that only the owning user can read the database.

### Issues

**C1 — No `busy_timeout` pragma set**

If two processes open the vault concurrently (e.g., a script running `wzrd-vault get` in parallel with another `wzrd-vault set`), the second writer will receive `SQLITE_BUSY` immediately and fail. SQLite's `busy_timeout` causes it to retry for a specified period before returning the error.

Add after the WAL pragma:

```go
if _, err := db.Exec("PRAGMA busy_timeout=5000;"); err != nil {
    _ = db.Close()
    return nil, fmt.Errorf("set busy timeout: %w", err)
}
```

5000 ms is a reasonable default for a CLI tool.

**C2 — Connection pool size not limited**

`database/sql` maintains a connection pool. For a pure-Go SQLite driver (`modernc.org/sqlite`), multiple connections to the same file from the same process are legal but unnecessary and can cause locking surprises. Setting `db.SetMaxOpenConns(1)` makes the behavior explicit and avoids any pool-related SQLITE_BUSY within a single process:

```go
db.SetMaxOpenConns(1)
```

**C3 — `os.Chmod` after `Open` leaves a window**

The database file is created by `sql.Open` with default umask permissions (typically `0644`), and `0600` is applied only after the schema migration completes. On a shared system, another process on the same user account could read the file during that window. The practical risk on macOS (single-user machines) is low, but the fix is to create the file with `O_CREATE|O_RDWR` at `0600` before calling `sql.Open`. Alternatively, set the umask before opening and restore it after.

---

## 6. Data Integrity

### What is good

- `ciphertext BLOB NOT NULL` prevents empty records.
- `created_at` and `updated_at` have server-side defaults.
- `ValidatePath` is called in `Set` before any DB write, preventing malformed paths from being stored.
- The UPSERT in `Set` preserves `created_at` correctly.

### Issues

**D1 — No CHECK constraint on `path` format in the database**

Path validation lives entirely in Go (`ValidatePath`). The database does not enforce the format. A path written directly to the SQLite file with an external tool would bypass validation. This is acceptable for a personal tool but worth noting.

**D2 — `updated_at` relies on application-provided `time.Now()`, not a database trigger**

If the system clock changes or a bug provides a wrong time, `updated_at` can be inaccurate. A `AFTER UPDATE` trigger would enforce consistency, but triggers in SQLite are heavier than they seem and this is a minor concern for a CLI tool.

**D3 — `metadata` column is not validated as JSON at the store layer**

The store accepts any string for metadata. Validation happens only in the command layer. A future store method that bypasses the command layer could store invalid JSON.

---

## 7. Performance

For a personal secrets vault with tens to low hundreds of secrets, there are no meaningful performance concerns. The following observations apply at larger scale.

**P1 — N+1 query pattern in `export` (dotenv and shell formats)**

```go
entries, err := s.List(prefix)           // 1 query
for _, entry := range entries {
    secret, err := s.Get(entry.Path)     // 1 query per entry
    ...
}
```

`List` intentionally excludes `ciphertext` to avoid loading bulk data. The `export` command then fetches each secret individually, producing N+1 queries. For a vault with 100 secrets this is 101 queries. The fix for export specifically is to add a `GetAll(prefix string) ([]Secret, error)` method that includes `ciphertext` in the `List` SELECT, or to accept that N+1 is fine for a CLI tool where the bottleneck is decryption, not database I/O.

The JSON export path accumulates all results before writing, so it already pays the full N+1 cost up front — consistent but not ideal.

**P2 — `import` performs `Exists` + `Set` per secret (N*2 queries)**

```go
for _, path := range paths {
    if exists, err := s.Exists(path); ...  // 1 query
    ...
    if err := s.Set(path, ...); ...        // 1 query (upsert)
}
```

The `Exists` check is there to implement skip-without-force behavior. Since `Set` uses `INSERT ... ON CONFLICT DO UPDATE`, the `Exists` check could be eliminated when `--force` is set, saving N queries in that case. When `--force` is not set, the pattern is unavoidable with the current API surface. Acceptable for a CLI import tool.

**P3 — Import is not wrapped in a transaction**

If import fails partway through (e.g., encryption error on entry 50 of 100), the first 49 secrets have already been committed. The caller has no atomic import guarantee. For a CLI import tool this is typically acceptable, but a wrapping transaction would make partial-failure behavior cleaner.

---

## 8. SQLite-Specific Concerns

**W1 — WAL mode persistence**

WAL mode is sticky in SQLite — once set, it persists in the database file across connections. Setting it on every `Open` is harmless (it is a no-op if already enabled) and is the correct defensive practice. No issue.

**W2 — WAL checkpoint not managed**

With WAL mode, write-ahead log frames accumulate until a checkpoint occurs. SQLite performs automatic checkpoints when the WAL reaches 1000 pages by default. For a low-write secrets vault this is not a concern, but it is worth knowing that long-running processes holding read transactions can delay checkpointing. Since every command opens and closes its own connection, this is not a problem here.

**W3 — `modernc.org/sqlite` and `database/sql` pool interactions**

The pure-Go driver serializes writes internally. With `MaxOpenConns(1)` (recommended in C2 above), the pool and the driver's internal serialization align. Without it, `database/sql` may attempt concurrent connections that the driver serializes anyway, which wastes goroutines.

---

## 9. Error Handling

### What is good

- All errors are wrapped with `fmt.Errorf("... %q: %w", path, err)`, giving callers and users precise context.
- `NotFoundError` is a typed error with `errors.As` support, allowing commands to distinguish "not found" from other errors and set appropriate exit codes.
- `rows.Err()` is checked after the scan loop in `List` — this is the correct pattern and often missed.
- `rows.Close()` is deferred correctly in `List`.

### Issues

**E1 — `migrate()` returns raw `tx.Commit()` error without wrapping**

```go
return tx.Commit()
```

If the commit fails, the error has no context. Prefer:

```go
if err := tx.Commit(); err != nil {
    return fmt.Errorf("committing migration transaction: %w", err)
}
return nil
```

**E2 — `db.Close()` error silently discarded in all commands**

```go
defer func() { _ = s.Close() }()
```

This is standard practice for deferred close in Go CLI tools — the process is exiting and there is nothing useful to do with the error. This is acceptable as-is but noted for completeness.

---

## 10. Transaction Boundaries in Commands

**T1 — `delete --prefix` has a TOCTOU window**

```go
entries, err := s.List(prefix)      // snapshot of what exists
// user confirms...
count, err := s.DeletePrefix(prefix) // actual delete
```

Between the `List` (used to show the confirmation prompt) and the `DeletePrefix`, new secrets could be added under the prefix by another process. The user confirms deletion of N secrets but N+M are deleted. For a single-user CLI this is extremely unlikely but the gap exists.

**T2 — `set` has a TOCTOU race on existence check**

```go
if exists, err := s.Exists(path); ...  // check
// user confirms overwrite...
if err := s.Set(path, ...); ...         // write
```

A concurrent process could delete the secret between the `Exists` check and the `Set`, or create it after the check. Since the UPSERT in `Set` is atomic regardless of what was there before, the practical impact is zero — the write always succeeds. The `Exists` check is only for the UX prompt. No fix required.

**T3 — `import` is not transactional (see P3 above)**

---

## 11. Command Layer Observations

### `cmd/delete.go` — `deleteSingle` calls `Exists` then `Delete`

The double-trip (Exists + Delete) exists to provide a better error message at the confirmation prompt step. Since `Delete` already returns `NotFoundError`, the `Exists` check could be removed if the confirmation prompt were moved to after the delete attempt. This is a minor style point.

### `cmd/export.go` — `s` variable shadowing

In the JSON export loop, `s` is reused as a variable name for both the `*store.Store` (outer scope) and `decryptedSecret` values:

```go
for _, s := range secrets {   // line 162 in export.go
    m[s.path] = s.value
```

Wait — looking more carefully, the outer `s` is `*store.Store` (named in the RunE closure), and the inner loop uses `s` for `decryptedSecret`. This is a shadowing bug: the inner `s` in `exportJSON` is a function parameter so it does not shadow the outer store, but within the export `RunE` itself the loop variable `entry` is used, not `s`, so there is no actual shadowing. No issue.

### `cmd/list.go` — `json.Unmarshal` error silently discarded

```go
_ = json.Unmarshal([]byte(*e.Metadata), &meta)
```

If `metadata` contains invalid JSON, `meta` remains `nil` and the JSON output contains `"metadata": null` with no warning. Since the store layer accepts any string for metadata (see D3), a corrupted metadata value would be silently swallowed. Consider logging a warning to stderr.

---

## Findings Summary

| ID | Severity | Category | Description |
|---|---|---|---|
| S2 | Medium | Schema | `schema_version` has no uniqueness constraint; `LIMIT 1` masks potential duplicates |
| C1 | Medium | Connection | No `busy_timeout` pragma; concurrent CLI invocations fail immediately with SQLITE_BUSY |
| C2 | Low | Connection | Connection pool not capped at 1; relies on driver-internal serialization |
| C3 | Low | Connection | `0644` permission window between `sql.Open` and `os.Chmod` |
| P1 | Low | Performance | N+1 queries in `export` (list + get per secret) |
| P3 | Low | Integrity | `import` is not wrapped in a transaction; partial import possible on error |
| M1 | Low | Migration | No exclusive lock during migrate; check-then-create is not atomic |
| M2 | Low | Migration | No upgrade path for future schema versions beyond version 1 |
| E1 | Low | Errors | `tx.Commit()` error not wrapped in `migrate()` |
| T1 | Low | Correctness | `delete --prefix` TOCTOU between confirmation List and DeletePrefix |
| D3 | Info | Integrity | `metadata` not validated as JSON at the store layer |
| S3 | Info | Schema | `metadata` column has no database-level format constraint |
| S1 | Info | Schema | No index on timestamp columns (not needed now) |

---

## Recommended Action Order

1. **Add `busy_timeout` pragma** (C1) — one line, zero risk, prevents confusing errors in scripted use.
2. **Fix `schema_version` uniqueness** (S2) — requires a migration, but the fix is simple and prevents a class of silent bugs.
3. **Cap `MaxOpenConns(1)`** (C2) — one line after `sql.Open`, makes concurrency behavior explicit.
4. **Wrap `import` in a transaction** (P3) — prevents partial state on import failure; straightforward to add.
5. **Wrap `tx.Commit()` error** (E1) — trivial one-line fix.
6. **Document the N+1 in export** (P1) — add a comment; address with a bulk-fetch method if vault size grows.
