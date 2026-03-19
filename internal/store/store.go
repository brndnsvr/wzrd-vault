package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS secrets (
    path        TEXT PRIMARY KEY,
    ciphertext  BLOB NOT NULL,
    metadata    TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at  TEXT
);

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_secrets_path_prefix ON secrets(path);
CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at) WHERE expires_at IS NOT NULL;
`

// NotFoundError is returned when a secret path does not exist in the store.
type NotFoundError struct {
	Path string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("secret not found: %q — run \"wzrd-vault list\" to see available paths", e.Path)
}

// IsNotFound reports whether err is a NotFoundError.
func IsNotFound(err error) bool {
	var nfe *NotFoundError
	return errors.As(err, &nfe)
}

// Secret holds the full record retrieved from the store.
type Secret struct {
	Path       string
	Ciphertext []byte
	Metadata   *string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ExpiresAt  *time.Time
}

// ListEntry holds the path and metadata fields returned by List queries.
// Ciphertext is intentionally excluded to avoid loading bulk data unnecessarily.
type ListEntry struct {
	Path      string
	Metadata  *string
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt *time.Time
}

// Store wraps a SQLite database and provides CRUD operations for secrets.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at dbPath, enables WAL mode,
// and applies the schema migration.
func Open(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database %q: %w", dbPath, err)
	}

	// Enable WAL mode for better concurrent read performance.
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable WAL mode: %w", err)
	}

	// Enable foreign keys.
	if _, err := db.Exec("PRAGMA foreign_keys=ON;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// migrate creates the schema if the database is new, or validates the schema
// version for an existing database.
func (s *Store) migrate() error {
	// Check whether schema_version table exists already.
	var count int
	err := s.db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'",
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("check schema_version table: %w", err)
	}

	if count == 0 {
		// Fresh database — apply schema and record version.
		if _, err := s.db.Exec(schemaSQL); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		if _, err := s.db.Exec("INSERT INTO schema_version (version) VALUES (1)"); err != nil {
			return fmt.Errorf("record schema version: %w", err)
		}
		return nil
	}

	// Existing database — verify version is compatible.
	version, err := s.SchemaVersion()
	if err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("unsupported schema version %d (expected 1) — upgrade wzrd-vault", version)
	}

	return nil
}

// SchemaVersion returns the current schema version recorded in the database.
func (s *Store) SchemaVersion() (int, error) {
	var version int
	err := s.db.QueryRow("SELECT version FROM schema_version LIMIT 1").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

// Set stores or updates a secret at path. path is validated before any DB
// operation. If the path already exists, the ciphertext, metadata, expires_at,
// and updated_at fields are updated (created_at is preserved).
func (s *Store) Set(path string, ciphertext []byte, metadata *string, expiresAt *time.Time) error {
	if err := ValidatePath(path); err != nil {
		return err
	}

	var expiresStr *string
	if expiresAt != nil {
		v := expiresAt.UTC().Format(time.RFC3339)
		expiresStr = &v
	}

	now := time.Now().UTC().Format(time.RFC3339)

	_, err := s.db.Exec(`
		INSERT INTO secrets (path, ciphertext, metadata, created_at, updated_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET
			ciphertext = excluded.ciphertext,
			metadata   = excluded.metadata,
			updated_at = excluded.updated_at,
			expires_at = excluded.expires_at
	`, path, ciphertext, metadata, now, now, expiresStr)
	if err != nil {
		return fmt.Errorf("set secret %q: %w", path, err)
	}

	return nil
}

// Get retrieves a secret by path. Returns NotFoundError if the path does not exist.
func (s *Store) Get(path string) (*Secret, error) {
	row := s.db.QueryRow(`
		SELECT path, ciphertext, metadata, created_at, updated_at, expires_at
		FROM secrets
		WHERE path = ?
	`, path)

	var sec Secret
	var createdStr, updatedStr string
	var expiresStr *string

	err := row.Scan(
		&sec.Path,
		&sec.Ciphertext,
		&sec.Metadata,
		&createdStr,
		&updatedStr,
		&expiresStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{Path: path}
		}
		return nil, fmt.Errorf("get secret %q: %w", path, err)
	}

	sec.CreatedAt, err = time.Parse(time.RFC3339, createdStr)
	if err != nil {
		return nil, fmt.Errorf("parse created_at for %q: %w", path, err)
	}

	sec.UpdatedAt, err = time.Parse(time.RFC3339, updatedStr)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at for %q: %w", path, err)
	}

	if expiresStr != nil {
		t, err := time.Parse(time.RFC3339, *expiresStr)
		if err != nil {
			return nil, fmt.Errorf("parse expires_at for %q: %w", path, err)
		}
		sec.ExpiresAt = &t
	}

	return &sec, nil
}

// Exists reports whether a secret at path exists in the store.
func (s *Store) Exists(path string) bool {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM secrets WHERE path = ?", path).Scan(&count)
	return err == nil && count > 0
}

// List returns all secrets whose path starts with prefix, sorted by path.
// If prefix is empty, all secrets are returned.
func (s *Store) List(prefix string) ([]ListEntry, error) {
	var (
		rows *sql.Rows
		err  error
	)

	if prefix == "" {
		rows, err = s.db.Query(`
			SELECT path, metadata, created_at, updated_at, expires_at
			FROM secrets
			ORDER BY path ASC
		`)
	} else {
		// Escape LIKE special characters in the prefix.
		escaped := escapeLike(prefix)
		rows, err = s.db.Query(`
			SELECT path, metadata, created_at, updated_at, expires_at
			FROM secrets
			WHERE path LIKE ? ESCAPE '\'
			ORDER BY path ASC
		`, escaped+"%")
	}
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []ListEntry
	for rows.Next() {
		var e ListEntry
		var createdStr, updatedStr string
		var expiresStr *string

		if err := rows.Scan(&e.Path, &e.Metadata, &createdStr, &updatedStr, &expiresStr); err != nil {
			return nil, fmt.Errorf("scan list row: %w", err)
		}

		e.CreatedAt, err = time.Parse(time.RFC3339, createdStr)
		if err != nil {
			return nil, fmt.Errorf("parse created_at for %q: %w", e.Path, err)
		}

		e.UpdatedAt, err = time.Parse(time.RFC3339, updatedStr)
		if err != nil {
			return nil, fmt.Errorf("parse updated_at for %q: %w", e.Path, err)
		}

		if expiresStr != nil {
			t, err := time.Parse(time.RFC3339, *expiresStr)
			if err != nil {
				return nil, fmt.Errorf("parse expires_at for %q: %w", e.Path, err)
			}
			e.ExpiresAt = &t
		}

		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	return entries, nil
}

// Delete removes the secret at path. Returns NotFoundError if the path does
// not exist.
func (s *Store) Delete(path string) error {
	result, err := s.db.Exec("DELETE FROM secrets WHERE path = ?", path)
	if err != nil {
		return fmt.Errorf("delete secret %q: %w", path, err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete secret %q rows affected: %w", path, err)
	}
	if affected == 0 {
		return &NotFoundError{Path: path}
	}

	return nil
}

// DeletePrefix deletes all secrets whose path starts with prefix. Returns the
// number of deleted secrets.
func (s *Store) DeletePrefix(prefix string) (int64, error) {
	escaped := escapeLike(prefix)
	result, err := s.db.Exec(`
		DELETE FROM secrets WHERE path LIKE ? ESCAPE '\'
	`, escaped+"%")
	if err != nil {
		return 0, fmt.Errorf("delete prefix %q: %w", prefix, err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete prefix %q rows affected: %w", prefix, err)
	}

	return count, nil
}

// escapeLike escapes LIKE pattern special characters ('%', '_', '\') in s
// so the string is treated as a literal prefix.
func escapeLike(s string) string {
	out := make([]byte, 0, len(s)+4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' || c == '_' || c == '\\' {
			out = append(out, '\\')
		}
		out = append(out, c)
	}
	return string(out)
}
