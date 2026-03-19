package store

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open(%q) error: %v", dbPath, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpen_CreatesDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	defer func() { _ = s.Close() }()

	version, err := s.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion() error: %v", err)
	}
	if version != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", version)
	}
}

func TestSet_And_Get(t *testing.T) {
	s := newTestStore(t)

	err := s.Set("work/db/password", []byte("ciphertext-data"), nil, nil)
	if err != nil {
		t.Fatalf("Set() error: %v", err)
	}

	secret, err := s.Get("work/db/password")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if string(secret.Ciphertext) != "ciphertext-data" {
		t.Errorf("Ciphertext = %q, want %q", secret.Ciphertext, "ciphertext-data")
	}
	if secret.Path != "work/db/password" {
		t.Errorf("Path = %q, want %q", secret.Path, "work/db/password")
	}
}

func TestSet_Overwrite(t *testing.T) {
	s := newTestStore(t)

	_ = s.Set("work/key", []byte("old"), nil, nil)
	err := s.Set("work/key", []byte("new"), nil, nil)
	if err != nil {
		t.Fatalf("Set() overwrite error: %v", err)
	}

	secret, err := s.Get("work/key")
	if err != nil {
		t.Fatal(err)
	}
	if string(secret.Ciphertext) != "new" {
		t.Errorf("Ciphertext = %q, want %q", secret.Ciphertext, "new")
	}
}

func TestSet_InvalidPath(t *testing.T) {
	s := newTestStore(t)
	err := s.Set("INVALID", []byte("data"), nil, nil)
	if err == nil {
		t.Error("expected error for invalid path, got nil")
	}
}

func TestGet_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Get("nonexistent/path")
	if err == nil {
		t.Error("expected error for missing path, got nil")
	}
	if !IsNotFound(err) {
		t.Errorf("expected NotFound error, got: %v", err)
	}
}

func TestList_All(t *testing.T) {
	s := newTestStore(t)
	_ = s.Set("aa/bb", []byte("1"), nil, nil)
	_ = s.Set("cc/dd", []byte("2"), nil, nil)
	_ = s.Set("aa/ee", []byte("3"), nil, nil)

	entries, err := s.List("")
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("List() returned %d entries, want 3", len(entries))
	}
	if entries[0].Path != "aa/bb" {
		t.Errorf("entries[0].Path = %q, want %q", entries[0].Path, "aa/bb")
	}
	if entries[1].Path != "aa/ee" {
		t.Errorf("entries[1].Path = %q, want %q", entries[1].Path, "aa/ee")
	}
	if entries[2].Path != "cc/dd" {
		t.Errorf("entries[2].Path = %q, want %q", entries[2].Path, "cc/dd")
	}
}

func TestList_Prefix(t *testing.T) {
	s := newTestStore(t)
	_ = s.Set("work/aa", []byte("1"), nil, nil)
	_ = s.Set("work/bb", []byte("2"), nil, nil)
	_ = s.Set("home/cc", []byte("3"), nil, nil)

	entries, err := s.List("work/")
	if err != nil {
		t.Fatalf("List(work/) error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List(work/) returned %d entries, want 2", len(entries))
	}
}

func TestDelete(t *testing.T) {
	s := newTestStore(t)
	_ = s.Set("work/key", []byte("data"), nil, nil)

	err := s.Delete("work/key")
	if err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	_, err = s.Get("work/key")
	if !IsNotFound(err) {
		t.Errorf("expected NotFound after delete, got: %v", err)
	}
}

func TestDelete_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.Delete("nonexistent/path")
	if err == nil {
		t.Error("expected error for deleting missing path, got nil")
	}
	if !IsNotFound(err) {
		t.Errorf("expected NotFound error, got: %v", err)
	}
}

func TestExists(t *testing.T) {
	s := newTestStore(t)
	_ = s.Set("work/key", []byte("data"), nil, nil)

	if !s.Exists("work/key") {
		t.Error("Exists() = false for existing path")
	}
	if s.Exists("nonexistent/path") {
		t.Error("Exists() = true for missing path")
	}
}

func TestSet_WithMetadataAndExpiry(t *testing.T) {
	s := newTestStore(t)

	metadata := `{"tags":{"env":"prod"},"note":"test"}`
	expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	err := s.Set("work/key", []byte("data"), &metadata, &expires)
	if err != nil {
		t.Fatal(err)
	}

	secret, err := s.Get("work/key")
	if err != nil {
		t.Fatal(err)
	}
	if secret.Metadata == nil || *secret.Metadata != metadata {
		t.Errorf("Metadata = %v, want %q", secret.Metadata, metadata)
	}
	if secret.ExpiresAt == nil {
		t.Fatal("ExpiresAt is nil, want non-nil")
	}
}

func TestDeletePrefix(t *testing.T) {
	s := newTestStore(t)
	_ = s.Set("work/aa", []byte("1"), nil, nil)
	_ = s.Set("work/bb", []byte("2"), nil, nil)
	_ = s.Set("home/cc", []byte("3"), nil, nil)

	count, err := s.DeletePrefix("work/")
	if err != nil {
		t.Fatalf("DeletePrefix() error: %v", err)
	}
	if count != 2 {
		t.Errorf("DeletePrefix() deleted %d, want 2", count)
	}

	entries, _ := s.List("")
	if len(entries) != 1 {
		t.Errorf("remaining entries = %d, want 1", len(entries))
	}
}
