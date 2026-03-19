package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("WZVAULT_DB", "")

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}

	cfg := Load()
	want := filepath.Join(home, ".config", "wzrd-vault")
	if cfg.Dir != want {
		t.Errorf("Dir = %q, want %q", cfg.Dir, want)
	}
}

func TestXDGConfigDirOverride(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/test-xdg")
	t.Setenv("WZVAULT_DB", "")

	cfg := Load()
	want := filepath.Join("/tmp/test-xdg", "wzrd-vault")
	if cfg.Dir != want {
		t.Errorf("Dir = %q, want %q", cfg.Dir, want)
	}
}

func TestDBPath_Default(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/test-xdg")
	t.Setenv("WZVAULT_DB", "")

	cfg := Load()
	want := filepath.Join("/tmp/test-xdg", "wzrd-vault", "stash.db")
	if cfg.DBPath != want {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, want)
	}
}

func TestDBPath_EnvOverride(t *testing.T) {
	t.Setenv("WZVAULT_DB", "/custom/path/secrets.db")

	cfg := Load()
	want := "/custom/path/secrets.db"
	if cfg.DBPath != want {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, want)
	}
}

func TestIdentityPaths(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/test-xdg")
	t.Setenv("WZVAULT_DB", "")

	cfg := Load()

	wantKey := filepath.Join("/tmp/test-xdg", "wzrd-vault", "identity.age")
	if cfg.IdentityPath != wantKey {
		t.Errorf("IdentityPath = %q, want %q", cfg.IdentityPath, wantKey)
	}

	wantPub := filepath.Join("/tmp/test-xdg", "wzrd-vault", "identity.pub")
	if cfg.PublicKeyPath != wantPub {
		t.Errorf("PublicKeyPath = %q, want %q", cfg.PublicKeyPath, wantPub)
	}
}

func TestAgeKeyEnv(t *testing.T) {
	t.Setenv("WZVAULT_AGE_KEY", "AGE-SECRET-KEY-1FAKE")
	cfg := Load()
	if cfg.AgeKey != "AGE-SECRET-KEY-1FAKE" {
		t.Errorf("AgeKey = %q, want %q", cfg.AgeKey, "AGE-SECRET-KEY-1FAKE")
	}
}

func TestPassphraseFDEnv(t *testing.T) {
	t.Setenv("WZVAULT_PASSPHRASE_FD", "9")
	cfg := Load()
	if cfg.PassphraseFD != "9" {
		t.Errorf("PassphraseFD = %q, want %q", cfg.PassphraseFD, "9")
	}
}
