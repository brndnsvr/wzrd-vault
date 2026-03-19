package config

import (
	"os"
	"path/filepath"
)

// Config holds resolved paths and environment settings for wzrd-vault.
type Config struct {
	// Dir is the wzrd-vault configuration directory.
	Dir string

	// DBPath is the path to the SQLite database file.
	DBPath string

	// IdentityPath is the path to the passphrase-encrypted age private key.
	IdentityPath string

	// PublicKeyPath is the path to the age public key.
	PublicKeyPath string

	// AgeKey is the raw age private key material from WZVAULT_AGE_KEY.
	// Empty if not set.
	AgeKey string

	// PassphraseFD is the file descriptor number from WZVAULT_PASSPHRASE_FD.
	// Empty if not set.
	PassphraseFD string
}

// Load resolves configuration from environment variables and XDG paths.
// Environment variables take precedence over defaults.
func Load() Config {
	dir := configDir()

	dbPath := os.Getenv("WZVAULT_DB")
	if dbPath == "" {
		dbPath = filepath.Join(dir, "stash.db")
	}

	return Config{
		Dir:           dir,
		DBPath:        dbPath,
		IdentityPath:  filepath.Join(dir, "identity.age"),
		PublicKeyPath: filepath.Join(dir, "identity.pub"),
		AgeKey:        os.Getenv("WZVAULT_AGE_KEY"),
		PassphraseFD:  os.Getenv("WZVAULT_PASSPHRASE_FD"),
	}
}

// configDir returns the wzrd-vault configuration directory.
// Uses $XDG_CONFIG_HOME/wzrd-vault if set, otherwise ~/.config/wzrd-vault.
func configDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "wzrd-vault")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".config", "wzrd-vault")
	}
	return filepath.Join(home, ".config", "wzrd-vault")
}
