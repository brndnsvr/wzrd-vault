package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/brndnsvr/wzrd-vault/internal/cli"
	"github.com/brndnsvr/wzrd-vault/internal/config"
	"github.com/brndnsvr/wzrd-vault/internal/crypto"
	"github.com/brndnsvr/wzrd-vault/internal/store"
	"github.com/spf13/cobra"
)

var initForce bool

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new wzrd-vault store",
	Long: `Initialize a new wzrd-vault store. Generates an age keypair, encrypts
the private key with a passphrase, creates the SQLite database, and writes
a default configuration file.

The passphrase is collected via terminal prompt — it is never accepted as
a command-line argument.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()

		// Check if store already exists.
		if _, err := os.Stat(cfg.DBPath); err == nil && !initForce {
			return fmt.Errorf("store already exists at %s — use --force to reinitialize (this will destroy existing secrets)", cfg.DBPath)
		}

		// Create config directory.
		if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
			return fmt.Errorf("creating config directory at %s: %w", cfg.Dir, err)
		}

		// Prompt for passphrase.
		passphrase, err := cli.ReadSecretInteractive("Passphrase")
		if err != nil {
			return err
		}
		if passphrase == "" {
			return fmt.Errorf("passphrase cannot be empty")
		}

		// Generate age keypair.
		identity, err := crypto.GenerateIdentity()
		if err != nil {
			return err
		}

		// Encrypt and store private key.
		encrypted, err := crypto.EncryptIdentity(identity.PrivateKey, passphrase)
		if err != nil {
			return err
		}
		if err := os.WriteFile(cfg.IdentityPath, encrypted, 0o600); err != nil {
			return fmt.Errorf("writing encrypted identity to %s: %w", cfg.IdentityPath, err)
		}

		// Store public key.
		if err := os.WriteFile(cfg.PublicKeyPath, []byte(identity.PublicKey+"\n"), 0o644); err != nil {
			return fmt.Errorf("writing public key to %s: %w", cfg.PublicKeyPath, err)
		}

		// Create SQLite database (open applies schema, then close immediately).
		s, err := store.Open(cfg.DBPath)
		if err != nil {
			return err
		}
		if err := s.Close(); err != nil {
			return fmt.Errorf("closing database: %w", err)
		}

		// Write default config file if it doesn't exist.
		configPath := filepath.Join(cfg.Dir, "config.toml")
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			defaultConfig := "# wzrd-vault configuration\n# See config.example.toml for all options.\n\n# db = \"" + cfg.DBPath + "\"\n# editor = \"vi\"\n# default_expires = \"\"\n"
			if err := os.WriteFile(configPath, []byte(defaultConfig), 0o600); err != nil {
				return fmt.Errorf("writing config file: %w", err)
			}
		}

		fmt.Fprintln(os.Stderr, "Vault initialized successfully.")
		fmt.Fprintln(os.Stderr, "Config directory:", cfg.Dir)
		fmt.Fprintln(os.Stderr, "Database:", cfg.DBPath)
		// Public key to stdout (useful for piping).
		fmt.Println(identity.PublicKey)

		return nil
	},
}

func init() {
	initCmd.Flags().BoolVar(&initForce, "force", false, "reinitialize even if store already exists")
	rootCmd.AddCommand(initCmd)
}
