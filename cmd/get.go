package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/brndnsvr/wzrd-vault/internal/cli"
	"github.com/brndnsvr/wzrd-vault/internal/config"
	"github.com/brndnsvr/wzrd-vault/internal/crypto"
	"github.com/brndnsvr/wzrd-vault/internal/store"
	"github.com/spf13/cobra"
)

var getNewline bool

var getCmd = &cobra.Command{
	Use:   "get <path>",
	Short: "Retrieve and decrypt a secret",
	Long: `Retrieve and decrypt a secret. The plaintext is written to stdout with no
trailing newline by default, making it safe for piping into other commands.

Use -n/--newline to append a newline for terminal readability.

The passphrase prompt goes to stderr, so piping works correctly:
  curl -H "Authorization: Bearer $(wzrd-vault get dev/github/pat)" https://api.github.com/user`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		cfg := config.Load()

		// Verify store exists.
		if _, err := os.Stat(cfg.DBPath); os.IsNotExist(err) {
			return fmt.Errorf("database not found at %s — run \"wzrd-vault init\" to create it", cfg.DBPath)
		}

		// Open store.
		s, err := store.Open(cfg.DBPath)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		// Retrieve ciphertext.
		secret, err := s.Get(path)
		if err != nil {
			if store.IsNotFound(err) {
				// Exit code 3 for not found.
				fmt.Fprintln(os.Stderr, err)
				os.Exit(3)
			}
			return err
		}

		// Get private key.
		privateKey, err := resolvePrivateKey(cfg)
		if err != nil {
			return err
		}

		// Decrypt.
		plaintext, err := crypto.Decrypt(secret.Ciphertext, privateKey)
		if err != nil {
			return fmt.Errorf("decrypting secret at %q — wrong passphrase? %w", path, err)
		}

		// Output.
		if getNewline {
			fmt.Println(string(plaintext))
		} else {
			fmt.Print(string(plaintext))
		}
		return nil
	},
}

// resolvePrivateKey gets the private key using the configured method:
// 1. WZVAULT_AGE_KEY env var (raw key)
// 2. WZVAULT_PASSPHRASE_FD — read passphrase from file descriptor
// 3. Interactive passphrase prompt to decrypt identity.age
func resolvePrivateKey(cfg config.Config) (string, error) {
	// 1. WZVAULT_AGE_KEY — raw private key from env.
	if cfg.AgeKey != "" {
		return cfg.AgeKey, nil
	}

	// 2. WZVAULT_PASSPHRASE_FD — read passphrase from file descriptor.
	if cfg.PassphraseFD != "" {
		fd, err := strconv.Atoi(cfg.PassphraseFD)
		if err != nil {
			return "", fmt.Errorf("invalid WZVAULT_PASSPHRASE_FD value %q: %w", cfg.PassphraseFD, err)
		}
		encrypted, err := os.ReadFile(cfg.IdentityPath)
		if err != nil {
			return "", fmt.Errorf("reading identity at %s — run \"wzrd-vault init\" to create it: %w", cfg.IdentityPath, err)
		}
		passphrase, err := cli.ReadPassphraseFromFD(fd)
		if err != nil {
			return "", err
		}
		privateKey, err := crypto.DecryptIdentity(encrypted, passphrase)
		if err != nil {
			return "", fmt.Errorf("decrypting identity — wrong passphrase from fd %d? %w", fd, err)
		}
		return privateKey, nil
	}

	// 3. Interactive prompt — fallback.
	encrypted, err := os.ReadFile(cfg.IdentityPath)
	if err != nil {
		return "", fmt.Errorf("reading identity at %s — run \"wzrd-vault init\" to create it: %w", cfg.IdentityPath, err)
	}

	passphrase, err := cli.PromptPassphrase()
	if err != nil {
		return "", err
	}

	privateKey, err := crypto.DecryptIdentity(encrypted, passphrase)
	if err != nil {
		return "", fmt.Errorf("decrypting identity — wrong passphrase? %w", err)
	}
	return privateKey, nil
}

func init() {
	getCmd.Flags().BoolVarP(&getNewline, "newline", "n", false, "append trailing newline to output")
	rootCmd.AddCommand(getCmd)
}
