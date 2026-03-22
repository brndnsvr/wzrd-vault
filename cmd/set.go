package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/brndnsvr/wzrd-vault/internal/cli"
	"github.com/brndnsvr/wzrd-vault/internal/config"
	"github.com/brndnsvr/wzrd-vault/internal/crypto"
	"github.com/brndnsvr/wzrd-vault/internal/duration"
	"github.com/brndnsvr/wzrd-vault/internal/store"
	"github.com/spf13/cobra"
)

var (
	setForce   bool
	setExpires string
	setTags    []string
	setNote    string
)

var setCmd = &cobra.Command{
	Use:   "set <path>",
	Short: "Store a secret at the given path",
	Long: `Store a secret at the given path. The secret value is read from stdin —
never from command-line arguments — because arguments are visible to every
user on the system via /proc/PID/cmdline.

If stdin is a terminal, you'll be prompted to enter the secret with echo
disabled and asked to confirm. If stdin is a pipe, the value is read
silently until EOF.

Examples:
  echo "my-api-key" | wzrd-vault set dev/github/pat
  cat keyfile | wzrd-vault set work/ssh/private_key
  wzrd-vault set personal/wifi/password   # interactive prompt`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Security check: secrets must never appear as positional arguments.
		// cobra.MinimumNArgs(1) is used so we can detect and explain this
		// ourselves rather than emitting cobra's generic argument-count error.
		if len(args) > 1 {
			return fmt.Errorf("secrets must be provided via stdin, not as arguments — arguments are\nvisible to all users via /proc/PID/cmdline.\n\nUsage:\n  echo \"my-secret\" | wzrd-vault set %s\n  wzrd-vault set %s  # interactive prompt", args[0], args[0])
		}

		path := args[0]
		cfg := config.Load()

		// Verify store exists.
		if err := requireStore(cfg); err != nil {
			return err
		}

		// Read public key.
		pubKeyData, err := os.ReadFile(cfg.PublicKeyPath)
		if err != nil {
			return fmt.Errorf("reading public key at %s — run \"wzrd-vault init\" to create it: %w", cfg.PublicKeyPath, err)
		}
		publicKey := strings.TrimSpace(string(pubKeyData))

		// Open store and check for existing secret BEFORE reading stdin.
		// This avoids consuming stdin then failing on the existence check —
		// the overwrite prompt must use /dev/tty since stdin may be a pipe.
		s, err := store.Open(cfg.DBPath)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		if exists, err := s.Exists(path); err != nil {
			return err
		} else if !setForce && exists {
			tty, ttyErr := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
			if ttyErr != nil {
				return fmt.Errorf("secret %q already exists — use --force to overwrite", path)
			}
			defer func() { _ = tty.Close() }()
			confirmed := cli.PromptYesNo(tty, os.Stderr, fmt.Sprintf("Secret %q already exists. Overwrite?", path))
			if !confirmed {
				return newExitError(2, "aborted — use --force to overwrite")
			}
		}

		// Read secret from stdin.
		var secret string
		if cli.IsTerminal(int(os.Stdin.Fd())) {
			secret, err = cli.ReadSecretInteractive("Enter secret")
			if err != nil {
				return err
			}
		} else {
			secret, err = cli.ReadSecretFromPipe(os.Stdin)
			if err != nil {
				return err
			}
		}

		if secret == "" {
			return fmt.Errorf("secret value is empty — provide a non-empty value via stdin")
		}

		// Encrypt.
		ciphertext, err := crypto.Encrypt([]byte(secret), publicKey)
		if err != nil {
			return err
		}

		// Build metadata JSON.
		var metadata *string
		if len(setTags) > 0 || setNote != "" {
			meta := map[string]any{}
			if len(setTags) > 0 {
				tags := map[string]string{}
				for _, tag := range setTags {
					k, v, ok := strings.Cut(tag, "=")
					if !ok {
						return fmt.Errorf("invalid tag %q: expected key=value format", tag)
					}
					tags[k] = v
				}
				meta["tags"] = tags
			}
			if setNote != "" {
				meta["note"] = setNote
			}
			jsonBytes, err := json.Marshal(meta)
			if err != nil {
				return fmt.Errorf("encoding metadata: %w", err)
			}
			metaStr := string(jsonBytes)
			metadata = &metaStr
		}

		// Parse expiry.
		var expiresAt *time.Time
		if setExpires != "" {
			t, err := duration.ParseExpiry(setExpires)
			if err != nil {
				return err
			}
			expiresAt = &t
		}

		// Store.
		if err := s.Set(path, ciphertext, metadata, expiresAt); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "Secret stored at %q\n", path)
		return nil
	},
}

func init() {
	setCmd.Flags().BoolVar(&setForce, "force", false, "overwrite existing secret without confirmation")
	setCmd.Flags().StringVar(&setExpires, "expires", "", "set expiry (90d, 24h, 12w, 6m, 1y, or 2026-12-31)")
	setCmd.Flags().StringArrayVar(&setTags, "tag", nil, "key=value tag (repeatable)")
	setCmd.Flags().StringVar(&setNote, "note", "", "human-readable note")
	rootCmd.AddCommand(setCmd)
}
