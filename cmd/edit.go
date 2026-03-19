package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/brndnsvr/wzrd-vault/internal/config"
	"github.com/brndnsvr/wzrd-vault/internal/crypto"
	"github.com/brndnsvr/wzrd-vault/internal/store"
	"github.com/spf13/cobra"
)

var editCmd = &cobra.Command{
	Use:   "edit <path>",
	Short: "Edit a secret in your editor",
	Long: `Decrypt a secret, open it in your preferred editor, and re-encrypt
the updated value. Uses $EDITOR, $VISUAL, or vi as fallback.

The plaintext is written to a temporary file in a RAM-backed directory
when possible. The file is securely wiped (overwritten with zeros and
unlinked) on exit, even if interrupted by SIGINT or SIGTERM.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		cfg := config.Load()

		if _, err := os.Stat(cfg.DBPath); os.IsNotExist(err) {
			return fmt.Errorf("database not found at %s — run \"wzrd-vault init\" to create it", cfg.DBPath)
		}

		s, err := store.Open(cfg.DBPath)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		// Get existing secret.
		secret, err := s.Get(path)
		if err != nil {
			if store.IsNotFound(err) {
				return fmt.Errorf("secret %q does not exist — use \"wzrd-vault set %s\" to create it", path, path)
			}
			return err
		}

		// Decrypt.
		privateKey, err := resolvePrivateKey(cfg)
		if err != nil {
			return err
		}
		plaintext, err := crypto.Decrypt(secret.Ciphertext, privateKey)
		if err != nil {
			return fmt.Errorf("decrypting %q: %w", path, err)
		}

		// Read public key for re-encryption.
		pubKeyData, err := os.ReadFile(cfg.PublicKeyPath)
		if err != nil {
			return fmt.Errorf("reading public key: %w", err)
		}
		publicKey := strings.TrimRight(string(pubKeyData), "\n")

		// Create secure temp file.
		tmpDir := secureTmpDir()
		tmpFile, err := os.CreateTemp(tmpDir, "wzrd-vault-edit-*")
		if err != nil {
			return fmt.Errorf("creating temp file in %s: %w", tmpDir, err)
		}
		tmpPath := tmpFile.Name()

		// Ensure cleanup on any exit path.
		cleanup := func() {
			secureDelete(tmpPath)
		}
		defer cleanup()

		// Register signal handlers for cleanup.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cleanup()
			os.Exit(1)
		}()

		// Set permissions and write plaintext.
		if err := tmpFile.Chmod(0o600); err != nil {
			_ = tmpFile.Close()
			return fmt.Errorf("setting temp file permissions: %w", err)
		}
		if _, err := tmpFile.Write(plaintext); err != nil {
			_ = tmpFile.Close()
			return fmt.Errorf("writing to temp file: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			return fmt.Errorf("closing temp file: %w", err)
		}

		// Open editor.
		editor := chooseEditor()
		editorCmd := exec.Command(editor, tmpPath)
		editorCmd.Stdin = os.Stdin
		editorCmd.Stdout = os.Stdout
		editorCmd.Stderr = os.Stderr

		if err := editorCmd.Run(); err != nil {
			return fmt.Errorf("editor exited with error: %w — secret not updated", err)
		}

		// Read edited content.
		edited, err := os.ReadFile(tmpPath)
		if err != nil {
			return fmt.Errorf("reading edited file: %w", err)
		}

		// Check if unchanged.
		if bytes.Equal(plaintext, edited) {
			fmt.Fprintln(os.Stderr, "No changes detected — secret not updated.")
			return nil
		}

		// Re-encrypt and store.
		ciphertext, err := crypto.Encrypt(edited, publicKey)
		if err != nil {
			return fmt.Errorf("encrypting updated secret: %w", err)
		}
		if err := s.Set(path, ciphertext, secret.Metadata, secret.ExpiresAt); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "Secret %q updated.\n", path)
		return nil
	},
}

// secureTmpDir returns the most secure temporary directory available.
// Prefers RAM-backed filesystems to avoid writing secrets to disk.
func secureTmpDir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}
	if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
		return "/dev/shm"
	}
	return os.TempDir()
}

// chooseEditor returns the user's preferred editor.
func chooseEditor() string {
	if editor := os.Getenv("EDITOR"); editor != "" {
		return editor
	}
	if editor := os.Getenv("VISUAL"); editor != "" {
		return editor
	}
	return "vi"
}

// secureDelete overwrites a file with zeros then removes it.
func secureDelete(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return // File doesn't exist, nothing to clean up.
	}
	// Overwrite with zeros.
	zeros := make([]byte, info.Size())
	_ = os.WriteFile(path, zeros, 0o600)
	// Remove the file.
	_ = os.Remove(path)
}

func init() {
	rootCmd.AddCommand(editCmd)
}
