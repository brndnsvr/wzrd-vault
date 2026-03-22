package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
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
unlinked) on exit, even if interrupted by SIGINT or SIGTERM.

The editor subprocess environment is sanitized — WZVAULT_AGE_KEY and
WZVAULT_PASSPHRASE_FD are stripped to prevent secret material from
leaking to the editor or its child processes.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		cfg := config.Load()

		if err := requireStore(cfg); err != nil {
			return err
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
		publicKey := strings.TrimSpace(string(pubKeyData))

		// Create secure temp file.
		tmpDir := secureTmpDir()
		tmpFile, err := os.CreateTemp(tmpDir, "wzrd-vault-edit-*")
		if err != nil {
			return fmt.Errorf("creating temp file in %s: %w", tmpDir, err)
		}
		tmpPath := tmpFile.Name()

		// Ensure cleanup on any exit path — use sync.Once for thread safety.
		var cleanupOnce sync.Once
		cleanup := func() {
			cleanupOnce.Do(func() { secureDelete(tmpPath) })
		}
		defer cleanup()

		// Register signal handlers for cleanup.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
		go func() {
			if _, ok := <-sigCh; ok {
				cleanup()
				os.Exit(1)
			}
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
		editorCmd := exec.Command(editor, tmpPath) //nolint:gosec // editor is user-chosen via $EDITOR/$VISUAL
		editorCmd.Stdin = os.Stdin
		editorCmd.Stdout = os.Stdout
		editorCmd.Stderr = os.Stderr
		// Don't leak sensitive env vars to the editor process.
		editorCmd.Env = filterEnv(filterEnv(os.Environ(), "WZVAULT_AGE_KEY"), "WZVAULT_PASSPHRASE_FD")

		if err := editorCmd.Run(); err != nil {
			return fmt.Errorf("editor exited with error: %w — secret not updated", err)
		}
		signal.Stop(sigCh)
		close(sigCh)

		// Read edited content.
		edited, err := os.ReadFile(tmpPath) //nolint:gosec // path is a temp file we created
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
	// On macOS, create a private temp directory under the user cache.
	if cacheDir, err := os.UserCacheDir(); err == nil {
		privDir := filepath.Join(cacheDir, "wzrd-vault")
		if err := os.MkdirAll(privDir, 0o700); err == nil {
			return privDir
		}
	}
	return os.TempDir()
}

// chooseEditor returns the user's preferred editor.
func chooseEditor() string {
	if editor := os.Getenv("VISUAL"); editor != "" {
		return editor
	}
	if editor := os.Getenv("EDITOR"); editor != "" {
		return editor
	}
	return "vi"
}

// secureDelete overwrites a file with zeros in place, fsyncs, then removes it.
func secureDelete(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // path is the temp file we created
	if err != nil {
		// File may already be gone.
		_ = os.Remove(path)
		return
	}
	info, err := f.Stat()
	if err == nil && info.Size() > 0 {
		zeros := make([]byte, info.Size())
		if _, err := f.WriteAt(zeros, 0); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to zero temp file %s: %v\n", path, err)
		}
		if err := f.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to sync temp file %s: %v\n", path, err)
		}
	}
	_ = f.Close()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "warning: failed to remove temp file %s: %v\n", path, err)
	}
}

// filterEnv returns a copy of env with the named variable removed.
func filterEnv(env []string, name string) []string {
	prefix := name + "="
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, prefix) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func init() {
	rootCmd.AddCommand(editCmd)
}
