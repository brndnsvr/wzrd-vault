package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/brndnsvr/wzrd-vault/internal/config"
	"github.com/brndnsvr/wzrd-vault/internal/crypto"
	"github.com/brndnsvr/wzrd-vault/internal/store"
	"github.com/spf13/cobra"
)

var (
	exportFormat      string
	exportPrefixStrip string
)

// decryptedSecret holds a path and its decrypted plaintext value.
type decryptedSecret struct {
	path  string
	value string
}

var exportCmd = &cobra.Command{
	Use:   "export [prefix]",
	Short: "Decrypt and export secrets",
	Long: `Decrypt and export secrets in various formats for use in shell scripts,
.env files, or programmatic consumption.

Formats:
  dotenv (default): WORK_TACACS_KEY=value
  json:             {"work/tacacs/key": "value", ...}
  shell:            export WORK_TACACS_KEY='value'

Examples:
  wzrd-vault export work/ --format shell
  eval "$(wzrd-vault export work/ --prefix-strip work/ --format shell)"
  wzrd-vault export --format json > secrets.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()

		if err := requireStore(cfg); err != nil {
			return err
		}

		s, err := store.Open(cfg.DBPath)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		prefix := ""
		if len(args) > 0 {
			prefix = args[0]
		}

		entries, err := s.List(prefix)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			return fmt.Errorf("no secrets found to export")
		}

		// Resolve private key for decryption.
		privateKey, err := resolvePrivateKey(cfg)
		if err != nil {
			return err
		}

		switch exportFormat {
		case "json":
			// JSON needs all values at once for the map.
			secrets := make([]decryptedSecret, 0, len(entries))
			for _, entry := range entries {
				secret, err := s.Get(entry.Path)
				if err != nil {
					return err
				}
				plaintext, err := crypto.Decrypt(secret.Ciphertext, privateKey)
				if err != nil {
					return fmt.Errorf("decrypting %q: %w", entry.Path, err)
				}
				secrets = append(secrets, decryptedSecret{path: entry.Path, value: string(plaintext)})
			}
			return exportJSON(secrets)

		case "shell":
			for _, entry := range entries {
				secret, err := s.Get(entry.Path)
				if err != nil {
					return err
				}
				plaintext, err := crypto.Decrypt(secret.Ciphertext, privateKey)
				if err != nil {
					return fmt.Errorf("decrypting %q: %w", entry.Path, err)
				}
				value := string(plaintext)
				envVar := pathToEnvVar(entry.Path)
				if strings.ContainsAny(value, "\n\r") {
					escaped := strings.ReplaceAll(value, `\`, `\\`)
					escaped = strings.ReplaceAll(escaped, "'", `\'`)
					escaped = strings.ReplaceAll(escaped, "\n", `\n`)
					escaped = strings.ReplaceAll(escaped, "\r", `\r`)
					fmt.Printf("export %s=$'%s'\n", envVar, escaped)
				} else {
					escaped := strings.ReplaceAll(value, "'", `'\''`)
					fmt.Printf("export %s='%s'\n", envVar, escaped)
				}
			}
			return nil

		case "dotenv", "":
			for _, entry := range entries {
				secret, err := s.Get(entry.Path)
				if err != nil {
					return err
				}
				plaintext, err := crypto.Decrypt(secret.Ciphertext, privateKey)
				if err != nil {
					return fmt.Errorf("decrypting %q: %w", entry.Path, err)
				}
				value := string(plaintext)
				envVar := pathToEnvVar(entry.Path)
				if needsQuoting(value) {
					escaped := strings.ReplaceAll(value, `\`, `\\`)
					escaped = strings.ReplaceAll(escaped, `"`, `\"`)
					escaped = strings.ReplaceAll(escaped, "\n", `\n`)
					escaped = strings.ReplaceAll(escaped, "$", `\$`)
					escaped = strings.ReplaceAll(escaped, "`", "\\`")
					escaped = strings.ReplaceAll(escaped, "\r", `\r`)
					fmt.Printf("%s=\"%s\"\n", envVar, escaped)
				} else {
					fmt.Printf("%s=%s\n", envVar, value)
				}
			}
			return nil

		default:
			return fmt.Errorf("unknown format %q — use dotenv, json, or shell", exportFormat)
		}
	},
}

// pathToEnvVar converts a secret path to an environment variable name.
// An optional prefix is stripped first, then slashes are replaced with
// underscores and the result is uppercased.
func pathToEnvVar(path string) string {
	if exportPrefixStrip != "" {
		// Ensure prefix ends with / for clean stripping.
		strip := exportPrefixStrip
		if !strings.HasSuffix(strip, "/") {
			strip += "/"
		}
		path = strings.TrimPrefix(path, strip)
	}
	return strings.ToUpper(strings.ReplaceAll(path, "/", "_"))
}

func needsQuoting(s string) bool {
	return strings.ContainsAny(s, " \t\n\r\"'$#\\`!") || s == ""
}

func exportJSON(secrets []decryptedSecret) error {
	m := make(map[string]string, len(secrets))
	for _, s := range secrets {
		m[s.path] = s.value
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

func init() {
	exportCmd.Flags().StringVar(&exportFormat, "format", "dotenv", "output format: dotenv, json, or shell")
	exportCmd.Flags().StringVar(&exportPrefixStrip, "prefix-strip", "", "strip this prefix from paths before converting to env var names")
	rootCmd.AddCommand(exportCmd)
}
