package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/brndnsvr/wzrd-vault/internal/config"
	"github.com/brndnsvr/wzrd-vault/internal/crypto"
	"github.com/brndnsvr/wzrd-vault/internal/store"
	"github.com/spf13/cobra"
)

var (
	importFormat string
	importPrefix string
	importDryRun bool
	importForce  bool
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import secrets from stdin in dotenv or JSON format",
	Long: `Import secrets from stdin in dotenv or JSON format. Secrets are encrypted
with the public key — no passphrase is required for import.

Format auto-detection: if the first non-whitespace character is '{' or '[' the
input is treated as JSON, otherwise it is parsed as dotenv.

Dotenv rules:
  - Lines in KEY=value format are imported
  - Lines starting with '#' and blank lines are ignored
  - Keys are lowercased and underscores replaced with slashes for path conversion
  - Double- and single-quoted values have their surrounding quotes stripped

JSON format: a flat object mapping path strings to secret values.

Examples:
  cat .env | wzrd-vault import --prefix dev/myapp
  cat secrets.json | wzrd-vault import --format json
  cat .env | wzrd-vault import --dry-run
  cat .env | wzrd-vault import --force`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()

		// Verify store exists.
		if err := requireStore(cfg); err != nil {
			return err
		}

		// Read all of stdin.
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		data := string(raw)

		if strings.TrimSpace(data) == "" {
			return fmt.Errorf("no input provided — pipe dotenv or JSON to stdin")
		}

		// Detect format if not specified.
		format := importFormat
		if format == "" {
			format = detectFormat(data)
		}

		// Parse into map[string]string.
		var secrets map[string]string
		switch format {
		case "json":
			secrets, err = parseJSON(data)
			if err != nil {
				return fmt.Errorf("parsing JSON input: %w", err)
			}
		case "dotenv":
			raw, err := parseDotenv(data)
			if err != nil {
				return fmt.Errorf("parsing dotenv input: %w", err)
			}
			// Convert env var keys to vault paths.
			secrets = make(map[string]string, len(raw))
			for k, v := range raw {
				secrets[envVarToPath(k)] = v
			}
		default:
			return fmt.Errorf("unknown format %q — use dotenv or json", format)
		}

		if len(secrets) == 0 {
			return fmt.Errorf("no secrets found in input")
		}

		// Apply prefix.
		if importPrefix != "" {
			prefix := strings.TrimRight(importPrefix, "/") + "/"
			prefixed := make(map[string]string, len(secrets))
			for k, v := range secrets {
				prefixed[prefix+k] = v
			}
			secrets = prefixed
		}

		if importDryRun {
			// Sort for deterministic output.
			paths := make([]string, 0, len(secrets))
			for p := range secrets {
				paths = append(paths, p)
			}
			sort.Strings(paths)
			fmt.Fprintf(os.Stderr, "Dry run — would import %d secret(s):\n", len(paths))
			for _, p := range paths {
				fmt.Fprintf(os.Stderr, "  %s\n", p)
			}
			return nil
		}

		// Read public key (no passphrase needed — import only encrypts).
		pubKeyData, err := os.ReadFile(cfg.PublicKeyPath)
		if err != nil {
			return fmt.Errorf("reading public key at %s — run \"wzrd-vault init\" to create it: %w", cfg.PublicKeyPath, err)
		}
		publicKey := strings.TrimRight(string(pubKeyData), "\n")

		// Open store.
		s, err := store.Open(cfg.DBPath)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		// Sort paths for deterministic processing order.
		paths := make([]string, 0, len(secrets))
		for p := range secrets {
			paths = append(paths, p)
		}
		sort.Strings(paths)

		var imported, skipped int
		for _, path := range paths {
			value := secrets[path]

			if exists, err := s.Exists(path); err != nil {
				return err
			} else if exists && !importForce {
				fmt.Fprintf(os.Stderr, "skipping %q — already exists (use --force to overwrite)\n", path)
				skipped++
				continue
			}

			ciphertext, err := crypto.Encrypt([]byte(value), publicKey)
			if err != nil {
				return fmt.Errorf("encrypting %q: %w", path, err)
			}

			if err := s.Set(path, ciphertext, nil, nil); err != nil {
				return fmt.Errorf("storing %q: %w", path, err)
			}
			imported++
		}

		fmt.Fprintf(os.Stderr, "Imported %d secret(s)", imported)
		if skipped > 0 {
			fmt.Fprintf(os.Stderr, ", skipped %d (already exist)", skipped)
		}
		fmt.Fprintln(os.Stderr)
		return nil
	},
}

// parseDotenv parses dotenv-formatted text into a map of KEY → value.
// Lines beginning with '#' and blank lines are ignored. Surrounding double-
// or single-quotes are stripped from values.
func parseDotenv(data string) (map[string]string, error) {
	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// Strip surrounding quotes.
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		result[key] = value
	}
	return result, scanner.Err()
}

// parseJSON parses a flat JSON object into a map of path → value.
func parseJSON(data string) (map[string]string, error) {
	var m map[string]string
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// envVarToPath converts an environment variable name to a vault path by
// lowercasing the key and replacing underscores with slashes.
func envVarToPath(key string) string {
	return strings.ToLower(strings.ReplaceAll(key, "_", "/"))
}

// detectFormat returns "json" if the first non-whitespace character is '{' or
// '[', otherwise returns "dotenv".
func detectFormat(data string) string {
	trimmed := strings.TrimSpace(data)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return "json"
	}
	return "dotenv"
}

func init() {
	importCmd.Flags().StringVar(&importFormat, "format", "", "input format: dotenv or json (auto-detected if not set)")
	importCmd.Flags().StringVar(&importPrefix, "prefix", "", "prepend this path prefix to all imported keys")
	importCmd.Flags().BoolVar(&importDryRun, "dry-run", false, "show what would be imported without storing anything")
	importCmd.Flags().BoolVar(&importForce, "force", false, "overwrite existing secrets")
	rootCmd.AddCommand(importCmd)
}
