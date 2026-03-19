package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/brndnsvr/wzrd-vault/internal/config"
	"github.com/brndnsvr/wzrd-vault/internal/duration"
	"github.com/brndnsvr/wzrd-vault/internal/store"
	"github.com/spf13/cobra"
)

var (
	listJSON     bool
	listExpired  bool
	listExpiring string
)

var listCmd = &cobra.Command{
	Use:   "list [prefix]",
	Short: "List secret paths in the store",
	Long: `List secret paths stored in the vault. Does not require a passphrase
because paths are not encrypted — only values are.

Optionally filter by prefix:
  wzrd-vault list work/network/`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()

		if _, err := os.Stat(cfg.DBPath); os.IsNotExist(err) {
			return fmt.Errorf("database not found at %s — run \"wzrd-vault init\" to create it", cfg.DBPath)
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

		// Filter by expiry.
		if listExpired || listExpiring != "" {
			now := time.Now()
			var filtered []store.ListEntry
			for _, e := range entries {
				if e.ExpiresAt == nil {
					continue
				}
				if listExpired && e.ExpiresAt.Before(now) {
					filtered = append(filtered, e)
					continue
				}
				if listExpiring != "" {
					threshold, err := duration.ParseExpiry(listExpiring)
					if err != nil {
						return err
					}
					if e.ExpiresAt.After(now) && e.ExpiresAt.Before(threshold) {
						filtered = append(filtered, e)
					}
				}
			}
			entries = filtered
		}

		if len(entries) == 0 {
			if prefix != "" {
				fmt.Fprintf(os.Stderr, "No secrets found matching prefix %q\n", prefix)
			} else {
				fmt.Fprintln(os.Stderr, "No secrets stored — use \"wzrd-vault set <path>\" to add one")
			}
			return nil
		}

		if listJSON {
			type jsonEntry struct {
				Path      string  `json:"path"`
				Metadata  any     `json:"metadata,omitempty"`
				CreatedAt string  `json:"created_at"`
				UpdatedAt string  `json:"updated_at"`
				ExpiresAt *string `json:"expires_at,omitempty"`
			}
			var out []jsonEntry
			for _, e := range entries {
				je := jsonEntry{
					Path:      e.Path,
					CreatedAt: e.CreatedAt.Format(time.RFC3339),
					UpdatedAt: e.UpdatedAt.Format(time.RFC3339),
				}
				if e.Metadata != nil {
					var meta any
					_ = json.Unmarshal([]byte(*e.Metadata), &meta)
					je.Metadata = meta
				}
				if e.ExpiresAt != nil {
					s := e.ExpiresAt.Format(time.RFC3339)
					je.ExpiresAt = &s
				}
				out = append(out, je)
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}

		for _, entry := range entries {
			fmt.Println(entry.Path)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolVar(&listJSON, "json", false, "output as JSON array")
	listCmd.Flags().BoolVar(&listExpired, "expired", false, "show only expired secrets")
	listCmd.Flags().StringVar(&listExpiring, "expiring", "", "show secrets expiring within duration (e.g. 30d)")
}
