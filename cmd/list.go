package cmd

import (
	"fmt"
	"os"

	"github.com/brndnsvr/wzrd-vault/internal/config"
	"github.com/brndnsvr/wzrd-vault/internal/store"
	"github.com/spf13/cobra"
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

		if len(entries) == 0 {
			if prefix != "" {
				fmt.Fprintf(os.Stderr, "No secrets found matching prefix %q\n", prefix)
			} else {
				fmt.Fprintln(os.Stderr, "No secrets stored — use \"wzrd-vault set <path>\" to add one")
			}
			return nil
		}

		for _, entry := range entries {
			fmt.Println(entry.Path)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
