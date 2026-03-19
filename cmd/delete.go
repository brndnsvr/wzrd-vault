package cmd

import (
	"fmt"
	"os"

	"github.com/brndnsvr/wzrd-vault/internal/cli"
	"github.com/brndnsvr/wzrd-vault/internal/config"
	"github.com/brndnsvr/wzrd-vault/internal/store"
	"github.com/spf13/cobra"
)

var (
	deleteForce  bool
	deletePrefix bool
)

var deleteCmd = &cobra.Command{
	Use:   "delete <path>",
	Short: "Remove a secret from the store",
	Long: `Remove a secret from the store. Prompts for confirmation unless --force is set.

Use --prefix to delete all secrets matching a prefix:
  wzrd-vault delete --prefix work/legacy/ --force`,
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

		if deletePrefix {
			return deleteByPrefix(s, path)
		}
		return deleteSingle(s, path)
	},
}

func deleteSingle(s *store.Store, path string) error {
	if !s.Exists(path) {
		fmt.Fprintf(os.Stderr, "secret not found: %q — run \"wzrd-vault list\" to see available paths\n", path)
		os.Exit(3)
	}

	if !deleteForce {
		confirmed := cli.PromptYesNo(os.Stdin, os.Stderr, fmt.Sprintf("Delete secret %q?", path))
		if !confirmed {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return nil
		}
	}

	if err := s.Delete(path); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Deleted %q\n", path)
	return nil
}

func deleteByPrefix(s *store.Store, prefix string) error {
	entries, err := s.List(prefix)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "No secrets found matching prefix %q\n", prefix)
		os.Exit(3)
	}

	if !deleteForce {
		fmt.Fprintf(os.Stderr, "The following %d secrets will be deleted:\n", len(entries))
		for _, e := range entries {
			fmt.Fprintf(os.Stderr, "  %s\n", e.Path)
		}
		confirmed := cli.PromptYesNo(os.Stdin, os.Stderr, "Continue?")
		if !confirmed {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return nil
		}
	}

	count, err := s.DeletePrefix(prefix)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Deleted %d secrets\n", count)
	return nil
}

func init() {
	deleteCmd.Flags().BoolVar(&deleteForce, "force", false, "delete without confirmation")
	deleteCmd.Flags().BoolVar(&deletePrefix, "prefix", false, "delete all secrets matching the path as a prefix")
	rootCmd.AddCommand(deleteCmd)
}
