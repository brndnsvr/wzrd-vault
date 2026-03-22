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

		if err := requireStore(cfg); err != nil {
			return err
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
	if exists, err := s.Exists(path); err != nil {
		return err
	} else if !exists {
		return newExitError(3, "secret not found: %q — run \"wzrd-vault list\" to see available paths", path)
	}

	if !deleteForce {
		tty, ttyErr := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
		if ttyErr != nil {
			return fmt.Errorf("cannot prompt for confirmation — use --force to skip: %w", ttyErr)
		}
		defer func() { _ = tty.Close() }()
		confirmed := cli.PromptYesNo(tty, os.Stderr, fmt.Sprintf("Delete secret %q?", path))
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
		return newExitError(3, "no secrets found matching prefix %q", prefix)
	}

	if !deleteForce {
		fmt.Fprintf(os.Stderr, "The following %d secrets will be deleted:\n", len(entries))
		for _, e := range entries {
			fmt.Fprintf(os.Stderr, "  %s\n", e.Path)
		}
		tty, ttyErr := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
		if ttyErr != nil {
			return fmt.Errorf("cannot prompt for confirmation — use --force to skip: %w", ttyErr)
		}
		defer func() { _ = tty.Close() }()
		confirmed := cli.PromptYesNo(tty, os.Stderr, "Continue?")
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
