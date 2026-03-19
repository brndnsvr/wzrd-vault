package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "wzrd-vault",
	Short: "Local-first secrets manager that never leaks secrets to process arguments",
	Long: `wzrd-vault is a local-first secrets manager. It stores secrets in an
age-encrypted SQLite database, retrieves them via stdout for piping into
other tools, and never exposes secrets through process arguments.

Secrets are always read from stdin — never from command-line arguments —
because arguments are visible to every user on the system via /proc/PID/cmdline.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func SetVersionInfo(v, c, d string) {
	versionStr = v
	commitStr = c
	dateStr = d
}

func Execute() error {
	return rootCmd.Execute()
}

var (
	versionStr string
	commitStr  string
	dateStr    string
)
