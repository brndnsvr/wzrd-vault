package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print wzrd-vault version information",
	Long:  "Print the version, git commit, and build date of the wzrd-vault binary.",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("wzrd-vault version %s (commit %s, built %s)\n", versionStr, commitStr, dateStr)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
