package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var versionJSON bool

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print wzrd-vault version information",
	Long:  "Print the version, git commit, and build date of the wzrd-vault binary.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if versionJSON {
			out := map[string]string{
				"version": versionStr,
				"commit":  commitStr,
				"date":    dateStr,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}
		fmt.Printf("wzrd-vault version %s (commit %s, built %s)\n", versionStr, commitStr, dateStr)
		return nil
	},
}

func init() {
	versionCmd.Flags().BoolVar(&versionJSON, "json", false, "output as JSON")
	rootCmd.AddCommand(versionCmd)
}
