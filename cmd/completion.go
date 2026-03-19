package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion <shell>",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for wzrd-vault.

Supported shells: bash, zsh, fish, powershell

To install completions:
  bash:  wzrd-vault completion bash > /etc/bash_completion.d/wzrd-vault
  zsh:   wzrd-vault completion zsh > "${fpath[1]}/_wzrd-vault"
  fish:  wzrd-vault completion fish > ~/.config/fish/completions/wzrd-vault.fish`,
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			return rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		default:
			return fmt.Errorf("unsupported shell %q — use bash, zsh, fish, or powershell", args[0])
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
