package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "agedir",
	Short: "Bulk secret file management tool using age encryption",
	Long: `agedir encrypts, decrypts, and places multiple secret files
scattered across a project based on mappings in agedir.yaml,
using age encryption as the backend.`,
}

// Execute runs the root command with the given version string.
func Execute(version string) {
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(rekeyCmd)
}
