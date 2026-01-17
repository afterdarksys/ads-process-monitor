package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	outputJSON bool
	Version    = "0.1.0"
)

var rootCmd = &cobra.Command{
	Use:   "ads-process-monitor",
	Short: "macOS Process Attack Visibility Tool",
	Long: `ADS Process Monitor - Real-time process visibility for macOS security.

Monitor process execution, detect suspicious behavior, and track process
hierarchies for incident response and threat hunting.

Part of the ADS macOS Security Suite.`,
	Version: Version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "output-json", false, "Output results as JSON")
}
