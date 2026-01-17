package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/afterdarksystems/ads-process-monitor/internal/ai"
	"github.com/afterdarksystems/ads-process-monitor/internal/process"
	"github.com/spf13/cobra"
)

var (
	analyzePID        int32
	analyzeAll        bool
	analyzeSuspicious bool
	analyzeConfigPath string
	analyzeTier       string
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "AI-powered process threat analysis",
	Long: `Analyze processes for threats using multi-tier AI analysis.

Analysis Tiers:
  - rules: Rule-based detection (always available, free)
  - onnx:  On-device ML model (Pro+ license, no network)
  - cloud: Cloud AI analysis (Pro+ license, requires API key)

Examples:
  # Analyze a specific process
  ads-process-monitor analyze --pid 1234

  # Analyze all suspicious processes
  ads-process-monitor analyze --suspicious

  # Analyze all processes with JSON output
  ads-process-monitor analyze --all --output-json

  # Use specific config file
  ads-process-monitor analyze --config ~/.ads/custom-config.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load config
		config, err := ai.LoadConfig(analyzeConfigPath)
		if err != nil && analyzeConfigPath != "" {
			return fmt.Errorf("failed to load config: %w", err)
		}
		if config == nil {
			config = ai.DefaultConfig()
		}

		// Load license
		licenseMgr := ai.NewLicenseManager()
		if err := licenseMgr.LoadLicense(""); err != nil {
			// Non-fatal - will use free license
			fmt.Fprintf(os.Stderr, "Note: Using free license (%v)\n", err)
		}

		// Create analyzer
		analyzer := ai.NewTieredAnalyzer(config, licenseMgr)

		// Get processes to analyze
		var procs []*process.Info

		if analyzePID > 0 {
			// Analyze specific process
			allProcs, err := process.List()
			if err != nil {
				return fmt.Errorf("failed to list processes: %w", err)
			}
			for _, p := range allProcs {
				if p.PID == analyzePID {
					procs = append(procs, p)
					break
				}
			}
			if len(procs) == 0 {
				return fmt.Errorf("process %d not found", analyzePID)
			}
		} else if analyzeSuspicious {
			// Analyze only suspicious processes
			allProcs, err := process.List()
			if err != nil {
				return fmt.Errorf("failed to list processes: %w", err)
			}
			for _, p := range allProcs {
				if len(p.Suspicious) > 0 {
					procs = append(procs, p)
				}
			}
		} else if analyzeAll {
			// Analyze all processes
			var err error
			procs, err = process.List()
			if err != nil {
				return fmt.Errorf("failed to list processes: %w", err)
			}
		} else {
			// Default: analyze suspicious processes
			allProcs, err := process.List()
			if err != nil {
				return fmt.Errorf("failed to list processes: %w", err)
			}
			for _, p := range allProcs {
				if len(p.Suspicious) > 0 {
					procs = append(procs, p)
				}
			}
		}

		if len(procs) == 0 {
			if outputJSON {
				return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
					"version":  Version,
					"count":    0,
					"results":  []interface{}{},
					"tiers":    analyzer.GetAvailableTiers(),
					"license":  analyzer.GetLicenseInfo(),
				})
			}
			fmt.Println("No processes to analyze")
			return nil
		}

		// Run analysis
		results, err := analyzer.AnalyzeBatch(procs)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		if outputJSON {
			return outputAnalysisJSON(results, analyzer)
		}

		return outputAnalysisTable(results, analyzer)
	},
}

func outputAnalysisJSON(results []*ai.AnalysisResult, analyzer *ai.TieredAnalyzer) error {
	output := map[string]interface{}{
		"version": Version,
		"count":   len(results),
		"results": results,
		"tiers":   analyzer.GetAvailableTiers(),
		"license": analyzer.GetLicenseInfo(),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func outputAnalysisTable(results []*ai.AnalysisResult, analyzer *ai.TieredAnalyzer) error {
	// Print available tiers
	fmt.Printf("Available analysis tiers: %v\n", analyzer.GetAvailableTiers())
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PID\tNAME\tVERDICT\tCONF\tTIER\tTHREAT TYPE\tEXPLANATION")
	fmt.Fprintln(w, "---\t----\t-------\t----\t----\t-----------\t-----------")

	for _, r := range results {
		verdictIcon := ""
		switch r.Verdict {
		case ai.VerdictClean:
			verdictIcon = "✓"
		case ai.VerdictSuspicious:
			verdictIcon = "⚠️"
		case ai.VerdictMalicious:
			verdictIcon = "🚨"
		default:
			verdictIcon = "?"
		}

		explanation := r.Explanation
		if len(explanation) > 50 {
			explanation = explanation[:47] + "..."
		}

		threatType := r.ThreatType
		if threatType == "" {
			threatType = "-"
		}

		fmt.Fprintf(w, "%d\t%s\t%s %s\t%d%%\t%s\t%s\t%s\n",
			r.PID,
			truncate(r.Name, 15),
			verdictIcon,
			r.Verdict,
			r.Confidence,
			r.AnalysisTier,
			threatType,
			explanation,
		)
	}

	return w.Flush()
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
	Long:  `View or initialize the AI analysis configuration.`,
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize default configuration",
	Long:  `Create a default configuration file at ~/.ads/process-monitor.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config := ai.DefaultConfig()
		path := ai.DefaultConfigPath()

		if err := ai.SaveConfig(config, path); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("Configuration initialized at: %s\n", path)
		fmt.Println("\nEdit this file to:")
		fmt.Println("  - Enable ONNX analysis (requires model file)")
		fmt.Println("  - Enable Cloud AI analysis (requires API key)")
		fmt.Println("  - Adjust confidence thresholds")
		fmt.Println("  - Configure auto-escalation")

		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := ai.LoadDefaultConfig()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(config)
	},
}

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "Show license information",
	RunE: func(cmd *cobra.Command, args []string) error {
		licenseMgr := ai.NewLicenseManager()
		if err := licenseMgr.LoadLicense(""); err != nil {
			fmt.Fprintf(os.Stderr, "Note: %v\n", err)
		}

		license := licenseMgr.GetLicense()

		if outputJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(license)
		}

		fmt.Printf("License ID:    %s\n", license.LicenseID)
		fmt.Printf("Type:          %s\n", license.Type)
		fmt.Printf("Customer:      %s\n", license.CustomerName)
		fmt.Printf("Expires:       %s\n", license.ExpiresAt.Format("2006-01-02"))
		fmt.Println()
		fmt.Println("Features:")
		fmt.Printf("  Rules Analysis:       %v\n", license.Features.RulesAnalysis)
		fmt.Printf("  ONNX Analysis:        %v\n", license.Features.ONNXAnalysis)
		fmt.Printf("  Cloud Analysis:       %v\n", license.Features.CloudAnalysis)
		fmt.Printf("  Realtime Monitoring:  %v\n", license.Features.RealTimeMonitoring)
		fmt.Printf("  HTTP Server:          %v\n", license.Features.HTTPServer)
		fmt.Printf("  Custom Rules:         %v\n", license.Features.CustomRules)
		fmt.Printf("  SIEM Integration:     %v\n", license.Features.SIEMIntegration)
		fmt.Printf("  API Access:           %v\n", license.Features.APIAccess)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().Int32VarP(&analyzePID, "pid", "p", 0, "Analyze specific process by PID")
	analyzeCmd.Flags().BoolVarP(&analyzeAll, "all", "a", false, "Analyze all processes")
	analyzeCmd.Flags().BoolVarP(&analyzeSuspicious, "suspicious", "s", false, "Analyze only suspicious processes (default)")
	analyzeCmd.Flags().StringVarP(&analyzeConfigPath, "config", "c", "", "Path to config file")
	analyzeCmd.Flags().StringVarP(&analyzeTier, "tier", "t", "", "Force specific tier (rules, onnx, cloud)")

	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configShowCmd)

	rootCmd.AddCommand(licenseCmd)
}
