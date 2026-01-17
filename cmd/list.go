package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/afterdarksystems/ads-process-monitor/internal/process"
	"github.com/spf13/cobra"
)

var (
	listAll     bool
	listByUser  string
	listSuspicious bool
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List running processes",
	Long:  `List all running processes with security-relevant details.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		procs, err := process.List()
		if err != nil {
			return fmt.Errorf("failed to list processes: %w", err)
		}

		// Filter by user if specified
		if listByUser != "" {
			filtered := make([]*process.Info, 0)
			for _, p := range procs {
				if p.Username == listByUser {
					filtered = append(filtered, p)
				}
			}
			procs = filtered
		}

		// Filter suspicious only
		if listSuspicious {
			filtered := make([]*process.Info, 0)
			for _, p := range procs {
				if len(p.Suspicious) > 0 {
					filtered = append(filtered, p)
				}
			}
			procs = filtered
		}

		// Sort by PID
		sort.Slice(procs, func(i, j int) bool {
			return procs[i].PID < procs[j].PID
		})

		if outputJSON {
			return outputJSONList(procs)
		}

		return outputTable(procs)
	},
}

func outputJSONList(procs []*process.Info) error {
	output := map[string]interface{}{
		"version":   Version,
		"count":     len(procs),
		"processes": procs,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func outputTable(procs []*process.Info) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PID\tPPID\tUSER\tNAME\tCPU%\tMEM%\tSTATUS\tFLAGS")
	fmt.Fprintln(w, "---\t----\t----\t----\t----\t----\t------\t-----")

	for _, p := range procs {
		flags := ""
		if len(p.Suspicious) > 0 {
			flags = "⚠️ " + p.Suspicious[0]
		}
		fmt.Fprintf(w, "%d\t%d\t%s\t%s\t%.1f\t%.1f\t%s\t%s\n",
			p.PID, p.PPID, p.Username, truncate(p.Name, 20),
			p.CPUPercent, p.MemPercent, p.Status, flags)
	}

	return w.Flush()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolVarP(&listAll, "all", "a", false, "Show all processes including system")
	listCmd.Flags().StringVarP(&listByUser, "user", "u", "", "Filter by username")
	listCmd.Flags().BoolVarP(&listSuspicious, "suspicious", "s", false, "Show only suspicious processes")
}
