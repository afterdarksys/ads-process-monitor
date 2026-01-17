package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/afterdarksystems/ads-process-monitor/internal/process"
	"github.com/spf13/cobra"
)

var watchInterval int

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch for new process executions",
	Long:  `Monitor for new process executions in real-time. Useful for detecting malicious process spawning.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(os.Stderr, "Watching for new processes... (Ctrl+C to stop)")

		// Track known PIDs
		known := make(map[int32]bool)
		procs, _ := process.List()
		for _, p := range procs {
			known[p.PID] = true
		}

		// Handle interrupt
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		ticker := time.NewTicker(time.Duration(watchInterval) * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-sigChan:
				fmt.Fprintln(os.Stderr, "\nStopping watch...")
				return nil
			case <-ticker.C:
				procs, err := process.List()
				if err != nil {
					continue
				}

				for _, p := range procs {
					if !known[p.PID] {
						known[p.PID] = true
						outputNewProcess(p)
					}
				}

				// Clean up dead PIDs periodically
				currentPIDs := make(map[int32]bool)
				for _, p := range procs {
					currentPIDs[p.PID] = true
				}
				for pid := range known {
					if !currentPIDs[pid] {
						delete(known, pid)
					}
				}
			}
		}
	},
}

func outputNewProcess(p *process.Info) {
	if outputJSON {
		event := map[string]interface{}{
			"event":     "new_process",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"process":   p,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.Encode(event)
	} else {
		suspicious := ""
		if len(p.Suspicious) > 0 {
			suspicious = " ⚠️ SUSPICIOUS: " + p.Suspicious[0]
		}
		fmt.Printf("[%s] NEW: PID=%d PPID=%d USER=%s CMD=%s%s\n",
			time.Now().Format("15:04:05"),
			p.PID, p.PPID, p.Username, p.Cmdline, suspicious)
	}
}

func init() {
	rootCmd.AddCommand(watchCmd)
	watchCmd.Flags().IntVarP(&watchInterval, "interval", "i", 500, "Poll interval in milliseconds")
}
