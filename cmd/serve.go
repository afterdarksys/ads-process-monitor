package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/afterdarksystems/ads-process-monitor/internal/process"
	"github.com/spf13/cobra"
)

var servePort int

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run as HTTP JSON API server",
	Long: `Run ads-process-monitor as an HTTP server exposing JSON API endpoints.

Endpoints:
  GET /health     - Health check
  GET /info       - Tool version and capabilities
  GET /processes  - List all processes
  GET /tree       - Process tree (optional ?pid=N)
  GET /suspicious - List suspicious processes only

This mode is used by the ADS Security Console GUI.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		mux := http.NewServeMux()

		// Health check
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "healthy",
				"time":   time.Now().UTC().Format(time.RFC3339),
			})
		})

		// Info
		mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"name":    "ads-process-monitor",
				"version": Version,
				"endpoints": []string{
					"/health",
					"/info",
					"/processes",
					"/tree",
					"/suspicious",
				},
			})
		})

		// List processes
		mux.HandleFunc("/processes", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			procs, err := process.List()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}

			sort.Slice(procs, func(i, j int) bool {
				return procs[i].PID < procs[j].PID
			})

			json.NewEncoder(w).Encode(map[string]interface{}{
				"version":   Version,
				"count":     len(procs),
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"processes": procs,
			})
		})

		// Process tree
		mux.HandleFunc("/tree", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			var rootPID int32 = 1
			// Could parse ?pid=N here if needed

			tree, err := process.BuildTree(rootPID)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"version":   Version,
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"tree":      tree,
			})
		})

		// Suspicious processes
		mux.HandleFunc("/suspicious", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			procs, err := process.List()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}

			suspicious := make([]*process.Info, 0)
			for _, p := range procs {
				if len(p.Suspicious) > 0 {
					suspicious = append(suspicious, p)
				}
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"version":   Version,
				"count":     len(suspicious),
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"processes": suspicious,
			})
		})

		addr := fmt.Sprintf("127.0.0.1:%d", servePort)
		fmt.Printf("ADS Process Monitor API server starting on http://%s\n", addr)
		fmt.Println("Endpoints: /health, /info, /processes, /tree, /suspicious")

		return http.ListenAndServe(addr, mux)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 9001, "Port to listen on")
}
