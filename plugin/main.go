// ads-process-monitor-plugin - darkd service plugin for process monitoring
//
// This plugin integrates ads-process-monitor with afterdark-darkd,
// allowing it to run as a managed service within the daemon.
//
// Build:
//   go build -o ads-process-monitor-plugin .
//
// Install:
//   sudo cp ads-process-monitor-plugin /var/lib/afterdark-darkd/plugins/
//
// Configure in darkd.yaml:
//   plugins:
//     ads-process-monitor:
//       watch_interval_ms: 500
//       enable_ai_analysis: true
//       alert_on_suspicious: true
//
package main

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	sdk "github.com/afterdarksys/afterdark-darkd/pkg/pluginsdk"

	"github.com/afterdarksystems/ads-process-monitor/internal/ai"
	"github.com/afterdarksystems/ads-process-monitor/internal/process"
)

const (
	PluginName    = "ads-process-monitor"
	PluginVersion = "0.1.0"
)

// ProcessMonitorPlugin implements the darkd ServicePlugin interface
type ProcessMonitorPlugin struct {
	sdk.BaseServicePlugin

	// Configuration
	watchInterval   time.Duration
	enableAI        bool
	alertSuspicious bool

	// State
	analyzer    *ai.TieredAnalyzer
	knownPIDs   map[int32]bool
	mutex       sync.RWMutex
	stopChan    chan struct{}
	logger      sdk.Logger
}

func (p *ProcessMonitorPlugin) Info() sdk.PluginInfo {
	return sdk.PluginInfo{
		Name:        PluginName,
		Version:     PluginVersion,
		Type:        sdk.PluginTypeService,
		Description: "macOS Process Attack Visibility - monitors processes for suspicious activity",
		Author:      "After Dark Systems",
		License:     "Proprietary",
		Capabilities: []string{
			"process_list",
			"process_tree",
			"process_watch",
			"ai_analysis",
		},
	}
}

func (p *ProcessMonitorPlugin) Configure(config map[string]interface{}) error {
	if err := p.BaseServicePlugin.Configure(config); err != nil {
		return err
	}

	// Parse configuration
	if interval, ok := config["watch_interval_ms"].(float64); ok {
		p.watchInterval = time.Duration(interval) * time.Millisecond
	} else {
		p.watchInterval = 500 * time.Millisecond
	}

	if enableAI, ok := config["enable_ai_analysis"].(bool); ok {
		p.enableAI = enableAI
	} else {
		p.enableAI = true
	}

	if alert, ok := config["alert_on_suspicious"].(bool); ok {
		p.alertSuspicious = alert
	} else {
		p.alertSuspicious = true
	}

	// Initialize AI analyzer if enabled
	if p.enableAI {
		aiConfig := ai.DefaultConfig()
		licenseMgr := ai.NewLicenseManager()
		licenseMgr.LoadLicense("")
		p.analyzer = ai.NewTieredAnalyzer(aiConfig, licenseMgr)
	}

	return nil
}

func (p *ProcessMonitorPlugin) Start(ctx context.Context) error {
	if err := p.BaseServicePlugin.Start(ctx); err != nil {
		return err
	}

	p.knownPIDs = make(map[int32]bool)
	p.stopChan = make(chan struct{})

	// Initialize known PIDs
	procs, err := process.List()
	if err == nil {
		for _, proc := range procs {
			p.knownPIDs[proc.PID] = true
		}
	}

	// Start background watcher
	go p.watchLoop()

	p.SetState(sdk.PluginStateRunning, "monitoring processes")
	return nil
}

func (p *ProcessMonitorPlugin) Stop(ctx context.Context) error {
	close(p.stopChan)
	p.SetState(sdk.PluginStateStopped, "stopped")
	return p.BaseServicePlugin.Stop(ctx)
}

func (p *ProcessMonitorPlugin) Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	switch action {
	case "list":
		return p.handleList(params)
	case "tree":
		return p.handleTree(params)
	case "analyze":
		return p.handleAnalyze(params)
	case "status":
		return p.handleStatus()
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (p *ProcessMonitorPlugin) handleList(params map[string]interface{}) (map[string]interface{}, error) {
	procs, err := process.List()
	if err != nil {
		return nil, err
	}

	// Filter if requested
	if user, ok := params["user"].(string); ok && user != "" {
		filtered := make([]*process.Info, 0)
		for _, proc := range procs {
			if proc.Username == user {
				filtered = append(filtered, proc)
			}
		}
		procs = filtered
	}

	if suspicious, ok := params["suspicious"].(bool); ok && suspicious {
		filtered := make([]*process.Info, 0)
		for _, proc := range procs {
			if len(proc.Suspicious) > 0 {
				filtered = append(filtered, proc)
			}
		}
		procs = filtered
	}

	return map[string]interface{}{
		"count":     len(procs),
		"processes": procs,
	}, nil
}

func (p *ProcessMonitorPlugin) handleTree(params map[string]interface{}) (map[string]interface{}, error) {
	var rootPID int32 = 1
	if pid, ok := params["pid"].(float64); ok {
		rootPID = int32(pid)
	}

	tree, err := process.BuildTree(rootPID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"tree": tree,
	}, nil
}

func (p *ProcessMonitorPlugin) handleAnalyze(params map[string]interface{}) (map[string]interface{}, error) {
	if p.analyzer == nil {
		return nil, fmt.Errorf("AI analysis not enabled")
	}

	pid, ok := params["pid"].(float64)
	if !ok {
		return nil, fmt.Errorf("pid parameter required")
	}

	// Get process info
	procs, err := process.List()
	if err != nil {
		return nil, err
	}

	var targetProc *process.Info
	for _, proc := range procs {
		if proc.PID == int32(pid) {
			targetProc = proc
			break
		}
	}

	if targetProc == nil {
		return nil, fmt.Errorf("process %d not found", int32(pid))
	}

	// Analyze
	result, err := p.analyzer.AnalyzeProcess(targetProc)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"result": result,
	}, nil
}

func (p *ProcessMonitorPlugin) handleStatus() (map[string]interface{}, error) {
	p.mutex.RLock()
	knownCount := len(p.knownPIDs)
	p.mutex.RUnlock()

	tiers := []string{}
	if p.analyzer != nil {
		tiers = p.analyzer.GetAvailableTiers()
	}

	return map[string]interface{}{
		"known_processes":  knownCount,
		"watch_interval":   p.watchInterval.String(),
		"ai_enabled":       p.enableAI,
		"alert_suspicious": p.alertSuspicious,
		"available_tiers":  tiers,
	}, nil
}

func (p *ProcessMonitorPlugin) watchLoop() {
	ticker := time.NewTicker(p.watchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.checkForNewProcesses()
		}
	}
}

func (p *ProcessMonitorPlugin) checkForNewProcesses() {
	procs, err := process.List()
	if err != nil {
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	currentPIDs := make(map[int32]bool)

	for _, proc := range procs {
		currentPIDs[proc.PID] = true

		if !p.knownPIDs[proc.PID] {
			// New process detected
			p.knownPIDs[proc.PID] = true
			p.handleNewProcess(proc)
		}
	}

	// Clean up dead PIDs
	for pid := range p.knownPIDs {
		if !currentPIDs[pid] {
			delete(p.knownPIDs, pid)
		}
	}
}

func (p *ProcessMonitorPlugin) handleNewProcess(proc *process.Info) {
	// Check if suspicious
	if p.alertSuspicious && len(proc.Suspicious) > 0 {
		// Would emit event to daemon here
		// p.emitEvent("suspicious_process", proc)
	}

	// Run AI analysis if enabled
	if p.enableAI && p.analyzer != nil {
		result, err := p.analyzer.AnalyzeProcess(proc)
		if err == nil && result.Verdict != ai.VerdictClean {
			// Would emit event to daemon here
			// p.emitEvent("ai_detection", result)
		}
	}
}

func main() {
	sdk.ServeServicePlugin(&ProcessMonitorPlugin{})
}

// Required for compilation - would be imported from actual darkd SDK
import "fmt"
