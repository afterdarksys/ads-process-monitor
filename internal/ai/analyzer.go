package ai

import (
	"fmt"

	"github.com/afterdarksystems/ads-process-monitor/internal/process"
)

// TieredAnalyzer orchestrates analysis across all tiers
type TieredAnalyzer struct {
	config  *Config
	license *LicenseManager

	// Analysis tiers
	rulesAnalyzer *RulesAnalyzer
	onnxAnalyzer  *ONNXAnalyzer
	cloudAnalyzer *CloudAnalyzer
}

// NewTieredAnalyzer creates a new tiered analyzer
func NewTieredAnalyzer(config *Config, license *LicenseManager) *TieredAnalyzer {
	ta := &TieredAnalyzer{
		config:  config,
		license: license,
	}

	// Initialize available analyzers based on config and license
	if config.Tiers.RulesEnabled && license.HasFeature("rules_analysis") {
		ta.rulesAnalyzer = NewRulesAnalyzer(config)
	}

	if config.Tiers.ONNXEnabled && license.HasFeature("onnx_analysis") {
		ta.onnxAnalyzer = NewONNXAnalyzer(config)
	}

	if config.Tiers.CloudEnabled && license.HasFeature("cloud_analysis") {
		ta.cloudAnalyzer = NewCloudAnalyzer(config)
	}

	return ta
}

// AnalyzeProcess analyzes a single process through the tier system
func (ta *TieredAnalyzer) AnalyzeProcess(proc *process.Info) (*AnalysisResult, error) {
	// Build context for the process
	ctx := &ProcessContext{
		Process: proc,
	}

	// Get parent chain if available
	ancestors, err := process.FindAncestors(proc.PID)
	if err == nil && len(ancestors) > 1 {
		ctx.ParentChain = ancestors[1:] // Skip self
	}

	return ta.Analyze(ctx)
}

// Analyze performs tiered analysis on a process context
func (ta *TieredAnalyzer) Analyze(ctx *ProcessContext) (*AnalysisResult, error) {
	var results []*AnalysisResult
	var finalResult *AnalysisResult

	// Tier 1: Rule-based (always try first)
	if ta.rulesAnalyzer != nil && ta.rulesAnalyzer.IsAvailable() {
		result, err := ta.rulesAnalyzer.Analyze(ctx)
		if err == nil {
			results = append(results, result)
			finalResult = result
		}
	}

	// Tier 2: ONNX on-device (if available and enabled)
	if ta.onnxAnalyzer != nil && ta.onnxAnalyzer.IsAvailable() {
		result, err := ta.onnxAnalyzer.Analyze(ctx)
		if err == nil {
			results = append(results, result)
			// ONNX takes precedence if available
			if finalResult == nil || result.Confidence > finalResult.Confidence {
				finalResult = result
			}
		}
	}

	// Tier 3: Cloud AI (if enabled and conditions met)
	if ta.cloudAnalyzer != nil && ta.cloudAnalyzer.IsAvailable() {
		// Only call cloud if:
		// 1. Previous results indicate suspicion, OR
		// 2. Auto-escalate is enabled and confidence is low
		shouldEscalate := false

		if finalResult != nil {
			if finalResult.Verdict == VerdictSuspicious || finalResult.Verdict == VerdictMalicious {
				shouldEscalate = true
			}
			if ta.config.Analysis.AutoEscalate && finalResult.Confidence < ta.config.Analysis.EscalateThreshold {
				shouldEscalate = true
			}
		} else {
			// No previous results, try cloud
			shouldEscalate = true
		}

		if shouldEscalate {
			result, err := ta.cloudAnalyzer.Analyze(ctx)
			if err == nil {
				results = append(results, result)
				// Cloud takes highest precedence
				finalResult = result
			}
		}
	}

	if finalResult == nil {
		return &AnalysisResult{
			PID:          ctx.Process.PID,
			Name:         ctx.Process.Name,
			Verdict:      VerdictUnknown,
			Confidence:   0,
			AnalysisTier: "none",
			Explanation:  "No analyzers available",
		}, nil
	}

	// Merge tier scores from all results
	if finalResult.TierScores == nil {
		finalResult.TierScores = make(map[string]int)
	}
	for _, r := range results {
		for tier, score := range r.TierScores {
			finalResult.TierScores[tier] = score
		}
	}

	return finalResult, nil
}

// AnalyzeBatch analyzes multiple processes
func (ta *TieredAnalyzer) AnalyzeBatch(procs []*process.Info) ([]*AnalysisResult, error) {
	results := make([]*AnalysisResult, 0, len(procs))

	for _, proc := range procs {
		result, err := ta.AnalyzeProcess(proc)
		if err != nil {
			// Log error but continue with other processes
			result = &AnalysisResult{
				PID:         proc.PID,
				Name:        proc.Name,
				Verdict:     VerdictUnknown,
				Confidence:  0,
				Explanation: fmt.Sprintf("Analysis error: %v", err),
			}
		}
		results = append(results, result)
	}

	return results, nil
}

// AnalyzeSuspiciousOnly analyzes only processes with suspicious indicators
func (ta *TieredAnalyzer) AnalyzeSuspiciousOnly(procs []*process.Info) ([]*AnalysisResult, error) {
	suspicious := make([]*process.Info, 0)
	for _, proc := range procs {
		if len(proc.Suspicious) > 0 {
			suspicious = append(suspicious, proc)
		}
	}
	return ta.AnalyzeBatch(suspicious)
}

// GetAvailableTiers returns which analysis tiers are available
func (ta *TieredAnalyzer) GetAvailableTiers() []string {
	tiers := make([]string, 0, 3)

	if ta.rulesAnalyzer != nil && ta.rulesAnalyzer.IsAvailable() {
		tiers = append(tiers, "rules")
	}
	if ta.onnxAnalyzer != nil && ta.onnxAnalyzer.IsAvailable() {
		tiers = append(tiers, "onnx")
	}
	if ta.cloudAnalyzer != nil && ta.cloudAnalyzer.IsAvailable() {
		tiers = append(tiers, "cloud")
	}

	return tiers
}

// GetLicenseInfo returns current license information
func (ta *TieredAnalyzer) GetLicenseInfo() map[string]interface{} {
	license := ta.license.GetLicense()
	return map[string]interface{}{
		"license_id":      license.LicenseID,
		"type":            license.Type,
		"expires_at":      license.ExpiresAt,
		"features": map[string]bool{
			"rules_analysis":      license.Features.RulesAnalysis,
			"onnx_analysis":       license.Features.ONNXAnalysis,
			"cloud_analysis":      license.Features.CloudAnalysis,
			"realtime_monitoring": license.Features.RealTimeMonitoring,
			"http_server":         license.Features.HTTPServer,
			"custom_rules":        license.Features.CustomRules,
		},
	}
}
