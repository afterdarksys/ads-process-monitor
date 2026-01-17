package ai

import "github.com/afterdarksystems/ads-process-monitor/internal/process"

// AnalysisResult represents the result of AI analysis on a process
type AnalysisResult struct {
	// Process that was analyzed
	PID  int32  `json:"pid"`
	Name string `json:"name"`

	// Analysis verdict
	Verdict    Verdict `json:"verdict"`
	Confidence int     `json:"confidence"` // 0-100

	// Threat classification
	ThreatType  string   `json:"threat_type,omitempty"`
	ThreatTags  []string `json:"threat_tags,omitempty"`
	MITREIDs    []string `json:"mitre_ids,omitempty"` // MITRE ATT&CK IDs

	// Explanation and recommendation
	Explanation    string `json:"explanation"`
	Recommendation string `json:"recommendation,omitempty"`

	// Which tier produced this result
	AnalysisTier string `json:"analysis_tier"` // "rules", "onnx", "cloud"

	// Raw scores from each tier (for debugging/transparency)
	TierScores map[string]int `json:"tier_scores,omitempty"`
}

// Verdict represents the analysis verdict
type Verdict string

const (
	VerdictClean      Verdict = "clean"
	VerdictSuspicious Verdict = "suspicious"
	VerdictMalicious  Verdict = "malicious"
	VerdictUnknown    Verdict = "unknown"
)

// ProcessContext contains all context needed for AI analysis
type ProcessContext struct {
	// Core process info
	Process *process.Info `json:"process"`

	// Parent chain (ancestors)
	ParentChain []*process.Info `json:"parent_chain,omitempty"`

	// Child processes
	Children []*process.Info `json:"children,omitempty"`

	// Network connections (if available)
	NetworkConnections []NetworkConnection `json:"network_connections,omitempty"`

	// Open files (if available)
	OpenFiles []string `json:"open_files,omitempty"`

	// Environment variables (sanitized)
	Environment map[string]string `json:"environment,omitempty"`

	// Behavioral events (from watch mode)
	BehaviorSequence []string `json:"behavior_sequence,omitempty"`
}

// NetworkConnection represents a process network connection
type NetworkConnection struct {
	Type       string `json:"type"` // "tcp", "udp"
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	Status     string `json:"status"`
}

// Analyzer is the interface all analysis tiers implement
type Analyzer interface {
	// Name returns the analyzer name/tier
	Name() string

	// Analyze performs analysis on a process context
	Analyze(ctx *ProcessContext) (*AnalysisResult, error)

	// IsAvailable returns true if this analyzer is ready to use
	IsAvailable() bool
}
