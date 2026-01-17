package ai

import (
	"strings"
)

// RulesAnalyzer implements rule-based threat detection (Tier 1)
// Always available, no dependencies, no API keys required
type RulesAnalyzer struct {
	config *Config
	rules  []Rule
}

// Rule defines a detection rule
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    int // 1-10
	MITREIDs    []string
	ThreatType  string
	Check       func(ctx *ProcessContext) (bool, string)
}

// NewRulesAnalyzer creates a new rules-based analyzer
func NewRulesAnalyzer(config *Config) *RulesAnalyzer {
	ra := &RulesAnalyzer{
		config: config,
	}
	ra.initRules()
	return ra
}

func (ra *RulesAnalyzer) Name() string {
	return "rules"
}

func (ra *RulesAnalyzer) IsAvailable() bool {
	return true // Always available
}

func (ra *RulesAnalyzer) Analyze(ctx *ProcessContext) (*AnalysisResult, error) {
	result := &AnalysisResult{
		PID:          ctx.Process.PID,
		Name:         ctx.Process.Name,
		Verdict:      VerdictClean,
		Confidence:   100,
		AnalysisTier: "rules",
		TierScores:   make(map[string]int),
	}

	var matchedRules []Rule
	var explanations []string
	maxSeverity := 0

	for _, rule := range ra.rules {
		matched, detail := rule.Check(ctx)
		if matched {
			matchedRules = append(matchedRules, rule)
			explanations = append(explanations, detail)
			if rule.Severity > maxSeverity {
				maxSeverity = rule.Severity
			}
			result.ThreatTags = append(result.ThreatTags, rule.ThreatType)
			result.MITREIDs = append(result.MITREIDs, rule.MITREIDs...)
		}
	}

	// Calculate verdict based on severity
	if maxSeverity >= 8 {
		result.Verdict = VerdictMalicious
		result.Confidence = 90
	} else if maxSeverity >= 5 {
		result.Verdict = VerdictSuspicious
		result.Confidence = 70
	} else if maxSeverity >= 3 {
		result.Verdict = VerdictSuspicious
		result.Confidence = 50
	}

	// Build explanation
	if len(explanations) > 0 {
		result.Explanation = strings.Join(explanations, "; ")
		result.ThreatType = matchedRules[0].ThreatType
	} else {
		result.Explanation = "No suspicious indicators detected by rule-based analysis"
	}

	result.TierScores["rules"] = maxSeverity * 10

	return result, nil
}

func (ra *RulesAnalyzer) initRules() {
	ra.rules = []Rule{
		// Network-based threats
		{
			ID:          "NET001",
			Name:        "Reverse Shell Detection",
			Description: "Detects potential reverse shell patterns",
			Severity:    9,
			MITREIDs:    []string{"T1059", "T1071"},
			ThreatType:  "reverse_shell",
			Check: func(ctx *ProcessContext) (bool, string) {
				cmd := strings.ToLower(ctx.Process.Cmdline)
				if strings.Contains(cmd, "/dev/tcp") || strings.Contains(cmd, "/dev/udp") {
					return true, "Bash reverse shell pattern detected (/dev/tcp or /dev/udp)"
				}
				if strings.Contains(cmd, "nc -e") || strings.Contains(cmd, "ncat -e") {
					return true, "Netcat reverse shell pattern detected"
				}
				if strings.Contains(cmd, "bash -i") && strings.Contains(cmd, ">&") {
					return true, "Interactive bash redirect pattern detected"
				}
				return false, ""
			},
		},
		{
			ID:          "NET002",
			Name:        "Suspicious Network Tool",
			Description: "Known network exploitation tools",
			Severity:    7,
			MITREIDs:    []string{"T1095"},
			ThreatType:  "network_tool",
			Check: func(ctx *ProcessContext) (bool, string) {
				name := strings.ToLower(ctx.Process.Name)
				tools := []string{"nc", "ncat", "netcat", "socat", "nmap", "masscan"}
				for _, tool := range tools {
					if name == tool {
						return true, "Network reconnaissance/exploitation tool: " + tool
					}
				}
				return false, ""
			},
		},

		// Execution from suspicious locations
		{
			ID:          "EXEC001",
			Name:        "Temp Directory Execution",
			Description: "Process running from temp directory",
			Severity:    6,
			MITREIDs:    []string{"T1204"},
			ThreatType:  "suspicious_location",
			Check: func(ctx *ProcessContext) (bool, string) {
				exe := ctx.Process.Exe
				if strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/var/tmp/") {
					return true, "Execution from temporary directory: " + exe
				}
				return false, ""
			},
		},
		{
			ID:          "EXEC002",
			Name:        "Hidden File Execution",
			Description: "Process running from hidden file",
			Severity:    7,
			MITREIDs:    []string{"T1564"},
			ThreatType:  "hidden_execution",
			Check: func(ctx *ProcessContext) (bool, string) {
				if strings.Contains(ctx.Process.Exe, "/.") {
					return true, "Execution from hidden file: " + ctx.Process.Exe
				}
				return false, ""
			},
		},
		{
			ID:          "EXEC003",
			Name:        "Downloads Execution",
			Description: "Process running from Downloads folder",
			Severity:    5,
			MITREIDs:    []string{"T1204"},
			ThreatType:  "downloads_execution",
			Check: func(ctx *ProcessContext) (bool, string) {
				if strings.Contains(ctx.Process.Exe, "/Downloads/") {
					return true, "Execution from Downloads directory: " + ctx.Process.Exe
				}
				return false, ""
			},
		},

		// Script execution
		{
			ID:          "SCRIPT001",
			Name:        "Encoded Command Execution",
			Description: "Base64 or encoded command execution",
			Severity:    8,
			MITREIDs:    []string{"T1027", "T1059"},
			ThreatType:  "encoded_execution",
			Check: func(ctx *ProcessContext) (bool, string) {
				cmd := strings.ToLower(ctx.Process.Cmdline)
				if strings.Contains(cmd, "base64") && (strings.Contains(cmd, "-d") || strings.Contains(cmd, "--decode")) {
					return true, "Base64 decode in command line"
				}
				if strings.Contains(cmd, "eval") && strings.Contains(cmd, "base64") {
					return true, "Eval with base64 encoded payload"
				}
				return false, ""
			},
		},
		{
			ID:          "SCRIPT002",
			Name:        "Long Encoded Argument",
			Description: "Suspiciously long encoded argument",
			Severity:    6,
			MITREIDs:    []string{"T1027"},
			ThreatType:  "obfuscation",
			Check: func(ctx *ProcessContext) (bool, string) {
				if len(ctx.Process.Cmdline) > 1000 {
					// Check if it looks like base64
					noSpaces := strings.ReplaceAll(ctx.Process.Cmdline, " ", "")
					if len(noSpaces) > 500 {
						return true, "Very long command line argument (potential encoded payload)"
					}
				}
				return false, ""
			},
		},
		{
			ID:          "SCRIPT003",
			Name:        "Osascript Execution",
			Description: "AppleScript execution (often used for macOS malware)",
			Severity:    5,
			MITREIDs:    []string{"T1059.002"},
			ThreatType:  "applescript",
			Check: func(ctx *ProcessContext) (bool, string) {
				if ctx.Process.Name == "osascript" {
					cmd := ctx.Process.Cmdline
					// More suspicious if executing inline script
					if strings.Contains(cmd, "-e") {
						return true, "Inline AppleScript execution via osascript"
					}
				}
				return false, ""
			},
		},

		// Credential access
		{
			ID:          "CRED001",
			Name:        "Keychain Access",
			Description: "Suspicious keychain access",
			Severity:    7,
			MITREIDs:    []string{"T1555.001"},
			ThreatType:  "credential_access",
			Check: func(ctx *ProcessContext) (bool, string) {
				cmd := strings.ToLower(ctx.Process.Cmdline)
				if strings.Contains(cmd, "security find-") || strings.Contains(cmd, "security dump-") {
					return true, "Keychain credential extraction attempt"
				}
				return false, ""
			},
		},
		{
			ID:          "CRED002",
			Name:        "SSH Key Access",
			Description: "Potential SSH key theft",
			Severity:    6,
			MITREIDs:    []string{"T1552.004"},
			ThreatType:  "credential_access",
			Check: func(ctx *ProcessContext) (bool, string) {
				for _, file := range ctx.OpenFiles {
					if strings.Contains(file, ".ssh/id_") {
						return true, "Access to SSH private key: " + file
					}
				}
				return false, ""
			},
		},

		// Persistence
		{
			ID:          "PERSIST001",
			Name:        "Launch Agent Modification",
			Description: "Modification of LaunchAgents",
			Severity:    8,
			MITREIDs:    []string{"T1543.001"},
			ThreatType:  "persistence",
			Check: func(ctx *ProcessContext) (bool, string) {
				cmd := ctx.Process.Cmdline
				if strings.Contains(cmd, "LaunchAgents") || strings.Contains(cmd, "LaunchDaemons") {
					if strings.Contains(cmd, "cp ") || strings.Contains(cmd, "mv ") || strings.Contains(cmd, "write") {
						return true, "Potential persistence via LaunchAgent/LaunchDaemon"
					}
				}
				return false, ""
			},
		},

		// Process masquerading
		{
			ID:          "MASQ001",
			Name:        "Process Masquerading",
			Description: "Process name doesn't match executable",
			Severity:    7,
			MITREIDs:    []string{"T1036"},
			ThreatType:  "masquerading",
			Check: func(ctx *ProcessContext) (bool, string) {
				if ctx.Process.Exe == "" || ctx.Process.Name == "" {
					return false, ""
				}
				// Get basename of exe
				exeBase := ctx.Process.Exe
				if idx := strings.LastIndex(ctx.Process.Exe, "/"); idx >= 0 {
					exeBase = ctx.Process.Exe[idx+1:]
				}
				// Check if running from suspicious location with mismatched name
				if strings.HasPrefix(ctx.Process.Exe, "/tmp/") && exeBase != ctx.Process.Name {
					return true, "Process masquerading: name=" + ctx.Process.Name + " exe=" + ctx.Process.Exe
				}
				return false, ""
			},
		},

		// Cryptomining
		{
			ID:          "CRYPTO001",
			Name:        "Cryptominer Detection",
			Description: "Known cryptomining patterns",
			Severity:    6,
			MITREIDs:    []string{"T1496"},
			ThreatType:  "cryptominer",
			Check: func(ctx *ProcessContext) (bool, string) {
				cmd := strings.ToLower(ctx.Process.Cmdline)
				indicators := []string{"stratum+tcp", "xmrig", "minerd", "cpuminer", "cryptonight"}
				for _, ind := range indicators {
					if strings.Contains(cmd, ind) {
						return true, "Cryptomining indicator: " + ind
					}
				}
				return false, ""
			},
		},
	}
}

// AddRule adds a custom rule (for Pro+ licenses)
func (ra *RulesAnalyzer) AddRule(rule Rule) {
	ra.rules = append(ra.rules, rule)
}
