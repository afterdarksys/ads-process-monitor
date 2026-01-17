package ai

import (
	"fmt"
	"os"
	"path/filepath"
)

// ONNXAnalyzer implements on-device ML inference (Tier 2)
// Requires Pro+ license and ONNX model file
type ONNXAnalyzer struct {
	config    *Config
	modelPath string
	loaded    bool
	// In a full implementation, this would hold the ONNX runtime session
	// session *ort.Session
}

// NewONNXAnalyzer creates a new ONNX-based analyzer
func NewONNXAnalyzer(config *Config) *ONNXAnalyzer {
	modelPath := config.Models.ONNXModelPath

	// Expand ~ to home directory
	if len(modelPath) >= 2 && modelPath[:2] == "~/" {
		home, _ := os.UserHomeDir()
		modelPath = filepath.Join(home, modelPath[2:])
	}

	return &ONNXAnalyzer{
		config:    config,
		modelPath: modelPath,
		loaded:    false,
	}
}

func (oa *ONNXAnalyzer) Name() string {
	return "onnx"
}

func (oa *ONNXAnalyzer) IsAvailable() bool {
	// Check if model file exists
	if _, err := os.Stat(oa.modelPath); err != nil {
		return false
	}

	// Check if ONNX is enabled in config
	if !oa.config.Tiers.ONNXEnabled {
		return false
	}

	return true
}

// LoadModel loads the ONNX model into memory
func (oa *ONNXAnalyzer) LoadModel() error {
	if oa.loaded {
		return nil
	}

	// Check if model exists
	if _, err := os.Stat(oa.modelPath); err != nil {
		return fmt.Errorf("ONNX model not found at %s: %w", oa.modelPath, err)
	}

	// TODO: In full implementation, load ONNX model using onnxruntime_go
	// Example:
	// ort.SetSharedLibraryPath("/path/to/libonnxruntime.dylib")
	// err := ort.InitializeEnvironment()
	// session, err := ort.NewSession(oa.modelPath, ...)

	oa.loaded = true
	return nil
}

func (oa *ONNXAnalyzer) Analyze(ctx *ProcessContext) (*AnalysisResult, error) {
	if !oa.IsAvailable() {
		return nil, fmt.Errorf("ONNX analyzer not available - model not found or disabled")
	}

	// Ensure model is loaded
	if err := oa.LoadModel(); err != nil {
		return nil, err
	}

	result := &AnalysisResult{
		PID:          ctx.Process.PID,
		Name:         ctx.Process.Name,
		Verdict:      VerdictUnknown,
		Confidence:   0,
		AnalysisTier: "onnx",
		TierScores:   make(map[string]int),
	}

	// Extract features for the model
	features := oa.extractFeatures(ctx)

	// TODO: In full implementation, run inference
	// inputTensor, _ := ort.NewTensor(features)
	// outputs, _ := oa.session.Run([]ort.Tensor{inputTensor})
	// scores := outputs[0].GetData().([]float32)

	// For now, return a placeholder result
	// The actual implementation would use the model output
	result.Verdict = VerdictUnknown
	result.Confidence = 0
	result.Explanation = "ONNX model inference not yet implemented - model file required"

	// Placeholder: simulate model output based on features
	score := oa.simulateModelScore(features)
	result.TierScores["onnx"] = score

	if score >= 80 {
		result.Verdict = VerdictMalicious
		result.Confidence = score
		result.ThreatType = "ml_detected_threat"
		result.Explanation = "On-device ML model detected malicious behavior patterns"
	} else if score >= 50 {
		result.Verdict = VerdictSuspicious
		result.Confidence = score
		result.Explanation = "On-device ML model detected suspicious behavior patterns"
	} else {
		result.Verdict = VerdictClean
		result.Confidence = 100 - score
		result.Explanation = "On-device ML model found no significant threats"
	}

	return result, nil
}

// extractFeatures converts process context to model input features
func (oa *ONNXAnalyzer) extractFeatures(ctx *ProcessContext) []float32 {
	// Feature vector for process classification
	// This would be tailored to match your trained model
	features := make([]float32, 50) // Example: 50 features

	// Feature 1-5: Process name characteristics
	features[0] = float32(len(ctx.Process.Name))
	features[1] = boolToFloat(hasSpecialChars(ctx.Process.Name))
	features[2] = boolToFloat(ctx.Process.Name == "")

	// Feature 6-10: Command line characteristics
	features[5] = float32(len(ctx.Process.Cmdline))
	features[6] = boolToFloat(containsSuspiciousKeywords(ctx.Process.Cmdline))
	features[7] = boolToFloat(hasBase64Pattern(ctx.Process.Cmdline))

	// Feature 11-15: Executable path
	features[10] = boolToFloat(isFromTempDir(ctx.Process.Exe))
	features[11] = boolToFloat(isHiddenPath(ctx.Process.Exe))
	features[12] = boolToFloat(isFromDownloads(ctx.Process.Exe))

	// Feature 16-20: Process hierarchy
	features[15] = float32(len(ctx.ParentChain))
	features[16] = boolToFloat(hasUnusualParent(ctx))

	// Feature 21-25: Network indicators
	features[20] = float32(len(ctx.NetworkConnections))
	features[21] = boolToFloat(hasExternalConnections(ctx))

	// Feature 26-30: File access indicators
	features[25] = float32(len(ctx.OpenFiles))
	features[26] = boolToFloat(accessesSensitiveFiles(ctx))

	// ... more features would be added based on model requirements

	return features
}

// simulateModelScore provides a placeholder score until real model is integrated
func (oa *ONNXAnalyzer) simulateModelScore(features []float32) int {
	// Simple heuristic simulation - replace with actual model inference
	score := 0

	if features[6] > 0 { // Suspicious keywords
		score += 30
	}
	if features[7] > 0 { // Base64 pattern
		score += 25
	}
	if features[10] > 0 { // Temp dir
		score += 20
	}
	if features[11] > 0 { // Hidden path
		score += 25
	}
	if features[21] > 0 { // External connections
		score += 15
	}
	if features[26] > 0 { // Sensitive files
		score += 20
	}

	if score > 100 {
		score = 100
	}

	return score
}

// Helper functions for feature extraction
func boolToFloat(b bool) float32 {
	if b {
		return 1.0
	}
	return 0.0
}

func hasSpecialChars(s string) bool {
	for _, c := range s {
		if c < 32 || c > 126 {
			return true
		}
	}
	return false
}

func containsSuspiciousKeywords(s string) bool {
	keywords := []string{"base64", "eval", "exec", "shell", "reverse", "payload", "exploit"}
	for _, kw := range keywords {
		if containsIgnoreCase(s, kw) {
			return true
		}
	}
	return false
}

func hasBase64Pattern(s string) bool {
	// Simple check for base64-like content
	if len(s) < 20 {
		return false
	}
	b64Chars := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			b64Chars++
		}
	}
	return float32(b64Chars)/float32(len(s)) > 0.8
}

func isFromTempDir(path string) bool {
	return len(path) >= 5 && (path[:5] == "/tmp/" || (len(path) >= 9 && path[:9] == "/var/tmp/"))
}

func isHiddenPath(path string) bool {
	return containsIgnoreCase(path, "/.")
}

func isFromDownloads(path string) bool {
	return containsIgnoreCase(path, "/Downloads/")
}

func hasUnusualParent(ctx *ProcessContext) bool {
	if len(ctx.ParentChain) < 2 {
		return false
	}
	// Check for unusual parent processes
	unusualParents := []string{"python", "python3", "perl", "ruby", "bash", "sh", "zsh"}
	parent := ctx.ParentChain[0]
	for _, up := range unusualParents {
		if parent.Name == up && containsIgnoreCase(parent.Cmdline, "-c") {
			return true
		}
	}
	return false
}

func hasExternalConnections(ctx *ProcessContext) bool {
	for _, conn := range ctx.NetworkConnections {
		if conn.RemoteAddr != "" && conn.RemoteAddr != "127.0.0.1" && conn.RemoteAddr != "::1" {
			return true
		}
	}
	return false
}

func accessesSensitiveFiles(ctx *ProcessContext) bool {
	sensitivePatterns := []string{".ssh/", "keychain", ".aws/", ".gnupg/", "passwd", "shadow"}
	for _, file := range ctx.OpenFiles {
		for _, pattern := range sensitivePatterns {
			if containsIgnoreCase(file, pattern) {
				return true
			}
		}
	}
	return false
}

func containsIgnoreCase(s, substr string) bool {
	sLower := make([]byte, len(s))
	substrLower := make([]byte, len(substr))
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			sLower[i] = s[i] + 32
		} else {
			sLower[i] = s[i]
		}
	}
	for i := 0; i < len(substr); i++ {
		if substr[i] >= 'A' && substr[i] <= 'Z' {
			substrLower[i] = substr[i] + 32
		} else {
			substrLower[i] = substr[i]
		}
	}
	return bytesContains(sLower, substrLower)
}

func bytesContains(s, substr []byte) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
