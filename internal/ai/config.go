package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds AI analysis configuration
type Config struct {
	// Analysis tier settings
	Tiers TierConfig `json:"tiers"`

	// API keys for cloud providers
	APIKeys APIKeysConfig `json:"api_keys"`

	// Model paths for on-device inference
	Models ModelsConfig `json:"models"`

	// Analysis behavior settings
	Analysis AnalysisConfig `json:"analysis"`
}

// TierConfig controls which analysis tiers are enabled
type TierConfig struct {
	// Tier 1: Rule-based (always available, no dependencies)
	RulesEnabled bool `json:"rules_enabled"`

	// Tier 2: On-device ONNX model
	ONNXEnabled bool `json:"onnx_enabled"`

	// Tier 3: Cloud AI (requires API key)
	CloudEnabled bool   `json:"cloud_enabled"`
	CloudProvider string `json:"cloud_provider"` // "anthropic", "openai", "openrouter"
}

// APIKeysConfig holds API keys for cloud AI providers
type APIKeysConfig struct {
	Anthropic  string `json:"anthropic,omitempty"`
	OpenAI     string `json:"openai,omitempty"`
	OpenRouter string `json:"openrouter,omitempty"`
}

// ModelsConfig holds paths to local AI models
type ModelsConfig struct {
	// ONNX model for process classification
	ONNXModelPath string `json:"onnx_model_path,omitempty"`

	// Optional: local LLM for advanced analysis
	LocalLLMPath string `json:"local_llm_path,omitempty"`
}

// AnalysisConfig controls analysis behavior
type AnalysisConfig struct {
	// Minimum confidence threshold for alerts (0-100)
	ConfidenceThreshold int `json:"confidence_threshold"`

	// Auto-escalate to cloud if on-device confidence is low
	AutoEscalate bool `json:"auto_escalate"`

	// Escalation threshold - if on-device confidence below this, use cloud
	EscalateThreshold int `json:"escalate_threshold"`

	// Cache analysis results to avoid repeated API calls
	CacheResults bool `json:"cache_results"`

	// Cache TTL in seconds
	CacheTTLSeconds int `json:"cache_ttl_seconds"`

	// Maximum processes to analyze per batch (cloud API)
	BatchSize int `json:"batch_size"`
}

// DefaultConfig returns a sensible default configuration
func DefaultConfig() *Config {
	return &Config{
		Tiers: TierConfig{
			RulesEnabled:  true,
			ONNXEnabled:   false, // Disabled until model is available
			CloudEnabled:  false, // Disabled until API key provided
			CloudProvider: "anthropic",
		},
		APIKeys: APIKeysConfig{},
		Models: ModelsConfig{
			ONNXModelPath: "~/.ads/models/process-classifier.onnx",
		},
		Analysis: AnalysisConfig{
			ConfidenceThreshold: 70,
			AutoEscalate:        true,
			EscalateThreshold:   50,
			CacheResults:        true,
			CacheTTLSeconds:     300,
			BatchSize:           10,
		},
	}
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(path string) (*Config, error) {
	// If no path provided, use default
	if path == "" {
		path = DefaultConfigPath()
	}

	// Expand ~ to home directory
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, path[2:])
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config if file doesn't exist
			return DefaultConfig(), nil
		}
		return nil, err
	}

	config := DefaultConfig()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

// SaveConfig saves configuration to a JSON file
func SaveConfig(config *Config, path string) error {
	// Expand ~ to home directory
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = filepath.Join(home, path[2:])
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// DefaultConfigPath returns the default config file path
func DefaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ads", "process-monitor.json")
}

// LoadDefaultConfig loads config from the default path
func LoadDefaultConfig() (*Config, error) {
	return LoadConfig(DefaultConfigPath())
}
