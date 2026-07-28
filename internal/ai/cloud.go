package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// CloudAnalyzer implements cloud-based AI analysis (Tier 3)
// Requires API key for the selected provider
type CloudAnalyzer struct {
	config     *Config
	httpClient *http.Client
}

// NewCloudAnalyzer creates a new cloud-based analyzer
func NewCloudAnalyzer(config *Config) *CloudAnalyzer {
	return &CloudAnalyzer{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (ca *CloudAnalyzer) Name() string {
	return "cloud"
}

func (ca *CloudAnalyzer) IsAvailable() bool {
	if !ca.config.Tiers.CloudEnabled {
		return false
	}

	// Check if API key is configured for the selected provider
	switch ca.config.Tiers.CloudProvider {
	case "anthropic":
		return ca.config.APIKeys.Anthropic != ""
	case "openai":
		return ca.config.APIKeys.OpenAI != ""
	case "openrouter":
		return ca.config.APIKeys.OpenRouter != ""
	default:
		return false
	}
}

func (ca *CloudAnalyzer) Analyze(ctx *ProcessContext) (*AnalysisResult, error) {
	if !ca.IsAvailable() {
		return nil, fmt.Errorf("cloud analyzer not available - API key not configured")
	}

	// Build analysis prompt
	prompt := ca.buildPrompt(ctx)

	// Call the appropriate provider
	var response string
	var err error

	switch ca.config.Tiers.CloudProvider {
	case "anthropic":
		response, err = ca.callAnthropic(prompt)
	case "openai":
		response, err = ca.callOpenAI(prompt)
	case "openrouter":
		response, err = ca.callOpenRouter(prompt)
	default:
		return nil, fmt.Errorf("unknown cloud provider: %s", ca.config.Tiers.CloudProvider)
	}

	if err != nil {
		return nil, fmt.Errorf("cloud API call failed: %w", err)
	}

	// Parse the response
	return ca.parseResponse(ctx, response)
}

func (ca *CloudAnalyzer) buildPrompt(ctx *ProcessContext) string {
	// Build a structured prompt for the AI
	processJSON, _ := json.MarshalIndent(ctx.Process, "", "  ")
	parentJSON := "[]"
	if len(ctx.ParentChain) > 0 {
		parentBytes, _ := json.MarshalIndent(ctx.ParentChain, "", "  ")
		if len(parentBytes) > 0 {
			parentJSON = string(parentBytes)
		}
	}

	prompt := fmt.Sprintf(`You are a macOS security analyst AI. Analyze this process for potential threats.

PROCESS DATA:
%s

PARENT CHAIN:
%s

NETWORK CONNECTIONS:
%v

OPEN FILES:
%v

Analyze this process and respond in this exact JSON format:
{
  "verdict": "clean" | "suspicious" | "malicious",
  "confidence": 0-100,
  "threat_type": "string or null",
  "mitre_ids": ["T1234", ...] or [],
  "explanation": "detailed explanation",
  "recommendation": "what to do"
}

Consider:
1. Is the process name legitimate?
2. Is the executable path suspicious?
3. Does the command line contain encoded/obfuscated content?
4. Is the parent chain unusual?
5. Are there suspicious network connections?
6. Is the process accessing sensitive files?

	Respond ONLY with the JSON, no other text.`, processJSON, parentJSON, ctx.NetworkConnections, ctx.OpenFiles)

	return redactCloudData(prompt)
}

var cloudSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)[^\s"']+`),
	regexp.MustCompile(`(?i)(\b(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)[^\s,}"']+`),
	regexp.MustCompile(`\b(?:ghp|github_pat|sk|xox[baprs])_[A-Za-z0-9_\-]{12,}\b`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`(?i)(/Users/|/home/|/var/|/private/)[^\s"']+`),
}

func redactCloudData(prompt string) string {
	redacted := prompt
	for _, pattern := range cloudSecretPatterns {
		redacted = pattern.ReplaceAllStringFunc(redacted, func(value string) string {
			if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "Authorization") || strings.HasPrefix(value, "authorization") {
				return "<redacted>"
			}
			if idx := strings.IndexAny(value, ":="); idx >= 0 {
				return value[:idx+1] + "<redacted>"
			}
			return "<redacted>"
		})
	}
	return redacted
}

func (ca *CloudAnalyzer) callAnthropic(prompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model":      "claude-sonnet-4-20250514",
		"max_tokens": 1024,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", ca.config.APIKeys.Anthropic)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := ca.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Anthropic API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty response from Anthropic")
	}

	return result.Content[0].Text, nil
}

func (ca *CloudAnalyzer) callOpenAI(prompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens": 1024,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ca.config.APIKeys.OpenAI)

	resp, err := ca.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OpenAI API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty response from OpenAI")
	}

	return result.Choices[0].Message.Content, nil
}

func (ca *CloudAnalyzer) callOpenRouter(prompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model": "anthropic/claude-sonnet-4-20250514",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens": 1024,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://openrouter.ai/api/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ca.config.APIKeys.OpenRouter)
	req.Header.Set("HTTP-Referer", "https://afterdarksys.com")
	req.Header.Set("X-Title", "ADS Process Monitor")

	resp, err := ca.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OpenRouter API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty response from OpenRouter")
	}

	return result.Choices[0].Message.Content, nil
}

func (ca *CloudAnalyzer) parseResponse(ctx *ProcessContext, response string) (*AnalysisResult, error) {
	// Parse the JSON response from the AI
	var aiResponse struct {
		Verdict        string   `json:"verdict"`
		Confidence     int      `json:"confidence"`
		ThreatType     string   `json:"threat_type"`
		MITREIDs       []string `json:"mitre_ids"`
		Explanation    string   `json:"explanation"`
		Recommendation string   `json:"recommendation"`
	}

	// Clean up response (remove markdown code blocks if present)
	cleanResponse := response
	if len(response) > 7 && response[:7] == "```json" {
		// Find end of code block
		end := len(response) - 3
		if response[end:] == "```" {
			cleanResponse = response[7:end]
		}
	} else if len(response) > 3 && response[:3] == "```" {
		end := len(response) - 3
		if response[end:] == "```" {
			cleanResponse = response[3:end]
		}
	}

	if err := json.Unmarshal([]byte(cleanResponse), &aiResponse); err != nil {
		// If parsing fails, create a basic result
		return &AnalysisResult{
			PID:          ctx.Process.PID,
			Name:         ctx.Process.Name,
			Verdict:      VerdictUnknown,
			Confidence:   0,
			AnalysisTier: "cloud",
			Explanation:  "Failed to parse AI response: " + err.Error() + "\nRaw: " + response[:min(200, len(response))],
		}, nil
	}

	result := &AnalysisResult{
		PID:            ctx.Process.PID,
		Name:           ctx.Process.Name,
		Verdict:        Verdict(aiResponse.Verdict),
		Confidence:     aiResponse.Confidence,
		ThreatType:     aiResponse.ThreatType,
		MITREIDs:       aiResponse.MITREIDs,
		Explanation:    aiResponse.Explanation,
		Recommendation: aiResponse.Recommendation,
		AnalysisTier:   "cloud",
		TierScores:     map[string]int{"cloud": aiResponse.Confidence},
	}

	// Validate verdict
	switch result.Verdict {
	case VerdictClean, VerdictSuspicious, VerdictMalicious:
		// Valid
	default:
		result.Verdict = VerdictUnknown
	}

	return result, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
