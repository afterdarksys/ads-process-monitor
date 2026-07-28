package ai

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// License represents a feature license
type License struct {
	// License identification
	LicenseID    string `json:"license_id"`
	CustomerID   string `json:"customer_id"`
	CustomerName string `json:"customer_name,omitempty"`

	// License type
	Type LicenseType `json:"type"`

	// Feature flags
	Features LicenseFeatures `json:"features"`

	// Validity
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`

	// Machine binding (optional)
	MachineID string `json:"machine_id,omitempty"`

	// Signature for validation
	Signature string `json:"signature"`
}

// LicenseType represents the license tier
type LicenseType string

const (
	LicenseTypeFree       LicenseType = "free"
	LicenseTypePro        LicenseType = "pro"
	LicenseTypeEnterprise LicenseType = "enterprise"
)

// LicenseFeatures defines which features are enabled
type LicenseFeatures struct {
	// Analysis tiers
	RulesAnalysis bool `json:"rules_analysis"` // Always true
	ONNXAnalysis  bool `json:"onnx_analysis"`  // Pro+
	CloudAnalysis bool `json:"cloud_analysis"` // Pro+ (uses their API key)

	// Advanced features
	RealTimeMonitoring bool `json:"realtime_monitoring"` // Pro+
	ProcessTree        bool `json:"process_tree"`        // Free+
	JSONExport         bool `json:"json_export"`         // Free+
	HTTPServer         bool `json:"http_server"`         // Pro+
	SIEMIntegration    bool `json:"siem_integration"`    // Enterprise
	CustomRules        bool `json:"custom_rules"`        // Pro+
	APIAccess          bool `json:"api_access"`          // Enterprise

	// Limits
	MaxProcessesPerScan int `json:"max_processes_per_scan"`  // -1 for unlimited
	MaxCloudCallsPerDay int `json:"max_cloud_calls_per_day"` // -1 for unlimited
}

// DefaultFreeLicense returns a free tier license
func DefaultFreeLicense() *License {
	return &License{
		LicenseID:  "free",
		CustomerID: "community",
		Type:       LicenseTypeFree,
		Features: LicenseFeatures{
			RulesAnalysis:       true,
			ONNXAnalysis:        false,
			CloudAnalysis:       false,
			RealTimeMonitoring:  false,
			ProcessTree:         true,
			JSONExport:          true,
			HTTPServer:          false,
			SIEMIntegration:     false,
			CustomRules:         false,
			APIAccess:           false,
			MaxProcessesPerScan: 100,
			MaxCloudCallsPerDay: 0,
		},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().AddDate(100, 0, 0), // Never expires
	}
}

// LicenseManager handles license validation and feature checks
type LicenseManager struct {
	license    *License
	publicKey  ed25519.PublicKey
	configPath string
}

// NewLicenseManager creates a new license manager
func NewLicenseManager() *LicenseManager {
	lm := &LicenseManager{
		license:    DefaultFreeLicense(),
		configPath: DefaultLicensePath(),
	}
	if encoded := os.Getenv("ADS_PROCESS_MONITOR_LICENSE_PUBLIC_KEY"); encoded != "" {
		if key, err := base64.StdEncoding.DecodeString(encoded); err == nil && len(key) == ed25519.PublicKeySize {
			lm.publicKey = ed25519.PublicKey(key)
		}
	}
	return lm
}

// DefaultLicensePath returns the default license file path
func DefaultLicensePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ads", "license.json")
}

// LoadLicense loads a license from file
func (lm *LicenseManager) LoadLicense(path string) error {
	if path == "" {
		path = lm.configPath
	}

	// Expand ~ to home directory
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = filepath.Join(home, path[2:])
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Use default free license
			lm.license = DefaultFreeLicense()
			return nil
		}
		return err
	}

	var license License
	if err := json.Unmarshal(data, &license); err != nil {
		return err
	}

	// Validate license
	if err := lm.validateLicense(&license); err != nil {
		// Invalid license, fall back to free
		lm.license = DefaultFreeLicense()
		return err
	}

	lm.license = &license
	return nil
}

// validateLicense checks if a license is valid
func (lm *LicenseManager) validateLicense(license *License) error {
	// Check expiration
	if time.Now().After(license.ExpiresAt) {
		return ErrLicenseExpired
	}

	// Verify signature (simplified - in production use proper crypto)
	if !lm.verifySignature(license) {
		return ErrInvalidSignature
	}

	return nil
}

// verifySignature verifies the license signature
func (lm *LicenseManager) verifySignature(license *License) bool {
	if len(lm.publicKey) != ed25519.PublicKeySize {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(license.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(lm.publicKey, licensePayload(license), signature)
}

func licensePayload(license *License) []byte {
	copy := *license
	copy.Signature = ""
	payload, _ := json.Marshal(copy)
	return payload
}

// GetLicense returns the current license
func (lm *LicenseManager) GetLicense() *License {
	return lm.license
}

// HasFeature checks if a feature is enabled
func (lm *LicenseManager) HasFeature(feature string) bool {
	f := lm.license.Features

	switch feature {
	case "rules_analysis":
		return f.RulesAnalysis
	case "onnx_analysis":
		return f.ONNXAnalysis
	case "cloud_analysis":
		return f.CloudAnalysis
	case "realtime_monitoring":
		return f.RealTimeMonitoring
	case "process_tree":
		return f.ProcessTree
	case "json_export":
		return f.JSONExport
	case "http_server":
		return f.HTTPServer
	case "siem_integration":
		return f.SIEMIntegration
	case "custom_rules":
		return f.CustomRules
	case "api_access":
		return f.APIAccess
	default:
		return false
	}
}

// GetLicenseType returns the license type
func (lm *LicenseManager) GetLicenseType() LicenseType {
	return lm.license.Type
}

// IsExpired checks if the license has expired
func (lm *LicenseManager) IsExpired() bool {
	return time.Now().After(lm.license.ExpiresAt)
}

// License errors
type LicenseError struct {
	Message string
}

func (e *LicenseError) Error() string {
	return e.Message
}

var (
	ErrLicenseExpired   = &LicenseError{"license has expired"}
	ErrInvalidSignature = &LicenseError{"invalid license signature"}
	ErrFeatureDisabled  = &LicenseError{"feature not available in current license"}
)

// GenerateLicense creates a new license (for internal use / license server)
func GenerateLicense(customerID, customerName string, licenseType LicenseType, validDays int, secretKey []byte) *License {
	license := &License{
		LicenseID:    generateLicenseID(),
		CustomerID:   customerID,
		CustomerName: customerName,
		Type:         licenseType,
		IssuedAt:     time.Now(),
		ExpiresAt:    time.Now().AddDate(0, 0, validDays),
	}

	// Set features based on license type
	switch licenseType {
	case LicenseTypeFree:
		license.Features = LicenseFeatures{
			RulesAnalysis:       true,
			ONNXAnalysis:        false,
			CloudAnalysis:       false,
			RealTimeMonitoring:  false,
			ProcessTree:         true,
			JSONExport:          true,
			HTTPServer:          false,
			SIEMIntegration:     false,
			CustomRules:         false,
			APIAccess:           false,
			MaxProcessesPerScan: 100,
			MaxCloudCallsPerDay: 0,
		}
	case LicenseTypePro:
		license.Features = LicenseFeatures{
			RulesAnalysis:       true,
			ONNXAnalysis:        true,
			CloudAnalysis:       true,
			RealTimeMonitoring:  true,
			ProcessTree:         true,
			JSONExport:          true,
			HTTPServer:          true,
			SIEMIntegration:     false,
			CustomRules:         true,
			APIAccess:           false,
			MaxProcessesPerScan: -1,
			MaxCloudCallsPerDay: 1000,
		}
	case LicenseTypeEnterprise:
		license.Features = LicenseFeatures{
			RulesAnalysis:       true,
			ONNXAnalysis:        true,
			CloudAnalysis:       true,
			RealTimeMonitoring:  true,
			ProcessTree:         true,
			JSONExport:          true,
			HTTPServer:          true,
			SIEMIntegration:     true,
			CustomRules:         true,
			APIAccess:           true,
			MaxProcessesPerScan: -1,
			MaxCloudCallsPerDay: -1,
		}
	}

	// The license server derives its private signing key from its secret input.
	// The corresponding public key is distributed separately to clients.
	seed := sha256.Sum256(secretKey)
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	license.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, licensePayload(license)))

	return license
}

func generateLicenseID() string {
	// Use a hash-derived identifier so generated licenses are not all identical.
	seed := sha256.Sum256([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	return base64.URLEncoding.EncodeToString(seed[:])[:22]
}
