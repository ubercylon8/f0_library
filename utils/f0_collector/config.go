package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config represents the collector configuration
type Config struct {
	Version        string              `json:"version"`
	Collector      CollectorConfig     `json:"collector"`
	Elasticsearch  ElasticsearchConfig `json:"elasticsearch"`
	Logging        LoggingConfig       `json:"logging"`
	Validation     ValidationConfig    `json:"validation"`
}

// CollectorConfig holds collector-specific settings
type CollectorConfig struct {
	ScanPath       string `json:"scanPath"`
	ScanPattern    string `json:"scanPattern"`
	StateFile      string `json:"stateFile"`
	MoveCollected  bool   `json:"moveCollected"`
	CollectedPath  string `json:"collectedPath"`
}

// ElasticsearchConfig holds Elasticsearch connection settings
type ElasticsearchConfig struct {
	Enabled       bool     `json:"enabled"`
	Endpoints     []string `json:"endpoints"`
	CloudID       string   `json:"cloudId"`
	APIKey        string   `json:"apiKey"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	IndexPrefix   string   `json:"indexPrefix"`
	IndexPattern  string   `json:"indexPattern"`
	BulkSize      int      `json:"bulkSize"`
	Timeout       int      `json:"timeout"`
	RetryAttempts int      `json:"retryAttempts"`
	RetryDelay    int      `json:"retryDelay"`
	TLSVerify     bool     `json:"tlsVerify"`
	TLSCert       string   `json:"tlsCert"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level      string `json:"level"`
	File       string `json:"file"`
	MaxSizeMB  int    `json:"maxSizeMB"`
	MaxBackups int    `json:"maxBackups"`
	Console    bool   `json:"console"`
}

// ValidationConfig holds validation settings
type ValidationConfig struct {
	SchemaVersion string `json:"schemaVersion"`
	StrictMode    bool   `json:"strictMode"`
	SkipInvalid   bool   `json:"skipInvalid"`
}

// LoadConfig loads and validates configuration from file
func LoadConfig(path string) (*Config, error) {
	// Read config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	// Override with environment variables if present
	config.applyEnvironmentOverrides()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// applyEnvironmentOverrides applies environment variable overrides
func (c *Config) applyEnvironmentOverrides() {
	// Elasticsearch API Key
	if apiKey := os.Getenv("F0_ELASTIC_API_KEY"); apiKey != "" {
		c.Elasticsearch.APIKey = apiKey
	}

	// Elasticsearch Username
	if username := os.Getenv("F0_ELASTIC_USERNAME"); username != "" {
		c.Elasticsearch.Username = username
	}

	// Elasticsearch Password
	if password := os.Getenv("F0_ELASTIC_PASSWORD"); password != "" {
		c.Elasticsearch.Password = password
	}

	// Elasticsearch Cloud ID
	if cloudID := os.Getenv("F0_ELASTIC_CLOUD_ID"); cloudID != "" {
		c.Elasticsearch.CloudID = cloudID
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate Elasticsearch config if enabled
	if c.Elasticsearch.Enabled {
		if err := c.validateElasticsearch(); err != nil {
			return err
		}
	}

	// Validate collector config
	if c.Collector.ScanPath == "" {
		return fmt.Errorf("collector.scanPath is required")
	}

	if c.Collector.StateFile == "" {
		return fmt.Errorf("collector.stateFile is required")
	}

	// Validate logging config
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}

	// Validate schema version
	if c.Validation.SchemaVersion == "" {
		c.Validation.SchemaVersion = "2.0"
	}

	return nil
}

// validateElasticsearch validates Elasticsearch configuration
func (c *Config) validateElasticsearch() error {
	// Must have either endpoints or cloudId
	if len(c.Elasticsearch.Endpoints) == 0 && c.Elasticsearch.CloudID == "" {
		return fmt.Errorf("elasticsearch.endpoints or elasticsearch.cloudId is required")
	}

	// Must have authentication
	hasAPIKey := c.Elasticsearch.APIKey != ""
	hasBasicAuth := c.Elasticsearch.Username != "" && c.Elasticsearch.Password != ""

	if !hasAPIKey && !hasBasicAuth {
		return fmt.Errorf("elasticsearch authentication required (apiKey or username/password)")
	}

	// Validate index prefix
	if c.Elasticsearch.IndexPrefix == "" {
		return fmt.Errorf("elasticsearch.indexPrefix is required")
	}

	// Set defaults
	if c.Elasticsearch.BulkSize == 0 {
		c.Elasticsearch.BulkSize = 100
	}

	if c.Elasticsearch.Timeout == 0 {
		c.Elasticsearch.Timeout = 30
	}

	if c.Elasticsearch.RetryAttempts == 0 {
		c.Elasticsearch.RetryAttempts = 3
	}

	if c.Elasticsearch.RetryDelay == 0 {
		c.Elasticsearch.RetryDelay = 5
	}

	return nil
}
