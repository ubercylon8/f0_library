package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Validator validates test result files against schema
type Validator struct {
	config *ValidationConfig
	logger *Logger
}

// NewValidator creates a new validator
func NewValidator(config *ValidationConfig, logger *Logger) *Validator {
	return &Validator{
		config: config,
		logger: logger,
	}
}

// TestResult represents a minimal test result structure for validation
type TestResult struct {
	SchemaVersion     string                 `json:"schemaVersion"`
	TestID            string                 `json:"testId"`
	TestName          string                 `json:"testName"`
	TestMetadata      map[string]interface{} `json:"testMetadata"`
	ExecutionContext  map[string]interface{} `json:"executionContext"`
	StartTime         string                 `json:"startTime"`
	EndTime           string                 `json:"endTime"`
	DurationMs        int64                  `json:"durationMs"`
	ExitCode          int                    `json:"exitCode"`
	ExitReason        string                 `json:"exitReason"`
	Outcome           map[string]interface{} `json:"outcome"`
	SystemInfo        map[string]interface{} `json:"systemInfo"`
	Phases            []interface{}          `json:"phases"`
	Messages          []interface{}          `json:"messages"`
	FilesDropped      []interface{}          `json:"filesDropped"`
	ProcessesExecuted []interface{}          `json:"processesExecuted"`
	Metrics           map[string]interface{} `json:"metrics"`
}

// ValidationResult represents the result of validation
type ValidationResult struct {
	Valid    bool
	Errors   []string
	Warnings []string
}

// ValidateFile validates a test result file
func (v *Validator) ValidateFile(path string) (*TestResult, *ValidationResult, error) {
	v.logger.Debugf("Validating %s", path)

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse JSON
	var result TestResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, &ValidationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("Invalid JSON: %v", err)},
		}, nil
	}

	// Validate schema
	validationResult := v.validate(&result)

	if !validationResult.Valid {
		v.logger.Warnf("Validation failed for %s: %v", path, validationResult.Errors)
	} else if len(validationResult.Warnings) > 0 {
		v.logger.Warnf("Validation warnings for %s: %v", path, validationResult.Warnings)
	} else {
		v.logger.Debugf("Validation passed for %s", path)
	}

	return &result, validationResult, nil
}

// validate performs schema validation
func (v *Validator) validate(result *TestResult) *ValidationResult {
	validationResult := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Check schema version
	if result.SchemaVersion != v.config.SchemaVersion {
		msg := fmt.Sprintf("Schema version mismatch: expected %s, got %s",
			v.config.SchemaVersion, result.SchemaVersion)
		if v.config.StrictMode {
			validationResult.Errors = append(validationResult.Errors, msg)
			validationResult.Valid = false
		} else {
			validationResult.Warnings = append(validationResult.Warnings, msg)
		}
	}

	// Check required fields
	if result.TestID == "" {
		validationResult.Errors = append(validationResult.Errors, "testId is required")
		validationResult.Valid = false
	}

	if result.TestName == "" {
		validationResult.Errors = append(validationResult.Errors, "testName is required")
		validationResult.Valid = false
	}

	if result.TestMetadata == nil {
		validationResult.Errors = append(validationResult.Errors, "testMetadata is required")
		validationResult.Valid = false
	}

	if result.ExecutionContext == nil {
		validationResult.Errors = append(validationResult.Errors, "executionContext is required")
		validationResult.Valid = false
	}

	if result.StartTime == "" {
		validationResult.Errors = append(validationResult.Errors, "startTime is required")
		validationResult.Valid = false
	}

	if result.EndTime == "" {
		validationResult.Errors = append(validationResult.Errors, "endTime is required")
		validationResult.Valid = false
	}

	if result.Outcome == nil {
		validationResult.Errors = append(validationResult.Errors, "outcome is required")
		validationResult.Valid = false
	}

	if result.SystemInfo == nil {
		validationResult.Errors = append(validationResult.Errors, "systemInfo is required")
		validationResult.Valid = false
	}

	if result.Phases == nil {
		validationResult.Errors = append(validationResult.Errors, "phases is required")
		validationResult.Valid = false
	}

	if result.Messages == nil {
		validationResult.Errors = append(validationResult.Errors, "messages is required")
		validationResult.Valid = false
	}

	if result.FilesDropped == nil {
		validationResult.Errors = append(validationResult.Errors, "filesDropped is required")
		validationResult.Valid = false
	}

	if result.ProcessesExecuted == nil {
		validationResult.Errors = append(validationResult.Errors, "processesExecuted is required")
		validationResult.Valid = false
	}

	// Additional logical validations
	if result.DurationMs < 0 {
		validationResult.Warnings = append(validationResult.Warnings, "durationMs is negative")
	}

	if result.StartTime != "" && result.EndTime != "" && result.StartTime > result.EndTime {
		validationResult.Warnings = append(validationResult.Warnings, "startTime is after endTime")
	}

	return validationResult
}
