package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// CollectorState represents the persistent state
type CollectorState struct {
	Version        string          `json:"version"`
	LastRun        string          `json:"lastRun"`
	CollectedFiles []CollectedFile `json:"collectedFiles"`
	FailedFiles    []FailedFile    `json:"failedFiles"`
	Statistics     Statistics      `json:"statistics"`
}

// CollectedFile represents a successfully collected file
type CollectedFile struct {
	FilePath   string   `json:"filePath"`
	FileHash   string   `json:"fileHash"`
	CollectedAt string   `json:"collectedAt"`
	ExportedTo []string `json:"exportedTo"`
	Status     string   `json:"status"`
}

// FailedFile represents a file that failed to collect
type FailedFile struct {
	FilePath    string `json:"filePath"`
	FileHash    string `json:"fileHash"`
	LastAttempt string `json:"lastAttempt"`
	Attempts    int    `json:"attempts"`
	LastError   string `json:"lastError"`
	Status      string `json:"status"`
}

// Statistics holds collection statistics
type Statistics struct {
	TotalCollected int    `json:"totalCollected"`
	TotalFailed    int    `json:"totalFailed"`
	LastSuccess    string `json:"lastSuccess"`
}

// LoadState loads the state file
func LoadState(path string) (*CollectorState, error) {
	// Check if state file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create new state
		return &CollectorState{
			Version:        "1.0",
			LastRun:        "",
			CollectedFiles: []CollectedFile{},
			FailedFiles:    []FailedFile{},
			Statistics: Statistics{
				TotalCollected: 0,
				TotalFailed:    0,
				LastSuccess:    "",
			},
		}, nil
	}

	// Read state file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	// Parse JSON
	var state CollectorState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse state JSON: %w", err)
	}

	return &state, nil
}

// SaveState saves the state file
func SaveState(path string, state *CollectorState) error {
	// Update last run time
	state.LastRun = time.Now().UTC().Format(time.RFC3339)

	// Marshal to JSON
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}

// IsCollected checks if a file has been collected
func (s *CollectorState) IsCollected(filePath, fileHash string) bool {
	for _, collected := range s.CollectedFiles {
		if collected.FilePath == filePath && collected.FileHash == fileHash {
			return true
		}
	}
	return false
}

// AddCollected adds a file to the collected list
func (s *CollectorState) AddCollected(filePath, fileHash string, exportedTo []string) {
	collected := CollectedFile{
		FilePath:    filePath,
		FileHash:    fileHash,
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		ExportedTo:  exportedTo,
		Status:      "success",
	}

	s.CollectedFiles = append(s.CollectedFiles, collected)
	s.Statistics.TotalCollected++
	s.Statistics.LastSuccess = collected.CollectedAt
}

// AddFailed adds a file to the failed list or updates existing entry
func (s *CollectorState) AddFailed(filePath, fileHash, errorMsg string) {
	// Check if already in failed list
	for i, failed := range s.FailedFiles {
		if failed.FilePath == filePath && failed.FileHash == fileHash {
			// Update existing entry
			s.FailedFiles[i].Attempts++
			s.FailedFiles[i].LastAttempt = time.Now().UTC().Format(time.RFC3339)
			s.FailedFiles[i].LastError = errorMsg
			return
		}
	}

	// Add new failed entry
	failed := FailedFile{
		FilePath:    filePath,
		FileHash:    fileHash,
		LastAttempt: time.Now().UTC().Format(time.RFC3339),
		Attempts:    1,
		LastError:   errorMsg,
		Status:      "failed",
	}

	s.FailedFiles = append(s.FailedFiles, failed)
	s.Statistics.TotalFailed++
}

// RemoveFailed removes a file from the failed list
func (s *CollectorState) RemoveFailed(filePath, fileHash string) {
	for i, failed := range s.FailedFiles {
		if failed.FilePath == filePath && failed.FileHash == fileHash {
			s.FailedFiles = append(s.FailedFiles[:i], s.FailedFiles[i+1:]...)
			return
		}
	}
}

// CleanupOldEntries removes entries older than retention period
func (s *CollectorState) CleanupOldEntries(retentionDays int) {
	if retentionDays <= 0 {
		return
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)

	// Clean up collected files
	var newCollected []CollectedFile
	for _, collected := range s.CollectedFiles {
		collectedTime, err := time.Parse(time.RFC3339, collected.CollectedAt)
		if err != nil || collectedTime.After(cutoff) {
			newCollected = append(newCollected, collected)
		}
	}
	s.CollectedFiles = newCollected

	// Clean up failed files
	var newFailed []FailedFile
	for _, failed := range s.FailedFiles {
		attemptTime, err := time.Parse(time.RFC3339, failed.LastAttempt)
		if err != nil || attemptTime.After(cutoff) {
			newFailed = append(newFailed, failed)
		}
	}
	s.FailedFiles = newFailed
}
