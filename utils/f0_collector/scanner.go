package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Scanner scans for test result files
type Scanner struct {
	config *CollectorConfig
	logger *Logger
}

// NewScanner creates a new scanner
func NewScanner(config *CollectorConfig, logger *Logger) *Scanner {
	return &Scanner{
		config: config,
		logger: logger,
	}
}

// ScanResult represents a found test result file
type ScanResult struct {
	FilePath string
	FileHash string
	FileSize int64
}

// Scan scans for test result files
func (s *Scanner) Scan() ([]ScanResult, error) {
	s.logger.Debugf("Scanning %s for %s", s.config.ScanPath, s.config.ScanPattern)

	var results []ScanResult

	// Convert glob pattern to simple matching
	// For now, we'll look for test_execution_log.json files
	err := filepath.Walk(s.config.ScanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip directories we can't access
			if os.IsPermission(err) {
				s.logger.Debugf("Skipping %s (permission denied)", path)
				return nil
			}
			return err
		}

		// Skip directories
		if info.IsDir() {
			// Skip collected directory to avoid re-scanning
			if s.config.MoveCollected && filepath.Base(path) == filepath.Base(s.config.CollectedPath) {
				s.logger.Debugf("Skipping collected directory: %s", path)
				return filepath.SkipDir
			}
			return nil
		}

		// Check if filename matches pattern
		if s.matchesPattern(path, s.config.ScanPattern) {
			// Calculate file hash
			hash, err := s.calculateFileHash(path)
			if err != nil {
				s.logger.Warnf("Failed to calculate hash for %s: %v", path, err)
				return nil
			}

			result := ScanResult{
				FilePath: path,
				FileHash: hash,
				FileSize: info.Size(),
			}

			results = append(results, result)
			s.logger.Debugf("Found: %s (hash: %s, size: %d)", path, hash, info.Size())
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan directory: %w", err)
	}

	s.logger.Infof("Found %d result file(s)", len(results))
	return results, nil
}

// matchesPattern checks if a file path matches the scan pattern
func (s *Scanner) matchesPattern(path, pattern string) bool {
	// Simple pattern matching - for now just check if filename ends with what we're looking for
	// Full glob pattern matching can be added later

	// Extract the filename pattern from the full pattern
	// E.g., "**/test_execution_log.json" -> "test_execution_log.json"
	parts := strings.Split(pattern, "/")
	filenamePattern := parts[len(parts)-1]

	// Check if the file matches
	filename := filepath.Base(path)

	// Simple wildcard matching
	if strings.Contains(filenamePattern, "*") {
		// For now, just check if it ends with .json and contains "test_execution_log"
		return strings.Contains(filename, "test_execution_log") && strings.HasSuffix(filename, ".json")
	}

	// Exact match
	return filename == filenamePattern
}

// calculateFileHash calculates SHA256 hash of a file
func (s *Scanner) calculateFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}
