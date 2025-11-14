package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Collector orchestrates the collection process
type Collector struct {
	config    *Config
	logger    *Logger
	scanner   *Scanner
	validator *Validator
	exporter  *ElasticsearchExporter
	state     *CollectorState
}

// NewCollector creates a new collector
func NewCollector(config *Config, logger *Logger) *Collector {
	return &Collector{
		config:    config,
		logger:    logger,
		scanner:   NewScanner(&config.Collector, logger),
		validator: NewValidator(&config.Validation, logger),
		exporter:  NewElasticsearchExporter(&config.Elasticsearch, logger),
	}
}

// Collect performs the collection process
func (c *Collector) Collect(force, dryRun bool) error {
	c.logger.Info("Starting collection...")

	// Load state
	var err error
	c.state, err = LoadState(c.config.Collector.StateFile)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	// Scan for test result files
	scanResults, err := c.scanner.Scan()
	if err != nil {
		return fmt.Errorf("failed to scan for files: %w", err)
	}

	if len(scanResults) == 0 {
		c.logger.Info("No test result files found")
		return nil
	}

	// Filter out already collected files (unless force is true)
	var toCollect []ScanResult
	for _, result := range scanResults {
		if !force && c.state.IsCollected(result.FilePath, result.FileHash) {
			c.logger.Debugf("Skipping already collected file: %s", result.FilePath)
			continue
		}
		toCollect = append(toCollect, result)
	}

	if len(toCollect) == 0 {
		c.logger.Info("No new files to collect")
		return nil
	}

	c.logger.Infof("Found %d new file(s) to collect", len(toCollect))

	// Process files
	var successCount, failCount int
	var successfulResults []*TestResult
	var successfulPaths []string

	for _, scanResult := range toCollect {
		c.logger.Infof("Processing %s", scanResult.FilePath)

		// Validate file
		testResult, validationResult, err := c.validator.ValidateFile(scanResult.FilePath)
		if err != nil {
			c.logger.Errorf("Failed to validate %s: %v", scanResult.FilePath, err)
			c.state.AddFailed(scanResult.FilePath, scanResult.FileHash, fmt.Sprintf("Validation error: %v", err))
			failCount++
			continue
		}

		// Check validation result
		if !validationResult.Valid {
			errorMsg := fmt.Sprintf("Validation failed: %v", validationResult.Errors)
			c.logger.Warnf("%s: %s", scanResult.FilePath, errorMsg)

			if c.config.Validation.SkipInvalid {
				c.logger.Info("Skipping invalid file")
				c.state.AddFailed(scanResult.FilePath, scanResult.FileHash, errorMsg)
				failCount++
				continue
			} else {
				c.logger.Error("Validation failed and skipInvalid is false - aborting")
				return fmt.Errorf("validation failed for %s", scanResult.FilePath)
			}
		}

		// If dry run, skip export
		if dryRun {
			c.logger.Info("DRY RUN: Would export this file")
			successCount++
			continue
		}

		// Add to batch for export
		successfulResults = append(successfulResults, testResult)
		successfulPaths = append(successfulPaths, scanResult.FilePath)
	}

	// Export to Elasticsearch (if not dry run)
	if !dryRun && len(successfulResults) > 0 {
		if err := c.exportResults(successfulResults, successfulPaths); err != nil {
			c.logger.Errorf("Failed to export results: %v", err)
			// Mark all as failed
			for i, path := range successfulPaths {
				hash := toCollect[i].FileHash
				c.state.AddFailed(path, hash, fmt.Sprintf("Export error: %v", err))
			}
			failCount += len(successfulResults)
		} else {
			// Mark all as collected
			for i, path := range successfulPaths {
				hash := toCollect[i].FileHash
				c.state.AddCollected(path, hash, []string{"elasticsearch"})

				// Move file if configured
				if c.config.Collector.MoveCollected {
					if err := c.moveCollectedFile(path); err != nil {
						c.logger.Warnf("Failed to move collected file %s: %v", path, err)
					}
				}
			}
			successCount += len(successfulResults)
		}
	}

	// Cleanup old state entries (30 days)
	c.state.CleanupOldEntries(30)

	// Save state
	if err := SaveState(c.config.Collector.StateFile, c.state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	c.logger.Infof("Collection complete: %d collected, %d failed", successCount, failCount)
	return nil
}

// exportResults exports test results to Elasticsearch
func (c *Collector) exportResults(results []*TestResult, paths []string) error {
	c.logger.Infof("Exporting %d result(s) to Elasticsearch", len(results))

	// Use batch export if configured
	if c.config.Elasticsearch.BulkSize > 0 && len(results) > 1 {
		// Process in batches
		for i := 0; i < len(results); i += c.config.Elasticsearch.BulkSize {
			end := i + c.config.Elasticsearch.BulkSize
			if end > len(results) {
				end = len(results)
			}

			batch := results[i:end]
			batchPaths := paths[i:end]

			if err := c.exporter.ExportBatch(batch, batchPaths); err != nil {
				return fmt.Errorf("failed to export batch: %w", err)
			}
		}
	} else {
		// Export individually
		for i, result := range results {
			if err := c.exporter.ExportResult(result, paths[i]); err != nil {
				return fmt.Errorf("failed to export result: %w", err)
			}
		}
	}

	return nil
}

// moveCollectedFile moves a collected file to the collected directory
func (c *Collector) moveCollectedFile(path string) error {
	// Create collected directory if it doesn't exist
	if err := os.MkdirAll(c.config.Collector.CollectedPath, 0755); err != nil {
		return fmt.Errorf("failed to create collected directory: %w", err)
	}

	// Generate destination path
	filename := filepath.Base(path)
	destPath := filepath.Join(c.config.Collector.CollectedPath, filename)

	// If file already exists, append timestamp
	if _, err := os.Stat(destPath); err == nil {
		base := filepath.Base(path)
		ext := filepath.Ext(base)
		name := base[:len(base)-len(ext)]
		destPath = filepath.Join(c.config.Collector.CollectedPath,
			fmt.Sprintf("%s_%d%s", name, os.Getpid(), ext))
	}

	// Move file
	if err := os.Rename(path, destPath); err != nil {
		return fmt.Errorf("failed to move file: %w", err)
	}

	c.logger.Debugf("Moved %s to %s", path, destPath)
	return nil
}
