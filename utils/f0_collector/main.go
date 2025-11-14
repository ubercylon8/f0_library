package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

const (
	VERSION = "1.0.0"
)

var (
	configPath string
	dryRun     bool
	force      bool
	verbose    bool
	once       bool
	interval   int
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "f0_collector",
		Short: "F0RT1KA Results Collector",
		Long: `F0RT1KA Results Collector - Collects test result JSON files
from Windows endpoints and exports them to Elasticsearch for analytics
and dashboard visualization.`,
		Version: VERSION,
	}

	// Collect command
	collectCmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect and export test results",
		Long:  `Scan for test result files, validate against schema v2.0, and export to Elasticsearch.`,
		Run:   runCollect,
	}

	collectCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Scan and validate only, don't export")
	collectCmd.Flags().BoolVar(&force, "force", false, "Force re-collection of already collected files")
	collectCmd.Flags().BoolVar(&once, "once", false, "Run once and exit (vs. continuous mode)")
	collectCmd.Flags().IntVar(&interval, "interval", 300, "Collection interval in seconds (continuous mode)")

	// Validate command
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration and connectivity",
		Long:  `Validate configuration file and test connectivity to Elasticsearch.`,
		Run:   runValidate,
	}

	// Status command
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show collection status and statistics",
		Long:  `Display collection statistics from state file.`,
		Run:   runStatus,
	}

	// Reset command
	resetCmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset state file (re-collect all files)",
		Long:  `Reset the state file to force re-collection of all test results.`,
		Run:   runReset,
	}

	// Add commands to root
	rootCmd.AddCommand(collectCmd, validateCmd, statusCmd, resetCmd)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "c:\\F0\\collector_config.json", "Path to configuration file")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose logging")

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCollect(cmd *cobra.Command, args []string) {
	// Initialize
	config, logger := initialize()

	logger.Infof("f0_collector v%s starting", VERSION)
	logger.Infof("Mode: %s", func() string {
		if once {
			return "one-time collection"
		}
		return fmt.Sprintf("continuous (interval: %ds)", interval)
	}())

	if dryRun {
		logger.Warn("DRY RUN MODE - No files will be exported")
	}

	// Create collector
	collector := NewCollector(config, logger)

	// Run collection
	if once {
		// Single collection run
		if err := collector.Collect(force, dryRun); err != nil {
			logger.Errorf("Collection failed: %v", err)
			os.Exit(1)
		}
		logger.Info("Collection complete")
	} else {
		// Continuous collection mode
		logger.Infof("Starting continuous collection (interval: %ds)", interval)
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		// Run immediately on start
		if err := collector.Collect(force, dryRun); err != nil {
			logger.Errorf("Collection failed: %v", err)
		}

		// Then run on interval
		for range ticker.C {
			if err := collector.Collect(force, dryRun); err != nil {
				logger.Errorf("Collection failed: %v", err)
			}
		}
	}
}

func runValidate(cmd *cobra.Command, args []string) {
	config, logger := initialize()

	logger.Info("Validating configuration...")

	// Test Elasticsearch connectivity
	if config.Elasticsearch.Enabled {
		exporter := NewElasticsearchExporter(config.Elasticsearch, logger)
		if err := exporter.TestConnection(); err != nil {
			logger.Errorf("Elasticsearch connectivity test FAILED: %v", err)
			os.Exit(1)
		}
		logger.Info("Elasticsearch connectivity test PASSED")
	}

	logger.Info("Configuration validation PASSED")
}

func runStatus(cmd *cobra.Command, args []string) {
	config, logger := initialize()

	// Load state
	state, err := LoadState(config.Collector.StateFile)
	if err != nil {
		logger.Errorf("Failed to load state: %v", err)
		os.Exit(1)
	}

	// Display statistics
	fmt.Println("\n========================================")
	fmt.Println("F0RT1KA Collector Status")
	fmt.Println("========================================")
	fmt.Printf("Version:          %s\n", VERSION)
	fmt.Printf("Last Run:         %s\n", state.LastRun)
	fmt.Printf("Total Collected:  %d\n", state.Statistics.TotalCollected)
	fmt.Printf("Total Failed:     %d\n", state.Statistics.TotalFailed)
	fmt.Printf("Last Success:     %s\n", state.Statistics.LastSuccess)
	fmt.Println("========================================")

	if len(state.FailedFiles) > 0 {
		fmt.Println("\nFailed Files:")
		for _, failed := range state.FailedFiles {
			fmt.Printf("  - %s (attempts: %d, last error: %s)\n",
				failed.FilePath, failed.Attempts, failed.LastError)
		}
	}
}

func runReset(cmd *cobra.Command, args []string) {
	config, logger := initialize()

	logger.Warn("Resetting state file - all files will be re-collected on next run")

	// Create empty state
	state := &CollectorState{
		Version:        "1.0",
		LastRun:        time.Now().UTC().Format(time.RFC3339),
		CollectedFiles: []CollectedFile{},
		FailedFiles:    []FailedFile{},
		Statistics: Statistics{
			TotalCollected: 0,
			TotalFailed:    0,
			LastSuccess:    "",
		},
	}

	// Save state
	if err := SaveState(config.Collector.StateFile, state); err != nil {
		logger.Errorf("Failed to reset state: %v", err)
		os.Exit(1)
	}

	logger.Info("State file reset successfully")
}

func initialize() (*Config, *Logger) {
	// Load configuration
	config, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger := NewLogger(config.Logging, verbose)

	return config, logger
}
