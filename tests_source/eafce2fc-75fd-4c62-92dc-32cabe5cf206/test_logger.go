// test_logger.go - Enhanced logging for F0RT1KA multi-stage tests
// Provides comprehensive structured logging with multi-stage support
// Stage binaries can attach to shared log file for coordinated logging
//
// MULTI-STAGE ENHANCEMENTS:
// - AttachLogger() for stage binaries to attach to existing log
// - LogStageStart(), LogStageEnd(), LogStageBlocked() for stage-specific logging
// - Thread-safe log file operations for concurrent stage execution
// - Stage result tracking in JSON/text logs

//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

// ==============================================================================
// DATA STRUCTURES
// ==============================================================================

// TestLog is the main structure containing all test execution data
type TestLog struct {
	TestID                string                  `json:"testId"`
	TestName              string                  `json:"testName"`
	IsMultiStage          bool                    `json:"isMultiStage"`
	StartTime             time.Time               `json:"startTime"`
	EndTime               time.Time               `json:"endTime"`
	Duration              int64                   `json:"durationMs"`
	ExitCode              int                     `json:"exitCode"`
	ExitReason            string                  `json:"exitReason"`
	Phases                []PhaseLog              `json:"phases"`
	Stages                []StageLog              `json:"stages,omitempty"` // Multi-stage only
	BlockedAtStage        int                     `json:"blockedAtStage,omitempty"`
	BlockedTechnique      string                  `json:"blockedTechnique,omitempty"`
	CertBypass            *CertBypassLog          `json:"certBypass,omitempty"`
	NetworkTest           *NetworkTestSummary     `json:"networkTest,omitempty"`
	IdentifierExtraction  *IdentifierLog          `json:"identifierExtraction,omitempty"`
	SystemInfo            SystemInfo              `json:"systemInfo"`
	Messages              []LogEntry              `json:"messages"`
	FilesDropped          []FileDropLog           `json:"filesDropped"`
	ProcessesExecuted     []ProcessLog            `json:"processesExecuted"`
}

// StageLog tracks individual stage execution in multi-stage tests
type StageLog struct {
	StageID      int       `json:"stageId"`
	Technique    string    `json:"technique"` // MITRE ATT&CK ID (e.g., "T1134.001")
	Name         string    `json:"name"`
	StartTime    time.Time `json:"startTime"`
	EndTime      time.Time `json:"endTime"`
	DurationMs   int64     `json:"durationMs"`
	Status       string    `json:"status"` // "success", "blocked", "error"
	ExitCode     int       `json:"exitCode"`
	BlockedBy    string    `json:"blockedBy,omitempty"`
	ErrorMessage string    `json:"errorMessage,omitempty"`
}

// PhaseLog tracks individual test phases
type PhaseLog struct {
	PhaseNumber int       `json:"phaseNumber"`
	PhaseName   string    `json:"phaseName"`
	StartTime   time.Time `json:"startTime"`
	EndTime     time.Time `json:"endTime"`
	DurationMs  int64     `json:"durationMs"`
	Status      string    `json:"status"` // "success", "failed", "blocked", "skipped"
	Details     string    `json:"details"`
	Errors      []string  `json:"errors,omitempty"`
}

// CertBypassLog tracks certificate bypass attempts
type CertBypassLog struct {
	Mode            string    `json:"mode"`
	Attempted       bool      `json:"attempted"`
	Success         bool      `json:"success"`
	Blocked         bool      `json:"blocked"`
	BlockedBy       string    `json:"blockedBy,omitempty"`
	WatchdogActive  bool      `json:"watchdogActive"`
	RestoreSuccess  bool      `json:"restoreSuccess"`
	DurationMs      int64     `json:"durationMs"`
	PatchAddress    string    `json:"patchAddress,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// IdentifierLog tracks identifier extraction
type IdentifierLog struct {
	Method       string    `json:"method"` // "registry", "config", "wmi", "simulated"
	MDEInstalled bool      `json:"mdeInstalled"`
	Success      bool      `json:"success"`
	MachineID    string    `json:"machineId"`
	TenantID     string    `json:"tenantId"`
	SenseID      string    `json:"senseId,omitempty"`
	OrgID        string    `json:"orgId,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"` // "INFO", "WARN", "ERROR", "CRITICAL", "SUCCESS"
	Phase     string    `json:"phase"`
	Message   string    `json:"message"`
}

// SystemInfo captures system context
type SystemInfo struct {
	Hostname        string `json:"hostname"`
	OSVersion       string `json:"osVersion"`
	Architecture    string `json:"architecture"`
	DefenderRunning bool   `json:"defenderRunning"`
	MDEInstalled    bool   `json:"mdeInstalled"`
	MDEVersion      string `json:"mdeVersion,omitempty"`
	ProcessID       int    `json:"processId"`
	Username        string `json:"username"`
	IsAdmin         bool   `json:"isAdmin"`
}

// FileDropLog tracks files dropped during test
type FileDropLog struct {
	Filename    string    `json:"filename"`
	Path        string    `json:"path"`
	Size        int64     `json:"size"`
	Quarantined bool      `json:"quarantined"`
	Timestamp   time.Time `json:"timestamp"`
}

// ProcessLog tracks processes executed during test
type ProcessLog struct {
	ProcessName string    `json:"processName"`
	CommandLine string    `json:"commandLine"`
	PID         int       `json:"pid,omitempty"`
	Success     bool      `json:"success"`
	ExitCode    int       `json:"exitCode,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	ErrorMsg    string    `json:"errorMsg,omitempty"`
}

// TimestampWriter wraps writes with timestamps for stdout/stderr capture
type TimestampWriter struct {
	file        *os.File
	mu          sync.Mutex
	lastNewline bool // Track if last write ended with newline
}

// Write implements io.Writer interface with timestamp prefixing
func (w *TimestampWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return 0, fmt.Errorf("stdout file not initialized")
	}

	// Convert bytes to string for processing
	text := string(p)
	if text == "" {
		return 0, nil
	}

	// Split into lines
	lines := strings.Split(text, "\n")

	for i, line := range lines {
		// Skip empty lines except the last one (which might be just \n)
		if line == "" && i < len(lines)-1 {
			if i > 0 || w.lastNewline {
				// Write newline for empty line
				if _, err := w.file.WriteString("\n"); err != nil {
					return 0, err
				}
			}
			continue
		}

		// If this is not the first line or last write ended with newline, add timestamp
		if i > 0 || w.lastNewline {
			timestamp := time.Now().Format("2006-01-02 15:04:05.000")
			if _, err := w.file.WriteString(fmt.Sprintf("%s %s", timestamp, line)); err != nil {
				return 0, err
			}
		} else {
			// Continue previous line without timestamp
			if _, err := w.file.WriteString(line); err != nil {
				return 0, err
			}
		}

		// Add newline if not the last line
		if i < len(lines)-1 {
			if _, err := w.file.WriteString("\n"); err != nil {
				return 0, err
			}
		}
	}

	// Track if this write ended with newline
	w.lastNewline = strings.HasSuffix(text, "\n")
	if w.lastNewline && len(lines) > 0 && lines[len(lines)-1] == "" {
		// Ended with newline, write it
		if _, err := w.file.WriteString("\n"); err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

// ==============================================================================
// GLOBAL STATE
// ==============================================================================

var (
	globalLog      *TestLog
	logMutex       sync.Mutex
	logFile        *os.File
	isStage        bool = false // true if this is a stage binary (not main orchestrator)
	stdoutFile     *os.File     // Raw stdout capture file
	originalStdout *os.File     // Original stdout for restoration
	originalStderr *os.File     // Original stderr for restoration
)

// ==============================================================================
// INITIALIZATION FUNCTIONS
// ==============================================================================

// InitLogger initializes the global test logger (main orchestrator only)
func InitLogger(testID, testName string) *TestLog {
	logMutex.Lock()
	defer logMutex.Unlock()

	globalLog = &TestLog{
		TestID:            testID,
		TestName:          testName,
		IsMultiStage:      false, // Will be set to true if stages are used
		StartTime:         time.Now(),
		Phases:            []PhaseLog{},
		Stages:            []StageLog{},
		Messages:          []LogEntry{},
		FilesDropped:      []FileDropLog{},
		ProcessesExecuted: []ProcessLog{},
	}

	// Capture system info
	globalLog.SystemInfo = captureSystemInfo()

	// Set up stdout/stderr capture to test_execution_stdout.txt
	targetDir := "C:\\F0"
	os.MkdirAll(targetDir, 0755)
	stdoutPath := filepath.Join(targetDir, "test_execution_stdout.txt")

	var err error
	stdoutFile, err = os.Create(stdoutPath)
	if err != nil {
		// If we can't create stdout file, just continue without capture
		fmt.Printf("[WARNING] Failed to create stdout capture file: %v\n", err)
		addMessage("WARN", "Initialization", fmt.Sprintf("Failed to create stdout capture: %v", err))
	} else {
		// Save original stdout/stderr
		originalStdout = os.Stdout
		originalStderr = os.Stderr

		// Create pipes for capturing output
		rOut, wOut, _ := os.Pipe()
		rErr, wErr, _ := os.Pipe()

		// Redirect stdout and stderr to pipes
		os.Stdout = wOut
		os.Stderr = wErr

		// Create timestamped writer
		timestampWriter := &TimestampWriter{
			file:        stdoutFile,
			lastNewline: true,
		}

		// Start goroutines to copy from pipes to both console and file
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := rOut.Read(buf)
				if n > 0 {
					// Write to original stdout (console)
					originalStdout.Write(buf[:n])
					// Write to timestamped file
					timestampWriter.Write(buf[:n])
				}
				if err != nil {
					break
				}
			}
		}()

		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := rErr.Read(buf)
				if n > 0 {
					// Write to original stderr (console)
					originalStderr.Write(buf[:n])
					// Write to timestamped file
					timestampWriter.Write(buf[:n])
				}
				if err != nil {
					break
				}
			}
		}()

		addMessage("INFO", "Initialization", fmt.Sprintf("Stdout/stderr capture enabled: %s", stdoutPath))
	}

	addMessage("INFO", "Initialization", fmt.Sprintf("Test logger initialized for %s", testName))
	addMessage("INFO", "Initialization", fmt.Sprintf("Running as: %s (Admin: %v)",
		globalLog.SystemInfo.Username, globalLog.SystemInfo.IsAdmin))

	return globalLog
}

// AttachLogger attaches a stage binary to existing shared log
// Stage binaries call this instead of InitLogger()
func AttachLogger(testID, stageName string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	isStage = true

	// Load existing log if available
	logPath := filepath.Join("C:\\F0", "test_execution_log.json")
	if data, err := os.ReadFile(logPath); err == nil {
		if err := json.Unmarshal(data, &globalLog); err == nil {
			// Successfully loaded existing log
			addMessage("INFO", stageName, "Stage attached to shared log")
			return
		}
	}

	// Create minimal log if file doesn't exist yet
	globalLog = &TestLog{
		TestID:            testID,
		TestName:          "Multi-Stage Test",
		IsMultiStage:      true,
		StartTime:         time.Now(),
		Phases:            []PhaseLog{},
		Stages:            []StageLog{},
		Messages:          []LogEntry{},
		FilesDropped:      []FileDropLog{},
		ProcessesExecuted: []ProcessLog{},
		SystemInfo:        captureSystemInfo(),
	}

	addMessage("INFO", stageName, "Stage created new log (orchestrator not started yet)")
}

// ==============================================================================
// MULTI-STAGE LOGGING FUNCTIONS
// ==============================================================================

// LogStageStart starts tracking a stage execution
func LogStageStart(stageID int, technique, name string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	globalLog.IsMultiStage = true

	stage := StageLog{
		StageID:   stageID,
		Technique: technique,
		Name:      name,
		StartTime: time.Now(),
		Status:    "in_progress",
	}

	globalLog.Stages = append(globalLog.Stages, stage)
	addMessage("INFO", technique, fmt.Sprintf("Stage %d started: %s", stageID, name))
}

// LogStageEnd completes a stage with status
func LogStageEnd(stageID int, technique, status, details string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	// Find and update stage
	for i := range globalLog.Stages {
		if globalLog.Stages[i].StageID == stageID && globalLog.Stages[i].Technique == technique {
			globalLog.Stages[i].EndTime = time.Now()
			globalLog.Stages[i].Status = status
			globalLog.Stages[i].DurationMs = globalLog.Stages[i].EndTime.Sub(globalLog.Stages[i].StartTime).Milliseconds()

			addMessage("INFO", technique, fmt.Sprintf("Stage %d completed: %s (%dms)", stageID, status, globalLog.Stages[i].DurationMs))

			// Persist to disk immediately (for stage coordination)
			if isStage {
				persistLog()
			}
			return
		}
	}
}

// LogStageBlocked logs a stage being blocked by EDR
func LogStageBlocked(stageID int, technique, reason string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	// Find and update stage
	for i := range globalLog.Stages {
		if globalLog.Stages[i].StageID == stageID && globalLog.Stages[i].Technique == technique {
			globalLog.Stages[i].EndTime = time.Now()
			globalLog.Stages[i].Status = "blocked"
			globalLog.Stages[i].BlockedBy = reason
			globalLog.Stages[i].DurationMs = globalLog.Stages[i].EndTime.Sub(globalLog.Stages[i].StartTime).Milliseconds()
			globalLog.Stages[i].ExitCode = 126

			globalLog.BlockedAtStage = stageID
			globalLog.BlockedTechnique = technique

			addMessage("ERROR", technique, fmt.Sprintf("Stage %d BLOCKED: %s", stageID, reason))

			// Persist to disk immediately
			if isStage {
				persistLog()
			}
			return
		}
	}
}

// ==============================================================================
// STANDARD LOGGING FUNCTIONS
// ==============================================================================

// LogPhaseStart starts tracking a new phase
func LogPhaseStart(phaseNumber int, phaseName string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	phase := PhaseLog{
		PhaseNumber: phaseNumber,
		PhaseName:   phaseName,
		StartTime:   time.Now(),
		Status:      "in_progress",
		Errors:      []string{},
	}

	globalLog.Phases = append(globalLog.Phases, phase)
	addMessage("INFO", phaseName, fmt.Sprintf("Phase %d started: %s", phaseNumber, phaseName))
}

// LogPhaseEnd completes a phase with status and details
func LogPhaseEnd(phaseNumber int, status string, details string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if phaseNumber >= 0 && phaseNumber < len(globalLog.Phases) {
		globalLog.Phases[phaseNumber].EndTime = time.Now()
		globalLog.Phases[phaseNumber].Status = status
		globalLog.Phases[phaseNumber].Details = details
		globalLog.Phases[phaseNumber].DurationMs = globalLog.Phases[phaseNumber].EndTime.Sub(globalLog.Phases[phaseNumber].StartTime).Milliseconds()

		addMessage("INFO", globalLog.Phases[phaseNumber].PhaseName,
			fmt.Sprintf("Phase %d completed: %s (%d ms)", phaseNumber, status, globalLog.Phases[phaseNumber].DurationMs))
	}
}

// LogPhaseError adds an error to a phase
func LogPhaseError(phaseNumber int, errorMsg string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if phaseNumber >= 0 && phaseNumber < len(globalLog.Phases) {
		globalLog.Phases[phaseNumber].Errors = append(globalLog.Phases[phaseNumber].Errors, errorMsg)
		addMessage("ERROR", globalLog.Phases[phaseNumber].PhaseName, errorMsg)
	}
}

// LogMessage adds a message to the log (thread-safe)
func LogMessage(level, phase, message string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	addMessage(level, phase, message)

	// Persist immediately if this is a stage binary
	if isStage {
		persistLog()
	}
}

// addMessage internal function (assumes lock is held)
func addMessage(level, phase, message string) {
	msg := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Phase:     phase,
		Message:   message,
	}

	globalLog.Messages = append(globalLog.Messages, msg)
}

// LogConsole logs a message to both console and raw stdout file with timestamp
// This function should be used for all console output to ensure capture
func LogConsole(format string, args ...interface{}) {
	// Format the message
	msg := fmt.Sprintf(format, args...)

	// Print to console
	fmt.Println(msg)

	// Write to stdout file with timestamp (if enabled)
	if stdoutFile != nil {
		timestamp := time.Now().Format("2006-01-02 15:04:05.000")
		fmt.Fprintf(stdoutFile, "%s %s\n", timestamp, msg)
	}
}

// LogConsolef is like LogConsole but doesn't add a newline (for Printf-style usage)
func LogConsolef(format string, args ...interface{}) {
	// Format the message
	msg := fmt.Sprintf(format, args...)

	// Print to console without newline
	fmt.Print(msg)

	// Write to stdout file with timestamp (if enabled)
	if stdoutFile != nil {
		timestamp := time.Now().Format("2006-01-02 15:04:05.000")
		fmt.Fprintf(stdoutFile, "%s %s", timestamp, msg)
	}
}

// LogFileDropped logs a file drop operation
func LogFileDropped(filename, path string, size int64, quarantined bool) {
	logMutex.Lock()
	defer logMutex.Unlock()

	fileDrop := FileDropLog{
		Filename:    filename,
		Path:        path,
		Size:        size,
		Quarantined: quarantined,
		Timestamp:   time.Now(),
	}

	globalLog.FilesDropped = append(globalLog.FilesDropped, fileDrop)

	status := "dropped"
	if quarantined {
		status = "quarantined"
	}
	addMessage("INFO", "File Operations", fmt.Sprintf("File %s: %s (%d bytes)", status, filename, size))
}

// LogProcessExecution logs a process execution
func LogProcessExecution(processName, commandLine string, pid int, success bool, exitCode int, errorMsg string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	procLog := ProcessLog{
		ProcessName: processName,
		CommandLine: commandLine,
		PID:         pid,
		Success:     success,
		ExitCode:    exitCode,
		Timestamp:   time.Now(),
		ErrorMsg:    errorMsg,
	}

	globalLog.ProcessesExecuted = append(globalLog.ProcessesExecuted, procLog)

	if success {
		addMessage("INFO", "Process Execution", fmt.Sprintf("Executed: %s (PID: %d)", processName, pid))
	} else {
		addMessage("ERROR", "Process Execution", fmt.Sprintf("Failed: %s - %s", processName, errorMsg))
	}
}

// ==============================================================================
// SAVE FUNCTIONS
// ==============================================================================

// SaveLog saves the complete log to disk
func SaveLog(exitCode int, exitReason string) error {
	logMutex.Lock()
	defer logMutex.Unlock()

	globalLog.EndTime = time.Now()
	globalLog.Duration = globalLog.EndTime.Sub(globalLog.StartTime).Milliseconds()
	globalLog.ExitCode = exitCode
	globalLog.ExitReason = exitReason

	// Close and restore stdout/stderr before persisting logs
	if stdoutFile != nil {
		// Restore original stdout/stderr
		if originalStdout != nil {
			os.Stdout = originalStdout
		}
		if originalStderr != nil {
			os.Stderr = originalStderr
		}

		// Give goroutines a moment to finish writing
		time.Sleep(100 * time.Millisecond)

		// Close the stdout capture file
		stdoutFile.Sync()  // Flush any pending writes
		stdoutFile.Close()
		stdoutFile = nil
	}

	return persistLog()
}

// persistLog writes log to disk (assumes lock is held)
func persistLog() error {
	targetDir := "C:\\F0"
	os.MkdirAll(targetDir, 0755)

	// Save JSON log
	jsonPath := filepath.Join(targetDir, "test_execution_log.json")
	jsonData, err := json.MarshalIndent(globalLog, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON log: %v", err)
	}

	// Save human-readable text log
	txtPath := filepath.Join(targetDir, "test_execution_log.txt")
	txtData := formatTextLog(globalLog)
	if err := os.WriteFile(txtPath, []byte(txtData), 0644); err != nil {
		return fmt.Errorf("failed to write text log: %v", err)
	}

	// Only print confirmation if main orchestrator (not stage)
	if !isStage {
		fmt.Printf("\n[*] ========================================\n")
		fmt.Printf("[*] Execution logs saved:\n")
		fmt.Printf("[*]   JSON:   %s\n", jsonPath)
		fmt.Printf("[*]   TEXT:   %s\n", txtPath)
		stdoutPath := filepath.Join(targetDir, "test_execution_stdout.txt")
		if _, err := os.Stat(stdoutPath); err == nil {
			fmt.Printf("[*]   STDOUT: %s\n", stdoutPath)
		}
		fmt.Printf("[*] ========================================\n\n")
	}

	return nil
}

// formatTextLog creates human-readable text log
func formatTextLog(log *TestLog) string {
	var out strings.Builder

	out.WriteString(strings.Repeat("=", 80) + "\n")
	out.WriteString("F0RT1KA SECURITY TEST - EXECUTION LOG\n")
	out.WriteString(strings.Repeat("=", 80) + "\n\n")

	// Test information
	out.WriteString(fmt.Sprintf("Test ID:      %s\n", log.TestID))
	out.WriteString(fmt.Sprintf("Test Name:    %s\n", log.TestName))
	out.WriteString(fmt.Sprintf("Multi-Stage:  %v\n", log.IsMultiStage))
	out.WriteString(fmt.Sprintf("Start Time:   %s\n", log.StartTime.Format("2006-01-02 15:04:05.000")))
	out.WriteString(fmt.Sprintf("End Time:     %s\n", log.EndTime.Format("2006-01-02 15:04:05.000")))
	out.WriteString(fmt.Sprintf("Duration:     %d ms (%.2f seconds)\n", log.Duration, float64(log.Duration)/1000))
	out.WriteString(fmt.Sprintf("Exit Code:    %d\n", log.ExitCode))
	out.WriteString(fmt.Sprintf("Exit Reason:  %s\n\n", log.ExitReason))

	// Multi-stage information
	if log.IsMultiStage && len(log.Stages) > 0 {
		out.WriteString("STAGE EXECUTION SUMMARY\n")
		out.WriteString(strings.Repeat("-", 80) + "\n")
		out.WriteString(fmt.Sprintf("Total Stages: %d\n", len(log.Stages)))
		if log.BlockedAtStage > 0 {
			out.WriteString(fmt.Sprintf("Blocked At:   Stage %d (%s)\n", log.BlockedAtStage, log.BlockedTechnique))
		}
		out.WriteString("\nStage Details:\n")
		for _, stage := range log.Stages {
			out.WriteString(fmt.Sprintf("\nStage %d: %s (%s)\n", stage.StageID, stage.Name, stage.Technique))
			out.WriteString(fmt.Sprintf("  Status:    %s\n", stage.Status))
			out.WriteString(fmt.Sprintf("  Duration:  %d ms\n", stage.DurationMs))
			out.WriteString(fmt.Sprintf("  Exit Code: %d\n", stage.ExitCode))
			if stage.BlockedBy != "" {
				out.WriteString(fmt.Sprintf("  Blocked:   %s\n", stage.BlockedBy))
			}
			if stage.ErrorMessage != "" {
				out.WriteString(fmt.Sprintf("  Error:     %s\n", stage.ErrorMessage))
			}
		}
		out.WriteString("\n")
	}

	// System information
	out.WriteString("SYSTEM INFORMATION\n")
	out.WriteString(strings.Repeat("-", 80) + "\n")
	out.WriteString(fmt.Sprintf("Hostname:          %s\n", log.SystemInfo.Hostname))
	out.WriteString(fmt.Sprintf("OS Version:        %s\n", log.SystemInfo.OSVersion))
	out.WriteString(fmt.Sprintf("Architecture:      %s\n", log.SystemInfo.Architecture))
	out.WriteString(fmt.Sprintf("Username:          %s\n", log.SystemInfo.Username))
	out.WriteString(fmt.Sprintf("Administrator:     %v\n", log.SystemInfo.IsAdmin))
	out.WriteString(fmt.Sprintf("Process ID:        %d\n", log.SystemInfo.ProcessID))
	out.WriteString(fmt.Sprintf("Defender Running:  %v\n", log.SystemInfo.DefenderRunning))
	out.WriteString(fmt.Sprintf("MDE Installed:     %v\n", log.SystemInfo.MDEInstalled))
	if log.SystemInfo.MDEVersion != "" {
		out.WriteString(fmt.Sprintf("MDE Version:       %s\n", log.SystemInfo.MDEVersion))
	}
	out.WriteString("\n")

	// Phase execution
	if len(log.Phases) > 0 {
		out.WriteString("PHASE EXECUTION\n")
		out.WriteString(strings.Repeat("-", 80) + "\n")
		for _, phase := range log.Phases {
			out.WriteString(fmt.Sprintf("\nPhase %d: %s\n", phase.PhaseNumber, phase.PhaseName))
			out.WriteString(fmt.Sprintf("  Status:   %s\n", phase.Status))
			out.WriteString(fmt.Sprintf("  Duration: %d ms\n", phase.DurationMs))
			if phase.Details != "" {
				out.WriteString(fmt.Sprintf("  Details:  %s\n", phase.Details))
			}
			if len(phase.Errors) > 0 {
				out.WriteString("  Errors:\n")
				for _, err := range phase.Errors {
					out.WriteString(fmt.Sprintf("    - %s\n", err))
				}
			}
		}
		out.WriteString("\n")
	}

	// Files dropped
	if len(log.FilesDropped) > 0 {
		out.WriteString("FILES DROPPED\n")
		out.WriteString(strings.Repeat("-", 80) + "\n")
		for i, file := range log.FilesDropped {
			status := "OK"
			if file.Quarantined {
				status = "QUARANTINED"
			}
			out.WriteString(fmt.Sprintf("%d. %s [%s]\n", i+1, file.Filename, status))
			out.WriteString(fmt.Sprintf("   Path: %s\n", file.Path))
			out.WriteString(fmt.Sprintf("   Size: %d bytes\n", file.Size))
		}
		out.WriteString("\n")
	}

	// Processes executed
	if len(log.ProcessesExecuted) > 0 {
		out.WriteString("PROCESSES EXECUTED\n")
		out.WriteString(strings.Repeat("-", 80) + "\n")
		for i, proc := range log.ProcessesExecuted {
			status := "SUCCESS"
			if !proc.Success {
				status = "FAILED"
			}
			out.WriteString(fmt.Sprintf("%d. %s [%s]\n", i+1, proc.ProcessName, status))
			if proc.PID > 0 {
				out.WriteString(fmt.Sprintf("   PID: %d\n", proc.PID))
			}
			if proc.CommandLine != "" {
				out.WriteString(fmt.Sprintf("   CMD: %s\n", proc.CommandLine))
			}
			if proc.ErrorMsg != "" {
				out.WriteString(fmt.Sprintf("   Error: %s\n", proc.ErrorMsg))
			}
		}
		out.WriteString("\n")
	}

	// Detailed message log
	out.WriteString("DETAILED MESSAGE LOG\n")
	out.WriteString(strings.Repeat("-", 80) + "\n")
	for _, msg := range log.Messages {
		timestamp := msg.Timestamp.Format("15:04:05.000")
		out.WriteString(fmt.Sprintf("[%s] [%-8s] [%-25s] %s\n",
			timestamp, msg.Level, truncateString(msg.Phase, 25), msg.Message))
	}

	out.WriteString("\n" + strings.Repeat("=", 80) + "\n")
	out.WriteString("END OF LOG\n")
	out.WriteString(strings.Repeat("=", 80) + "\n")

	return out.String()
}

// ==============================================================================
// HELPER FUNCTIONS
// ==============================================================================

func captureSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()

	info := SystemInfo{
		Hostname:        hostname,
		OSVersion:       getOSVersion(),
		Architecture:    getArchitecture(),
		DefenderRunning: isDefenderRunning(),
		MDEInstalled:    isMDEInstalled(),
		ProcessID:       os.Getpid(),
		Username:        os.Getenv("USERNAME"),
		IsAdmin:         isAdmin(),
	}

	if info.MDEInstalled {
		info.MDEVersion = getMDEVersion()
	}

	return info
}

func getOSVersion() string {
	cmd := exec.Command("cmd", "/C", "ver")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

func getArchitecture() string {
	if os.Getenv("PROCESSOR_ARCHITECTURE") != "" {
		return os.Getenv("PROCESSOR_ARCHITECTURE")
	}
	return "Unknown"
}

func isDefenderRunning() bool {
	cmd := exec.Command("sc", "query", "WinDefend")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "RUNNING")
}

func isMDEInstalled() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Advanced Threat Protection`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	return true
}

func getMDEVersion() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Advanced Threat Protection`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()

	version, _, err := key.GetStringValue("Version")
	if err != nil {
		return "Unknown"
	}
	return version
}

func isAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// NetworkTestSummary stub for compatibility
type NetworkTestSummary struct {
	TotalEndpoints     int `json:"totalEndpoints"`
	SuccessfulTests    int `json:"successfulTests"`
	FailedTests        int `json:"failedTests"`
	VulnerableCount    int `json:"vulnerableCount"`
	ProtectedCount     int `json:"protectedCount"`
	OverallVulnerable  bool `json:"overallVulnerable"`
	Results            []interface{} `json:"results,omitempty"`
}

// MDEIdentifiers stub for compatibility
type MDEIdentifiers struct {
	Source            string
	MDEInstalled      bool
	ExtractionSuccess bool
	MachineID         string
	TenantID          string
	SenseID           string
	OrgID             string
}

// BypassResult stub for compatibility
type BypassResult struct {
	Success      bool
	Blocked      bool
	BlockedBy    string
	TestDuration time.Duration
}
