//go:build windows
// +build windows

/*
ID: 67165014-0377-4300-8197-ab459bd9249b
NAME: PowerShell Security and Logging Validator
TECHNIQUES: T1059.001, T1027, T1140, T1105
TACTICS: execution, defense-evasion
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: baseline
TAGS: powershell, logging, constrained-language, script-block-logging, cis-controls
UNIT: response
CREATED: 2025-01-11
AUTHOR: sectest-builder
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID = "67165014-0377-4300-8197-ab459bd9249b"
	TEST_NAME = "PowerShell Security and Logging Validator"

	// PowerShell Logging Registry Paths
	SCRIPTBLOCK_LOGGING_PATH = `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
	MODULE_LOGGING_PATH      = `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging`
	TRANSCRIPTION_PATH       = `SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`

	// Registry Value Names
	ENABLE_SCRIPTBLOCK_LOGGING = "EnableScriptBlockLogging"
	ENABLE_MODULE_LOGGING      = "EnableModuleLogging"
	ENABLE_TRANSCRIPTING       = "EnableTranscripting"

	// Expected Values
	LOGGING_ENABLED = 1
)

// PSSecurityCheck represents a PowerShell security configuration check
type PSSecurityCheck struct {
	Name          string
	Description   string
	RegistryPath  string
	ValueName     string
	ExpectedValue uint64
	ActualValue   uint64
	Configured    bool
	Compliant     bool
	Source        string // "registry", "powershell", "not_found"
	IsCritical    bool   // Critical checks fail the test if non-compliant
}

// PSLanguageModeCheck represents the language mode check result
type PSLanguageModeCheck struct {
	Mode       string
	Compliant  bool
	Configured bool
	Source     string
}

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA CYBER-HYGIENE TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("READ-ONLY configuration validation - no system changes")
	Endpoint.Say("")
	Endpoint.Say("PURPOSE: Validate PowerShell security controls and logging")
	Endpoint.Say("         PowerShell abuse (T1059.001) is the #1 attack technique")
	Endpoint.Say("         with 46,155+ observed instances in 2024.")
	Endpoint.Say("")

	// Ensure C:\F0 directory exists for logging
	os.MkdirAll("c:\\F0", 0755)

	// Initialize logger with Schema v2.0 metadata
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "execution", // Validating defenses against execution techniques
		Severity:   "high",
		Techniques: []string{"T1059.001", "T1027", "T1140", "T1105"},
		Tactics:    []string{"execution", "defense-evasion"},
		Score:      8.0,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5, // Checks actual production PowerShell security settings
			TechnicalSophistication: 2.0, // Registry + PowerShell language mode checks
			SafetyMechanisms:        2.0, // Read-only, no modifications
			DetectionOpportunities:  0.5, // Single detection point (compliance)
			LoggingObservability:    1.0, // Comprehensive logging per check
		},
		Tags: []string{"cyber-hygiene", "powershell", "logging", "configuration-validation", "read-only", "cis-benchmark"},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         60000, // 1 minute timeout
			CertificateMode:   "not-required",
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Panic: %v", r))
		}
	}()

	// Run the test with timeout
	done := make(chan bool, 1)
	var exitCode int
	var exitReason string

	go func() {
		exitCode, exitReason = runPSSecurityValidation()
		done <- true
	}()

	timeout := 1 * time.Minute
	select {
	case <-done:
		Endpoint.Say("")
		Endpoint.Say("Test completed")
		SaveLog(exitCode, exitReason)
		Endpoint.Stop(exitCode)
	case <-time.After(timeout):
		Endpoint.Say("Test timed out after %v", timeout)
		LogMessage("ERROR", "Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
		SaveLog(Endpoint.TimeoutExceeded, "Test timed out")
		Endpoint.Stop(Endpoint.TimeoutExceeded)
	}
}

// runPSSecurityValidation performs the PowerShell security configuration validation
func runPSSecurityValidation() (int, string) {
	// Phase 0: Initialization
	LogPhaseStart(0, "Initialization")
	Endpoint.Say("Initializing PowerShell Security validation...")
	LogMessage("INFO", "Initialization", "Starting PowerShell security and logging validation")
	LogMessage("INFO", "Initialization", "Checking 3 critical logging settings + 1 informational setting")
	LogPhaseEnd(0, "success", "Initialization complete")

	// Define the checks
	checks := []PSSecurityCheck{
		{
			Name:          "Script Block Logging",
			Description:   "Logs all PowerShell script blocks that are processed (Event ID 4104)",
			RegistryPath:  SCRIPTBLOCK_LOGGING_PATH,
			ValueName:     ENABLE_SCRIPTBLOCK_LOGGING,
			ExpectedValue: LOGGING_ENABLED,
			IsCritical:    true,
		},
		{
			Name:          "Module Logging",
			Description:   "Logs pipeline execution details for specified modules (Event ID 4103)",
			RegistryPath:  MODULE_LOGGING_PATH,
			ValueName:     ENABLE_MODULE_LOGGING,
			ExpectedValue: LOGGING_ENABLED,
			IsCritical:    true,
		},
		{
			Name:          "Transcription",
			Description:   "Creates text transcript of all PowerShell sessions",
			RegistryPath:  TRANSCRIPTION_PATH,
			ValueName:     ENABLE_TRANSCRIPTING,
			ExpectedValue: LOGGING_ENABLED,
			IsCritical:    true,
		},
	}

	// Phase 1: Check PowerShell logging via registry
	LogPhaseStart(1, "Registry Logging Check")
	Endpoint.Say("")
	Endpoint.Say("[Phase 1] Checking PowerShell logging configuration via Registry...")
	Endpoint.Say("")

	for i := range checks {
		checkRegistrySetting(&checks[i])
	}

	registryCompliant := countCompliantChecks(checks)
	LogMessage("INFO", "Registry Logging Check", fmt.Sprintf("%d of %d critical logging settings found compliant in registry", registryCompliant, len(checks)))
	LogPhaseEnd(1, "success", fmt.Sprintf("Registry check complete - %d/%d compliant", registryCompliant, len(checks)))

	// Phase 2: Check Module Logging modules list
	LogPhaseStart(2, "Module Names Check")
	Endpoint.Say("")
	Endpoint.Say("[Phase 2] Checking Module Logging configuration...")

	moduleNamesConfigured := checkModuleNames()
	if moduleNamesConfigured {
		LogMessage("INFO", "Module Names Check", "Module logging is configured to log all modules (*)")
		Endpoint.Say("  [+] ModuleNames includes '*' - all modules will be logged")
	} else {
		LogMessage("WARN", "Module Names Check", "Module logging ModuleNames not configured for all modules")
		Endpoint.Say("  [!] ModuleNames does not include '*' - consider logging all modules")
	}
	LogPhaseEnd(2, "success", fmt.Sprintf("ModuleNames check complete - all modules: %v", moduleNamesConfigured))

	// Phase 3: Check Constrained Language Mode (informational)
	LogPhaseStart(3, "Language Mode Check")
	Endpoint.Say("")
	Endpoint.Say("[Phase 3] Checking PowerShell Language Mode (informational)...")

	languageMode := checkLanguageMode()

	if languageMode.Configured {
		if languageMode.Compliant {
			LogMessage("INFO", "Language Mode Check", fmt.Sprintf("PowerShell is in %s mode (recommended)", languageMode.Mode))
			Endpoint.Say("  [+] PowerShell Language Mode: %s (recommended)", languageMode.Mode)
		} else {
			LogMessage("WARN", "Language Mode Check", fmt.Sprintf("PowerShell is in %s mode - consider ConstrainedLanguage for high-security environments", languageMode.Mode))
			Endpoint.Say("  [~] PowerShell Language Mode: %s", languageMode.Mode)
			Endpoint.Say("      Note: ConstrainedLanguage mode is recommended for high-security environments")
			Endpoint.Say("      but may break legitimate scripts. Informational only - not counted as failure.")
		}
	} else {
		LogMessage("WARN", "Language Mode Check", "Could not determine PowerShell language mode")
		Endpoint.Say("  [?] Could not determine PowerShell language mode")
	}
	LogPhaseEnd(3, "success", fmt.Sprintf("Language mode check complete - mode: %s", languageMode.Mode))

	// Phase 4: Analyze and report results
	LogPhaseStart(4, "Analysis")
	Endpoint.Say("")
	Endpoint.Say("[Phase 4] Analyzing PowerShell Security Configuration...")
	Endpoint.Say("")

	// Display results table
	Endpoint.Say("%-30s %-15s %-10s %-10s", "Security Setting", "Status", "Value", "Source")
	Endpoint.Say(strings.Repeat("-", 70))

	criticalCompliant := 0
	criticalTotal := 0

	for _, check := range checks {
		if check.IsCritical {
			criticalTotal++
		}

		var status string
		var indicator string

		if !check.Configured {
			status = "NOT FOUND"
			indicator = "!"
		} else if check.Compliant {
			status = "ENABLED"
			indicator = "+"
			if check.IsCritical {
				criticalCompliant++
			}
		} else {
			status = "DISABLED"
			indicator = "!"
		}

		var valueStr string
		if check.Configured {
			valueStr = fmt.Sprintf("%d", check.ActualValue)
		} else {
			valueStr = "N/A"
		}

		Endpoint.Say("[%s] %-28s %-15s %-10s %-10s", indicator, check.Name, status, valueStr, check.Source)

		// Log each check result
		if check.Compliant {
			LogMessage("INFO", "Analysis", fmt.Sprintf("[COMPLIANT] %s = Enabled", check.Name))
		} else if !check.Configured {
			LogMessage("WARN", "Analysis", fmt.Sprintf("[MISSING] %s - not configured", check.Name))
		} else {
			LogMessage("WARN", "Analysis", fmt.Sprintf("[NON-COMPLIANT] %s = Disabled (should be 1)", check.Name))
		}
	}

	// Add language mode to display (informational)
	langIndicator := "~"
	langStatus := languageMode.Mode
	if languageMode.Compliant {
		langIndicator = "+"
	}
	Endpoint.Say("[%s] %-28s %-15s %-10s %-10s", langIndicator, "Constrained Language Mode", langStatus, "(info)", languageMode.Source)

	Endpoint.Say(strings.Repeat("-", 70))
	Endpoint.Say("")

	// Summary
	Endpoint.Say("SUMMARY:")
	Endpoint.Say("  Critical Logging Settings:    %d of %d compliant", criticalCompliant, criticalTotal)
	Endpoint.Say("    - Script Block Logging:     %s", getCheckStatus(checks, "Script Block Logging"))
	Endpoint.Say("    - Module Logging:           %s", getCheckStatus(checks, "Module Logging"))
	Endpoint.Say("    - Transcription:            %s", getCheckStatus(checks, "Transcription"))
	Endpoint.Say("  Informational Settings:")
	Endpoint.Say("    - Constrained Lang Mode:    %s (not required for compliance)", languageMode.Mode)
	Endpoint.Say("    - Log All Modules (*):      %s", boolToYesNo(moduleNamesConfigured))
	Endpoint.Say("")

	LogMessage("INFO", "Analysis", fmt.Sprintf("Summary: %d/%d critical logging settings compliant", criticalCompliant, criticalTotal))

	// Determine exit code and reason
	var exitCode int
	var exitReason string

	if criticalCompliant == criticalTotal {
		// All 3 critical logging settings are enabled - COMPLIANT
		exitCode = Endpoint.ExecutionPrevented // 126
		exitReason = fmt.Sprintf("COMPLIANT: All %d critical PowerShell logging settings are enabled", criticalTotal)
		Endpoint.Say("[+] RESULT: COMPLIANT - All critical PowerShell logging settings are enabled")
		Endpoint.Say("    PowerShell activity will be logged to Windows Event Log:")
		Endpoint.Say("    - Event ID 4103: Module Logging events")
		Endpoint.Say("    - Event ID 4104: Script Block Logging events")
		LogMessage("SUCCESS", "Analysis", exitReason)
		LogPhaseEnd(4, "success", "All critical logging settings compliant")
	} else {
		// One or more critical logging settings are not enabled - NON-COMPLIANT
		exitCode = Endpoint.Unprotected // 101
		failedChecks := criticalTotal - criticalCompliant
		exitReason = fmt.Sprintf("NON-COMPLIANT: %d of %d critical PowerShell logging settings are not enabled", failedChecks, criticalTotal)
		Endpoint.Say("[!] RESULT: NON-COMPLIANT - %d critical logging setting(s) need remediation", failedChecks)
		Endpoint.Say("    PowerShell-based attacks may go undetected!")
		LogMessage("WARN", "Analysis", exitReason)
		LogPhaseEnd(4, "failed", fmt.Sprintf("%d critical settings non-compliant", failedChecks))

		// Provide remediation guidance
		Endpoint.Say("")
		Endpoint.Say("REMEDIATION:")
		Endpoint.Say("  Configure via Group Policy:")
		Endpoint.Say("  Computer Configuration > Administrative Templates > Windows Components")
		Endpoint.Say("  > Windows PowerShell")
		Endpoint.Say("")
		Endpoint.Say("  Required settings:")

		for _, check := range checks {
			if !check.Compliant && check.IsCritical {
				switch check.Name {
				case "Script Block Logging":
					Endpoint.Say("  - Turn on PowerShell Script Block Logging: ENABLED")
				case "Module Logging":
					Endpoint.Say("  - Turn on Module Logging: ENABLED")
					Endpoint.Say("    Module Names: * (to log all modules)")
				case "Transcription":
					Endpoint.Say("  - Turn on PowerShell Transcription: ENABLED")
				}
			}
		}

		Endpoint.Say("")
		Endpoint.Say("  Or configure via PowerShell (Run as Administrator):")
		Endpoint.Say("  # Enable Script Block Logging")
		Endpoint.Say("  New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force")
		Endpoint.Say("  Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1")
		Endpoint.Say("")
		Endpoint.Say("  # Enable Module Logging")
		Endpoint.Say("  New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Force")
		Endpoint.Say("  Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Name 'EnableModuleLogging' -Value 1")
		Endpoint.Say("")
		Endpoint.Say("  # Enable Transcription")
		Endpoint.Say("  New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -Force")
		Endpoint.Say("  Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -Name 'EnableTranscripting' -Value 1")
	}

	// CIS Benchmark Reference
	Endpoint.Say("")
	Endpoint.Say("REFERENCE:")
	Endpoint.Say("  CIS Controls v8: 8.2 (Collect Audit Logs), 8.5 (Collect Detailed Audit Logs)")
	Endpoint.Say("  MITRE ATT&CK: T1059.001 (PowerShell), T1027 (Obfuscated Files)")

	return exitCode, exitReason
}

// checkRegistrySetting checks a single registry setting
func checkRegistrySetting(check *PSSecurityCheck) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, check.RegistryPath, registry.QUERY_VALUE)
	if err != nil {
		// Key doesn't exist
		check.Configured = false
		check.Compliant = false
		check.Source = "not_found"
		LogMessage("WARN", "Registry Check", fmt.Sprintf("%s: Registry key not found at HKLM\\%s", check.Name, check.RegistryPath))
		Endpoint.Say("  [!] %s: Registry key not found", check.Name)
		return
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue(check.ValueName)
	if err != nil {
		// Value doesn't exist in key
		check.Configured = false
		check.Compliant = false
		check.Source = "not_found"
		LogMessage("WARN", "Registry Check", fmt.Sprintf("%s: Value '%s' not found", check.Name, check.ValueName))
		Endpoint.Say("  [!] %s: Value not configured", check.Name)
		return
	}

	check.ActualValue = value
	check.Configured = true
	check.Source = "registry"
	check.Compliant = (value == check.ExpectedValue)

	if check.Compliant {
		LogMessage("INFO", "Registry Check", fmt.Sprintf("%s: Enabled (value=%d)", check.Name, value))
		Endpoint.Say("  [+] %s: ENABLED", check.Name)
	} else {
		LogMessage("WARN", "Registry Check", fmt.Sprintf("%s: Disabled (value=%d, expected=%d)", check.Name, value, check.ExpectedValue))
		Endpoint.Say("  [!] %s: DISABLED (value=%d)", check.Name, value)
	}
}

// checkModuleNames checks if Module Logging is configured to log all modules (*)
func checkModuleNames() bool {
	// Check for ModuleNames under ModuleLogging
	moduleNamesPath := MODULE_LOGGING_PATH + `\ModuleNames`

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, moduleNamesPath, registry.QUERY_VALUE)
	if err != nil {
		LogMessage("INFO", "Module Names", "ModuleNames registry key not found")
		return false
	}
	defer key.Close()

	// Check for "*" value
	_, _, err = key.GetStringValue("*")
	if err == nil {
		return true
	}

	// If "*" not found, enumerate values to check
	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return false
	}

	for _, name := range valueNames {
		if name == "*" {
			return true
		}
	}

	return false
}

// checkLanguageMode checks the current PowerShell language mode
func checkLanguageMode() PSLanguageModeCheck {
	result := PSLanguageModeCheck{
		Mode:       "Unknown",
		Compliant:  false,
		Configured: false,
		Source:     "not_found",
	}

	// Use PowerShell to check language mode
	psCmd := `$ExecutionContext.SessionState.LanguageMode`

	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", psCmd)
	output, err := cmd.CombinedOutput()

	if cmd.Process != nil {
		LogProcessExecution("powershell.exe", "LanguageMode check", cmd.Process.Pid, err == nil, 0, "")
	}

	if err != nil {
		LogMessage("WARN", "Language Mode", fmt.Sprintf("Failed to check language mode: %v", err))
		return result
	}

	mode := strings.TrimSpace(string(output))
	result.Mode = mode
	result.Configured = true
	result.Source = "powershell"

	// ConstrainedLanguage or RestrictedLanguage are considered compliant
	// FullLanguage is common but less secure
	if mode == "ConstrainedLanguage" || mode == "RestrictedLanguage" {
		result.Compliant = true
	} else {
		result.Compliant = false
	}

	LogMessage("INFO", "Language Mode", fmt.Sprintf("PowerShell language mode: %s", mode))

	return result
}

// countCompliantChecks counts the number of compliant checks
func countCompliantChecks(checks []PSSecurityCheck) int {
	count := 0
	for _, check := range checks {
		if check.Compliant {
			count++
		}
	}
	return count
}

// getCheckStatus returns a status string for a named check
func getCheckStatus(checks []PSSecurityCheck, name string) string {
	for _, check := range checks {
		if check.Name == name {
			if check.Compliant {
				return "ENABLED"
			} else if check.Configured {
				return "DISABLED"
			}
			return "NOT CONFIGURED"
		}
	}
	return "UNKNOWN"
}

// boolToYesNo converts a bool to Yes/No string
func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
