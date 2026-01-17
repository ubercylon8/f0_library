//go:build windows
// +build windows

/*
ID: 742bf5df-ee2c-49ce-a477-1afbde3b6f2c
NAME: Microsoft Defender Configuration Validator
TECHNIQUES: T1562.001, T1562.004, T1070
TACTICS: defense-evasion
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: baseline
TAGS: defender, antivirus, real-time-protection, tamper-protection, cis-controls
UNIT: response
CREATED: 2026-01-11
AUTHOR: sectest-builder
*/

// Microsoft Defender Configuration Validator - Cyber Hygiene Test
//
// This test validates that Microsoft Defender Antivirus is properly configured
// with all critical protection features enabled. Proper Defender configuration
// is essential for preventing ransomware and other malware attacks.
//
// Configuration Checks (ALL 6 must pass for COMPLIANT):
// 1. Real-time Protection - Continuous file system monitoring
// 2. Behavior Monitoring - Detects suspicious process behavior
// 3. Tamper Protection - Prevents malware from disabling Defender
// 4. Cloud Protection (MAPS) - Cloud-based threat intelligence
// 5. Sample Submission - Automatic sample upload for analysis
// 6. PUA Protection - Potentially Unwanted Application blocking
//
// Exit Codes:
// - 126: All 6 checks pass (COMPLIANT)
// - 101: One or more checks fail (NON-COMPLIANT)
// - 999: Test error (Defender not installed, third-party AV, insufficient privileges)
//
// CIS Benchmark Reference:
// - CIS Controls v8: 10.1 (Deploy and Maintain Anti-Malware Software)
// - CIS Controls v8: 10.2 (Configure Automatic Updates)

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID = "742bf5df-ee2c-49ce-a477-1afbde3b6f2c"
	TEST_NAME = "Microsoft Defender Configuration Validator"
)

// CheckResult represents the result of a single configuration check
type CheckResult struct {
	Name        string
	Description string
	Compliant   bool
	Value       string
	Expected    string
	Details     string
	Method      string // "powershell" or "registry"
}

// DefenderStatus holds the Defender status from Get-MpComputerStatus
type DefenderStatus struct {
	RealTimeProtectionEnabled bool
	BehaviorMonitorEnabled    bool
	IsTamperProtected         bool
	AntivirusSignatureAge     int // days
	AMServiceEnabled          bool
	AntispywareEnabled        bool
	AntivirusEnabled          bool
}

// DefenderPreference holds the Defender preferences from Get-MpPreference
type DefenderPreference struct {
	MAPSReporting        int
	SubmitSamplesConsent int
	PUAProtection        int
}

// test performs the Microsoft Defender configuration validation
func test() {
	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "defense_evasion",
		Severity:   "critical",
		Techniques: []string{"T1562.001", "T1562.004", "T1070"},
		Tactics:    []string{"defense-evasion"},
		Score:      8.5,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"cyber-hygiene", "defender-configuration", "tamper-protection", "configuration-validation"},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         120000,
			CertificateMode:   "not-required",
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(999, fmt.Sprintf("Panic: %v", r))
		}
	}()

	// Phase 0: Initialization and Defender Detection
	LogPhaseStart(0, "Initialization")

	// Check for admin privileges
	if !isAdmin() {
		Endpoint.Say("[!] ERROR: Administrator privileges required for this test")
		LogMessage("ERROR", "Initialization", "Administrator privileges required")
		LogPhaseEnd(0, "failed", "Insufficient privileges")
		SaveLog(999, "Administrator privileges required")
		Endpoint.Stop(999)
	}
	LogMessage("INFO", "Initialization", "Running with administrator privileges")

	// Check if Windows Defender is available (not replaced by third-party AV)
	if !isDefenderAvailable() {
		Endpoint.Say("[!] ERROR: Windows Defender is not available")
		Endpoint.Say("    This may indicate a third-party antivirus is installed")
		LogMessage("ERROR", "Initialization", "Windows Defender not available - may have third-party AV")
		LogPhaseEnd(0, "failed", "Defender not available")
		SaveLog(999, "Windows Defender not available - third-party AV may be installed")
		Endpoint.Stop(999)
	}
	LogMessage("INFO", "Initialization", "Windows Defender is available")

	LogPhaseEnd(0, "success", "Initialization complete")

	// Phase 1: Retrieve Defender Status
	LogPhaseStart(1, "Retrieve Defender Status")
	Endpoint.Say("[*] Retrieving Microsoft Defender status...")

	status, statusErr := getDefenderStatus()
	if statusErr != nil {
		Endpoint.Say("[!] WARNING: Could not retrieve Defender status via PowerShell")
		Endpoint.Say("    Will fall back to registry checks where possible")
		LogMessage("WARNING", "Status Retrieval", fmt.Sprintf("PowerShell status retrieval failed: %v", statusErr))
	} else {
		LogMessage("INFO", "Status Retrieval", "Successfully retrieved Defender status via Get-MpComputerStatus")
	}

	preferences, prefErr := getDefenderPreferences()
	if prefErr != nil {
		Endpoint.Say("[!] WARNING: Could not retrieve Defender preferences via PowerShell")
		LogMessage("WARNING", "Preferences Retrieval", fmt.Sprintf("PowerShell preferences retrieval failed: %v", prefErr))
	} else {
		LogMessage("INFO", "Preferences Retrieval", "Successfully retrieved Defender preferences via Get-MpPreference")
	}

	LogPhaseEnd(1, "success", "Status retrieval complete")

	// Phase 2: Run Configuration Checks
	LogPhaseStart(2, "Configuration Checks")

	var results []CheckResult

	// Check 1: Real-time Protection
	Endpoint.Say("")
	Endpoint.Say("[*] Check 1/6: Real-time Protection")
	result1 := checkRealTimeProtection(status, statusErr)
	results = append(results, result1)
	logCheckResult(result1)

	// Check 2: Behavior Monitoring
	Endpoint.Say("")
	Endpoint.Say("[*] Check 2/6: Behavior Monitoring")
	result2 := checkBehaviorMonitoring(status, statusErr)
	results = append(results, result2)
	logCheckResult(result2)

	// Check 3: Tamper Protection
	Endpoint.Say("")
	Endpoint.Say("[*] Check 3/6: Tamper Protection")
	result3 := checkTamperProtection(status, statusErr)
	results = append(results, result3)
	logCheckResult(result3)

	// Check 4: Cloud Protection (MAPS)
	Endpoint.Say("")
	Endpoint.Say("[*] Check 4/6: Cloud Protection (MAPS)")
	result4 := checkCloudProtection(preferences, prefErr)
	results = append(results, result4)
	logCheckResult(result4)

	// Check 5: Sample Submission
	Endpoint.Say("")
	Endpoint.Say("[*] Check 5/6: Sample Submission")
	result5 := checkSampleSubmission(preferences, prefErr)
	results = append(results, result5)
	logCheckResult(result5)

	// Check 6: PUA Protection
	Endpoint.Say("")
	Endpoint.Say("[*] Check 6/6: PUA Protection")
	result6 := checkPUAProtection(preferences, prefErr)
	results = append(results, result6)
	logCheckResult(result6)

	LogPhaseEnd(2, "success", "All configuration checks completed")

	// Phase 3: Check Signature Age (Warning Only)
	LogPhaseStart(3, "Signature Age Check")
	if status != nil {
		checkSignatureAge(status.AntivirusSignatureAge)
	} else {
		Endpoint.Say("[!] Could not check signature age - status unavailable")
		LogMessage("WARNING", "Signature Age", "Could not check signature age - status unavailable")
	}
	LogPhaseEnd(3, "success", "Signature age check complete")

	// Phase 4: Compliance Determination
	LogPhaseStart(4, "Compliance Determination")

	passedChecks := 0
	for _, r := range results {
		if r.Compliant {
			passedChecks++
		}
	}

	allCompliant := passedChecks == 6

	// Generate summary
	Endpoint.Say("")
	Endpoint.Say("================================================================================")
	Endpoint.Say("           MICROSOFT DEFENDER CONFIGURATION VALIDATION SUMMARY")
	Endpoint.Say("================================================================================")
	Endpoint.Say("")

	for i, r := range results {
		status := "FAIL"
		if r.Compliant {
			status = "PASS"
		}
		Endpoint.Say("[%s] Check %d: %-35s Value: %s", status, i+1, r.Name, r.Value)
	}

	Endpoint.Say("")
	Endpoint.Say("--------------------------------------------------------------------------------")
	Endpoint.Say("Overall: %d/6 checks passed", passedChecks)

	if allCompliant {
		Endpoint.Say("")
		Endpoint.Say("[COMPLIANT] All Microsoft Defender protection features are properly configured.")
		Endpoint.Say("            System has comprehensive anti-malware protection enabled.")
		LogMessage("SUCCESS", "Compliance", "All 6 Defender configuration checks passed - system is COMPLIANT")
		LogPhaseEnd(4, "success", fmt.Sprintf("All checks passed (%d/6)", passedChecks))
		SaveLog(126, "System is COMPLIANT - all Microsoft Defender protection features enabled")
		Endpoint.Stop(126)
	} else {
		Endpoint.Say("")
		Endpoint.Say("[NON-COMPLIANT] Microsoft Defender configuration is incomplete.")
		Endpoint.Say("                System may be vulnerable to malware attacks.")
		Endpoint.Say("")
		Endpoint.Say("Remediation Steps:")

		for _, r := range results {
			if !r.Compliant {
				printRemediation(r.Name)
			}
		}

		LogMessage("WARNING", "Compliance", fmt.Sprintf("Only %d/6 checks passed - system is NON-COMPLIANT", passedChecks))
		LogPhaseEnd(4, "failed", fmt.Sprintf("Not all checks passed (%d/6)", passedChecks))
		SaveLog(101, fmt.Sprintf("System is NON-COMPLIANT - only %d/6 Defender protection features enabled", passedChecks))
		Endpoint.Stop(101)
	}
}

// isDefenderAvailable checks if Windows Defender is available and not replaced by third-party AV
func isDefenderAvailable() bool {
	// Check if the Windows Defender service exists and is accessible
	cmd := exec.Command("sc", "query", "WinDefend")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// If service exists, it should return something about the service
	return strings.Contains(string(output), "WinDefend")
}

// getDefenderStatus retrieves Defender status via PowerShell Get-MpComputerStatus
func getDefenderStatus() (*DefenderStatus, error) {
	psScript := `
$status = Get-MpComputerStatus -ErrorAction Stop
Write-Output "RealTimeProtectionEnabled=$($status.RealTimeProtectionEnabled)"
Write-Output "BehaviorMonitorEnabled=$($status.BehaviorMonitorEnabled)"
Write-Output "IsTamperProtected=$($status.IsTamperProtected)"
Write-Output "AntivirusSignatureAge=$($status.AntivirusSignatureAge)"
Write-Output "AMServiceEnabled=$($status.AMServiceEnabled)"
Write-Output "AntispywareEnabled=$($status.AntispywareEnabled)"
Write-Output "AntivirusEnabled=$($status.AntivirusEnabled)"
`
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", psScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		saveDefenderOutput("status", stdout.String(), stderr.String())
		return nil, fmt.Errorf("PowerShell error: %v - %s", err, stderr.String())
	}

	saveDefenderOutput("status", stdout.String(), stderr.String())

	status := &DefenderStatus{}
	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "RealTimeProtectionEnabled=") {
			status.RealTimeProtectionEnabled = strings.ToLower(strings.TrimPrefix(line, "RealTimeProtectionEnabled=")) == "true"
		} else if strings.HasPrefix(line, "BehaviorMonitorEnabled=") {
			status.BehaviorMonitorEnabled = strings.ToLower(strings.TrimPrefix(line, "BehaviorMonitorEnabled=")) == "true"
		} else if strings.HasPrefix(line, "IsTamperProtected=") {
			status.IsTamperProtected = strings.ToLower(strings.TrimPrefix(line, "IsTamperProtected=")) == "true"
		} else if strings.HasPrefix(line, "AntivirusSignatureAge=") {
			age, _ := strconv.Atoi(strings.TrimPrefix(line, "AntivirusSignatureAge="))
			status.AntivirusSignatureAge = age
		} else if strings.HasPrefix(line, "AMServiceEnabled=") {
			status.AMServiceEnabled = strings.ToLower(strings.TrimPrefix(line, "AMServiceEnabled=")) == "true"
		} else if strings.HasPrefix(line, "AntispywareEnabled=") {
			status.AntispywareEnabled = strings.ToLower(strings.TrimPrefix(line, "AntispywareEnabled=")) == "true"
		} else if strings.HasPrefix(line, "AntivirusEnabled=") {
			status.AntivirusEnabled = strings.ToLower(strings.TrimPrefix(line, "AntivirusEnabled=")) == "true"
		}
	}

	return status, nil
}

// getDefenderPreferences retrieves Defender preferences via PowerShell Get-MpPreference
func getDefenderPreferences() (*DefenderPreference, error) {
	psScript := `
$pref = Get-MpPreference -ErrorAction Stop
Write-Output "MAPSReporting=$($pref.MAPSReporting)"
Write-Output "SubmitSamplesConsent=$($pref.SubmitSamplesConsent)"
Write-Output "PUAProtection=$($pref.PUAProtection)"
`
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", psScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		saveDefenderOutput("preferences", stdout.String(), stderr.String())
		return nil, fmt.Errorf("PowerShell error: %v - %s", err, stderr.String())
	}

	saveDefenderOutput("preferences", stdout.String(), stderr.String())

	pref := &DefenderPreference{}
	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "MAPSReporting=") {
			pref.MAPSReporting, _ = strconv.Atoi(strings.TrimPrefix(line, "MAPSReporting="))
		} else if strings.HasPrefix(line, "SubmitSamplesConsent=") {
			pref.SubmitSamplesConsent, _ = strconv.Atoi(strings.TrimPrefix(line, "SubmitSamplesConsent="))
		} else if strings.HasPrefix(line, "PUAProtection=") {
			pref.PUAProtection, _ = strconv.Atoi(strings.TrimPrefix(line, "PUAProtection="))
		}
	}

	return pref, nil
}

// checkRealTimeProtection validates real-time protection is enabled
func checkRealTimeProtection(status *DefenderStatus, statusErr error) CheckResult {
	result := CheckResult{
		Name:        "Real-time Protection",
		Description: "Continuous file system monitoring",
		Expected:    "Enabled (True)",
	}

	// Try PowerShell result first
	if status != nil {
		result.Method = "powershell"
		if status.RealTimeProtectionEnabled {
			result.Value = "Enabled"
			result.Compliant = true
			result.Details = "Real-time protection is enabled via Get-MpComputerStatus"
		} else {
			result.Value = "Disabled"
			result.Compliant = false
			result.Details = "Real-time protection is disabled"
		}
		return result
	}

	// Fall back to registry check
	result.Method = "registry"
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, registry.QUERY_VALUE)
	if err != nil {
		// Key doesn't exist - check default behavior
		result.Value = "Not explicitly disabled"
		result.Compliant = true
		result.Details = "DisableRealtimeMonitoring policy not set (default: enabled)"
		return result
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("DisableRealtimeMonitoring")
	if err != nil {
		result.Value = "Not explicitly disabled"
		result.Compliant = true
		result.Details = "DisableRealtimeMonitoring value not found (default: enabled)"
		return result
	}

	if value == 0 {
		result.Value = "Enabled (policy)"
		result.Compliant = true
		result.Details = "DisableRealtimeMonitoring = 0 (protection enabled)"
	} else {
		result.Value = "Disabled (policy)"
		result.Compliant = false
		result.Details = "DisableRealtimeMonitoring = 1 (protection disabled)"
	}

	return result
}

// checkBehaviorMonitoring validates behavior monitoring is enabled
func checkBehaviorMonitoring(status *DefenderStatus, statusErr error) CheckResult {
	result := CheckResult{
		Name:        "Behavior Monitoring",
		Description: "Detects suspicious process behavior",
		Expected:    "Enabled (True)",
	}

	if status != nil {
		result.Method = "powershell"
		if status.BehaviorMonitorEnabled {
			result.Value = "Enabled"
			result.Compliant = true
			result.Details = "Behavior monitoring is enabled via Get-MpComputerStatus"
		} else {
			result.Value = "Disabled"
			result.Compliant = false
			result.Details = "Behavior monitoring is disabled"
		}
		return result
	}

	// Fall back to registry check
	result.Method = "registry"
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, registry.QUERY_VALUE)
	if err != nil {
		result.Value = "Not explicitly disabled"
		result.Compliant = true
		result.Details = "DisableBehaviorMonitoring policy not set (default: enabled)"
		return result
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("DisableBehaviorMonitoring")
	if err != nil {
		result.Value = "Not explicitly disabled"
		result.Compliant = true
		result.Details = "DisableBehaviorMonitoring value not found (default: enabled)"
		return result
	}

	if value == 0 {
		result.Value = "Enabled (policy)"
		result.Compliant = true
		result.Details = "DisableBehaviorMonitoring = 0 (monitoring enabled)"
	} else {
		result.Value = "Disabled (policy)"
		result.Compliant = false
		result.Details = "DisableBehaviorMonitoring = 1 (monitoring disabled)"
	}

	return result
}

// checkTamperProtection validates tamper protection is enabled
func checkTamperProtection(status *DefenderStatus, statusErr error) CheckResult {
	result := CheckResult{
		Name:        "Tamper Protection",
		Description: "Prevents malware from disabling Defender",
		Expected:    "Enabled (True)",
	}

	if status != nil {
		result.Method = "powershell"
		if status.IsTamperProtected {
			result.Value = "Enabled"
			result.Compliant = true
			result.Details = "Tamper protection is enabled via Get-MpComputerStatus"
		} else {
			result.Value = "Disabled"
			result.Compliant = false
			result.Details = "Tamper protection is disabled - critical vulnerability!"
		}
		return result
	}

	// Tamper protection can only be reliably checked via Get-MpComputerStatus
	// Registry check is less reliable but we'll try
	result.Method = "registry"
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender\Features`, registry.QUERY_VALUE)
	if err != nil {
		result.Value = "Unknown"
		result.Compliant = false
		result.Details = "Could not verify tamper protection status - unable to access registry key"
		return result
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("TamperProtection")
	if err != nil {
		result.Value = "Unknown"
		result.Compliant = false
		result.Details = "TamperProtection value not found"
		return result
	}

	// TamperProtection: 0 = Off, 1 = On (in audit mode), 4 = Off, 5 = On
	if value == 5 || value == 1 {
		result.Value = fmt.Sprintf("Enabled (%d)", value)
		result.Compliant = true
		result.Details = "Tamper protection is enabled via registry"
	} else {
		result.Value = fmt.Sprintf("Disabled (%d)", value)
		result.Compliant = false
		result.Details = fmt.Sprintf("TamperProtection = %d (not enabled)", value)
	}

	return result
}

// checkCloudProtection validates MAPS (Cloud Protection) is set to Advanced
func checkCloudProtection(pref *DefenderPreference, prefErr error) CheckResult {
	result := CheckResult{
		Name:        "Cloud Protection (MAPS)",
		Description: "Cloud-based threat intelligence",
		Expected:    "Advanced (2)",
	}

	if pref != nil {
		result.Method = "powershell"
		// MAPSReporting: 0 = Disabled, 1 = Basic, 2 = Advanced
		switch pref.MAPSReporting {
		case 2:
			result.Value = "Advanced (2)"
			result.Compliant = true
			result.Details = "MAPS reporting is set to Advanced level"
		case 1:
			result.Value = "Basic (1)"
			result.Compliant = false
			result.Details = "MAPS reporting is Basic - should be Advanced (2)"
		default:
			result.Value = fmt.Sprintf("Disabled (%d)", pref.MAPSReporting)
			result.Compliant = false
			result.Details = "MAPS cloud protection is disabled"
		}
		return result
	}

	// Fall back to registry check
	result.Method = "registry"
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`, registry.QUERY_VALUE)
	if err != nil {
		result.Value = "Unknown (no policy)"
		result.Compliant = false
		result.Details = "SpynetReporting policy not configured"
		return result
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("SpynetReporting")
	if err != nil {
		result.Value = "Unknown"
		result.Compliant = false
		result.Details = "SpynetReporting value not found"
		return result
	}

	if value == 2 {
		result.Value = "Advanced (2)"
		result.Compliant = true
		result.Details = "MAPS reporting policy is Advanced"
	} else {
		result.Value = fmt.Sprintf("Not Advanced (%d)", value)
		result.Compliant = false
		result.Details = fmt.Sprintf("SpynetReporting = %d (expected 2)", value)
	}

	return result
}

// checkSampleSubmission validates automatic sample submission is enabled
func checkSampleSubmission(pref *DefenderPreference, prefErr error) CheckResult {
	result := CheckResult{
		Name:        "Sample Submission",
		Description: "Automatic sample upload for analysis",
		Expected:    "1 (Send safe samples) or 3 (Send all samples)",
	}

	if pref != nil {
		result.Method = "powershell"
		// SubmitSamplesConsent: 0 = Always prompt, 1 = Send safe samples, 2 = Never send, 3 = Send all samples
		switch pref.SubmitSamplesConsent {
		case 1:
			result.Value = "Send safe samples (1)"
			result.Compliant = true
			result.Details = "Automatic safe sample submission enabled"
		case 3:
			result.Value = "Send all samples (3)"
			result.Compliant = true
			result.Details = "Automatic all sample submission enabled"
		case 0:
			result.Value = "Always prompt (0)"
			result.Compliant = false
			result.Details = "Sample submission requires user prompt - should be automatic"
		case 2:
			result.Value = "Never send (2)"
			result.Compliant = false
			result.Details = "Sample submission is disabled - security risk"
		default:
			result.Value = fmt.Sprintf("Unknown (%d)", pref.SubmitSamplesConsent)
			result.Compliant = false
			result.Details = fmt.Sprintf("Unknown SubmitSamplesConsent value: %d", pref.SubmitSamplesConsent)
		}
		return result
	}

	// Fall back to registry check
	result.Method = "registry"
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`, registry.QUERY_VALUE)
	if err != nil {
		result.Value = "Unknown (no policy)"
		result.Compliant = false
		result.Details = "SubmitSamplesConsent policy not configured"
		return result
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("SubmitSamplesConsent")
	if err != nil {
		result.Value = "Unknown"
		result.Compliant = false
		result.Details = "SubmitSamplesConsent value not found"
		return result
	}

	if value == 1 || value == 3 {
		result.Value = fmt.Sprintf("Enabled (%d)", value)
		result.Compliant = true
		result.Details = "Sample submission is enabled via policy"
	} else {
		result.Value = fmt.Sprintf("Not compliant (%d)", value)
		result.Compliant = false
		result.Details = fmt.Sprintf("SubmitSamplesConsent = %d (expected 1 or 3)", value)
	}

	return result
}

// checkPUAProtection validates PUA (Potentially Unwanted Application) protection is enabled
func checkPUAProtection(pref *DefenderPreference, prefErr error) CheckResult {
	result := CheckResult{
		Name:        "PUA Protection",
		Description: "Potentially Unwanted Application blocking",
		Expected:    "Enabled (1)",
	}

	if pref != nil {
		result.Method = "powershell"
		// PUAProtection: 0 = Disabled, 1 = Enabled (block), 2 = Audit mode
		switch pref.PUAProtection {
		case 1:
			result.Value = "Enabled (1)"
			result.Compliant = true
			result.Details = "PUA protection is enabled in block mode"
		case 2:
			result.Value = "Audit mode (2)"
			result.Compliant = false
			result.Details = "PUA protection is in audit mode - should be enabled (1)"
		default:
			result.Value = fmt.Sprintf("Disabled (%d)", pref.PUAProtection)
			result.Compliant = false
			result.Details = "PUA protection is disabled"
		}
		return result
	}

	// Fall back to registry check
	result.Method = "registry"
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows Defender`, registry.QUERY_VALUE)
	if err != nil {
		result.Value = "Unknown (no policy)"
		result.Compliant = false
		result.Details = "PUAProtection policy not configured"
		return result
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("PUAProtection")
	if err != nil {
		result.Value = "Unknown"
		result.Compliant = false
		result.Details = "PUAProtection value not found"
		return result
	}

	if value == 1 {
		result.Value = "Enabled (1)"
		result.Compliant = true
		result.Details = "PUA protection is enabled via policy"
	} else {
		result.Value = fmt.Sprintf("Not enabled (%d)", value)
		result.Compliant = false
		result.Details = fmt.Sprintf("PUAProtection = %d (expected 1)", value)
	}

	return result
}

// checkSignatureAge logs a warning if antivirus signatures are outdated
func checkSignatureAge(age int) {
	Endpoint.Say("")
	Endpoint.Say("[*] Signature Age Check (Warning Only):")

	if age <= 1 {
		Endpoint.Say("    [+] Signatures are current (age: %d day(s))", age)
		LogMessage("INFO", "Signature Age", fmt.Sprintf("Antivirus signatures are current - %d day(s) old", age))
	} else if age <= 7 {
		Endpoint.Say("    [~] Signatures are recent (age: %d days)", age)
		LogMessage("INFO", "Signature Age", fmt.Sprintf("Antivirus signatures are recent - %d days old", age))
	} else {
		Endpoint.Say("    [!] WARNING: Signatures are outdated (age: %d days)", age)
		Endpoint.Say("        Recommendation: Update antivirus signatures immediately")
		LogMessage("WARNING", "Signature Age", fmt.Sprintf("Antivirus signatures are OUTDATED - %d days old (should be < 7 days)", age))
	}
}

// saveDefenderOutput saves the PowerShell output for debugging
func saveDefenderOutput(queryType, stdout, stderr string) {
	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)

	outputPath := filepath.Join(targetDir, fmt.Sprintf("defender_%s_output.txt", queryType))
	content := fmt.Sprintf("=== Defender %s Query Output ===\n\nSTDOUT:\n%s\n\nSTDERR:\n%s\n", queryType, stdout, stderr)

	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		LogMessage("WARNING", "Output Save", fmt.Sprintf("Failed to save %s output: %v", queryType, err))
	} else {
		LogMessage("INFO", "Output Save", fmt.Sprintf("Output saved to: %s", outputPath))
	}
}

// logCheckResult logs a check result to the structured log
func logCheckResult(result CheckResult) {
	LogMessage("INFO", result.Name, fmt.Sprintf("Description: %s", result.Description))
	LogMessage("INFO", result.Name, fmt.Sprintf("Method: %s", result.Method))
	LogMessage("INFO", result.Name, fmt.Sprintf("Expected: %s", result.Expected))
	LogMessage("INFO", result.Name, fmt.Sprintf("Actual: %s", result.Value))
	LogMessage("INFO", result.Name, fmt.Sprintf("Compliant: %v", result.Compliant))
	LogMessage("INFO", result.Name, fmt.Sprintf("Details: %s", result.Details))

	if result.Compliant {
		Endpoint.Say("    [+] %s: %s", result.Name, result.Value)
	} else {
		Endpoint.Say("    [-] %s: %s", result.Name, result.Value)
	}
}

// printRemediation prints remediation steps for a specific check
func printRemediation(checkName string) {
	switch checkName {
	case "Real-time Protection":
		Endpoint.Say("  - Enable Real-time Protection:")
		Endpoint.Say("    Set-MpPreference -DisableRealtimeMonitoring $false")
	case "Behavior Monitoring":
		Endpoint.Say("  - Enable Behavior Monitoring:")
		Endpoint.Say("    Set-MpPreference -DisableBehaviorMonitoring $false")
	case "Tamper Protection":
		Endpoint.Say("  - Enable Tamper Protection:")
		Endpoint.Say("    Via Windows Security > Virus & threat protection > Tamper Protection")
		Endpoint.Say("    Or via Intune/SCCM for enterprise management")
	case "Cloud Protection (MAPS)":
		Endpoint.Say("  - Enable Cloud Protection (Advanced):")
		Endpoint.Say("    Set-MpPreference -MAPSReporting Advanced")
	case "Sample Submission":
		Endpoint.Say("  - Enable Sample Submission:")
		Endpoint.Say("    Set-MpPreference -SubmitSamplesConsent SendAllSamples")
	case "PUA Protection":
		Endpoint.Say("  - Enable PUA Protection:")
		Endpoint.Say("    Set-MpPreference -PUAProtection Enabled")
	}
}

// main is the entry point
func main() {
	Endpoint.Say("================================================================================")
	Endpoint.Say("  F0RT1KA CYBER HYGIENE TEST: Microsoft Defender Configuration Validator")
	Endpoint.Say("  Test ID: %s", TEST_UUID)
	Endpoint.Say("================================================================================")
	Endpoint.Say("")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("This is a READ-ONLY configuration validation test.")
	Endpoint.Say("")

	// Ensure C:\F0 exists for log output
	os.MkdirAll("c:\\F0", 0755)

	done := make(chan bool, 1)
	go func() {
		test()
		done <- true
	}()

	// Timeout: 2 minutes (should complete much faster)
	timeout := 2 * time.Minute

	select {
	case <-done:
		Endpoint.Say("")
		Endpoint.Say("Test completed successfully")
	case <-time.After(timeout):
		Endpoint.Say("")
		Endpoint.Say("Test timed out after %v", timeout)
		if globalLog != nil {
			LogMessage("ERROR", "Test Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
			SaveLog(999, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		}
		Endpoint.Stop(999)
	}
}
