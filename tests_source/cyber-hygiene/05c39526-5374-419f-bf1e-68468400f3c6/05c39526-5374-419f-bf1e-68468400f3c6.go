//go:build windows
// +build windows

/*
ID: 05c39526-5374-419f-bf1e-68468400f3c6
NAME: Local Administrator Password Solution (LAPS) Validator
TECHNIQUES: T1078.003, T1021.002, T1550.002
TACTICS: credential-access, lateral-movement
SEVERITY: high
TARGET: active-directory, windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: baseline
TAGS: laps, local-admin, password-management, nsa-top10, cis-controls
UNIT: response
CREATED: 2026-01-11
AUTHOR: sectest-builder
*/

// Local Administrator Password Solution (LAPS) Validator - Cyber Hygiene Test
//
// This test validates that Local Administrator Password Solution (LAPS) is
// properly configured to prevent shared local admin password attacks. NSA/CISA's
// Top 10 Misconfigurations highlights "poor credential hygiene" as critical.
// Shared local admin passwords enable lateral movement across entire networks.
//
// Configuration Checks (At least ONE LAPS method must be configured for exit 126):
// 1. Windows LAPS (Built-in) - Check for LAPS cmdlets and GPO configuration
// 2. Legacy LAPS - Check for CSE installation and registry policy
//
// Exit Codes:
// - 126: At least one LAPS method is configured (COMPLIANT)
// - 101: No LAPS configuration detected (NON-COMPLIANT)
// - 999: Test error (insufficient privileges)
//
// CIS Benchmark Reference:
// - CIS Controls v8: 4.7 (Manage Default Accounts on Enterprise Assets)
// - CIS Controls v8: 5.2 (Use Unique Passwords)

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID = "05c39526-5374-419f-bf1e-68468400f3c6"
	TEST_NAME = "Local Administrator Password Solution (LAPS) Validator"
)

// CheckResult represents the result of a single configuration check
type CheckResult struct {
	Name        string
	Description string
	Compliant   bool
	Value       string
	Expected    string
	Details     string
}

// LAPSConfig holds all configuration check results
type LAPSConfig struct {
	// Windows LAPS (Built-in)
	WindowsLAPSCmdletAvailable bool
	WindowsLAPSGPOConfigured   bool
	WindowsLAPSPasswordLength  int
	WindowsLAPSPasswordAge     int

	// Legacy LAPS (Microsoft LAPS)
	LegacyLAPSEnabled     bool
	LegacyLAPSCSEInstalled bool
	LegacyLAPSPasswordLength int
	LegacyLAPSPasswordAge    int

	// Overall
	AnyLAPSConfigured bool
}

// test performs the LAPS configuration validation
func test() {
	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "credential_access",
		Severity:   "high",
		Techniques: []string{"T1078.003", "T1021.002", "T1550.002"},
		Tactics:    []string{"credential-access", "lateral-movement"},
		Score:      7.5,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.0,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"cyber-hygiene", "laps", "local-admin", "password-management", "configuration-validation"},
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

	// Save diagnostic info (must be after InitLogger)
	saveDiagnosticOutput()

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(999, fmt.Sprintf("Panic: %v", r))
		}
	}()

	// Phase 0: Initialization
	LogPhaseStart(0, "Initialization")

	// Check for admin privileges (required for registry access)
	if !isAdmin() {
		Endpoint.Say("[!] ERROR: Administrator privileges required for this test")
		LogMessage("ERROR", "Initialization", "Administrator privileges required")
		LogPhaseEnd(0, "failed", "Insufficient privileges")
		SaveLog(999, "Administrator privileges required")
		Endpoint.Stop(999)
	}

	// Check if this is a domain controller (LAPS doesn't apply)
	isDC := isDomainController()
	if isDC {
		Endpoint.Say("[!] NOTE: This appears to be a Domain Controller")
		Endpoint.Say("    LAPS is designed for workstations and member servers, not domain controllers.")
		LogMessage("INFO", "Initialization", "System is a Domain Controller - LAPS validation may not apply")
	}

	LogMessage("INFO", "Initialization", "Running with administrator privileges")
	LogPhaseEnd(0, "success", "Initialization complete")

	// Initialize config tracking
	config := LAPSConfig{}

	// Phase 1: Windows LAPS Cmdlet Check
	LogPhaseStart(1, "Windows LAPS Cmdlet Check")
	windowsCmdletResult := checkWindowsLAPSCmdlet()
	config.WindowsLAPSCmdletAvailable = windowsCmdletResult.Compliant
	logCheckResult(1, windowsCmdletResult)
	if windowsCmdletResult.Compliant {
		LogPhaseEnd(1, "success", "Windows LAPS cmdlets are available")
	} else {
		LogPhaseEnd(1, "failed", "Windows LAPS cmdlets not available")
	}

	// Phase 2: Windows LAPS GPO Check
	LogPhaseStart(2, "Windows LAPS GPO Check")
	windowsGPOResult := checkWindowsLAPSGPO(&config)
	config.WindowsLAPSGPOConfigured = windowsGPOResult.Compliant
	logCheckResult(2, windowsGPOResult)
	if windowsGPOResult.Compliant {
		LogPhaseEnd(2, "success", "Windows LAPS GPO is configured")
	} else {
		LogPhaseEnd(2, "failed", "Windows LAPS GPO not configured")
	}

	// Phase 3: Legacy LAPS Enabled Check
	LogPhaseStart(3, "Legacy LAPS Enabled Check")
	legacyEnabledResult := checkLegacyLAPSEnabled(&config)
	config.LegacyLAPSEnabled = legacyEnabledResult.Compliant
	logCheckResult(3, legacyEnabledResult)
	if legacyEnabledResult.Compliant {
		LogPhaseEnd(3, "success", "Legacy LAPS is enabled")
	} else {
		LogPhaseEnd(3, "failed", "Legacy LAPS is not enabled")
	}

	// Phase 4: Legacy LAPS CSE Check
	LogPhaseStart(4, "Legacy LAPS CSE Check")
	legacyCSEResult := checkLegacyLAPSCSE()
	config.LegacyLAPSCSEInstalled = legacyCSEResult.Compliant
	logCheckResult(4, legacyCSEResult)
	if legacyCSEResult.Compliant {
		LogPhaseEnd(4, "success", "Legacy LAPS CSE is installed")
	} else {
		LogPhaseEnd(4, "failed", "Legacy LAPS CSE not installed")
	}

	// Phase 5: Password Policy Check (Informational)
	LogPhaseStart(5, "Password Policy Check (Informational)")
	checkPasswordPolicy(&config)
	LogPhaseEnd(5, "success", "Password policy checked (informational only)")

	// Phase 6: Determine Overall Compliance
	LogPhaseStart(6, "Compliance Determination")

	// Determine if ANY LAPS method is configured
	windowsLAPSConfigured := config.WindowsLAPSCmdletAvailable && config.WindowsLAPSGPOConfigured
	legacyLAPSConfigured := config.LegacyLAPSEnabled && config.LegacyLAPSCSEInstalled

	config.AnyLAPSConfigured = windowsLAPSConfigured || legacyLAPSConfigured

	// Generate summary
	Endpoint.Say("")
	Endpoint.Say("================================================================================")
	Endpoint.Say("            LAPS CONFIGURATION VALIDATION SUMMARY")
	Endpoint.Say("================================================================================")
	Endpoint.Say("")

	// Windows LAPS Summary
	Endpoint.Say("Windows LAPS (Built-in, Windows 11/Server 2019+):")
	printCheckSummary("  Cmdlets Available", windowsCmdletResult)
	printCheckSummary("  GPO Configured", windowsGPOResult)
	if windowsLAPSConfigured {
		Endpoint.Say("  --> Windows LAPS: CONFIGURED")
	} else {
		Endpoint.Say("  --> Windows LAPS: NOT CONFIGURED")
	}

	Endpoint.Say("")

	// Legacy LAPS Summary
	Endpoint.Say("Legacy LAPS (Microsoft LAPS):")
	printCheckSummary("  AdmPwdEnabled Registry", legacyEnabledResult)
	printCheckSummary("  CSE DLL Installed", legacyCSEResult)
	if legacyLAPSConfigured {
		Endpoint.Say("  --> Legacy LAPS: CONFIGURED")
	} else {
		Endpoint.Say("  --> Legacy LAPS: NOT CONFIGURED")
	}

	Endpoint.Say("")

	// Password Policy (Informational)
	if config.WindowsLAPSPasswordLength > 0 || config.LegacyLAPSPasswordLength > 0 {
		Endpoint.Say("Password Policy (Informational):")
		if config.WindowsLAPSPasswordLength > 0 {
			Endpoint.Say("  Windows LAPS Password Length: %d characters", config.WindowsLAPSPasswordLength)
			if config.WindowsLAPSPasswordLength >= 14 {
				Endpoint.Say("    [OK] Meets minimum 14 character recommendation")
			} else {
				Endpoint.Say("    [!] Below recommended 14 character minimum")
			}
		}
		if config.WindowsLAPSPasswordAge > 0 {
			Endpoint.Say("  Windows LAPS Password Age: %d days", config.WindowsLAPSPasswordAge)
			if config.WindowsLAPSPasswordAge <= 30 {
				Endpoint.Say("    [OK] Within 30 day recommendation")
			} else {
				Endpoint.Say("    [!] Exceeds recommended 30 day maximum")
			}
		}
		Endpoint.Say("")
	}

	Endpoint.Say("--------------------------------------------------------------------------------")

	if config.AnyLAPSConfigured {
		Endpoint.Say("")
		Endpoint.Say("[COMPLIANT] At least one LAPS solution is configured.")
		Endpoint.Say("            Local administrator passwords are being managed.")

		var method string
		if windowsLAPSConfigured && legacyLAPSConfigured {
			method = "Both Windows LAPS and Legacy LAPS"
		} else if windowsLAPSConfigured {
			method = "Windows LAPS (recommended)"
		} else {
			method = "Legacy LAPS"
		}
		Endpoint.Say("            Method: %s", method)

		LogMessage("SUCCESS", "Compliance", fmt.Sprintf("LAPS is configured using: %s", method))
		LogPhaseEnd(6, "success", fmt.Sprintf("COMPLIANT - %s", method))
		SaveLog(126, fmt.Sprintf("System is COMPLIANT - LAPS configured via %s", method))
		Endpoint.Stop(126)
	} else {
		Endpoint.Say("")
		Endpoint.Say("[NON-COMPLIANT] No LAPS solution is configured.")
		Endpoint.Say("                Local admin passwords may be shared across systems.")
		Endpoint.Say("                This enables lateral movement attacks.")
		Endpoint.Say("")
		Endpoint.Say("Remediation Options:")
		Endpoint.Say("")
		Endpoint.Say("Option 1: Windows LAPS (Recommended for Windows 11/Server 2019+)")
		Endpoint.Say("  - Available via April 2023 Windows Update")
		Endpoint.Say("  - Configure via Group Policy:")
		Endpoint.Say("    Computer Configuration > Administrative Templates > System > LAPS")
		Endpoint.Say("  - Enable: 'Configure password backup directory'")
		Endpoint.Say("  - Set: 'Password Settings' (length >= 14, age <= 30 days)")
		Endpoint.Say("")
		Endpoint.Say("Option 2: Legacy Microsoft LAPS (Older systems)")
		Endpoint.Say("  - Download from Microsoft Download Center")
		Endpoint.Say("  - Extend AD schema: Update-AdmPwdADSchema")
		Endpoint.Say("  - Install CSE on all managed systems")
		Endpoint.Say("  - Configure via Group Policy:")
		Endpoint.Say("    Computer Configuration > Administrative Templates > LAPS")

		LogMessage("WARNING", "Compliance", "No LAPS solution configured - system is NON-COMPLIANT")
		LogPhaseEnd(6, "failed", "NON-COMPLIANT - No LAPS configured")
		SaveLog(101, "System is NON-COMPLIANT - no LAPS solution configured")
		Endpoint.Stop(101)
	}
}

// checkWindowsLAPSCmdlet checks if Windows LAPS PowerShell cmdlets are available
func checkWindowsLAPSCmdlet() CheckResult {
	result := CheckResult{
		Name:        "Windows LAPS Cmdlet",
		Description: "Windows LAPS PowerShell module availability",
		Expected:    "Get-LapsDiagnostics cmdlet exists",
	}

	Endpoint.Say("[*] Checking for Windows LAPS cmdlets...")
	LogMessage("INFO", "WindowsLAPS", "Checking for Windows LAPS PowerShell cmdlets")

	// Try to find the Get-LapsDiagnostics cmdlet (available in Windows LAPS)
	psScript := `
$cmd = Get-Command -Name Get-LapsDiagnostics -ErrorAction SilentlyContinue
if ($cmd) {
    Write-Output "AVAILABLE:$($cmd.Module.Name)"
} else {
    Write-Output "NOT_AVAILABLE"
}
`

	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", psScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		result.Value = "Query failed"
		result.Details = fmt.Sprintf("PowerShell query failed: %v - %s", err, stderr.String())
		result.Compliant = false
		Endpoint.Say("    [!] Failed to check for Windows LAPS cmdlets: %v", err)
		LogMessage("ERROR", "WindowsLAPS", result.Details)
		return result
	}

	output := strings.TrimSpace(stdout.String())

	if strings.HasPrefix(output, "AVAILABLE:") {
		module := strings.TrimPrefix(output, "AVAILABLE:")
		result.Value = fmt.Sprintf("Available (Module: %s)", module)
		result.Details = "Windows LAPS cmdlets are available on this system"
		result.Compliant = true
		Endpoint.Say("    [+] Windows LAPS cmdlets AVAILABLE (Module: %s)", module)
		LogMessage("SUCCESS", "WindowsLAPS", result.Details)
	} else {
		result.Value = "Not available"
		result.Details = "Windows LAPS cmdlets not found - may not be installed or OS too old"
		result.Compliant = false
		Endpoint.Say("    [-] Windows LAPS cmdlets NOT AVAILABLE")
		Endpoint.Say("        (Requires Windows 11 22H2+ or Server 2019+ with April 2023 update)")
		LogMessage("WARNING", "WindowsLAPS", result.Details)
	}

	return result
}

// checkWindowsLAPSGPO checks if Windows LAPS is configured via Group Policy
func checkWindowsLAPSGPO(config *LAPSConfig) CheckResult {
	result := CheckResult{
		Name:        "Windows LAPS GPO",
		Description: "Windows LAPS Group Policy configuration",
		Expected:    "Policy configured in HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LAPS",
	}

	Endpoint.Say("[*] Checking Windows LAPS Group Policy configuration...")
	LogMessage("INFO", "WindowsLAPS", "Checking HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LAPS")

	// Open the Windows LAPS policy registry key
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\LAPS`, registry.QUERY_VALUE)
	if err != nil {
		result.Value = "Key not found"
		result.Details = "Windows LAPS policy registry key does not exist - GPO not configured"
		result.Compliant = false
		Endpoint.Say("    [-] Windows LAPS policy key not found")
		LogMessage("WARNING", "WindowsLAPS", result.Details)
		return result
	}
	defer key.Close()

	// Check for BackupDirectory value (required for LAPS to function)
	backupDir, _, err := key.GetIntegerValue("BackupDirectory")
	if err != nil {
		result.Value = "Policy incomplete"
		result.Details = "BackupDirectory value not configured - LAPS not fully enabled"
		result.Compliant = false
		Endpoint.Say("    [-] BackupDirectory not configured")
		LogMessage("WARNING", "WindowsLAPS", result.Details)
		return result
	}

	// BackupDirectory values:
	// 0 = Disabled
	// 1 = Azure AD only
	// 2 = Active Directory only
	// Note: Value meanings may vary by Windows version

	if backupDir == 0 {
		result.Value = "Disabled"
		result.Details = "BackupDirectory is set to 0 (disabled)"
		result.Compliant = false
		Endpoint.Say("    [-] Windows LAPS BackupDirectory = 0 (DISABLED)")
		LogMessage("WARNING", "WindowsLAPS", result.Details)
		return result
	}

	var backupTarget string
	switch backupDir {
	case 1:
		backupTarget = "Azure AD"
	case 2:
		backupTarget = "Active Directory"
	default:
		backupTarget = fmt.Sprintf("Unknown (%d)", backupDir)
	}

	result.Value = fmt.Sprintf("Enabled (Backup to %s)", backupTarget)
	result.Details = fmt.Sprintf("Windows LAPS configured to backup passwords to %s", backupTarget)
	result.Compliant = true
	Endpoint.Say("    [+] Windows LAPS ENABLED (Backup to %s)", backupTarget)
	LogMessage("SUCCESS", "WindowsLAPS", result.Details)

	// Try to read password policy settings (informational)
	if pwdLength, _, err := key.GetIntegerValue("PasswordLength"); err == nil {
		config.WindowsLAPSPasswordLength = int(pwdLength)
		Endpoint.Say("        Password Length: %d characters", pwdLength)
		LogMessage("INFO", "WindowsLAPS", fmt.Sprintf("Password length configured: %d", pwdLength))
	}

	if pwdAge, _, err := key.GetIntegerValue("PasswordAgeDays"); err == nil {
		config.WindowsLAPSPasswordAge = int(pwdAge)
		Endpoint.Say("        Password Age: %d days", pwdAge)
		LogMessage("INFO", "WindowsLAPS", fmt.Sprintf("Password age configured: %d days", pwdAge))
	}

	return result
}

// checkLegacyLAPSEnabled checks if Legacy LAPS is enabled via registry
func checkLegacyLAPSEnabled(config *LAPSConfig) CheckResult {
	result := CheckResult{
		Name:        "Legacy LAPS Enabled",
		Description: "Microsoft LAPS (Legacy) AdmPwdEnabled registry setting",
		Expected:    "HKLM\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd\\AdmPwdEnabled = 1",
	}

	Endpoint.Say("[*] Checking Legacy LAPS (Microsoft LAPS) configuration...")
	LogMessage("INFO", "LegacyLAPS", "Checking HKLM\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd")

	// Open the Legacy LAPS policy registry key
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft Services\AdmPwd`, registry.QUERY_VALUE)
	if err != nil {
		result.Value = "Key not found"
		result.Details = "Legacy LAPS policy registry key does not exist - not configured via GPO"
		result.Compliant = false
		Endpoint.Say("    [-] Legacy LAPS policy key not found")
		LogMessage("WARNING", "LegacyLAPS", result.Details)
		return result
	}
	defer key.Close()

	// Check AdmPwdEnabled value
	enabled, _, err := key.GetIntegerValue("AdmPwdEnabled")
	if err != nil {
		result.Value = "Not configured"
		result.Details = "AdmPwdEnabled value does not exist"
		result.Compliant = false
		Endpoint.Say("    [-] AdmPwdEnabled not configured")
		LogMessage("WARNING", "LegacyLAPS", result.Details)
		return result
	}

	if enabled == 1 {
		result.Value = "1 (Enabled)"
		result.Details = "Legacy LAPS is enabled via Group Policy"
		result.Compliant = true
		Endpoint.Say("    [+] Legacy LAPS is ENABLED (AdmPwdEnabled = 1)")
		LogMessage("SUCCESS", "LegacyLAPS", result.Details)

		// Try to read password policy settings (informational)
		if pwdLength, _, err := key.GetIntegerValue("PasswordLength"); err == nil {
			config.LegacyLAPSPasswordLength = int(pwdLength)
			Endpoint.Say("        Password Length: %d characters", pwdLength)
			LogMessage("INFO", "LegacyLAPS", fmt.Sprintf("Password length configured: %d", pwdLength))
		}

		if pwdAge, _, err := key.GetIntegerValue("PasswordAgeDays"); err == nil {
			config.LegacyLAPSPasswordAge = int(pwdAge)
			Endpoint.Say("        Password Age: %d days", pwdAge)
			LogMessage("INFO", "LegacyLAPS", fmt.Sprintf("Password age configured: %d days", pwdAge))
		}
	} else {
		result.Value = fmt.Sprintf("%d (Disabled)", enabled)
		result.Details = fmt.Sprintf("AdmPwdEnabled is %d (expected 1)", enabled)
		result.Compliant = false
		Endpoint.Say("    [-] Legacy LAPS is DISABLED (AdmPwdEnabled = %d)", enabled)
		LogMessage("WARNING", "LegacyLAPS", result.Details)
	}

	return result
}

// checkLegacyLAPSCSE checks if Legacy LAPS Client Side Extension is installed
func checkLegacyLAPSCSE() CheckResult {
	result := CheckResult{
		Name:        "Legacy LAPS CSE",
		Description: "Microsoft LAPS Client Side Extension DLL",
		Expected:    "C:\\Program Files\\LAPS\\CSE\\AdmPwd.dll exists",
	}

	Endpoint.Say("[*] Checking for Legacy LAPS CSE installation...")
	LogMessage("INFO", "LegacyLAPS", "Checking for C:\\Program Files\\LAPS\\CSE\\AdmPwd.dll")

	// Check primary location
	csePath := `C:\Program Files\LAPS\CSE\AdmPwd.dll`
	if _, err := os.Stat(csePath); err == nil {
		result.Value = "Installed"
		result.Details = fmt.Sprintf("CSE found at %s", csePath)
		result.Compliant = true
		Endpoint.Say("    [+] Legacy LAPS CSE is INSTALLED")
		Endpoint.Say("        Path: %s", csePath)
		LogMessage("SUCCESS", "LegacyLAPS", result.Details)
		return result
	}

	// Check alternative location (x86 on x64)
	csePathX86 := `C:\Program Files (x86)\LAPS\CSE\AdmPwd.dll`
	if _, err := os.Stat(csePathX86); err == nil {
		result.Value = "Installed (x86)"
		result.Details = fmt.Sprintf("CSE found at %s", csePathX86)
		result.Compliant = true
		Endpoint.Say("    [+] Legacy LAPS CSE is INSTALLED (x86)")
		Endpoint.Say("        Path: %s", csePathX86)
		LogMessage("SUCCESS", "LegacyLAPS", result.Details)
		return result
	}

	// Check if the CSE GUID is registered
	cseGUID := `{D76B9641-3288-4f75-942D-087DE603E3EA}`
	cseRegPath := fmt.Sprintf(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\%s`, cseGUID)
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, cseRegPath, registry.QUERY_VALUE); err == nil {
		key.Close()
		result.Value = "Registered (GUID)"
		result.Details = "CSE GUID registered but DLL not found in standard location"
		result.Compliant = true
		Endpoint.Say("    [+] Legacy LAPS CSE is REGISTERED via GUID")
		LogMessage("SUCCESS", "LegacyLAPS", result.Details)
		return result
	}

	result.Value = "Not installed"
	result.Details = "Legacy LAPS CSE DLL not found - not installed on this system"
	result.Compliant = false
	Endpoint.Say("    [-] Legacy LAPS CSE is NOT INSTALLED")
	LogMessage("WARNING", "LegacyLAPS", result.Details)

	return result
}

// checkPasswordPolicy logs password policy settings (informational only)
func checkPasswordPolicy(config *LAPSConfig) {
	Endpoint.Say("[*] Evaluating password policy (informational)...")
	LogMessage("INFO", "PasswordPolicy", "Checking LAPS password policy settings")

	// Password length check
	if config.WindowsLAPSPasswordLength > 0 {
		if config.WindowsLAPSPasswordLength >= 14 {
			LogMessage("INFO", "PasswordPolicy", fmt.Sprintf("Windows LAPS password length (%d) meets recommendation (>=14)", config.WindowsLAPSPasswordLength))
		} else {
			LogMessage("WARNING", "PasswordPolicy", fmt.Sprintf("Windows LAPS password length (%d) below recommendation (>=14)", config.WindowsLAPSPasswordLength))
		}
	}

	if config.LegacyLAPSPasswordLength > 0 {
		if config.LegacyLAPSPasswordLength >= 14 {
			LogMessage("INFO", "PasswordPolicy", fmt.Sprintf("Legacy LAPS password length (%d) meets recommendation (>=14)", config.LegacyLAPSPasswordLength))
		} else {
			LogMessage("WARNING", "PasswordPolicy", fmt.Sprintf("Legacy LAPS password length (%d) below recommendation (>=14)", config.LegacyLAPSPasswordLength))
		}
	}

	// Password age check
	if config.WindowsLAPSPasswordAge > 0 {
		if config.WindowsLAPSPasswordAge <= 30 {
			LogMessage("INFO", "PasswordPolicy", fmt.Sprintf("Windows LAPS password age (%d days) within recommendation (<=30)", config.WindowsLAPSPasswordAge))
		} else {
			LogMessage("WARNING", "PasswordPolicy", fmt.Sprintf("Windows LAPS password age (%d days) exceeds recommendation (<=30)", config.WindowsLAPSPasswordAge))
		}
	}

	if config.LegacyLAPSPasswordAge > 0 {
		if config.LegacyLAPSPasswordAge <= 30 {
			LogMessage("INFO", "PasswordPolicy", fmt.Sprintf("Legacy LAPS password age (%d days) within recommendation (<=30)", config.LegacyLAPSPasswordAge))
		} else {
			LogMessage("WARNING", "PasswordPolicy", fmt.Sprintf("Legacy LAPS password age (%d days) exceeds recommendation (<=30)", config.LegacyLAPSPasswordAge))
		}
	}
}

// isDomainController checks if this system is a domain controller
func isDomainController() bool {
	// Check for NTDS service which runs on DCs
	cmd := exec.Command("sc", "query", "NTDS")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "RUNNING")
}

// logCheckResult logs a check result to the structured log
func logCheckResult(phaseNum int, result CheckResult) {
	LogMessage("INFO", result.Name, fmt.Sprintf("Check: %s", result.Description))
	LogMessage("INFO", result.Name, fmt.Sprintf("Expected: %s", result.Expected))
	LogMessage("INFO", result.Name, fmt.Sprintf("Actual: %s", result.Value))
	LogMessage("INFO", result.Name, fmt.Sprintf("Compliant: %v", result.Compliant))
	LogMessage("INFO", result.Name, fmt.Sprintf("Details: %s", result.Details))
}

// printCheckSummary prints a formatted check summary
func printCheckSummary(name string, result CheckResult) {
	status := "FAIL"
	if result.Compliant {
		status = "PASS"
	}
	Endpoint.Say("[%s] %-35s %s", status, name, result.Value)
}

// Note: isAdmin() is defined in test_logger.go

// saveDiagnosticOutput saves diagnostic information for troubleshooting
func saveDiagnosticOutput() {
	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)

	outputPath := filepath.Join(targetDir, "laps_diagnostic.txt")

	var content strings.Builder
	content.WriteString("=== LAPS Diagnostic Information ===\n\n")
	content.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format(time.RFC3339)))

	// Get Windows version
	cmd := exec.Command("cmd", "/c", "ver")
	if output, err := cmd.Output(); err == nil {
		content.WriteString(fmt.Sprintf("Windows Version: %s\n", strings.TrimSpace(string(output))))
	}

	// Get domain info
	cmd = exec.Command("cmd", "/c", "echo %USERDOMAIN%")
	if output, err := cmd.Output(); err == nil {
		content.WriteString(fmt.Sprintf("Domain: %s\n", strings.TrimSpace(string(output))))
	}

	content.WriteString("\n=== End Diagnostic ===\n")

	if err := os.WriteFile(outputPath, []byte(content.String()), 0644); err != nil {
		LogMessage("WARNING", "Diagnostic", fmt.Sprintf("Failed to save diagnostic: %v", err))
	} else {
		LogMessage("INFO", "Diagnostic", fmt.Sprintf("Diagnostic saved to: %s", outputPath))
	}
}

// main is the entry point
func main() {
	Endpoint.Say("================================================================================")
	Endpoint.Say("  F0RT1KA CYBER HYGIENE TEST: LAPS Validator")
	Endpoint.Say("  Test ID: %s", TEST_UUID)
	Endpoint.Say("================================================================================")
	Endpoint.Say("")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("This is a READ-ONLY configuration validation test.")
	Endpoint.Say("")

	// Ensure C:\F0 exists for log output
	os.MkdirAll("c:\\F0", 0755)

	// Note: saveDiagnosticOutput() is called inside test() after InitLogger()

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
