//go:build windows
// +build windows

/*
ID: b4b50f92-f19a-4aba-a119-6f0e26d54ba5
NAME: SMB Protocol Hardening Validator
TECHNIQUES: T1021.002, T1570, T1210, T1557
UNIT: response
CREATED: 2026-01-11
*/

// SMB Protocol Hardening Validator - Cyber Hygiene Test
//
// This test validates that SMB (Server Message Block) protocol is properly
// hardened with SMBv1 disabled and signing/encryption enabled. SMBv1
// vulnerabilities enabled WannaCry and NotPetya to cause billions in damages.
//
// Configuration Checks:
// 1. SMBv1 Server Disabled - Registry check
// 2. SMBv1 Client Disabled - Service start type check
// 3. Server Signing Required - Registry check
// 4. Client Signing Required - Registry check
// 5. SMB Encryption Enabled - PowerShell SMB configuration check
//
// Exit Codes:
// - 126: All 5 checks pass (COMPLIANT)
// - 101: One or more checks fail (NON-COMPLIANT)
// - 999: Test error (insufficient privileges)
//
// CIS Benchmark Reference:
// - CIS Controls v8: 4.8 (Uninstall/Disable Unnecessary Services)
// - CIS Controls v8: 3.10 (Encrypt Sensitive Data in Transit)

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
	TEST_UUID = "b4b50f92-f19a-4aba-a119-6f0e26d54ba5"
	TEST_NAME = "SMB Protocol Hardening Validator"
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

// test performs the SMB protocol hardening validation
func test() {
	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "lateral_movement",
		Severity:   "critical",
		Techniques: []string{"T1021.002", "T1570", "T1210", "T1557"},
		Tactics:    []string{"lateral-movement", "credential-access"},
		Score:      8.0,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"cyber-hygiene", "smb-hardening", "smbv1-disabled", "configuration-validation"},
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

	LogMessage("INFO", "Initialization", "Running with administrator privileges")
	LogPhaseEnd(0, "success", "Initialization complete")

	// Phase 1: SMBv1 Server Disabled Check
	LogPhaseStart(1, "SMBv1 Server Check")
	smbv1ServerResult := checkSMBv1Server()
	logCheckResult(1, smbv1ServerResult)
	if smbv1ServerResult.Compliant {
		LogPhaseEnd(1, "success", "SMBv1 Server is disabled")
	} else {
		LogPhaseEnd(1, "failed", "SMBv1 Server is enabled or not configured")
	}

	// Phase 2: SMBv1 Client Disabled Check
	LogPhaseStart(2, "SMBv1 Client Check")
	smbv1ClientResult := checkSMBv1Client()
	logCheckResult(2, smbv1ClientResult)
	if smbv1ClientResult.Compliant {
		LogPhaseEnd(2, "success", "SMBv1 Client is disabled")
	} else {
		LogPhaseEnd(2, "failed", "SMBv1 Client is enabled or not configured")
	}

	// Phase 3: Server Signing Required Check
	LogPhaseStart(3, "Server Signing Check")
	serverSigningResult := checkServerSigning()
	logCheckResult(3, serverSigningResult)
	if serverSigningResult.Compliant {
		LogPhaseEnd(3, "success", "Server signing is required")
	} else {
		LogPhaseEnd(3, "failed", "Server signing is not required")
	}

	// Phase 4: Client Signing Required Check
	LogPhaseStart(4, "Client Signing Check")
	clientSigningResult := checkClientSigning()
	logCheckResult(4, clientSigningResult)
	if clientSigningResult.Compliant {
		LogPhaseEnd(4, "success", "Client signing is required")
	} else {
		LogPhaseEnd(4, "failed", "Client signing is not required")
	}

	// Phase 5: SMB Encryption Enabled Check
	LogPhaseStart(5, "SMB Encryption Check")
	encryptionResult := checkSMBEncryption()
	logCheckResult(5, encryptionResult)
	if encryptionResult.Compliant {
		LogPhaseEnd(5, "success", "SMB encryption is enabled")
	} else {
		LogPhaseEnd(5, "failed", "SMB encryption is not enabled")
	}

	// Phase 6: Determine Overall Compliance
	LogPhaseStart(6, "Compliance Determination")

	allCompliant := smbv1ServerResult.Compliant &&
		smbv1ClientResult.Compliant &&
		serverSigningResult.Compliant &&
		clientSigningResult.Compliant &&
		encryptionResult.Compliant

	passedChecks := 0
	if smbv1ServerResult.Compliant {
		passedChecks++
	}
	if smbv1ClientResult.Compliant {
		passedChecks++
	}
	if serverSigningResult.Compliant {
		passedChecks++
	}
	if clientSigningResult.Compliant {
		passedChecks++
	}
	if encryptionResult.Compliant {
		passedChecks++
	}

	// Generate summary
	Endpoint.Say("")
	Endpoint.Say("================================================================================")
	Endpoint.Say("                    SMB PROTOCOL HARDENING VALIDATION SUMMARY")
	Endpoint.Say("================================================================================")
	Endpoint.Say("")
	printCheckSummary("SMBv1 Server Disabled", smbv1ServerResult)
	printCheckSummary("SMBv1 Client Disabled", smbv1ClientResult)
	printCheckSummary("Server Signing Required", serverSigningResult)
	printCheckSummary("Client Signing Required", clientSigningResult)
	printCheckSummary("SMB Encryption Enabled", encryptionResult)
	Endpoint.Say("")
	Endpoint.Say("--------------------------------------------------------------------------------")
	Endpoint.Say("Overall: %d/5 checks passed", passedChecks)

	if allCompliant {
		Endpoint.Say("")
		Endpoint.Say("[COMPLIANT] All SMB hardening configurations are properly set.")
		Endpoint.Say("            System is protected against SMB-based attacks.")
		LogMessage("SUCCESS", "Compliance", "All 5 SMB hardening checks passed - system is COMPLIANT")
		LogPhaseEnd(6, "success", fmt.Sprintf("All checks passed (%d/5)", passedChecks))
		SaveLog(126, "System is COMPLIANT - all SMB hardening configurations enabled")
		Endpoint.Stop(126)
	} else {
		Endpoint.Say("")
		Endpoint.Say("[NON-COMPLIANT] SMB hardening is incomplete.")
		Endpoint.Say("                System may be vulnerable to SMB-based attacks (WannaCry, NotPetya, etc.)")
		Endpoint.Say("")
		Endpoint.Say("Remediation Steps:")
		if !smbv1ServerResult.Compliant {
			Endpoint.Say("  - Disable SMBv1 Server:")
			Endpoint.Say("    Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'SMB1' -Value 0 -Type DWord")
			Endpoint.Say("    OR: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart")
		}
		if !smbv1ClientResult.Compliant {
			Endpoint.Say("  - Disable SMBv1 Client:")
			Endpoint.Say("    Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10' -Name 'Start' -Value 4 -Type DWord")
			Endpoint.Say("    sc config mrxsmb10 start= disabled")
		}
		if !serverSigningResult.Compliant {
			Endpoint.Say("  - Enable Server Signing:")
			Endpoint.Say("    Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord")
		}
		if !clientSigningResult.Compliant {
			Endpoint.Say("  - Enable Client Signing:")
			Endpoint.Say("    Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord")
		}
		if !encryptionResult.Compliant {
			Endpoint.Say("  - Enable SMB Encryption:")
			Endpoint.Say("    Set-SmbServerConfiguration -EncryptData $true -Force")
		}
		Endpoint.Say("")
		Endpoint.Say("Note: SMB signing adds ~15%% performance overhead but significantly improves security.")
		Endpoint.Say("Note: SMB encryption requires SMB 3.0+ on both endpoints.")

		LogMessage("WARNING", "Compliance", fmt.Sprintf("Only %d/5 checks passed - system is NON-COMPLIANT", passedChecks))
		LogPhaseEnd(6, "failed", fmt.Sprintf("Not all checks passed (%d/5)", passedChecks))
		SaveLog(101, fmt.Sprintf("System is NON-COMPLIANT - only %d/5 SMB hardening configurations enabled", passedChecks))
		Endpoint.Stop(101)
	}
}

// checkSMBv1Server checks if SMBv1 Server is disabled
func checkSMBv1Server() CheckResult {
	result := CheckResult{
		Name:        "SMBv1 Server",
		Description: "SMBv1 Server protocol disabled",
		Expected:    "0",
	}

	Endpoint.Say("[*] Checking SMBv1 Server configuration...")
	LogMessage("INFO", "SMBv1Server", "Checking HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1")

	// First check registry
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		result.Value = "Key not accessible"
		result.Details = fmt.Sprintf("Failed to open registry key: %v", err)
		result.Compliant = false
		Endpoint.Say("    [!] Failed to access LanmanServer registry key: %v", err)
		LogMessage("ERROR", "SMBv1Server", result.Details)
		return result
	}
	defer key.Close()

	// Try to read SMB1 value
	value, _, err := key.GetIntegerValue("SMB1")
	if err != nil {
		// Key doesn't exist - check via PowerShell as fallback
		result.Value = "Not configured (checking via PowerShell...)"
		LogMessage("INFO", "SMBv1Server", "SMB1 registry value does not exist, checking via PowerShell")

		// Use PowerShell to check SMB1Protocol feature and Get-SmbServerConfiguration
		psResult := checkSMBv1ViaPS()
		if psResult.Compliant {
			result = psResult
			result.Name = "SMBv1 Server"
			return result
		}

		// Neither method shows it as disabled
		result.Value = "Not explicitly disabled"
		result.Details = "SMB1 registry value does not exist and SMBv1 is not disabled via Windows Features"
		result.Compliant = false
		Endpoint.Say("    [!] SMBv1 not explicitly configured in registry")
		LogMessage("WARNING", "SMBv1Server", result.Details)
		return result
	}

	result.Value = fmt.Sprintf("%d", value)

	// SMB1 = 0 means disabled
	if value == 0 {
		result.Compliant = true
		result.Details = "SMBv1 Server is explicitly disabled via registry"
		Endpoint.Say("    [+] SMBv1 Server is DISABLED (value=0)")
		LogMessage("SUCCESS", "SMBv1Server", result.Details)
	} else {
		result.Compliant = false
		result.Details = fmt.Sprintf("SMBv1 Server is ENABLED (value=%d, expected 0)", value)
		Endpoint.Say("    [-] SMBv1 Server is ENABLED (value=%d)", value)
		LogMessage("WARNING", "SMBv1Server", result.Details)
	}

	return result
}

// checkSMBv1ViaPS checks SMBv1 status using PowerShell
func checkSMBv1ViaPS() CheckResult {
	result := CheckResult{
		Name:        "SMBv1 Server (PowerShell)",
		Description: "SMBv1 disabled via Windows Features or SMB configuration",
		Expected:    "Disabled",
	}

	// Check both Windows Feature and SMB Server Configuration
	psScript := `
$feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
$smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($feature -and $feature.State -eq 'Disabled') {
    Write-Output "FEATURE_DISABLED"
} elseif ($smbConfig -and $smbConfig.EnableSMB1Protocol -eq $false) {
    Write-Output "CONFIG_DISABLED"
} else {
    if ($smbConfig) {
        Write-Output "ENABLED:EnableSMB1Protocol=$($smbConfig.EnableSMB1Protocol)"
    } else {
        Write-Output "UNKNOWN"
    }
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
		LogMessage("ERROR", "SMBv1Server", result.Details)
		saveSMBOutput("smbv1_server_ps.txt", stdout.String(), stderr.String())
		return result
	}

	output := strings.TrimSpace(stdout.String())
	saveSMBOutput("smbv1_server_ps.txt", output, stderr.String())

	if output == "FEATURE_DISABLED" {
		result.Value = "Windows Feature Disabled"
		result.Details = "SMB1Protocol Windows Optional Feature is disabled"
		result.Compliant = true
		Endpoint.Say("    [+] SMBv1 Server is DISABLED via Windows Features")
		LogMessage("SUCCESS", "SMBv1Server", result.Details)
	} else if output == "CONFIG_DISABLED" {
		result.Value = "SMB Config Disabled"
		result.Details = "EnableSMB1Protocol is False in SMB Server Configuration"
		result.Compliant = true
		Endpoint.Say("    [+] SMBv1 Server is DISABLED via SMB Configuration")
		LogMessage("SUCCESS", "SMBv1Server", result.Details)
	} else {
		result.Value = output
		result.Details = "SMBv1 is not disabled"
		result.Compliant = false
		Endpoint.Say("    [-] SMBv1 Server appears ENABLED: %s", output)
		LogMessage("WARNING", "SMBv1Server", result.Details)
	}

	return result
}

// checkSMBv1Client checks if SMBv1 Client is disabled
func checkSMBv1Client() CheckResult {
	result := CheckResult{
		Name:        "SMBv1 Client",
		Description: "SMBv1 Client driver (mrxsmb10) disabled",
		Expected:    "4 (Disabled)",
	}

	Endpoint.Say("[*] Checking SMBv1 Client configuration...")
	LogMessage("INFO", "SMBv1Client", "Checking HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\\Start")

	// Check mrxsmb10 service start type
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\mrxsmb10`, registry.QUERY_VALUE)
	if err != nil {
		// If the key doesn't exist, SMBv1 client is likely not installed
		result.Value = "Service not found"
		result.Details = "mrxsmb10 service registry key not found - SMBv1 client may not be installed"
		result.Compliant = true // If the service doesn't exist, it can't be used
		Endpoint.Say("    [+] SMBv1 Client (mrxsmb10) service not found - likely not installed")
		LogMessage("SUCCESS", "SMBv1Client", result.Details)
		return result
	}
	defer key.Close()

	// Read Start value
	value, _, err := key.GetIntegerValue("Start")
	if err != nil {
		result.Value = "Start value not found"
		result.Details = fmt.Sprintf("Failed to read Start value: %v", err)
		result.Compliant = false
		Endpoint.Say("    [!] Failed to read mrxsmb10 Start value: %v", err)
		LogMessage("ERROR", "SMBv1Client", result.Details)
		return result
	}

	result.Value = fmt.Sprintf("%d", value)

	// Start = 4 means Disabled
	// 0 = Boot, 1 = System, 2 = Automatic, 3 = Manual, 4 = Disabled
	startTypeNames := map[uint64]string{
		0: "Boot",
		1: "System",
		2: "Automatic",
		3: "Manual",
		4: "Disabled",
	}

	startTypeName := startTypeNames[value]
	if startTypeName == "" {
		startTypeName = "Unknown"
	}

	if value == 4 {
		result.Compliant = true
		result.Details = fmt.Sprintf("mrxsmb10 service is disabled (Start=%d)", value)
		result.Value = fmt.Sprintf("%d (%s)", value, startTypeName)
		Endpoint.Say("    [+] SMBv1 Client is DISABLED (Start=%d - %s)", value, startTypeName)
		LogMessage("SUCCESS", "SMBv1Client", result.Details)
	} else {
		result.Compliant = false
		result.Details = fmt.Sprintf("mrxsmb10 service is NOT disabled (Start=%d - %s, expected 4 - Disabled)", value, startTypeName)
		result.Value = fmt.Sprintf("%d (%s)", value, startTypeName)
		Endpoint.Say("    [-] SMBv1 Client is ENABLED (Start=%d - %s)", value, startTypeName)
		LogMessage("WARNING", "SMBv1Client", result.Details)
	}

	return result
}

// checkServerSigning checks if SMB Server signing is required
func checkServerSigning() CheckResult {
	result := CheckResult{
		Name:        "Server Signing",
		Description: "SMB Server requires security signature",
		Expected:    "1",
	}

	Endpoint.Say("[*] Checking SMB Server signing configuration...")
	LogMessage("INFO", "ServerSigning", "Checking HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature")

	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		result.Value = "Key not accessible"
		result.Details = fmt.Sprintf("Failed to open registry key: %v", err)
		result.Compliant = false
		Endpoint.Say("    [!] Failed to access LanmanServer registry key: %v", err)
		LogMessage("ERROR", "ServerSigning", result.Details)
		return result
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("RequireSecuritySignature")
	if err != nil {
		result.Value = "Not configured"
		result.Details = "RequireSecuritySignature value does not exist - signing not required"
		result.Compliant = false
		Endpoint.Say("    [!] Server signing not configured (value does not exist)")
		LogMessage("WARNING", "ServerSigning", result.Details)
		return result
	}

	result.Value = fmt.Sprintf("%d", value)

	if value == 1 {
		result.Compliant = true
		result.Details = "SMB Server requires security signatures"
		Endpoint.Say("    [+] Server signing is REQUIRED (value=1)")
		LogMessage("SUCCESS", "ServerSigning", result.Details)
	} else {
		result.Compliant = false
		result.Details = fmt.Sprintf("SMB Server does not require signatures (value=%d, expected 1)", value)
		Endpoint.Say("    [-] Server signing is NOT REQUIRED (value=%d)", value)
		LogMessage("WARNING", "ServerSigning", result.Details)
	}

	return result
}

// checkClientSigning checks if SMB Client signing is required
func checkClientSigning() CheckResult {
	result := CheckResult{
		Name:        "Client Signing",
		Description: "SMB Client requires security signature",
		Expected:    "1",
	}

	Endpoint.Say("[*] Checking SMB Client signing configuration...")
	LogMessage("INFO", "ClientSigning", "Checking HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature")

	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		result.Value = "Key not accessible"
		result.Details = fmt.Sprintf("Failed to open registry key: %v", err)
		result.Compliant = false
		Endpoint.Say("    [!] Failed to access LanmanWorkstation registry key: %v", err)
		LogMessage("ERROR", "ClientSigning", result.Details)
		return result
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("RequireSecuritySignature")
	if err != nil {
		result.Value = "Not configured"
		result.Details = "RequireSecuritySignature value does not exist - signing not required"
		result.Compliant = false
		Endpoint.Say("    [!] Client signing not configured (value does not exist)")
		LogMessage("WARNING", "ClientSigning", result.Details)
		return result
	}

	result.Value = fmt.Sprintf("%d", value)

	if value == 1 {
		result.Compliant = true
		result.Details = "SMB Client requires security signatures"
		Endpoint.Say("    [+] Client signing is REQUIRED (value=1)")
		LogMessage("SUCCESS", "ClientSigning", result.Details)
	} else {
		result.Compliant = false
		result.Details = fmt.Sprintf("SMB Client does not require signatures (value=%d, expected 1)", value)
		Endpoint.Say("    [-] Client signing is NOT REQUIRED (value=%d)", value)
		LogMessage("WARNING", "ClientSigning", result.Details)
	}

	return result
}

// checkSMBEncryption checks if SMB encryption is enabled
func checkSMBEncryption() CheckResult {
	result := CheckResult{
		Name:        "SMB Encryption",
		Description: "SMB Server encryption enabled (EncryptData)",
		Expected:    "True",
	}

	Endpoint.Say("[*] Checking SMB encryption configuration...")
	LogMessage("INFO", "SMBEncryption", "Querying Get-SmbServerConfiguration EncryptData")

	// Use PowerShell to check SMB Server Configuration
	psScript := `
$config = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($config) {
    if ($config.EncryptData -eq $true) {
        Write-Output "ENABLED"
    } else {
        Write-Output "DISABLED:EncryptData=$($config.EncryptData)"
    }
} else {
    Write-Output "QUERY_FAILED"
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
		Endpoint.Say("    [!] Failed to query SMB encryption status: %v", err)
		LogMessage("ERROR", "SMBEncryption", result.Details)
		saveSMBOutput("smb_encryption.txt", stdout.String(), stderr.String())
		return result
	}

	output := strings.TrimSpace(stdout.String())
	saveSMBOutput("smb_encryption.txt", output, stderr.String())

	if output == "ENABLED" {
		result.Value = "True"
		result.Details = "SMB Server encryption (EncryptData) is enabled"
		result.Compliant = true
		Endpoint.Say("    [+] SMB Encryption is ENABLED")
		LogMessage("SUCCESS", "SMBEncryption", result.Details)
	} else if output == "QUERY_FAILED" {
		result.Value = "Query failed"
		result.Details = "Could not query SMB Server Configuration"
		result.Compliant = false
		Endpoint.Say("    [!] Could not query SMB Server Configuration")
		LogMessage("ERROR", "SMBEncryption", result.Details)
	} else {
		result.Value = "False"
		result.Details = fmt.Sprintf("SMB Server encryption is not enabled: %s", output)
		result.Compliant = false
		Endpoint.Say("    [-] SMB Encryption is NOT ENABLED: %s", output)
		LogMessage("WARNING", "SMBEncryption", result.Details)
	}

	return result
}

// saveSMBOutput saves PowerShell output for debugging
func saveSMBOutput(filename, stdout, stderr string) {
	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)

	outputPath := filepath.Join(targetDir, filename)
	content := fmt.Sprintf("=== SMB Configuration Query Output ===\n\nSTDOUT:\n%s\n\nSTDERR:\n%s\n", stdout, stderr)

	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		LogMessage("WARNING", "SMBOutput", fmt.Sprintf("Failed to save output: %v", err))
	} else {
		LogMessage("INFO", "SMBOutput", fmt.Sprintf("Output saved to: %s", outputPath))
	}
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
	Endpoint.Say("[%s] %-30s Value: %s", status, name, result.Value)
}

// isAdmin checks if the process is running with administrator privileges
func isAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// main is the entry point
func main() {
	Endpoint.Say("================================================================================")
	Endpoint.Say("  F0RT1KA CYBER HYGIENE TEST: SMB Protocol Hardening Validator")
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
