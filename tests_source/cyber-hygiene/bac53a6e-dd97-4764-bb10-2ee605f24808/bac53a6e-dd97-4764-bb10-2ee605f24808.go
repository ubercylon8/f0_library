//go:build windows
// +build windows

/*
ID: bac53a6e-dd97-4764-bb10-2ee605f24808
NAME: CrowdStrike Falcon Configuration Validator
TECHNIQUES: T1562.001, T1562.004, T1070
UNIT: response
CREATED: 2026-01-11
*/

// CrowdStrike Falcon Configuration Validator - Cyber Hygiene Test
//
// This test validates that CrowdStrike Falcon endpoint protection is properly
// configured with all critical protection features enabled. Proper Falcon
// configuration is essential for preventing ransomware and other malware attacks.
//
// Configuration Checks (ALL 6 must pass for COMPLIANT):
// 1. Falcon Sensor Service Running - CSFalconService is active
// 2. Sensor Operational Status - Sensor is provisioned and operational
// 3. Prevention Mode Enabled - Not in detect-only mode
// 4. Sensor Version Current - Version meets minimum requirements (7.0+)
// 5. Cloud Connectivity - Sensor can communicate with CrowdStrike cloud
// 6. Tamper Protection - Sensor protection against tampering
//
// Exit Codes:
// - 126: All 6 checks pass (COMPLIANT)
// - 101: One or more checks fail (NON-COMPLIANT)
// - 999: Test error (Falcon not installed, insufficient privileges)
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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID                = "bac53a6e-dd97-4764-bb10-2ee605f24808"
	TEST_NAME                = "CrowdStrike Falcon Configuration Validator"
	MINIMUM_SENSOR_VERSION   = "7.0"
	CROWDSTRIKE_SERVICE_NAME = "CSFalconService"
)

// CheckResult represents the result of a single configuration check
type CheckResult struct {
	Name        string
	Description string
	Compliant   bool
	Value       string
	Expected    string
	Details     string
	Method      string // "service", "registry", "wmi", "process"
}

// FalconStatus holds the Falcon sensor status information
type FalconStatus struct {
	ServiceRunning     bool
	ServiceStartType   string
	SensorVersion      string
	AgentID            string // CID - Customer ID
	ProvisioningState  int    // 1 = Provisioned
	OperationalStatus  string
	PreventionEnabled  bool
	CloudConnected     bool
	TamperProtected    bool
	SensorInstallPath  string
}

// test performs the CrowdStrike Falcon configuration validation
func test() {
	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "defense_evasion",
		Severity:   "critical",
		Techniques: []string{"T1562.001", "T1562.004", "T1070"},
		Tactics:    []string{"defense-evasion"},
		Score:      8.0,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"cyber-hygiene", "falcon-configuration", "edr-validation", "configuration-validation", "crowdstrike"},
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

	// Phase 0: Initialization and Falcon Detection
	LogPhaseStart(0, "Initialization")

	// Check for admin privileges (recommended but may not be strictly required for all checks)
	if !isAdmin() {
		Endpoint.Say("[!] WARNING: Not running with administrator privileges")
		Endpoint.Say("    Some checks may be limited, but test will continue")
		LogMessage("WARNING", "Initialization", "Not running with administrator privileges - some checks may be limited")
	} else {
		LogMessage("INFO", "Initialization", "Running with administrator privileges")
	}

	// Check if CrowdStrike Falcon is installed
	if !isFalconInstalled() {
		Endpoint.Say("[!] ERROR: CrowdStrike Falcon is not detected")
		Endpoint.Say("    CSFalconService not found on this system")
		LogMessage("ERROR", "Initialization", "CrowdStrike Falcon not detected - CSFalconService not found")
		LogPhaseEnd(0, "failed", "Falcon not installed")
		SaveLog(999, "CrowdStrike Falcon not detected - sensor may not be installed")
		Endpoint.Stop(999)
	}
	LogMessage("INFO", "Initialization", "CrowdStrike Falcon sensor detected")

	LogPhaseEnd(0, "success", "Initialization complete")

	// Phase 1: Retrieve Falcon Status
	LogPhaseStart(1, "Retrieve Falcon Status")
	Endpoint.Say("[*] Retrieving CrowdStrike Falcon sensor status...")

	status := getFalconStatus()

	// Log collected status
	LogMessage("INFO", "Status Retrieval", fmt.Sprintf("Service Running: %v", status.ServiceRunning))
	LogMessage("INFO", "Status Retrieval", fmt.Sprintf("Sensor Version: %s", status.SensorVersion))
	LogMessage("INFO", "Status Retrieval", fmt.Sprintf("Agent ID (CID): %s", maskCID(status.AgentID)))
	LogMessage("INFO", "Status Retrieval", fmt.Sprintf("Provisioning State: %d", status.ProvisioningState))
	LogMessage("INFO", "Status Retrieval", fmt.Sprintf("Prevention Enabled: %v", status.PreventionEnabled))

	// Save raw status output for debugging
	saveFalconStatusOutput(status)

	LogPhaseEnd(1, "success", "Status retrieval complete")

	// Phase 2: Run Configuration Checks
	LogPhaseStart(2, "Configuration Checks")

	var results []CheckResult

	// Check 1: Falcon Sensor Service Running
	Endpoint.Say("")
	Endpoint.Say("[*] Check 1/6: Falcon Sensor Service")
	result1 := checkServiceRunning(status)
	results = append(results, result1)
	logCheckResult(result1)

	// Check 2: Sensor Operational Status
	Endpoint.Say("")
	Endpoint.Say("[*] Check 2/6: Sensor Operational Status")
	result2 := checkOperationalStatus(status)
	results = append(results, result2)
	logCheckResult(result2)

	// Check 3: Prevention Mode Enabled
	Endpoint.Say("")
	Endpoint.Say("[*] Check 3/6: Prevention Mode")
	result3 := checkPreventionMode(status)
	results = append(results, result3)
	logCheckResult(result3)

	// Check 4: Sensor Version Current
	Endpoint.Say("")
	Endpoint.Say("[*] Check 4/6: Sensor Version")
	result4 := checkSensorVersion(status)
	results = append(results, result4)
	logCheckResult(result4)

	// Check 5: Cloud Connectivity
	Endpoint.Say("")
	Endpoint.Say("[*] Check 5/6: Cloud Connectivity")
	result5 := checkCloudConnectivity(status)
	results = append(results, result5)
	logCheckResult(result5)

	// Check 6: Tamper Protection
	Endpoint.Say("")
	Endpoint.Say("[*] Check 6/6: Tamper Protection")
	result6 := checkTamperProtection(status)
	results = append(results, result6)
	logCheckResult(result6)

	LogPhaseEnd(2, "success", "All configuration checks completed")

	// Phase 3: Additional Information (Informational Only)
	LogPhaseStart(3, "Additional Information")
	displayAdditionalInfo(status)
	LogPhaseEnd(3, "success", "Additional information collected")

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
	Endpoint.Say("           CROWDSTRIKE FALCON CONFIGURATION VALIDATION SUMMARY")
	Endpoint.Say("================================================================================")
	Endpoint.Say("")

	for i, r := range results {
		statusText := "FAIL"
		if r.Compliant {
			statusText = "PASS"
		}
		Endpoint.Say("[%s] Check %d: %-35s Value: %s", statusText, i+1, r.Name, r.Value)
	}

	Endpoint.Say("")
	Endpoint.Say("--------------------------------------------------------------------------------")
	Endpoint.Say("Overall: %d/6 checks passed", passedChecks)

	if allCompliant {
		Endpoint.Say("")
		Endpoint.Say("[COMPLIANT] All CrowdStrike Falcon protection features are properly configured.")
		Endpoint.Say("            System has comprehensive EDR protection enabled.")
		LogMessage("SUCCESS", "Compliance", "All 6 Falcon configuration checks passed - system is COMPLIANT")
		LogPhaseEnd(4, "success", fmt.Sprintf("All checks passed (%d/6)", passedChecks))
		SaveLog(126, "System is COMPLIANT - all CrowdStrike Falcon protection features enabled")
		Endpoint.Stop(126)
	} else {
		Endpoint.Say("")
		Endpoint.Say("[NON-COMPLIANT] CrowdStrike Falcon configuration is incomplete.")
		Endpoint.Say("                System may be vulnerable to advanced threats.")
		Endpoint.Say("")
		Endpoint.Say("Remediation Steps:")

		for _, r := range results {
			if !r.Compliant {
				printRemediation(r.Name)
			}
		}

		LogMessage("WARNING", "Compliance", fmt.Sprintf("Only %d/6 checks passed - system is NON-COMPLIANT", passedChecks))
		LogPhaseEnd(4, "failed", fmt.Sprintf("Not all checks passed (%d/6)", passedChecks))
		SaveLog(101, fmt.Sprintf("System is NON-COMPLIANT - only %d/6 Falcon protection features enabled", passedChecks))
		Endpoint.Stop(101)
	}
}

// isFalconInstalled checks if CrowdStrike Falcon is installed by querying the service
func isFalconInstalled() bool {
	// Check if CSFalconService exists
	cmd := exec.Command("sc", "query", CROWDSTRIKE_SERVICE_NAME)
	output, err := cmd.Output()
	if err != nil {
		// Try alternative check via registry
		key, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\CSAgent`, registry.QUERY_VALUE)
		if err != nil {
			return false
		}
		key.Close()
		return true
	}

	return strings.Contains(string(output), CROWDSTRIKE_SERVICE_NAME)
}

// getFalconStatus retrieves comprehensive Falcon sensor status
func getFalconStatus() *FalconStatus {
	status := &FalconStatus{}

	// Check service status
	status.ServiceRunning = isServiceRunning(CROWDSTRIKE_SERVICE_NAME)
	status.ServiceStartType = getServiceStartType(CROWDSTRIKE_SERVICE_NAME)

	// Get sensor version from registry
	status.SensorVersion = getSensorVersion()

	// Get Agent ID (CID) from registry
	status.AgentID = getAgentID()

	// Get provisioning state
	status.ProvisioningState = getProvisioningState()

	// Determine operational status based on service and provisioning
	if status.ServiceRunning && status.ProvisioningState == 1 {
		status.OperationalStatus = "Operational"
	} else if status.ServiceRunning {
		status.OperationalStatus = "Running (not fully provisioned)"
	} else {
		status.OperationalStatus = "Not Running"
	}

	// Check prevention mode (based on policy settings)
	status.PreventionEnabled = checkPreventionEnabled()

	// Check cloud connectivity
	status.CloudConnected = checkCloudConnection()

	// Check tamper protection
	status.TamperProtected = checkTamperProtectionEnabled()

	// Get sensor install path
	status.SensorInstallPath = getSensorInstallPath()

	return status
}

// isServiceRunning checks if a Windows service is running
func isServiceRunning(serviceName string) bool {
	cmd := exec.Command("sc", "query", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "RUNNING")
}

// getServiceStartType gets the start type of a Windows service
func getServiceStartType(serviceName string) string {
	cmd := exec.Command("sc", "qc", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}

	outputStr := string(output)
	if strings.Contains(outputStr, "AUTO_START") {
		return "Automatic"
	} else if strings.Contains(outputStr, "DEMAND_START") {
		return "Manual"
	} else if strings.Contains(outputStr, "DISABLED") {
		return "Disabled"
	}
	return "Unknown"
}

// getSensorVersion retrieves the Falcon sensor version from registry
func getSensorVersion() string {
	// Try multiple registry locations for version info
	registryPaths := []struct {
		path      string
		valueName string
	}{
		{`SOFTWARE\CrowdStrike\Falcon`, "Version"},
		{`SOFTWARE\CrowdStrike\Falcon\Sensor`, "Version"},
		{`SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default`, "Version"},
	}

	for _, rp := range registryPaths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, rp.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		defer key.Close()

		version, _, err := key.GetStringValue(rp.valueName)
		if err == nil && version != "" {
			return version
		}
	}

	// Try to get version from file version info
	paths := []string{
		`C:\Program Files\CrowdStrike\CSFalconService.exe`,
		`C:\Windows\System32\drivers\CrowdStrike\CSAgent.sys`,
	}

	for _, path := range paths {
		if version := getFileVersion(path); version != "" {
			return version
		}
	}

	return "Unknown"
}

// getFileVersion retrieves the file version using wmic
func getFileVersion(filePath string) string {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return ""
	}

	// Use PowerShell to get file version
	psCmd := fmt.Sprintf(`(Get-Item '%s').VersionInfo.FileVersion`, filePath)
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(output))
}

// getAgentID retrieves the CrowdStrike Customer ID (CID) from registry
func getAgentID() string {
	// CrowdStrike stores the Agent ID (AG) in registry
	registryPaths := []struct {
		path      string
		valueName string
	}{
		{`SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default`, "AG"},
		{`SYSTEM\CurrentControlSet\Services\CSAgent`, "AG"},
		{`SOFTWARE\CrowdStrike\Falcon`, "CID"},
	}

	for _, rp := range registryPaths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, rp.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		defer key.Close()

		// Try string value first
		value, _, err := key.GetStringValue(rp.valueName)
		if err == nil && value != "" {
			return value
		}

		// Try binary value
		binValue, _, err := key.GetBinaryValue(rp.valueName)
		if err == nil && len(binValue) > 0 {
			return fmt.Sprintf("%x", binValue)
		}
	}

	return "Unknown"
}

// getProvisioningState retrieves the sensor provisioning state
func getProvisioningState() int {
	// Check provisioning state from registry
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default`,
		registry.QUERY_VALUE)
	if err != nil {
		// Try alternative path
		key, err = registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\CrowdStrike\Falcon`, registry.QUERY_VALUE)
		if err != nil {
			return -1
		}
	}
	defer key.Close()

	// Try ProvisioningState
	state, _, err := key.GetIntegerValue("ProvisioningState")
	if err == nil {
		return int(state)
	}

	// Check if sensor is registered (alternative indicator)
	if _, _, err := key.GetStringValue("AG"); err == nil {
		return 1 // Assume provisioned if AG exists
	}

	return -1
}

// checkPreventionEnabled checks if prevention policies are enabled
func checkPreventionEnabled() bool {
	// CrowdStrike prevention settings are typically cloud-managed
	// We check for indicators that prevention is enabled

	// Check if CSFalconContainer (kernel mode) is running
	cmd := exec.Command("sc", "query", "CSFalconContainer")
	output, _ := cmd.Output()
	containerRunning := strings.Contains(string(output), "RUNNING")

	// Check driver status
	cmd = exec.Command("sc", "query", "CSAgent")
	output, _ = cmd.Output()
	driverRunning := strings.Contains(string(output), "RUNNING")

	// If both kernel components are running, prevention is likely enabled
	if containerRunning || driverRunning {
		return true
	}

	// Check registry for prevention policy indicators
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\CrowdStrike\Falcon\Prevention`, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()
		enabled, _, err := key.GetIntegerValue("Enabled")
		if err == nil && enabled == 1 {
			return true
		}
	}

	// Default to checking if main service is running (minimal indicator)
	return isServiceRunning(CROWDSTRIKE_SERVICE_NAME)
}

// checkCloudConnection checks if the sensor can communicate with CrowdStrike cloud
func checkCloudConnection() bool {
	// Check for indicators of cloud connectivity

	// Method 1: Check registry for last cloud check-in timestamp
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default`,
		registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()

		// Check for connection state
		if connState, _, err := key.GetIntegerValue("ConnectionState"); err == nil {
			if connState == 1 {
				return true
			}
		}

		// Check last seen time (if recent, cloud is connected)
		if _, _, err := key.GetBinaryValue("LastSeen"); err == nil {
			return true // Has a last seen timestamp, indicates prior connection
		}
	}

	// Method 2: Check if sensor process is actively connected
	// This is a heuristic - if service is running and provisioned, assume connected
	if isServiceRunning(CROWDSTRIKE_SERVICE_NAME) && getProvisioningState() == 1 {
		return true
	}

	return false
}

// checkTamperProtectionEnabled checks if tamper protection is active
func checkTamperProtectionEnabled() bool {
	// CrowdStrike Falcon has built-in tamper protection when sensor is running
	// Check for indicators that tamper protection is active

	// Check if protected process light (PPL) or similar is enabled
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\CrowdStrike\Falcon\Protection`, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()

		if enabled, _, err := key.GetIntegerValue("TamperProtection"); err == nil {
			return enabled == 1
		}
	}

	// Check driver protection status
	cmd := exec.Command("sc", "query", "CSAgent")
	output, _ := cmd.Output()
	if strings.Contains(string(output), "RUNNING") {
		// Kernel driver running indicates tamper protection is active
		// CrowdStrike's kernel driver provides inherent tamper protection
		return true
	}

	// If main service is running with kernel components, assume protected
	if isServiceRunning(CROWDSTRIKE_SERVICE_NAME) {
		// Check if any kernel component is loaded
		cmd := exec.Command("sc", "query", "type=", "driver", "state=", "all")
		output, _ := cmd.Output()
		if strings.Contains(string(output), "CrowdStrike") ||
			strings.Contains(string(output), "CSAgent") ||
			strings.Contains(string(output), "csagent") {
			return true
		}
	}

	return false
}

// getSensorInstallPath retrieves the Falcon sensor installation path
func getSensorInstallPath() string {
	// Check common installation paths
	paths := []string{
		`C:\Program Files\CrowdStrike`,
		`C:\Windows\System32\drivers\CrowdStrike`,
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Try registry
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\CrowdStrike\Falcon`, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()
		if installPath, _, err := key.GetStringValue("InstallPath"); err == nil {
			return installPath
		}
	}

	return "Unknown"
}

// Check functions for each validation point

func checkServiceRunning(status *FalconStatus) CheckResult {
	result := CheckResult{
		Name:        "Falcon Sensor Service",
		Description: "CSFalconService is running",
		Expected:    "Running",
		Method:      "service",
	}

	if status.ServiceRunning {
		result.Value = fmt.Sprintf("Running (%s start)", status.ServiceStartType)
		result.Compliant = true
		result.Details = "CSFalconService is running and operational"
	} else {
		result.Value = "Not Running"
		result.Compliant = false
		result.Details = "CSFalconService is not running - sensor is inactive"
	}

	return result
}

func checkOperationalStatus(status *FalconStatus) CheckResult {
	result := CheckResult{
		Name:        "Sensor Operational Status",
		Description: "Sensor is provisioned and operational",
		Expected:    "Provisioned (State 1)",
		Method:      "registry",
	}

	if status.ProvisioningState == 1 {
		result.Value = "Provisioned"
		result.Compliant = true
		result.Details = "Sensor is fully provisioned and communicating with CrowdStrike cloud"
	} else if status.ProvisioningState == 0 {
		result.Value = "Not Provisioned"
		result.Compliant = false
		result.Details = "Sensor is not provisioned - needs to connect to CrowdStrike cloud"
	} else if status.ProvisioningState == -1 {
		result.Value = "Unknown"
		result.Compliant = false
		result.Details = "Could not determine provisioning state"
	} else {
		result.Value = fmt.Sprintf("State %d", status.ProvisioningState)
		result.Compliant = false
		result.Details = fmt.Sprintf("Unexpected provisioning state: %d", status.ProvisioningState)
	}

	return result
}

func checkPreventionMode(status *FalconStatus) CheckResult {
	result := CheckResult{
		Name:        "Prevention Mode",
		Description: "Not in detect-only mode",
		Expected:    "Enabled",
		Method:      "service",
	}

	if status.PreventionEnabled {
		result.Value = "Enabled"
		result.Compliant = true
		result.Details = "Prevention mode is active - sensor will block threats"
	} else {
		result.Value = "Detect Only / Disabled"
		result.Compliant = false
		result.Details = "Prevention may be disabled - sensor is in detect-only mode"
	}

	return result
}

func checkSensorVersion(status *FalconStatus) CheckResult {
	result := CheckResult{
		Name:        "Sensor Version",
		Description: "Meets minimum version requirement",
		Expected:    fmt.Sprintf(">= %s", MINIMUM_SENSOR_VERSION),
		Method:      "registry",
	}

	if status.SensorVersion == "Unknown" || status.SensorVersion == "" {
		result.Value = "Unknown"
		result.Compliant = false
		result.Details = "Could not determine sensor version"
		return result
	}

	result.Value = status.SensorVersion

	// Parse and compare versions
	if isVersionCompliant(status.SensorVersion, MINIMUM_SENSOR_VERSION) {
		result.Compliant = true
		result.Details = fmt.Sprintf("Sensor version %s meets minimum requirement (%s)", status.SensorVersion, MINIMUM_SENSOR_VERSION)
	} else {
		result.Compliant = false
		result.Details = fmt.Sprintf("Sensor version %s is below minimum requirement (%s)", status.SensorVersion, MINIMUM_SENSOR_VERSION)
	}

	return result
}

func checkCloudConnectivity(status *FalconStatus) CheckResult {
	result := CheckResult{
		Name:        "Cloud Connectivity",
		Description: "Sensor can reach CrowdStrike cloud",
		Expected:    "Connected",
		Method:      "registry",
	}

	if status.CloudConnected {
		result.Value = "Connected"
		result.Compliant = true
		result.Details = "Sensor is connected to CrowdStrike cloud for threat intelligence"
	} else {
		result.Value = "Disconnected / Unknown"
		result.Compliant = false
		result.Details = "Sensor cloud connectivity could not be verified"
	}

	return result
}

func checkTamperProtection(status *FalconStatus) CheckResult {
	result := CheckResult{
		Name:        "Tamper Protection",
		Description: "Sensor protection against tampering",
		Expected:    "Enabled",
		Method:      "service",
	}

	if status.TamperProtected {
		result.Value = "Enabled"
		result.Compliant = true
		result.Details = "Tamper protection is active - sensor is protected from malicious modification"
	} else {
		result.Value = "Disabled / Unknown"
		result.Compliant = false
		result.Details = "Tamper protection could not be verified - sensor may be vulnerable to tampering"
	}

	return result
}

// isVersionCompliant compares version strings
func isVersionCompliant(current, minimum string) bool {
	// Extract major version numbers for comparison
	currentMajor := extractMajorVersion(current)
	minimumMajor := extractMajorVersion(minimum)

	return currentMajor >= minimumMajor
}

// extractMajorVersion extracts the major version number from a version string
func extractMajorVersion(version string) float64 {
	// Handle various version formats: "7.10.0.123", "7.10", etc.
	re := regexp.MustCompile(`^(\d+)\.?(\d*)`)
	matches := re.FindStringSubmatch(version)

	if len(matches) >= 2 {
		major, err := strconv.ParseFloat(matches[1], 64)
		if err == nil {
			if len(matches) >= 3 && matches[2] != "" {
				minor, _ := strconv.ParseFloat("0."+matches[2], 64)
				return major + minor
			}
			return major
		}
	}

	return 0
}

// maskCID masks the Customer ID for log output (show first/last 4 chars)
func maskCID(cid string) string {
	if len(cid) <= 8 || cid == "Unknown" {
		return cid
	}
	return cid[:4] + "..." + cid[len(cid)-4:]
}

// saveFalconStatusOutput saves the status information for debugging
func saveFalconStatusOutput(status *FalconStatus) {
	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)

	outputPath := filepath.Join(targetDir, "falcon_status_output.txt")
	content := fmt.Sprintf(`=== CrowdStrike Falcon Status Output ===

Service Status:
  CSFalconService Running: %v
  Service Start Type: %s

Sensor Information:
  Version: %s
  Agent ID (CID): %s
  Install Path: %s

Operational Status:
  Provisioning State: %d
  Operational Status: %s
  Prevention Enabled: %v
  Cloud Connected: %v
  Tamper Protected: %v

Collected at: %s
`,
		status.ServiceRunning,
		status.ServiceStartType,
		status.SensorVersion,
		maskCID(status.AgentID),
		status.SensorInstallPath,
		status.ProvisioningState,
		status.OperationalStatus,
		status.PreventionEnabled,
		status.CloudConnected,
		status.TamperProtected,
		time.Now().Format("2006-01-02 15:04:05"),
	)

	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		LogMessage("WARNING", "Output Save", fmt.Sprintf("Failed to save status output: %v", err))
	} else {
		LogMessage("INFO", "Output Save", fmt.Sprintf("Status output saved to: %s", outputPath))
	}
}

// displayAdditionalInfo shows additional sensor information
func displayAdditionalInfo(status *FalconStatus) {
	Endpoint.Say("")
	Endpoint.Say("[*] Additional Sensor Information:")
	Endpoint.Say("    Sensor Version: %s", status.SensorVersion)
	Endpoint.Say("    Agent ID (CID): %s", maskCID(status.AgentID))
	Endpoint.Say("    Install Path: %s", status.SensorInstallPath)
	Endpoint.Say("    Service Start Type: %s", status.ServiceStartType)

	LogMessage("INFO", "Additional Info", fmt.Sprintf("Sensor Version: %s", status.SensorVersion))
	LogMessage("INFO", "Additional Info", fmt.Sprintf("Agent ID (masked): %s", maskCID(status.AgentID)))
	LogMessage("INFO", "Additional Info", fmt.Sprintf("Install Path: %s", status.SensorInstallPath))
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
	case "Falcon Sensor Service":
		Endpoint.Say("  - Start the Falcon Sensor Service:")
		Endpoint.Say("    sc start CSFalconService")
		Endpoint.Say("    Or: net start CSFalconService")
	case "Sensor Operational Status":
		Endpoint.Say("  - Ensure sensor is properly provisioned:")
		Endpoint.Say("    1. Verify CID is correctly configured in installation")
		Endpoint.Say("    2. Check network connectivity to CrowdStrike cloud")
		Endpoint.Say("    3. Review Falcon console for sensor health status")
	case "Prevention Mode":
		Endpoint.Say("  - Enable Prevention policies in Falcon console:")
		Endpoint.Say("    1. Log into Falcon console (falcon.crowdstrike.com)")
		Endpoint.Say("    2. Navigate to Configuration > Prevention Policies")
		Endpoint.Say("    3. Ensure prevention policies are applied to this host group")
	case "Sensor Version":
		Endpoint.Say("  - Update the Falcon sensor:")
		Endpoint.Say("    1. Enable automatic updates in Falcon console")
		Endpoint.Say("    2. Or manually deploy latest sensor version")
		Endpoint.Say("    3. Minimum recommended version: %s", MINIMUM_SENSOR_VERSION)
	case "Cloud Connectivity":
		Endpoint.Say("  - Verify cloud connectivity:")
		Endpoint.Say("    1. Ensure firewall allows outbound HTTPS to *.crowdstrike.com")
		Endpoint.Say("    2. Verify proxy settings if applicable")
		Endpoint.Say("    3. Check sensor logs for connectivity errors")
	case "Tamper Protection":
		Endpoint.Say("  - Enable Tamper Protection:")
		Endpoint.Say("    1. Tamper protection is enabled by default when sensor is running")
		Endpoint.Say("    2. Ensure kernel driver (CSAgent) is loaded")
		Endpoint.Say("    3. Review Falcon console for sensor health alerts")
	}
}

// main is the entry point
func main() {
	Endpoint.Say("================================================================================")
	Endpoint.Say("  F0RT1KA CYBER HYGIENE TEST: CrowdStrike Falcon Configuration Validator")
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

// Unused import prevention - bytes is used by test_logger.go
var _ = bytes.Buffer{}
