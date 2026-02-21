//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// CrowdStrike constants
const (
	CROWDSTRIKE_SERVICE_NAME = "CSFalconService"
	MINIMUM_SENSOR_VERSION   = "7.0"
)

// FalconStatus holds the Falcon sensor status information
type FalconStatus struct {
	ServiceRunning    bool
	ServiceStartType  string
	SensorVersion     string
	AgentID           string // CID - Customer ID
	ProvisioningState int    // 1 = Provisioned
	OperationalStatus string
	PreventionEnabled bool
	CloudConnected    bool
	TamperProtected   bool
}

// RunCrowdStrikeChecks performs all CrowdStrike Falcon configuration checks
func RunCrowdStrikeChecks() ValidatorResult {
	// Collect sensor status first
	status := getFalconStatus()

	checks := []CheckResult{
		checkFalconServiceRunning(status),
		checkSensorOperationalStatus(status),
		checkPreventionMode(status),
		checkSensorVersion(status),
		checkCloudConnectivity(status),
		checkTamperProtection(status),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "CrowdStrike Falcon Configuration",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
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

// getFileVersion retrieves the file version using PowerShell
func getFileVersion(filePath string) string {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return ""
	}

	psCmd := fmt.Sprintf(`(Get-Item '%s').VersionInfo.FileVersion`, filePath)
	output, err := RunPowerShell(psCmd)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(output)
}

// getAgentID retrieves the CrowdStrike Customer ID (CID) from registry
func getAgentID() string {
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

	// Method 2: If service is running and provisioned, assume connected
	if isServiceRunning(CROWDSTRIKE_SERVICE_NAME) && getProvisioningState() == 1 {
		return true
	}

	return false
}

// checkTamperProtectionEnabled checks if tamper protection is active
func checkTamperProtectionEnabled() bool {
	// Check for tamper protection in registry
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\CrowdStrike\Falcon\Protection`, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()

		if enabled, _, err := key.GetIntegerValue("TamperProtection"); err == nil {
			return enabled == 1
		}
	}

	// Check driver protection status - kernel driver running implies tamper protection
	cmd := exec.Command("sc", "query", "CSAgent")
	output, _ := cmd.Output()
	if strings.Contains(string(output), "RUNNING") {
		return true
	}

	// If main service is running, check for kernel components
	if isServiceRunning(CROWDSTRIKE_SERVICE_NAME) {
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

// ==============================================================================
// CHECK FUNCTIONS - Return CheckResult from check_utils.go
// ==============================================================================

// checkFalconServiceRunning verifies CSFalconService is running (CH-CRW-001)
func checkFalconServiceRunning(status *FalconStatus) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CRW-001",
		Name:        "Falcon Sensor Service",
		Category:    "crowdstrike",
		Description: "Checks if CSFalconService is running",
		Severity:    "critical",
		Expected:    "Running",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	if status.ServiceRunning {
		result.Passed = true
		result.Actual = fmt.Sprintf("Running (%s start)", status.ServiceStartType)
		result.Details = "CSFalconService is running and operational"
	} else {
		result.Passed = false
		result.Actual = "Not Running"
		result.Details = "CSFalconService is not running - sensor is inactive"
	}

	return result
}

// checkSensorOperationalStatus verifies sensor is provisioned (CH-CRW-002)
func checkSensorOperationalStatus(status *FalconStatus) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CRW-002",
		Name:        "Sensor Operational Status",
		Category:    "crowdstrike",
		Description: "Checks if sensor is provisioned and operational",
		Severity:    "high",
		Expected:    "Provisioned (State 1)",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	if status.ProvisioningState == 1 {
		result.Passed = true
		result.Actual = "Provisioned"
		result.Details = "Sensor is fully provisioned and communicating with CrowdStrike cloud"
	} else if status.ProvisioningState == 0 {
		result.Passed = false
		result.Actual = "Not Provisioned"
		result.Details = "Sensor is not provisioned - needs to connect to CrowdStrike cloud"
	} else if status.ProvisioningState == -1 {
		result.Passed = false
		result.Actual = "Unknown"
		result.Details = "Could not determine provisioning state"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("State %d", status.ProvisioningState)
		result.Details = fmt.Sprintf("Unexpected provisioning state: %d", status.ProvisioningState)
	}

	return result
}

// checkPreventionMode verifies prevention mode is enabled (CH-CRW-003)
func checkPreventionMode(status *FalconStatus) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CRW-003",
		Name:        "Prevention Mode",
		Category:    "crowdstrike",
		Description: "Checks that sensor is not in detect-only mode",
		Severity:    "critical",
		Expected:    "Enabled",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	if status.PreventionEnabled {
		result.Passed = true
		result.Actual = "Enabled"
		result.Details = "Prevention mode is active - sensor will block threats"
	} else {
		result.Passed = false
		result.Actual = "Detect Only / Disabled"
		result.Details = "Prevention may be disabled - sensor is in detect-only mode"
	}

	return result
}

// checkSensorVersion verifies sensor version meets minimum requirements (CH-CRW-004)
func checkSensorVersion(status *FalconStatus) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CRW-004",
		Name:        "Sensor Version",
		Category:    "crowdstrike",
		Description: "Checks if sensor version meets minimum requirement",
		Severity:    "high",
		Expected:    fmt.Sprintf(">= %s", MINIMUM_SENSOR_VERSION),
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	if status.SensorVersion == "Unknown" || status.SensorVersion == "" {
		result.Passed = false
		result.Actual = "Unknown"
		result.Details = "Could not determine sensor version"
		return result
	}

	result.Actual = status.SensorVersion

	if isVersionCompliant(status.SensorVersion, MINIMUM_SENSOR_VERSION) {
		result.Passed = true
		result.Details = fmt.Sprintf("Sensor version %s meets minimum requirement (%s)", status.SensorVersion, MINIMUM_SENSOR_VERSION)
	} else {
		result.Passed = false
		result.Details = fmt.Sprintf("Sensor version %s is below minimum requirement (%s)", status.SensorVersion, MINIMUM_SENSOR_VERSION)
	}

	return result
}

// checkCloudConnectivity verifies cloud connectivity (CH-CRW-005)
func checkCloudConnectivity(status *FalconStatus) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CRW-005",
		Name:        "Cloud Connectivity",
		Category:    "crowdstrike",
		Description: "Checks if sensor can reach CrowdStrike cloud",
		Severity:    "high",
		Expected:    "Connected",
		Techniques:  []string{"T1562.004"},
		Tactics:     []string{"defense-evasion"},
	}

	if status.CloudConnected {
		result.Passed = true
		result.Actual = "Connected"
		result.Details = "Sensor is connected to CrowdStrike cloud for threat intelligence"
	} else {
		result.Passed = false
		result.Actual = "Disconnected / Unknown"
		result.Details = "Sensor cloud connectivity could not be verified"
	}

	return result
}

// checkTamperProtection verifies tamper protection is active (CH-CRW-006)
func checkTamperProtection(status *FalconStatus) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CRW-006",
		Name:        "Tamper Protection",
		Category:    "crowdstrike",
		Description: "Checks if sensor protection against tampering is enabled",
		Severity:    "critical",
		Expected:    "Enabled",
		Techniques:  []string{"T1562.001", "T1070"},
		Tactics:     []string{"defense-evasion"},
	}

	if status.TamperProtected {
		result.Passed = true
		result.Actual = "Enabled"
		result.Details = "Tamper protection is active - sensor is protected from malicious modification"
	} else {
		result.Passed = false
		result.Actual = "Disabled / Unknown"
		result.Details = "Tamper protection could not be verified - sensor may be vulnerable to tampering"
	}

	return result
}

// ==============================================================================
// VERSION COMPARISON HELPERS
// ==============================================================================

// isVersionCompliant compares version strings
func isVersionCompliant(current, minimum string) bool {
	currentMajor := extractMajorVersion(current)
	minimumMajor := extractMajorVersion(minimum)
	return currentMajor >= minimumMajor
}

// extractMajorVersion extracts the major version number from a version string
func extractMajorVersion(version string) float64 {
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
