//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const CROWDSTRIKE_SERVICE_NAME = "CSFalconService"

// FalconStatus holds locally observable Falcon sensor information.
type FalconStatus struct {
	ServiceRunning    bool
	ServiceQueryError bool
	ServiceStartType  string
	SensorVersion     string
	AgentID           string
	ProvisioningState int
	OperationalStatus string
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

	// Collect only evidence available locally. Policy enforcement requires central evidence.
	running, err := queryServiceRunning(CROWDSTRIKE_SERVICE_NAME)
	status.ServiceRunning = running
	status.ServiceQueryError = err != nil
	status.ServiceStartType = getServiceStartType(CROWDSTRIKE_SERVICE_NAME)
	status.SensorVersion = getSensorVersion()
	status.AgentID = getAgentID()
	status.ProvisioningState = getProvisioningState()

	if status.ServiceQueryError {
		status.OperationalStatus = "Unknown"
	} else if status.ServiceRunning && status.ProvisioningState == 1 {
		status.OperationalStatus = "Operational"
	} else if status.ServiceRunning {
		status.OperationalStatus = "Running (not fully provisioned)"
	} else {
		status.OperationalStatus = "Not Running"
	}

	return status
}

func queryServiceRunning(serviceName string) (bool, error) {
	cmd := exec.Command("sc", "query", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(output), "RUNNING"), nil
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

// ==============================================================================
// CHECK FUNCTIONS - Return CheckResult from check_utils.go
// ==============================================================================

// checkFalconServiceRunning verifies CSFalconService is running (CH-CRW-001)
func checkFalconServiceRunning(status *FalconStatus) CheckResult {
	result := CheckResult{
		ControlID:      "CH-CRW-001",
		Name:           "Falcon Sensor Service",
		Category:       "crowdstrike",
		Description:    "Checks if CSFalconService is running",
		Severity:       "critical",
		Expected:       "Running",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "sc.exe query CSFalconService",
	}
	if status.ServiceQueryError {
		result.Status = "UNKNOWN"
		result.Actual = "Service query failed"
		result.Details = "The local service state could not be read"
	} else if status.ServiceRunning {
		result.Passed = true
		result.Actual = fmt.Sprintf("Running (%s start)", status.ServiceStartType)
		result.Details = "CSFalconService is running"
	} else {
		result.Actual = "Not Running"
		result.Details = "CSFalconService is not running - sensor is inactive"
	}
	return result
}

// checkSensorOperationalStatus verifies sensor is provisioned (CH-CRW-002)
func checkSensorOperationalStatus(status *FalconStatus) CheckResult {
	result := CheckResult{
		ControlID:      "CH-CRW-002",
		Name:           "Sensor Provisioning Status",
		Category:       "crowdstrike",
		Description:    "Checks local sensor provisioning state; cloud check-in is evaluated separately",
		Severity:       "high",
		Expected:       "Provisioned (State 1)",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "local CrowdStrike registry",
	}
	if status.ProvisioningState == 1 {
		result.Passed = true
		result.Actual = "Provisioned"
		result.Details = "Sensor has local provisioning evidence; recent cloud check-in requires central evidence"
	} else if status.ProvisioningState == 0 {
		result.Actual = "Not Provisioned"
		result.Details = "Sensor is not provisioned"
	} else if status.ProvisioningState == -1 {
		result.Status = "UNKNOWN"
		result.Actual = "Unknown"
		result.Details = "Could not determine provisioning state"
	} else {
		result.Actual = fmt.Sprintf("State %d", status.ProvisioningState)
		result.Details = fmt.Sprintf("Unexpected provisioning state: %d", status.ProvisioningState)
	}
	return result
}

func checkPreventionMode(_ *FalconStatus) CheckResult {
	return CheckResult{
		ControlID:      "CH-CRW-003",
		Name:           "Prevention Mode",
		Category:       "crowdstrike",
		Description:    "Checks that the effective Falcon prevention policy is not detect-only",
		Severity:       "critical",
		Expected:       "Prevention enabled in the effective central policy",
		Status:         "UNKNOWN",
		Actual:         "Not verifiable from local service or driver state",
		Details:        "Read-only Falcon host and effective-policy evidence is required",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "central_falcon_api_required",
	}
}

func checkSensorVersion(status *FalconStatus) CheckResult {
	result := CheckResult{
		ControlID:      "CH-CRW-004",
		Name:           "Sensor Version Detected",
		Category:       "crowdstrike",
		Description:    "Reports the local sensor version; support and currency require central inventory evidence",
		Severity:       "high",
		Expected:       "A readable sensor version",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "local registry or executable version",
	}
	if status.SensorVersion == "Unknown" || status.SensorVersion == "" {
		result.Status = "UNKNOWN"
		result.Actual = "Unknown"
		result.Details = "Could not determine sensor version"
		return result
	}
	result.Passed = true
	result.Actual = status.SensorVersion
	result.Details = "Version detected locally; no support or currency claim is made without central evidence"
	return result
}

func checkCloudConnectivity(status *FalconStatus) CheckResult {
	return CheckResult{
		ControlID:      "CH-CRW-005",
		Name:           "Recent Cloud Check-in",
		Category:       "crowdstrike",
		Description:    "Checks recent successful sensor check-in with the Falcon tenant",
		Severity:       "high",
		Expected:       "Recent central last-seen evidence within the configured threshold",
		Status:         "UNKNOWN",
		Actual:         "Not verifiable from local provisioning or service state",
		Details:        "Read-only Falcon host inventory evidence is required",
		Techniques:     []string{"T1562.004"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "central_falcon_api_required",
		Evidence:       map[string]interface{}{"local_service_running": status.ServiceRunning},
	}
}

func checkTamperProtection(status *FalconStatus) CheckResult {
	return CheckResult{
		ControlID:      "CH-CRW-006",
		Name:           "Tamper Protection",
		Category:       "crowdstrike",
		Description:    "Checks the effective tamper-protection policy for the sensor",
		Severity:       "critical",
		Expected:       "Enabled in the effective central policy",
		Status:         "UNKNOWN",
		Actual:         "Not verifiable from a running driver or service",
		Details:        "Read-only Falcon policy evidence is required",
		Techniques:     []string{"T1562.001", "T1070"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "central_falcon_api_required",
		Evidence:       map[string]interface{}{"local_service_running": status.ServiceRunning},
	}
}
