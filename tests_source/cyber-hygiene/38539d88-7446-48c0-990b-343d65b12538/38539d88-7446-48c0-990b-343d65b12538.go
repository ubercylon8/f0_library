//go:build windows
// +build windows

/*
ID: 38539d88-7446-48c0-990b-343d65b12538
NAME: Network Protocol Hardening Validator
TECHNIQUES: T1557.001, T1040, T1557
UNIT: response
CREATED: 2026-01-11
*/

// Network Protocol Hardening Validator - Cyber Hygiene Test
//
// This test validates that dangerous legacy network protocols are disabled
// to prevent credential harvesting attacks. Tools like Responder exploit
// LLMNR and NetBIOS broadcast protocols to intercept authentication requests.
//
// Configuration Checks:
// 1. LLMNR Disabled - Prevents LLMNR poisoning attacks
// 2. NetBIOS Disabled - Prevents NBT-NS poisoning attacks (all adapters)
// 3. WPAD Mitigated - Prevents WPAD proxy attacks
//
// Exit Codes:
// - 126: All checks pass (COMPLIANT)
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
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID = "38539d88-7446-48c0-990b-343d65b12538"
	TEST_NAME = "Network Protocol Hardening Validator"
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

// AdapterNetBIOSResult represents NetBIOS status for a single adapter
type AdapterNetBIOSResult struct {
	AdapterName    string
	InterfaceGUID  string
	NetBIOSOption  int
	Compliant      bool
	StatusText     string
}

// test performs the network protocol hardening validation
func test() {
	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "credential_access",
		Severity:   "high",
		Techniques: []string{"T1557.001", "T1040", "T1557"},
		Tactics:    []string{"credential-access", "collection"},
		Score:      7.5,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 2.0,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"cyber-hygiene", "network-hardening", "llmnr", "netbios", "wpad", "responder"},
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

	// Phase 1: LLMNR Check
	LogPhaseStart(1, "LLMNR Check")
	llmnrResult := checkLLMNRDisabled()
	logCheckResult(1, llmnrResult)
	if llmnrResult.Compliant {
		LogPhaseEnd(1, "success", "LLMNR is disabled")
	} else {
		LogPhaseEnd(1, "failed", "LLMNR is not disabled")
	}

	// Phase 2: NetBIOS Check (all adapters)
	LogPhaseStart(2, "NetBIOS Check")
	netbiosResult, adapterResults := checkNetBIOSDisabled()
	logCheckResult(2, netbiosResult)
	// Log individual adapter results
	for _, adapter := range adapterResults {
		LogMessage("INFO", "NetBIOS", fmt.Sprintf("Adapter: %s | GUID: %s | Option: %d | Status: %s",
			adapter.AdapterName, adapter.InterfaceGUID, adapter.NetBIOSOption, adapter.StatusText))
	}
	if netbiosResult.Compliant {
		LogPhaseEnd(2, "success", "NetBIOS is disabled on all adapters")
	} else {
		LogPhaseEnd(2, "failed", "NetBIOS is not disabled on all adapters")
	}

	// Phase 3: WPAD Check
	LogPhaseStart(3, "WPAD Check")
	wpadResult := checkWPADMitigated()
	logCheckResult(3, wpadResult)
	if wpadResult.Compliant {
		LogPhaseEnd(3, "success", "WPAD is mitigated")
	} else {
		LogPhaseEnd(3, "failed", "WPAD is not mitigated")
	}

	// Phase 4: Determine Overall Compliance
	LogPhaseStart(4, "Compliance Determination")

	allCompliant := llmnrResult.Compliant && netbiosResult.Compliant && wpadResult.Compliant
	passedChecks := 0
	if llmnrResult.Compliant {
		passedChecks++
	}
	if netbiosResult.Compliant {
		passedChecks++
	}
	if wpadResult.Compliant {
		passedChecks++
	}

	// Generate summary
	Endpoint.Say("")
	Endpoint.Say("================================================================================")
	Endpoint.Say("                NETWORK PROTOCOL HARDENING VALIDATION SUMMARY")
	Endpoint.Say("================================================================================")
	Endpoint.Say("")
	printCheckSummary("LLMNR Disabled", llmnrResult)
	printCheckSummary("NetBIOS Disabled (All Adapters)", netbiosResult)
	printCheckSummary("WPAD Mitigated", wpadResult)
	Endpoint.Say("")

	// Print detailed NetBIOS per-adapter results
	if len(adapterResults) > 0 {
		Endpoint.Say("NetBIOS Per-Adapter Status:")
		for _, adapter := range adapterResults {
			status := "DISABLED"
			if !adapter.Compliant {
				status = "ENABLED"
			}
			Endpoint.Say("  [%s] %s (Option=%d)", status, adapter.AdapterName, adapter.NetBIOSOption)
		}
		Endpoint.Say("")
	}

	Endpoint.Say("--------------------------------------------------------------------------------")
	Endpoint.Say("Overall: %d/3 checks passed", passedChecks)

	if allCompliant {
		Endpoint.Say("")
		Endpoint.Say("[COMPLIANT] All network protocol hardening checks passed.")
		Endpoint.Say("            System is protected against broadcast poisoning attacks.")
		LogMessage("SUCCESS", "Compliance", "All 3 network hardening checks passed - system is COMPLIANT")
		LogPhaseEnd(4, "success", fmt.Sprintf("All checks passed (%d/3)", passedChecks))
		SaveLog(126, "System is COMPLIANT - all dangerous protocols are disabled")
		Endpoint.Stop(126)
	} else {
		Endpoint.Say("")
		Endpoint.Say("[NON-COMPLIANT] Network protocol hardening is incomplete.")
		Endpoint.Say("                System may be vulnerable to Responder-style attacks.")
		Endpoint.Say("")
		Endpoint.Say("Remediation Steps:")
		if !llmnrResult.Compliant {
			Endpoint.Say("  - Disable LLMNR via GPO or registry:")
			Endpoint.Say("    GPO: Computer Configuration > Administrative Templates > Network > DNS Client")
			Endpoint.Say("         > Turn off multicast name resolution = Enabled")
			Endpoint.Say("    Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast = 0")
		}
		if !netbiosResult.Compliant {
			Endpoint.Say("  - Disable NetBIOS on all network adapters:")
			Endpoint.Say("    Network Adapter Properties > TCP/IPv4 > Advanced > WINS tab")
			Endpoint.Say("         > Disable NetBIOS over TCP/IP")
			Endpoint.Say("    Or set registry: NetBT\\Parameters\\Interfaces\\Tcpip_*\\NetbiosOptions = 2")
		}
		if !wpadResult.Compliant {
			Endpoint.Say("  - Mitigate WPAD via GPO or registry:")
			Endpoint.Say("    GPO: Disable 'Automatically detect settings' in IE/Edge")
			Endpoint.Say("    Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WpadOverride = 1")
			Endpoint.Say("    Or disable WinHttpAutoProxySvc service")
		}

		LogMessage("WARNING", "Compliance", fmt.Sprintf("Only %d/3 checks passed - system is NON-COMPLIANT", passedChecks))
		LogPhaseEnd(4, "failed", fmt.Sprintf("Not all checks passed (%d/3)", passedChecks))
		SaveLog(101, fmt.Sprintf("System is NON-COMPLIANT - only %d/3 network hardening checks passed", passedChecks))
		Endpoint.Stop(101)
	}
}

// checkLLMNRDisabled checks if Link-Local Multicast Name Resolution is disabled
func checkLLMNRDisabled() CheckResult {
	result := CheckResult{
		Name:        "LLMNR Disabled",
		Description: "Link-Local Multicast Name Resolution disabled via GPO",
		Expected:    "EnableMulticast = 0",
	}

	Endpoint.Say("[*] Checking LLMNR status...")
	LogMessage("INFO", "LLMNR", "Checking HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast")

	// Open the DNS Client policy registry key
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, registry.QUERY_VALUE)
	if err != nil {
		// Key doesn't exist - policy not configured (LLMNR is enabled by default)
		result.Value = "Policy not configured"
		result.Details = "DNSClient GPO key does not exist - LLMNR is enabled by default"
		result.Compliant = false
		Endpoint.Say("    [!] LLMNR policy not configured (enabled by default)")
		LogMessage("WARNING", "LLMNR", result.Details)
		return result
	}
	defer key.Close()

	// Read EnableMulticast value
	value, _, err := key.GetIntegerValue("EnableMulticast")
	if err != nil {
		result.Value = "Value not set"
		result.Details = "EnableMulticast value does not exist in policy - LLMNR is enabled by default"
		result.Compliant = false
		Endpoint.Say("    [!] EnableMulticast value not set (LLMNR enabled by default)")
		LogMessage("WARNING", "LLMNR", result.Details)
		return result
	}

	result.Value = fmt.Sprintf("%d", value)

	// EnableMulticast = 0 means LLMNR is disabled
	if value == 0 {
		result.Compliant = true
		result.Details = "LLMNR is disabled via Group Policy"
		Endpoint.Say("    [+] LLMNR is DISABLED (EnableMulticast=%d)", value)
		LogMessage("SUCCESS", "LLMNR", result.Details)
	} else {
		result.Compliant = false
		result.Details = fmt.Sprintf("LLMNR is enabled (EnableMulticast=%d, expected 0)", value)
		Endpoint.Say("    [-] LLMNR is ENABLED (EnableMulticast=%d)", value)
		LogMessage("WARNING", "LLMNR", result.Details)
	}

	return result
}

// checkNetBIOSDisabled checks if NetBIOS over TCP/IP is disabled on ALL network adapters
func checkNetBIOSDisabled() (CheckResult, []AdapterNetBIOSResult) {
	result := CheckResult{
		Name:        "NetBIOS Disabled",
		Description: "NetBIOS over TCP/IP disabled on all network adapters",
		Expected:    "NetbiosOptions = 2 on all adapters",
	}

	adapterResults := []AdapterNetBIOSResult{}

	Endpoint.Say("[*] Checking NetBIOS status on all adapters...")
	LogMessage("INFO", "NetBIOS", "Enumerating HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces")

	// Open the NetBT Parameters Interfaces key to enumerate all adapters
	interfacesKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		result.Value = "Key not accessible"
		result.Details = fmt.Sprintf("Failed to open NetBT Interfaces key: %v", err)
		result.Compliant = false
		Endpoint.Say("    [!] Failed to access NetBT Interfaces registry key: %v", err)
		LogMessage("ERROR", "NetBIOS", result.Details)
		return result, adapterResults
	}
	defer interfacesKey.Close()

	// Enumerate all Tcpip_* subkeys (each represents a network adapter)
	subkeys, err := interfacesKey.ReadSubKeyNames(-1)
	if err != nil {
		result.Value = "Enumeration failed"
		result.Details = fmt.Sprintf("Failed to enumerate adapter interfaces: %v", err)
		result.Compliant = false
		Endpoint.Say("    [!] Failed to enumerate adapter interfaces: %v", err)
		LogMessage("ERROR", "NetBIOS", result.Details)
		return result, adapterResults
	}

	// Filter to only Tcpip_ interfaces
	tcpipInterfaces := []string{}
	for _, subkey := range subkeys {
		if strings.HasPrefix(subkey, "Tcpip_") {
			tcpipInterfaces = append(tcpipInterfaces, subkey)
		}
	}

	if len(tcpipInterfaces) == 0 {
		result.Value = "No adapters found"
		result.Details = "No TCP/IP network adapters found"
		result.Compliant = true // No adapters = nothing to check
		Endpoint.Say("    [!] No TCP/IP network adapters found")
		LogMessage("WARNING", "NetBIOS", result.Details)
		return result, adapterResults
	}

	Endpoint.Say("    Found %d TCP/IP network adapter(s)", len(tcpipInterfaces))
	LogMessage("INFO", "NetBIOS", fmt.Sprintf("Found %d TCP/IP adapters", len(tcpipInterfaces)))

	// Check each adapter
	allDisabled := true
	enabledCount := 0
	disabledCount := 0

	for _, interfaceKey := range tcpipInterfaces {
		adapterPath := `SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\` + interfaceKey
		adapterKey, err := registry.OpenKey(registry.LOCAL_MACHINE, adapterPath, registry.QUERY_VALUE)

		adapterResult := AdapterNetBIOSResult{
			InterfaceGUID: interfaceKey,
			AdapterName:   getAdapterFriendlyName(interfaceKey),
		}

		if err != nil {
			adapterResult.NetBIOSOption = -1
			adapterResult.Compliant = false
			adapterResult.StatusText = fmt.Sprintf("Cannot read: %v", err)
			allDisabled = false
			enabledCount++
			LogMessage("WARNING", "NetBIOS", fmt.Sprintf("Cannot read adapter %s: %v", interfaceKey, err))
		} else {
			netbiosOption, _, err := adapterKey.GetIntegerValue("NetbiosOptions")
			adapterKey.Close()

			if err != nil {
				// Value doesn't exist - defaults to 0 (DHCP default)
				adapterResult.NetBIOSOption = 0
				adapterResult.Compliant = false
				adapterResult.StatusText = "Not configured (default/DHCP)"
				allDisabled = false
				enabledCount++
			} else {
				adapterResult.NetBIOSOption = int(netbiosOption)
				// NetBIOS Options: 0 = Default (DHCP), 1 = Enabled, 2 = Disabled
				if netbiosOption == 2 {
					adapterResult.Compliant = true
					adapterResult.StatusText = "Disabled"
					disabledCount++
				} else {
					adapterResult.Compliant = false
					if netbiosOption == 0 {
						adapterResult.StatusText = "Default (DHCP - may be enabled)"
					} else {
						adapterResult.StatusText = "Explicitly Enabled"
					}
					allDisabled = false
					enabledCount++
				}
			}
		}

		adapterResults = append(adapterResults, adapterResult)
		Endpoint.Say("    - %s: Option=%d (%s)", adapterResult.AdapterName, adapterResult.NetBIOSOption, adapterResult.StatusText)
	}

	// Set overall result
	result.Value = fmt.Sprintf("%d/%d adapters disabled", disabledCount, len(tcpipInterfaces))

	if allDisabled {
		result.Compliant = true
		result.Details = fmt.Sprintf("NetBIOS is disabled on all %d adapters", len(tcpipInterfaces))
		Endpoint.Say("    [+] NetBIOS is DISABLED on all adapters")
		LogMessage("SUCCESS", "NetBIOS", result.Details)
	} else {
		result.Compliant = false
		result.Details = fmt.Sprintf("NetBIOS is enabled/default on %d of %d adapters", enabledCount, len(tcpipInterfaces))
		Endpoint.Say("    [-] NetBIOS is NOT DISABLED on all adapters (%d enabled/default)", enabledCount)
		LogMessage("WARNING", "NetBIOS", result.Details)
	}

	return result, adapterResults
}

// getAdapterFriendlyName attempts to get a friendly name for the network adapter
func getAdapterFriendlyName(interfaceKey string) string {
	// Extract GUID from Tcpip_{GUID}
	if !strings.HasPrefix(interfaceKey, "Tcpip_") {
		return interfaceKey
	}

	guid := strings.TrimPrefix(interfaceKey, "Tcpip_")

	// Try to look up the friendly name from network adapter configuration
	adapterPath := `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\` + guid + `\Connection`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, adapterPath, registry.QUERY_VALUE)
	if err != nil {
		return guid // Return GUID if we can't find friendly name
	}
	defer key.Close()

	name, _, err := key.GetStringValue("Name")
	if err != nil {
		return guid
	}

	return name
}

// checkWPADMitigated checks if Web Proxy Auto-Discovery is mitigated
func checkWPADMitigated() CheckResult {
	result := CheckResult{
		Name:        "WPAD Mitigated",
		Description: "Web Proxy Auto-Discovery is disabled or mitigated",
		Expected:    "WpadOverride = 1 or WinHttpAutoProxySvc disabled",
	}

	Endpoint.Say("[*] Checking WPAD mitigation status...")
	LogMessage("INFO", "WPAD", "Checking WPAD mitigation via registry and service status")

	// Method 1: Check WpadOverride registry key
	wpadOverrideSet := checkWpadOverrideRegistry()

	// Method 2: Check if WinHttpAutoProxySvc service is disabled
	winHttpServiceDisabled := checkWinHttpAutoProxySvcDisabled()

	// Method 3: Check if auto-detect is disabled in Internet Settings
	autoDetectDisabled := checkAutoDetectDisabled()

	// Save diagnostic output
	saveWPADDiagnostics(wpadOverrideSet, winHttpServiceDisabled, autoDetectDisabled)

	// Any of these mitigations is sufficient
	if wpadOverrideSet || winHttpServiceDisabled || autoDetectDisabled {
		result.Compliant = true
		mitigations := []string{}
		if wpadOverrideSet {
			mitigations = append(mitigations, "WpadOverride=1")
		}
		if winHttpServiceDisabled {
			mitigations = append(mitigations, "WinHttpAutoProxySvc disabled")
		}
		if autoDetectDisabled {
			mitigations = append(mitigations, "AutoDetect disabled")
		}
		result.Value = strings.Join(mitigations, ", ")
		result.Details = fmt.Sprintf("WPAD is mitigated via: %s", result.Value)
		Endpoint.Say("    [+] WPAD is MITIGATED (%s)", result.Value)
		LogMessage("SUCCESS", "WPAD", result.Details)
	} else {
		result.Compliant = false
		result.Value = "No mitigations found"
		result.Details = "WPAD auto-discovery may be active - none of the standard mitigations detected"
		Endpoint.Say("    [-] WPAD mitigations NOT FOUND")
		LogMessage("WARNING", "WPAD", result.Details)
	}

	return result
}

// checkWpadOverrideRegistry checks if WpadOverride registry value is set
func checkWpadOverrideRegistry() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		LogMessage("INFO", "WPAD", "Internet Settings key not accessible")
		return false
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("WpadOverride")
	if err != nil {
		LogMessage("INFO", "WPAD", "WpadOverride value not set")
		return false
	}

	if value == 1 {
		LogMessage("INFO", "WPAD", "WpadOverride is set to 1 (WPAD disabled)")
		return true
	}

	LogMessage("INFO", "WPAD", fmt.Sprintf("WpadOverride is %d (not mitigated)", value))
	return false
}

// checkWinHttpAutoProxySvcDisabled checks if the WinHTTP Auto-Proxy service is disabled
func checkWinHttpAutoProxySvcDisabled() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc`, registry.QUERY_VALUE)
	if err != nil {
		LogMessage("INFO", "WPAD", "WinHttpAutoProxySvc service key not found")
		return false // Service doesn't exist or can't be read
	}
	defer key.Close()

	startType, _, err := key.GetIntegerValue("Start")
	if err != nil {
		LogMessage("INFO", "WPAD", "Cannot read WinHttpAutoProxySvc Start type")
		return false
	}

	// Start type: 4 = Disabled, 3 = Manual, 2 = Automatic
	if startType == 4 {
		LogMessage("INFO", "WPAD", "WinHttpAutoProxySvc service is disabled (Start=4)")
		return true
	}

	LogMessage("INFO", "WPAD", fmt.Sprintf("WinHttpAutoProxySvc Start type is %d (not disabled)", startType))
	return false
}

// checkAutoDetectDisabled checks if automatic proxy detection is disabled in Internet Settings
func checkAutoDetectDisabled() bool {
	// Check HKCU first (user-level setting)
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections`, registry.QUERY_VALUE)
	if err != nil {
		LogMessage("INFO", "WPAD", "Internet Settings Connections key not accessible")
		return false
	}
	defer key.Close()

	// The DefaultConnectionSettings binary value contains proxy settings
	// Byte 8 contains flags: bit 3 (0x08) = Auto-detect enabled
	data, _, err := key.GetBinaryValue("DefaultConnectionSettings")
	if err != nil {
		LogMessage("INFO", "WPAD", "DefaultConnectionSettings not found")
		return false
	}

	if len(data) >= 9 {
		// Check if auto-detect flag (0x08) is NOT set
		if data[8]&0x08 == 0 {
			LogMessage("INFO", "WPAD", "Auto-detect is disabled in DefaultConnectionSettings")
			return true
		}
		LogMessage("INFO", "WPAD", "Auto-detect is enabled in DefaultConnectionSettings")
	}

	return false
}

// saveWPADDiagnostics saves WPAD diagnostic information
func saveWPADDiagnostics(wpadOverride, winHttpDisabled, autoDetectDisabled bool) {
	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)

	var buf bytes.Buffer
	buf.WriteString("=== WPAD Diagnostic Information ===\n\n")
	buf.WriteString(fmt.Sprintf("WpadOverride Registry: %v\n", wpadOverride))
	buf.WriteString(fmt.Sprintf("WinHttpAutoProxySvc Disabled: %v\n", winHttpDisabled))
	buf.WriteString(fmt.Sprintf("AutoDetect Disabled: %v\n", autoDetectDisabled))
	buf.WriteString(fmt.Sprintf("\nTimestamp: %s\n", time.Now().Format(time.RFC3339)))

	outputPath := filepath.Join(targetDir, "wpad_diagnostics.txt")
	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		LogMessage("WARNING", "WPAD", fmt.Sprintf("Failed to save diagnostics: %v", err))
	} else {
		LogMessage("INFO", "WPAD", fmt.Sprintf("Diagnostics saved to: %s", outputPath))
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
	Endpoint.Say("[%s] %-45s Value: %s", status, name, result.Value)
}

// main is the entry point
func main() {
	Endpoint.Say("================================================================================")
	Endpoint.Say("  F0RT1KA CYBER HYGIENE TEST: Network Protocol Hardening Validator")
	Endpoint.Say("  Test ID: %s", TEST_UUID)
	Endpoint.Say("================================================================================")
	Endpoint.Say("")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("This is a READ-ONLY configuration validation test.")
	Endpoint.Say("")
	Endpoint.Say("Validates that dangerous legacy protocols are disabled:")
	Endpoint.Say("  - LLMNR (Link-Local Multicast Name Resolution)")
	Endpoint.Say("  - NetBIOS over TCP/IP (all network adapters)")
	Endpoint.Say("  - WPAD (Web Proxy Auto-Discovery)")
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
