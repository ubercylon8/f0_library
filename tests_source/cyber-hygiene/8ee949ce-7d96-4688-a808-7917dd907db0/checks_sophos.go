//go:build windows

package main

import (
	"fmt"

	cyberhygiene "f0_library/tests_source/cyber-hygiene/shared"
)

func RunSophosChecks() []cyberhygiene.ControlResult {
	services, queryErr := cyberhygiene.QueryWindowsServices([]string{"Sophos Endpoint Defense Service", "Sophos MCS Agent"})
	controls := []cyberhygiene.ControlResult{
		cyberhygiene.NewControlResult("CH-SOP-001", "Sophos Endpoint Defense Service", "Sophos Local Agent Health", "critical", "Running with automatic start", "Win32_Service", []string{"T1562.001"}),
		cyberhygiene.NewControlResult("CH-SOP-002", "Sophos Management Communication Service", "Sophos Local Agent Health", "critical", "Sophos MCS Agent running with automatic start", "Win32_Service", []string{"T1562.001"}),
		cyberhygiene.NewControlResult("CH-SOP-003", "Sophos Endpoint Version Detected", "Sophos Local Agent Health", "high", "A readable local endpoint version; no currency claim", "local executable version", []string{"T1562.001"}),
	}
	controls[0] = cyberhygiene.EvaluateWindowsService(controls[0], services, "Sophos Endpoint Defense Service", true, queryErr)
	controls[1] = cyberhygiene.EvaluateWindowsService(controls[1], services, "Sophos MCS Agent", true, queryErr)
	controls[2] = cyberhygiene.DetectWindowsFileVersion(controls[2], []string{
		`C:\Program Files\Sophos\Endpoint Defense\SophosEndpointDefense.exe`,
		`C:\Program Files\Sophos\Endpoint Defense\SEDService.exe`,
		`C:\Program Files\Sophos\Sophos Anti-Virus\SavService.exe`,
	})
	controls = append(controls,
		cyberhygiene.CentralPolicyUnknown(cyberhygiene.NewControlResult("CH-SOP-004", "Sophos Prevention Policy", "Sophos Central Policy", "critical", "Recommended prevention, behavioral, exploit, and credential-theft protections enabled in the effective computer/server policy", "central_sophos_api_required", []string{"T1562.001"}), "central_sophos_api_required"),
		cyberhygiene.CentralPolicyUnknown(cyberhygiene.NewControlResult("CH-SOP-005", "Sophos Recent Cloud Check-in", "Sophos Central Policy", "high", "Endpoint lastSeenAt is within the configured central threshold", "central_sophos_api_required", []string{"T1562.001"}), "central_sophos_api_required"),
		cyberhygiene.CentralPolicyUnknown(cyberhygiene.NewControlResult("CH-SOP-006", "Sophos Tamper Protection", "Sophos Central Policy", "critical", "tamperProtectionEnabled=true on a tamper-capable endpoint", "central_sophos_api_required", []string{"T1562.001"}), "central_sophos_api_required"),
	)
	for i := range controls {
		if controls[i].Details == "" {
			controls[i].Details = fmt.Sprintf("%s: %s", controls[i].ControlName, controls[i].Actual)
		}
	}
	return controls
}
