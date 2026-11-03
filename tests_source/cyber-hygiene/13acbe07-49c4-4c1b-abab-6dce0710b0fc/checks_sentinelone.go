//go:build windows

package main

import cyberhygiene "f0_library/tests_source/cyber-hygiene/shared"

func RunSentinelOneChecks() []cyberhygiene.ControlResult {
	services, queryErr := cyberhygiene.QueryWindowsServices([]string{"SentinelAgent"})
	controls := []cyberhygiene.ControlResult{
		cyberhygiene.NewControlResult("CH-S1-001", "SentinelOne Agent Service", "SentinelOne Local Agent Health", "critical", "SentinelAgent running with automatic start", "Win32_Service", []string{"T1562.001"}),
		cyberhygiene.NewControlResult("CH-S1-002", "SentinelOne Agent Version Detected", "SentinelOne Local Agent Health", "high", "A readable local agent version; no currency claim", "local executable version", []string{"T1562.001"}),
	}
	controls[0] = cyberhygiene.EvaluateWindowsService(controls[0], services, "SentinelAgent", true, queryErr)
	controls[1] = cyberhygiene.DetectWindowsFileVersion(controls[1], []string{
		`C:\Program Files\SentinelOne\Sentinel Agent\SentinelAgent.exe`,
		`C:\Program Files\SentinelOne\Sentinel Agent\SentinelStaticEngine.exe`,
	})
	controls = append(controls,
		cyberhygiene.CentralPolicyUnknown(cyberhygiene.NewControlResult("CH-S1-003", "SentinelOne Prevention Mode", "SentinelOne Central Policy", "critical", "Agent is active and effective mitigationMode is not detect-only", "central_sentinelone_api_required", []string{"T1562.001"}), "central_sentinelone_api_required"),
		cyberhygiene.CentralPolicyUnknown(cyberhygiene.NewControlResult("CH-S1-004", "SentinelOne Recent Cloud Check-in", "SentinelOne Central Policy", "high", "Agent networkStatus is connected and lastActiveDate is within the configured threshold", "central_sentinelone_api_required", []string{"T1562.001"}), "central_sentinelone_api_required"),
		cyberhygiene.CentralPolicyUnknown(cyberhygiene.NewControlResult("CH-S1-005", "SentinelOne Anti-Tampering", "SentinelOne Central Policy", "critical", "antiTamperingOn=true in the effective account/site/group policy", "central_sentinelone_api_required", []string{"T1562.001"}), "central_sentinelone_api_required"),
		cyberhygiene.CentralPolicyUnknown(cyberhygiene.NewControlResult("CH-S1-006", "SentinelOne Detection Engines", "SentinelOne Central Policy", "high", "Required detection engines are enabled in the effective policy", "central_sentinelone_api_required", []string{"T1562.001"}), "central_sentinelone_api_required"),
	)
	return controls
}
