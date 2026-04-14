//go:build windows
// +build windows

/*
STAGE 4: Replication Through Removable Media — enumeration-only (T1091)

Simulates PROMPTFLUX's propagation reconnaissance: queries WMI Win32_LogicalDisk
for removable (DriveType=2) and network (DriveType=4) volumes and logs the
targets. THIS STAGE DELIBERATELY DOES NOT COPY the dropper to any discovered
target. Enumeration is the detection signal; the copy itself is out of scope
because a real propagation primitive would require handling file writes to
arbitrary external media / shares in a lab environment.

If WMI is unavailable (service stopped, WMI queries blocked, script host
constrained) the stage returns exit 126 (blocked) — this is the defence
signal: a hardened endpoint that has disabled WMI for non-admin callers
or that has a policy blocking Win32_LogicalDisk enumeration.

Detection opportunities:
  - Win32_LogicalDisk query from a non-admin-tool process (SCCM, MDT, etc.)
  - wmic.exe spawned with "logicaldisk" argument from c:\F0 binary
  - PowerShell Get-WmiObject Win32_LogicalDisk from a stage binary

Implementation note: we use wmic.exe as the query driver rather than a
Go WMI library to avoid pulling in CGO / ole32 dependencies. wmic.exe is
itself a GTIG-documented PROMPTFLUX living-off-the-land binary.
*/

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	TEST_UUID      = "0a749b39-409e-46f5-9338-ee886b439cfa"
	TECHNIQUE_ID   = "T1091"
	TECHNIQUE_NAME = "Replication Through Removable Media (enum-only)"
	STAGE_ID       = 4

	PROPAGATION_LOG = `c:\F0\stage4_propagation_targets.json`
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

type DriveTarget struct {
	DeviceID   string `json:"deviceId"`
	DriveType  int    `json:"driveType"`
	DriveLabel string `json:"driveLabel"`
	VolumeName string `json:"volumeName,omitempty"`
}

type PropagationReport struct {
	Timestamp   string        `json:"timestamp"`
	Query       string        `json:"query"`
	Mechanism   string        `json:"mechanism"`
	TargetCount int           `json:"targetCount"`
	Targets     []DriveTarget `json:"targets"`
	Note        string        `json:"note"`
}

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting PROMPTFLUX stage-4 (propagation enumeration via WMI)")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "WMI Win32_LogicalDisk enumeration — removable + network drives")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))

		exitCode := determineExitCode(err)
		if exitCode == StageBlocked || exitCode == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] Propagation enumeration complete\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Stage-4 enumeration complete")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "WMI Win32_LogicalDisk enumerated; targets logged")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Query via wmic.exe. Args: logicaldisk get DeviceID,DriveType,VolumeName /format:csv
	// The /format:csv output is column-header-prefixed; we parse it line by line.
	cmd := exec.Command("wmic.exe", "logicaldisk", "get", "DeviceID,DriveType,VolumeName", "/format:csv")
	cmd.Env = os.Environ()

	startTime := time.Now()
	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime)

	if err != nil {
		// wmic missing or access denied = the defence signal. Exit 126.
		return fmt.Errorf("wmic logicaldisk query permission denied: %v (output: %s)", err, truncate(string(output), 200))
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("wmic query returned %d bytes in %v", len(output), duration))

	// Empty output on a tamper-protected / policy-blocked WMI = blocked.
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return fmt.Errorf("wmic query returned empty output — permission denied by policy")
	}

	targets, parseErr := parseWmicLogicalDisk(string(output))
	if parseErr != nil {
		return fmt.Errorf("wmic output parse failed: %v", parseErr)
	}

	// Keep only removable (2) and network (4) drives — those are the
	// propagation candidates in a real PROMPTFLUX operator playbook.
	filtered := make([]DriveTarget, 0, len(targets))
	for _, t := range targets {
		if t.DriveType == 2 || t.DriveType == 4 {
			if t.DriveType == 2 {
				t.DriveLabel = "removable"
			} else {
				t.DriveLabel = "network"
			}
			filtered = append(filtered, t)
		}
	}

	report := PropagationReport{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Query:       "SELECT DeviceID, DriveType, VolumeName FROM Win32_LogicalDisk WHERE DriveType = 2 OR DriveType = 4",
		Mechanism:   "wmic.exe logicaldisk get ... /format:csv",
		TargetCount: len(filtered),
		Targets:     filtered,
		Note:        "Enumeration-only simulation — NO copy performed. A real PROMPTFLUX propagation primitive would write a copy of crypted_ScreenRec_webinstall.vbs to each DeviceID\\<filename>. F0RT1KA explicitly stops before that step to keep the test safe in a lab.",
	}

	reportBytes, marshalErr := json.MarshalIndent(report, "", "  ")
	if marshalErr != nil {
		return fmt.Errorf("propagation report marshal: %v", marshalErr)
	}

	if err := os.WriteFile(PROPAGATION_LOG, reportBytes, 0644); err != nil {
		return fmt.Errorf("propagation log write: %v", err)
	}
	LogFileDropped("stage4_propagation_targets.json", PROPAGATION_LOG, int64(len(reportBytes)), false)

	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Propagation enumeration: found %d target(s) (removable+network)", len(filtered)))
	for _, t := range filtered {
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("  target: DeviceID=%s DriveType=%d (%s) Volume=%q", t.DeviceID, t.DriveType, t.DriveLabel, t.VolumeName))
	}

	return nil
}

// parseWmicLogicalDisk parses the /format:csv output of
// "wmic.exe logicaldisk get DeviceID,DriveType,VolumeName /format:csv".
// The output is: Node,DeviceID,DriveType,VolumeName with CRLF line endings.
func parseWmicLogicalDisk(out string) ([]DriveTarget, error) {
	// Normalize line endings.
	out = strings.ReplaceAll(out, "\r\n", "\n")
	out = strings.ReplaceAll(out, "\r", "\n")
	lines := strings.Split(out, "\n")

	headerIdx := -1
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(strings.ToLower(line)), "node,") {
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 {
		return nil, fmt.Errorf("no CSV header found in wmic output")
	}
	headers := strings.Split(strings.TrimSpace(lines[headerIdx]), ",")
	colIdx := func(name string) int {
		for i, h := range headers {
			if strings.EqualFold(strings.TrimSpace(h), name) {
				return i
			}
		}
		return -1
	}
	devCol := colIdx("DeviceID")
	typeCol := colIdx("DriveType")
	volCol := colIdx("VolumeName")
	if devCol < 0 || typeCol < 0 {
		return nil, fmt.Errorf("required CSV columns missing")
	}

	targets := make([]DriveTarget, 0)
	for i := headerIdx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) <= typeCol {
			continue
		}

		var driveType int
		if _, scanErr := fmt.Sscanf(strings.TrimSpace(fields[typeCol]), "%d", &driveType); scanErr != nil {
			continue
		}
		t := DriveTarget{
			DeviceID:  strings.TrimSpace(fields[devCol]),
			DriveType: driveType,
		}
		if volCol >= 0 && volCol < len(fields) {
			t.VolumeName = strings.TrimSpace(fields[volCol])
		}
		targets = append(targets, t)
	}
	return targets, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ==============================================================================
// EXIT CODE — blame-free (Rule 1)
// ==============================================================================
//
// Stage 4 uses a slightly broader "blocked" interpretation per Q10: WMI
// permission denial, WMI empty-output, or wmic.exe missing all map to 126.
// Anything else maps to 999.

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available", "cannot find"}) {
		return StageError
	}
	return StageError
}

func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if containsCI(s, substr) {
			return true
		}
	}
	return false
}

func containsCI(s, substr string) bool {
	return len(s) >= len(substr) && indexIgnoreCase(s, substr) >= 0
}

func indexIgnoreCase(s, substr string) int {
	s = toLowerStr(s)
	substr = toLowerStr(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func toLowerStr(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}
