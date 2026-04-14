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

v1.2: Native WMI via COM (IWbemLocator through github.com/StackExchange/wmi).
Removed wmic.exe shellout because Microsoft removed wmic.exe from Windows 11
22H2+ default images (per Microsoft deprecation notice, Jan 2024). Native COM
is also more authentic to how real PROMPTFLUX operates — real malware uses
IWbemLocator, not the legacy wmic.exe CLI wrapper.

Exit-code signalling:
  - 0   — WMI query succeeded, targets enumerated & logged
  - 126 — WMI query actively blocked by policy (WDAC, registry hardening,
          AppLocker restriction on COM servers)
  - 999 — WMI service unavailable / not running / prerequisite missing
          (NOT a defence signal — a genuine test-infra failure)

Detection opportunities:
  - IWbemServices::ExecQuery of Win32_LogicalDisk from a non-admin-tool process
  - Unsigned/unusual caller invoking wmi via COM (WmiPrvSE.exe spawning under
    a c:\F0 binary parent)
  - Win32_LogicalDisk query immediately followed by file writes to DeviceID
*/

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/StackExchange/wmi"
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

// Win32_LogicalDisk WMI class — field names must match the CIM class exactly.
// DriveType values (MSDN):
//   0 = Unknown, 1 = NoRootDirectory, 2 = Removable, 3 = LocalDisk,
//   4 = NetworkDrive, 5 = CompactDisc, 6 = RAMDisk
type Win32_LogicalDisk struct {
	DeviceID   string
	DriveType  uint32
	VolumeName string
}

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

	LogMessage("INFO", TECHNIQUE_ID, "Starting PROMPTFLUX stage-4 (propagation enumeration via native WMI COM)")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "WMI Win32_LogicalDisk enumeration via IWbemLocator — removable + network drives")

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
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "WMI Win32_LogicalDisk enumerated via COM; targets logged")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Native WMI COM query via IWbemLocator -> IWbemServices::ExecQuery.
	// This is how real PROMPTFLUX (and most commodity malware) enumerates
	// drives — not via the deprecated wmic.exe CLI wrapper.
	query := "SELECT DeviceID, DriveType, VolumeName FROM Win32_LogicalDisk WHERE DriveType = 2 OR DriveType = 4"

	startTime := time.Now()

	var disks []Win32_LogicalDisk
	queryErr := wmi.Query(query, &disks)
	duration := time.Since(startTime)

	if queryErr != nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("wmi query returned error after %v: %v", duration, queryErr))
		return fmt.Errorf("wmi query Win32_LogicalDisk failed: %w", queryErr)
	}

	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("wmi query returned %d matching disk(s) in %v", len(disks), duration))

	// Convert to the report structure. All entries are already DriveType 2 or 4
	// per the WHERE clause, but we label them defensively.
	targets := make([]DriveTarget, 0, len(disks))
	for _, d := range disks {
		t := DriveTarget{
			DeviceID:   d.DeviceID,
			DriveType:  int(d.DriveType),
			VolumeName: d.VolumeName,
		}
		switch d.DriveType {
		case 2:
			t.DriveLabel = "removable"
		case 4:
			t.DriveLabel = "network"
		default:
			t.DriveLabel = "other"
		}
		targets = append(targets, t)
	}

	report := PropagationReport{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Query:       query,
		Mechanism:   "native WMI COM via IWbemLocator (github.com/StackExchange/wmi)",
		TargetCount: len(targets),
		Targets:     targets,
		Note:        "Enumeration-only simulation — NO copy performed. A real PROMPTFLUX propagation primitive would write a copy of crypted_ScreenRec_webinstall.vbs to each DeviceID\\<filename>. F0RT1KA explicitly stops before that step to keep the test safe in a lab.",
	}

	reportBytes, marshalErr := json.MarshalIndent(report, "", "  ")
	if marshalErr != nil {
		return fmt.Errorf("propagation report marshal failed: %w", marshalErr)
	}

	if err := os.WriteFile(PROPAGATION_LOG, reportBytes, 0644); err != nil {
		return fmt.Errorf("propagation log write failed: %w", err)
	}
	LogFileDropped("stage4_propagation_targets.json", PROPAGATION_LOG, int64(len(reportBytes)), false)

	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Propagation enumeration: found %d target(s) (removable+network)", len(targets)))
	for _, t := range targets {
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("  target: DeviceID=%s DriveType=%d (%s) Volume=%q",
				t.DeviceID, t.DriveType, t.DriveLabel, t.VolumeName))
	}

	return nil
}

// ==============================================================================
// EXIT CODE — blame-free (Rule 1)
// ==============================================================================
//
// With native WMI COM, the error paths are now distinguishable:
//
//   - A WMI service that's stopped / unavailable / not registered returns COM
//     errors like "Invalid class", "Provider load failure", "Invalid namespace",
//     or "RPC server is unavailable" → prereq not met → 999 (test-infra error).
//
//   - A policy/WDAC block on the WMI COM server returns errors like "E_ACCESSDENIED"
//     or wbem "WBEM_E_ACCESS_DENIED" → genuine defence signal → 126 (blocked).
//
// We keep the matcher narrow: only the ACCESS-class errors map to 126. Everything
// else (query syntax error, unavailable service, unknown class) is 999. The
// wrapper messages in performTechnique() describe the OPERATION that failed,
// never the cause — so this matcher only fires on error strings that the WMI
// runtime itself produced (via %w unwrap), not on our wrapper text.

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	// Defence signals from the WMI runtime. These are errors the COM/wbem
	// layer itself emits when a policy or ACL refuses the query.
	if containsAny(errStr, []string{
		"wbem_e_access_denied",
		"e_accessdenied",
		"access is denied",  // generic Windows error text from wbem
		"access denied",     // same, short form
	}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	// Everything else — WMI service stopped, namespace missing, class unknown,
	// RPC unavailable, query syntax — is a prereq failure, not a defence signal.
	return StageError
}

func containsAny(s string, substrings []string) bool {
	lower := strings.ToLower(s)
	for _, substr := range substrings {
		if strings.Contains(lower, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}
