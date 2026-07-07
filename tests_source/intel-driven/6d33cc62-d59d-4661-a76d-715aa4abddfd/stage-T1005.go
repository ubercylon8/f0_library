// Stage 2 — Synthetic Canary PII Collection
// Technique: T1005 (Data from Local System)
//
// Generates a fake "customer database" of synthetic canary PII (see canary.go for
// the safety invariants) into ARTIFACT_DIR so DLP/EDR file telemetry can observe a
// sensitive-data collection event, then collects the records into an egress payload
// written to LOG_DIR/pii_payload.json for Stage 3 to exfiltrate. The ARTIFACT_DIR
// canary files are cleaned up at the end of the stage (spec §6.4).
//
// This stage never fabricates a "blocked" verdict: the only block path is positive
// os.Stat evidence that a written canary file was quarantined.
//
// Exit codes: 0 = executed, 126 = canary DB quarantined (positive evidence),
//             999 = prerequisite not met (ARTIFACT_DIR unwritable).

//go:build windows || linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID      = "6d33cc62-d59d-4661-a76d-715aa4abddfd"
	TECHNIQUE_ID   = "T1005"
	TECHNIQUE_NAME = "Synthetic Canary PII Collection"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const canaryCount = 25

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))

	code, detail := runStage()

	switch code {
	case StageSuccess:
		LogMessage("SUCCESS", TECHNIQUE_ID, detail)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", detail)
	case StageBlocked, StageQuarantined:
		LogMessage("WARN", TECHNIQUE_ID, detail)
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, detail)
	default:
		LogMessage("ERROR", TECHNIQUE_ID, detail)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", detail)
	}
	os.Exit(code)
}

func runStage() (int, string) {
	if err := os.MkdirAll(ARTIFACT_DIR, 0755); err != nil {
		return StageError, fmt.Sprintf("ARTIFACT_DIR %s not provisioned: %v", ARTIFACT_DIR, err)
	}
	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		return StageError, fmt.Sprintf("LOG_DIR %s not provisioned: %v", LOG_DIR, err)
	}

	marker := GenerateRunMarker()
	records := GenerateCanarySet(canaryCount, marker)
	Endpoint.Say("    [+] Generated %d synthetic canary PII records (marker=%s)", len(records), marker)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Generated %d synthetic canary records, marker=%s", len(records), marker))

	csvPath := filepath.Join(ARTIFACT_DIR, "customer_records.csv")
	jsonPath := filepath.Join(ARTIFACT_DIR, "customer_records.json")

	// Best-effort cleanup of ARTIFACT_DIR canary DB (spec §6.4).
	defer func() {
		os.Remove(csvPath)
		os.Remove(jsonPath)
	}()

	// Write the fake customer DB (CSV) into ARTIFACT_DIR.
	var b strings.Builder
	b.WriteString("full_name,email,ssn,pan,marker\n")
	for _, r := range records {
		b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s\n", r.FullName, r.Email, r.SSN, r.PAN, r.Marker))
	}
	if err := os.WriteFile(csvPath, []byte(b.String()), 0644); err != nil {
		return StageError, fmt.Sprintf("could not write canary customer DB: %v", err)
	}
	LogFileDropped("customer_records.csv", csvPath, int64(b.Len()), false)
	Endpoint.Say("    [+] Wrote canary customer DB to %s", csvPath)

	// Positive-evidence quarantine check (CLAUDE.md Rule 3/8).
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		return StageBlocked, "canary customer DB was quarantined (os.Stat confirms removal by a control)"
	}

	// Collect records into the egress payload for Stage 3 (T1005 -> staging for exfil).
	payload := PIIPayload{
		Marker:      marker,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Records:     records,
	}
	// Mirror the DB as JSON in ARTIFACT_DIR too (collection realism).
	if err := WritePayload(jsonPath, payload); err != nil {
		return StageError, fmt.Sprintf("could not write canary JSON DB: %v", err)
	}
	LogFileDropped("customer_records.json", jsonPath, 0, false)

	if err := WritePayload(PayloadPath(), payload); err != nil {
		return StageError, fmt.Sprintf("could not stage egress payload: %v", err)
	}
	Endpoint.Say("    [+] Collected canary PII into egress payload: %s", PayloadPath())
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Collected %d records into egress payload at %s", len(records), PayloadPath()))

	return StageSuccess, fmt.Sprintf("Collected %d synthetic canary records into egress payload (marker=%s)", len(records), marker)
}
