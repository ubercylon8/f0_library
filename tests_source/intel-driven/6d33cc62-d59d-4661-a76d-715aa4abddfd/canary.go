// canary.go — synthetic canary-PII generation, shared by Stage 2 (collection)
// and Stage 3 (exfiltration fallback). NO build tag, NO main() — this file is
// listed explicitly in the stage-2 and stage-3 build commands only.
//
// SAFETY INVARIANT (spec §6.1): every record is format/checksum-valid but
// corresponds to NO real person:
//   - SSNs use the SSA advertising-reserved range 987-65-4320..987-65-4329,
//     which is structurally valid yet has NEVER been issued to anyone.
//   - PANs use the 4242 test BIN with a correctly-computed Luhn check digit
//     (a well-known payment-processor test range, not a real card).
//   - Emails use the RFC 2606 reserved .invalid TLD (non-routable, no real inbox).
// Every record is tagged with a run-unique marker so any downstream sighting is
// traceable back to this test run.

package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"
)

// CanaryRecord is one synthetic customer record.
type CanaryRecord struct {
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	SSN      string `json:"ssn"`
	PAN      string `json:"pan"`
	Marker   string `json:"marker"`
}

// PIIPayload is the collected canary set handed from Stage 2 to Stage 3.
type PIIPayload struct {
	Marker      string         `json:"marker"`
	GeneratedAt string         `json:"generated_at"`
	Records     []CanaryRecord `json:"records"`
}

var canaryFirstNames = []string{"Ada", "Grace", "Alan", "Linus", "Radia", "Barbara", "Dennis", "Karen", "Vint", "Hedy"}
var canaryLastNames = []string{"Testerson", "Sampleford", "Canarywood", "Fauxman", "Mockridge", "Dummyfield", "Placeholt", "Synthe"}

// randInt returns a cryptographically-random int in [0, n).
func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// GenerateRunMarker returns a run-unique traceability marker, e.g. F0-CANARY-a1b2c3d4.
func GenerateRunMarker() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("F0-CANARY-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("F0-CANARY-%x", b)
}

// syntheticSSN returns a structurally-valid, never-issued SSN (SSA ad-reserved range).
func syntheticSSN() string {
	return fmt.Sprintf("987-65-432%d", randInt(10))
}

// luhnCheckDigit computes the Luhn check digit for a partial number (no check digit yet).
func luhnCheckDigit(partial string) int {
	sum := 0
	double := true // digit immediately left of the check digit is doubled
	for i := len(partial) - 1; i >= 0; i-- {
		d := int(partial[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return (10 - (sum % 10)) % 10
}

// syntheticPAN returns a Luhn-valid 16-digit PAN in the 4242 test BIN (not a real card).
func syntheticPAN() string {
	partial := "4242"
	for i := 0; i < 11; i++ { // 4 (BIN) + 11 (random) + 1 (check) = 16
		partial += fmt.Sprintf("%d", randInt(10))
	}
	return partial + fmt.Sprintf("%d", luhnCheckDigit(partial))
}

// GenerateCanarySet builds n synthetic records all tagged with marker.
func GenerateCanarySet(n int, marker string) []CanaryRecord {
	records := make([]CanaryRecord, 0, n)
	for i := 0; i < n; i++ {
		first := canaryFirstNames[randInt(len(canaryFirstNames))]
		last := canaryLastNames[randInt(len(canaryLastNames))]
		short := marker
		if len(short) > 4 {
			short = short[len(short)-4:]
		}
		records = append(records, CanaryRecord{
			FullName: fmt.Sprintf("%s %s", first, last),
			Email:    fmt.Sprintf("%s.%s.%s@canary.invalid", first, last, short),
			SSN:      syntheticSSN(),
			PAN:      syntheticPAN(),
			Marker:   marker,
		})
	}
	return records
}

// WritePayload serializes a PIIPayload as JSON to path.
func WritePayload(path string, p PIIPayload) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize payload: %v", err)
	}
	return os.WriteFile(path, data, 0644)
}

// ReadPayload loads a PIIPayload JSON from path.
func ReadPayload(path string) (PIIPayload, error) {
	var p PIIPayload
	data, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("failed to read payload at %s: %v", path, err)
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("failed to parse payload at %s: %v", path, err)
	}
	return p, nil
}

// PayloadPath returns the canonical path where Stage 2 writes and Stage 3 reads the payload.
func PayloadPath() string {
	return LOG_DIR + string(os.PathSeparator) + "pii_payload.json"
}
