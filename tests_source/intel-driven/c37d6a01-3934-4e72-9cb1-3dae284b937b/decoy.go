// decoy.go — fictitious-user decoy file generation for Stage 3 (T1005).
// Compiled into the stage-3 binary only (see STAGE_EXTRA in build_all.sh).
//
// Pattern and SAFETY INVARIANTS follow tests_source/intel-driven/6d33cc62…/
// canary.go: every value is format-realistic but corresponds to NO real person:
//   - SSNs use the SSA advertising-reserved range 987-65-4320..987-65-4329,
//     structurally valid yet NEVER issued.
//   - PANs use the 4242 test BIN with a correct Luhn check digit (a well-known
//     payment-processor test range, not a real card).
//   - Emails use the RFC 2606 reserved .invalid TLD (non-routable).
//   - Passwords/credentials are obviously-synthetic test strings.
// Every file is tagged with a run-unique marker so any downstream sighting is
// traceable to this test run.
//
// No build tag, no main() — listed explicitly in the stage-3 build command.

package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var decoyFirstNames = []string{"Ada", "Grace", "Alan", "Linus", "Radia", "Barbara", "Dennis", "Karen", "Vint", "Hedy"}
var decoyLastNames = []string{"Testerson", "Sampleford", "Canarywood", "Fauxman", "Mockridge", "Dummyfield", "Placeholt", "Synthe"}

// decoyRandInt returns a cryptographically-random int in [0, n).
func decoyRandInt(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// DecoyRunMarker returns a run-unique traceability marker, e.g. F0-KOTHAMINE-a1b2c3d4.
func DecoyRunMarker() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("F0-KOTHAMINE-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("F0-KOTHAMINE-%x", b)
}

func decoySSN() string {
	return fmt.Sprintf("987-65-432%d", decoyRandInt(10))
}

// decoyLuhnDigit computes the Luhn check digit for a partial PAN.
func decoyLuhnDigit(partial string) int {
	sum := 0
	double := true
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

func decoyPAN() string {
	partial := "4242"
	for i := 0; i < 11; i++ {
		partial += fmt.Sprintf("%d", decoyRandInt(10))
	}
	return partial + fmt.Sprintf("%d", decoyLuhnDigit(partial))
}

func decoyName() (first, last string) {
	return decoyFirstNames[decoyRandInt(len(decoyFirstNames))], decoyLastNames[decoyRandInt(len(decoyLastNames))]
}

func decoyEmail(first, last, marker string) string {
	short := marker
	if len(short) > 4 {
		short = short[len(short)-4:]
	}
	return fmt.Sprintf("%s.%s.%s@canary.invalid", first, last, short)
}

// decoyFile pairs a path relative to ARTIFACT_DIR with its rendered content.
type decoyFile struct {
	RelPath string
	Content string
}

// renderDecoys builds the fictitious user's file set for this run.
func renderDecoys(marker string) []decoyFile {
	var custRows, payRows strings.Builder
	custRows.WriteString("customer_id,full_name,email,ssn,card_number\n")
	payRows.WriteString("employee,ssn,role,annual_salary_usd\n")
	for i := 1; i <= 12; i++ {
		f, l := decoyName()
		custRows.WriteString(fmt.Sprintf("CUST-%04d,%s %s,%s,%s,%s\n",
			1000+i, f, l, decoyEmail(f, l, marker), decoySSN(), decoyPAN()))
	}
	for i := 1; i <= 8; i++ {
		f, l := decoyName()
		payRows.WriteString(fmt.Sprintf("%s %s,%s,%s,%d\n",
			f, l, decoySSN(), []string{"Engineer", "Manager", "Analyst", "Director"}[decoyRandInt(4)],
			72000+decoyRandInt(120)*1000))
	}

	return []decoyFile{
		{
			RelPath: filepath.Join("Documents", "customer_records.csv"),
			Content: fmt.Sprintf("# Synthetic test data (%s) — no real persons\n", marker) + custRows.String(),
		},
		{
			RelPath: filepath.Join("Documents", "payroll_q3.csv"),
			Content: fmt.Sprintf("# Synthetic test data (%s) — no real persons\n", marker) + payRows.String(),
		},
		{
			RelPath: filepath.Join("Documents", "credential_notes.txt"),
			Content: fmt.Sprintf(`Personal credential notes — SYNTHETIC TEST DATA (%s)

wifi home:        FortiTestNet-%d / hunter2-test-%d
bank portal:      %s / TestPass!%d
email archive:    %s / TestPass!%d
password manager master: correct-horse-test-staple-%d
`,
				marker, decoyRandInt(100), decoyRandInt(10000),
				decoyEmail("Ada", "Testerson", marker), decoyRandInt(10000),
				decoyEmail("Grace", "Sampleford", marker), decoyRandInt(10000),
				decoyRandInt(10000)),
		},
		{
			RelPath: filepath.Join("Desktop", "travel_itinerary.md"),
			Content: fmt.Sprintf(`# Travel Itinerary — Q4 Offsite (SYNTHETIC TEST DATA %s)

- Traveler: %s %s <%s>
- Passport (synthetic): X%07d
- Flight: TA%04d JFK->SFO
- Hotel: Grand Test Hotel, confirmation HTL-%06d
`, marker, "Vint", "Placeholt", decoyEmail("Vint", "Placeholt", marker), decoyRandInt(10000000), decoyRandInt(9000), decoyRandInt(1000000)),
		},
		{
			RelPath: filepath.Join("Documents", "contracts", "vendor_msa_draft.txt"),
			Content: fmt.Sprintf(`MASTER SERVICES AGREEMENT — DRAFT (SYNTHETIC TEST DATA %s)

Between Fictitious Holdings Ltd. and Canary Consulting Group (%s).
Tax ID (synthetic): 98-76543%d. Payment terms NET-30.
Card on file (test PAN): %s
`, marker, decoyEmail("Hedy", "Mockridge", marker), decoyRandInt(10), decoyPAN()),
		},
	}
}

// CreateDecoyTree writes the fictitious user's decoy files under root
// (ARTIFACT_DIR) and returns the absolute paths created.
func CreateDecoyTree(root, marker string) ([]string, error) {
	var created []string
	for _, d := range renderDecoys(marker) {
		abs := filepath.Join(root, d.RelPath)
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			return created, fmt.Errorf("failed to create directory for %s: %v", abs, err)
		}
		if err := os.WriteFile(abs, []byte(d.Content), 0644); err != nil {
			return created, fmt.Errorf("failed to write %s: %v", abs, err)
		}
		created = append(created, abs)
		LogFileDropped(filepath.Base(abs), abs, int64(len(d.Content)), false)
	}
	return created, nil
}

// CleanupDecoyTree removes the decoy files and the now-empty directories this
// test created under root (best effort, per repo cleanup convention).
func CleanupDecoyTree(root string, paths []string) {
	for _, p := range paths {
		os.Remove(p)
	}
	// Remove the subdirectories we created if empty (deepest first).
	dirs := map[string]bool{}
	for _, p := range paths {
		dirs[filepath.Dir(p)] = true
	}
	var sorted []string
	for d := range dirs {
		sorted = append(sorted, d)
	}
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, d := range sorted {
		os.Remove(d) // fails silently if non-empty — correct
	}
	// Remove ARTIFACT_DIR/Documents|Desktop only if empty.
	os.Remove(filepath.Join(root, "Documents"))
	os.Remove(filepath.Join(root, "Desktop"))
}
