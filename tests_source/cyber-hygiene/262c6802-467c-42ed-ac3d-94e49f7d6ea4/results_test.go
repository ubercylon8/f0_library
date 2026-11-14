package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestMakeControlVerdicts(t *testing.T) {
	tests := []struct {
		name          string
		probes        []probeResult
		wantExit      int
		wantSkipped   bool
		wantCompliant bool
	}{
		{name: "absent runtime", probes: nil, wantSkipped: true},
		{name: "all rejected", probes: []probeResult{{Status: probeRejected}, {Status: probeRejected}}, wantExit: ExitCompliant, wantCompliant: true},
		{name: "accepted wins over rejection", probes: []probeResult{{Status: probeRejected}, {Status: probeAccepted}}, wantExit: ExitNonCompliant},
		{name: "error is never protected", probes: []probeResult{{Status: probeRejected}, {Status: probeError, Evidence: "unknown failure"}}, wantExit: ExitTestError},
		{name: "accepted wins over error", probes: []probeResult{{Status: probeError}, {Status: probeAccepted}}, wantExit: ExitNonCompliant},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control := makeControl("CH-TEST", "test", "test", test.probes, []string{"T1557"})
			if control.ExitCode != test.wantExit || control.Skipped != test.wantSkipped || control.Compliant != test.wantCompliant {
				t.Fatalf("unexpected verdict: exit=%d skipped=%v compliant=%v", control.ExitCode, control.Skipped, control.Compliant)
			}
		})
	}
}

func TestOverallResultRequiresCompleteAssessment(t *testing.T) {
	protected := makeControl("CH-TEST-1", "protected", "test", []probeResult{{Status: probeRejected}}, []string{"T1557"})
	inconclusive := makeControl("CH-TEST-2", "inconclusive", "test", []probeResult{{Status: probeError}}, []string{"T1557"})
	if code, _ := overallResult([]ControlResult{protected, inconclusive}); code != ExitTestError {
		t.Fatalf("inconclusive assessment returned %d", code)
	}
	if code, _ := overallResult([]ControlResult{protected}); code != ExitCompliant {
		t.Fatalf("complete protected assessment returned %d", code)
	}
}

func TestCurlClassification(t *testing.T) {
	if status := classifyCurl("curl: (60) SSL certificate problem: unable to get local issuer certificate", errors.New("exit 60")); status != probeRejected {
		t.Fatalf("certificate rejection classified as %s", status)
	}
	if status := classifyCurl("curl: (7) Failed to connect", errors.New("exit 7")); status != probeError {
		t.Fatalf("connection failure classified as %s", status)
	}
}

func TestGeneratedCaseCoverage(t *testing.T) {
	cases := generatedTLSCases()
	if len(cases) != 12 {
		t.Fatalf("expected 12 direct and cross-signed TLS cases, got %d", len(cases))
	}
	direct, cross, rollover := offlineTLSPaths()
	if len(direct) != 7 || len(cross) != 7 || len(rollover) != 2 {
		t.Fatalf("unexpected offline coverage: %d/%d/%d", len(direct), len(cross), len(rollover))
	}
}

func TestPrintControlsIncludesInconclusiveEvidence(t *testing.T) {
	control := makeControl("CH-TEST", "test", "test", []probeResult{{
		Runtime: "authenticode", Case: "ov-g3b-direct", Status: probeError,
		Evidence: "size=1220008 read=ok; HRESULT 0x80092003",
	}}, []string{"T1553.002"})

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()
	printControls([]ControlResult{control})
	writer.Close()
	os.Stdout = original
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), "authenticode ov-g3b-direct: size=1220008 read=ok; HRESULT 0x80092003") {
		t.Fatalf("inconclusive probe evidence missing from STDOUT:\n%s", output)
	}
}
