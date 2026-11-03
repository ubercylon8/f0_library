package cyberhygiene

import "testing"

func control(status ControlStatus) ControlResult {
	return ControlResult{Status: status}
}

func TestFinalizeControlResultLegacyCompatibility(t *testing.T) {
	tests := []struct {
		name       string
		control    ControlResult
		wantStatus ControlStatus
		wantExit   int
	}{
		{name: "legacy pass", control: ControlResult{Compliant: true}, wantStatus: StatusPass, wantExit: 126},
		{name: "legacy fail", control: ControlResult{}, wantStatus: StatusFail, wantExit: 101},
		{name: "legacy skipped", control: ControlResult{Skipped: true}, wantStatus: StatusSkipped, wantExit: 0},
		{name: "unknown", control: control(StatusUnknown), wantStatus: StatusUnknown, wantExit: 0},
		{name: "error", control: control(StatusError), wantStatus: StatusError, wantExit: 999},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			FinalizeControlResult(&tt.control)
			if tt.control.Status != tt.wantStatus || tt.control.ExitCode != tt.wantExit {
				t.Fatalf("got status=%s exit=%d", tt.control.Status, tt.control.ExitCode)
			}
			if tt.control.ObservedAt == "" {
				t.Fatal("observed_at was not populated")
			}
		})
	}
}

func TestFinalizeBundleResults(t *testing.T) {
	tests := []struct {
		name           string
		controls       []ControlResult
		wantExit       int
		wantExecution  string
		wantCompliance string
		wantComplete   bool
	}{
		{name: "all pass", controls: []ControlResult{control(StatusPass), control(StatusNotApplicable)}, wantExit: 126, wantExecution: "completed", wantCompliance: "compliant", wantComplete: true},
		{name: "genuine failure", controls: []ControlResult{control(StatusPass), control(StatusFail)}, wantExit: 101, wantExecution: "completed", wantCompliance: "non_compliant", wantComplete: true},
		{name: "partial with failure", controls: []ControlResult{control(StatusFail), control(StatusUnknown)}, wantExit: 101, wantExecution: "partial", wantCompliance: "non_compliant", wantComplete: false},
		{name: "partial without failure", controls: []ControlResult{control(StatusPass), control(StatusSkipped)}, wantExit: 999, wantExecution: "partial", wantCompliance: "incomplete", wantComplete: false},
		{name: "nothing evaluated", controls: []ControlResult{control(StatusError)}, wantExit: 999, wantExecution: "error", wantCompliance: "not_assessed", wantComplete: false},
		{name: "only not applicable", controls: []ControlResult{control(StatusNotApplicable)}, wantExit: 999, wantExecution: "error", wantCompliance: "not_assessed", wantComplete: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := BundleResults{Controls: tt.controls}
			FinalizeBundleResults(&bundle)
			if bundle.SchemaVersion != "1.1" || bundle.OverallExitCode != tt.wantExit ||
				bundle.ExecutionStatus != tt.wantExecution || bundle.ComplianceStatus != tt.wantCompliance ||
				bundle.AssessmentComplete != tt.wantComplete {
				t.Fatalf("unexpected summary: %+v", bundle)
			}
		})
	}
}
