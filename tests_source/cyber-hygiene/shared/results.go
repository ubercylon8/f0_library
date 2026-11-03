package cyberhygiene

import "time"

type ControlStatus string

const (
	StatusPass          ControlStatus = "PASS"
	StatusFail          ControlStatus = "FAIL"
	StatusNotApplicable ControlStatus = "NOT_APPLICABLE"
	StatusUnknown       ControlStatus = "UNKNOWN"
	StatusError         ControlStatus = "ERROR"
	StatusSkipped       ControlStatus = "SKIPPED"
	StatusNotEvaluated  ControlStatus = "NOT_EVALUATED"
)

type BenchmarkReference struct {
	Framework        string `json:"framework"`
	Product          string `json:"product"`
	Version          string `json:"version"`
	Profile          string `json:"profile"`
	RecommendationID string `json:"recommendation_id,omitempty"`
	Source           string `json:"source,omitempty"`
}

type ControlResult struct {
	ControlID      string                 `json:"control_id"`
	ControlName    string                 `json:"control_name"`
	Validator      string                 `json:"validator"`
	ExitCode       int                    `json:"exit_code"`
	Compliant      bool                   `json:"compliant"`
	Status         ControlStatus          `json:"status"`
	Severity       string                 `json:"severity"`
	Category       string                 `json:"category"`
	Subcategory    string                 `json:"subcategory"`
	Techniques     []string               `json:"techniques"`
	Tactics        []string               `json:"tactics"`
	Expected       string                 `json:"expected"`
	Actual         string                 `json:"actual"`
	Details        string                 `json:"details"`
	Skipped        bool                   `json:"skipped"`
	ErrorMessage   string                 `json:"error_message"`
	Description    string                 `json:"description,omitempty"`
	Applicability  string                 `json:"applicability,omitempty"`
	Benchmark      *BenchmarkReference    `json:"benchmark,omitempty"`
	EvidenceSource string                 `json:"evidence_source,omitempty"`
	ObservedAt     string                 `json:"observed_at,omitempty"`
	Remediation    string                 `json:"remediation,omitempty"`
	Evidence       map[string]interface{} `json:"evidence,omitempty"`
}

type BundleResults struct {
	SchemaVersion         string              `json:"schema_version"`
	BundleID              string              `json:"bundle_id"`
	BundleName            string              `json:"bundle_name"`
	BundleCategory        string              `json:"bundle_category"`
	BundleSubcategory     string              `json:"bundle_subcategory"`
	ExecutionID           string              `json:"execution_id"`
	StartedAt             string              `json:"started_at"`
	CompletedAt           string              `json:"completed_at"`
	OverallExitCode       int                 `json:"overall_exit_code"`
	ExecutionStatus       string              `json:"execution_status"`
	ComplianceStatus      string              `json:"compliance_status"`
	AssessmentComplete    bool                `json:"assessment_complete"`
	ContextError          string              `json:"context_error,omitempty"`
	EndpointContext       *EndpointContext    `json:"endpoint_context,omitempty"`
	Benchmark             *BenchmarkReference `json:"benchmark,omitempty"`
	TotalControls         int                 `json:"total_controls"`
	PassedControls        int                 `json:"passed_controls"`
	FailedControls        int                 `json:"failed_controls"`
	SkippedControls       int                 `json:"skipped_controls"`
	UnknownControls       int                 `json:"unknown_controls"`
	ErrorControls         int                 `json:"error_controls"`
	NotApplicableControls int                 `json:"not_applicable_controls"`
	NotEvaluatedControls  int                 `json:"not_evaluated_controls"`
	Controls              []ControlResult     `json:"controls"`
}

func FinalizeControlResult(control *ControlResult) {
	if control.ObservedAt == "" {
		control.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if control.Status == "" {
		switch {
		case control.Skipped:
			control.Status = StatusSkipped
		case control.Compliant:
			control.Status = StatusPass
		default:
			control.Status = StatusFail
		}
	}
	control.Skipped = control.Status == StatusSkipped
	switch control.Status {
	case StatusPass:
		control.Compliant = true
		control.ExitCode = 126
	case StatusFail:
		control.Compliant = false
		control.ExitCode = 101
	case StatusError:
		control.Compliant = false
		control.ExitCode = 999
	default:
		control.Compliant = false
		control.ExitCode = 0
	}
}

func FinalizeBundleResults(bundle *BundleResults) {
	if bundle.SchemaVersion == "" || bundle.SchemaVersion == "1.0" {
		bundle.SchemaVersion = "1.1"
	}
	bundle.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	bundle.TotalControls = len(bundle.Controls)
	bundle.PassedControls = 0
	bundle.FailedControls = 0
	bundle.SkippedControls = 0
	bundle.UnknownControls = 0
	bundle.ErrorControls = 0
	bundle.NotApplicableControls = 0
	bundle.NotEvaluatedControls = 0

	for i := range bundle.Controls {
		control := &bundle.Controls[i]
		FinalizeControlResult(control)
		switch control.Status {
		case StatusPass:
			bundle.PassedControls++
		case StatusFail:
			bundle.FailedControls++
		case StatusSkipped:
			bundle.SkippedControls++
		case StatusUnknown:
			bundle.UnknownControls++
		case StatusError:
			bundle.ErrorControls++
		case StatusNotApplicable:
			bundle.NotApplicableControls++
		case StatusNotEvaluated:
			bundle.NotEvaluatedControls++
		}
	}

	evaluated := bundle.PassedControls + bundle.FailedControls
	incomplete := bundle.SkippedControls+bundle.UnknownControls+bundle.ErrorControls+bundle.NotEvaluatedControls > 0
	bundle.AssessmentComplete = !incomplete && evaluated > 0

	switch {
	case evaluated == 0:
		bundle.ExecutionStatus = "error"
		bundle.ComplianceStatus = "not_assessed"
		bundle.OverallExitCode = 999
	case bundle.FailedControls > 0:
		bundle.ExecutionStatus = "completed"
		if incomplete {
			bundle.ExecutionStatus = "partial"
		}
		bundle.ComplianceStatus = "non_compliant"
		bundle.OverallExitCode = 101
	case incomplete:
		bundle.ExecutionStatus = "partial"
		bundle.ComplianceStatus = "incomplete"
		bundle.OverallExitCode = 999
	default:
		bundle.ExecutionStatus = "completed"
		bundle.ComplianceStatus = "compliant"
		bundle.OverallExitCode = 126
	}
}
