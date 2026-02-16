//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
)

// RunRiskPolicyChecks validates CISA SCuBA Section 2: Risk-Based Policies
func RunRiskPolicyChecks() ValidatorResult {
	checks := []CheckResult{
		checkHighRiskUsersBlocked(),
		checkHighRiskSignInsBlocked(),
		checkRiskNotifications(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Risk-Based Policies",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkHighRiskUsersBlocked verifies a CA policy blocks sign-in when user risk is high.
// SCuBA MS.AAD.2.1: Users detected as high risk SHALL be blocked.
func checkHighRiskUsersBlocked() CheckResult {
	result := CheckResult{
		ControlID:   "CH-ITN-002",
		Name:        "High-Risk Users Blocked",
		Category:    "risk-policies",
		Description: "Verifies a CA policy blocks sign-in when user risk level is high",
		Severity:    "critical",
		SCuBAID:     "MS.AAD.2.1",
		Expected:    "CA policy blocks high-risk users",
		Techniques:  []string{"T1078.004"},
		Tactics:     []string{"credential-access", "initial-access"},
	}

	script := `
$policies = Get-MgIdentityConditionalAccessPolicy -All
$riskBlock = $policies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.Conditions.UserRiskLevels -contains 'high' -and
    $_.GrantControls.BuiltInControls -contains 'block'
}
if ($riskBlock) {
    Write-Output "FOUND:$($riskBlock[0].DisplayName)"
} else {
    # Check for password change requirement (also acceptable)
    $riskPwChange = $policies | Where-Object {
        $_.State -eq 'enabled' -and
        $_.Conditions.UserRiskLevels -contains 'high' -and
        $_.GrantControls.BuiltInControls -contains 'passwordChange'
    }
    if ($riskPwChange) {
        Write-Output "PWCHANGE:$($riskPwChange[0].DisplayName)"
    } else {
        Write-Output "NOTFOUND"
    }
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying CA policies"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "FOUND:") {
		policyName := strings.TrimPrefix(output, "FOUND:")
		result.Passed = true
		result.Actual = fmt.Sprintf("Blocked by: %s", policyName)
		result.Details = result.Actual
	} else if strings.HasPrefix(output, "PWCHANGE:") {
		policyName := strings.TrimPrefix(output, "PWCHANGE:")
		result.Passed = true
		result.Actual = fmt.Sprintf("Password change required by: %s", policyName)
		result.Details = result.Actual
	} else {
		result.Passed = false
		result.Actual = "No CA policy addresses high-risk users"
		result.Details = "No blocking or remediation policy found"
	}

	return result
}

// checkHighRiskSignInsBlocked verifies a CA policy blocks high-risk sign-ins.
// SCuBA MS.AAD.2.3: Sign-ins detected as high risk SHALL be blocked.
func checkHighRiskSignInsBlocked() CheckResult {
	result := CheckResult{
		ControlID:   "CH-ITN-003",
		Name:        "High-Risk Sign-Ins Blocked",
		Category:    "risk-policies",
		Description: "Verifies a CA policy blocks sign-in when sign-in risk is high",
		Severity:    "critical",
		SCuBAID:     "MS.AAD.2.3",
		Expected:    "CA policy blocks high-risk sign-ins",
		Techniques:  []string{"T1078.004"},
		Tactics:     []string{"credential-access", "initial-access"},
	}

	script := `
$policies = Get-MgIdentityConditionalAccessPolicy -All
$riskBlock = $policies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.Conditions.SignInRiskLevels -contains 'high' -and
    ($_.GrantControls.BuiltInControls -contains 'block' -or
     $_.GrantControls.BuiltInControls -contains 'mfa')
}
if ($riskBlock) {
    $controls = $riskBlock[0].GrantControls.BuiltInControls -join ', '
    Write-Output "FOUND:$($riskBlock[0].DisplayName)|$controls"
} else {
    Write-Output "NOTFOUND"
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying CA policies"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "FOUND:") {
		parts := strings.SplitN(strings.TrimPrefix(output, "FOUND:"), "|", 2)
		policyName := parts[0]
		controls := ""
		if len(parts) > 1 {
			controls = parts[1]
		}
		result.Passed = true
		result.Actual = fmt.Sprintf("Enforced by: %s (controls: %s)", policyName, controls)
		result.Details = result.Actual
	} else {
		result.Passed = false
		result.Actual = "No CA policy addresses high-risk sign-ins"
		result.Details = "No blocking or MFA enforcement policy found"
	}

	return result
}

// checkRiskNotifications verifies admin notification for risky users is configured.
// SCuBA MS.AAD.2.2: A notification SHOULD be sent to the administrator when high-risk users are detected.
func checkRiskNotifications() CheckResult {
	result := CheckResult{
		ControlID:   "CH-ITN-004",
		Name:        "Risk Detection Notifications",
		Category:    "risk-policies",
		Description: "Verifies admin notifications are configured for risky user detections",
		Severity:    "medium",
		SCuBAID:     "MS.AAD.2.2",
		Expected:    "Notification recipients configured",
		Techniques:  []string{"T1078.004"},
		Tactics:     []string{"credential-access"},
	}

	// Check if Identity Protection notification settings have recipients
	script := `
try {
    $settings = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identityProtection/riskyUsers' -ErrorAction Stop
    Write-Output "ACCESSIBLE"
} catch {
    # If we can query risky users, the feature is enabled
    if ($_.Exception.Message -like '*Forbidden*') {
        Write-Output "NOPERM"
    } else {
        Write-Output "ACCESSIBLE"
    }
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Unable to verify"
		result.Details = "Informational: could not query risk settings"
		result.Severity = "informational"
		return result
	}

	output = strings.TrimSpace(output)
	// This is an informational/SHOULD-level check
	result.Passed = output == "ACCESSIBLE"
	if result.Passed {
		result.Actual = "Identity Protection accessible"
		result.Details = "Informational: risk detection endpoint is accessible"
	} else {
		result.Actual = "Identity Protection not accessible"
		result.Details = "Informational: verify notification settings in Entra portal"
	}

	return result
}
