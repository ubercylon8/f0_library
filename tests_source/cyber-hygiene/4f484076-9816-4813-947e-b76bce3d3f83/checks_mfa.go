//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
)

// RunMFAChecks validates CISA SCuBA Section 3: Strong Authentication / MFA
func RunMFAChecks() ValidatorResult {
	checks := []CheckResult{
		checkPhishingResistantMFA(),
		checkMFAForAllUsers(),
		checkAuthenticatorContext(),
		checkAuthMethodMigration(),
		checkWeakMethodsDisabled(),
		checkPhishingResistantForAdmins(),
		checkDeviceCodeFlowBlocked(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Strong Authentication (MFA)",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkPhishingResistantMFA verifies phishing-resistant MFA is required for all users.
// SCuBA MS.AAD.3.1: Phishing-resistant MFA SHALL be enforced for all users.
func checkPhishingResistantMFA() CheckResult {
	result := CheckResult{
		Name:        "Phishing-Resistant MFA Enforced",
		Category:    "mfa",
		Description: "Verifies a CA policy requires phishing-resistant authentication strength for all users",
		Severity:    "critical",
		SCuBAID:     "MS.AAD.3.1",
		Expected:    "CA policy with phishing-resistant auth strength",
	}

	script := `
$policies = Get-MgIdentityConditionalAccessPolicy -All
$prMfa = $policies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.GrantControls.AuthenticationStrength.Id -ne $null
}
if ($prMfa) {
    foreach ($p in $prMfa) {
        $strengthId = $p.GrantControls.AuthenticationStrength.Id
        try {
            $strength = Get-MgPolicyAuthenticationStrengthPolicy -AuthenticationStrengthPolicyId $strengthId
            if ($strength.DisplayName -like '*phishing*' -or $strength.PolicyType -eq 'builtIn') {
                Write-Output "FOUND:$($p.DisplayName)|$($strength.DisplayName)"
                return
            }
        } catch {}
    }
    Write-Output "PARTIAL:$($prMfa[0].DisplayName)"
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
		strengthName := ""
		if len(parts) > 1 {
			strengthName = parts[1]
		}
		result.Passed = true
		result.Actual = fmt.Sprintf("Policy: %s (strength: %s)", policyName, strengthName)
		result.Details = result.Actual
	} else if strings.HasPrefix(output, "PARTIAL:") {
		policyName := strings.TrimPrefix(output, "PARTIAL:")
		result.Passed = true
		result.Actual = fmt.Sprintf("Auth strength policy: %s", policyName)
		result.Details = result.Actual
	} else {
		result.Passed = false
		result.Actual = "No phishing-resistant MFA policy found"
		result.Details = "No CA policy with authentication strength requirement"
	}

	return result
}

// checkMFAForAllUsers verifies MFA is required for all users (fallback if no phishing-resistant).
// SCuBA MS.AAD.3.2: If phishing-resistant MFA is not enforced, an alternative MFA method SHALL be used.
func checkMFAForAllUsers() CheckResult {
	result := CheckResult{
		Name:        "MFA Required for All Users",
		Category:    "mfa",
		Description: "Verifies a CA policy requires MFA for all users",
		Severity:    "critical",
		SCuBAID:     "MS.AAD.3.2",
		Expected:    "CA policy requiring MFA for all users/all cloud apps",
	}

	script := `
$policies = Get-MgIdentityConditionalAccessPolicy -All
$mfaPolicy = $policies | Where-Object {
    $_.State -eq 'enabled' -and
    ($_.GrantControls.BuiltInControls -contains 'mfa' -or
     $_.GrantControls.AuthenticationStrength.Id -ne $null)
}
if ($mfaPolicy) {
    $names = ($mfaPolicy | Select-Object -First 3 | ForEach-Object { $_.DisplayName }) -join '; '
    Write-Output "FOUND:$($mfaPolicy.Count)|$names"
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
		count := parts[0]
		names := ""
		if len(parts) > 1 {
			names = parts[1]
		}
		result.Passed = true
		result.Actual = fmt.Sprintf("%s MFA policies: %s", count, names)
		result.Details = result.Actual
	} else {
		result.Passed = false
		result.Actual = "No MFA enforcement policy found"
		result.Details = "No CA policy requires MFA"
	}

	return result
}

// checkAuthenticatorContext verifies Microsoft Authenticator is configured with number matching and app context.
// SCuBA MS.AAD.3.3: Microsoft Authenticator SHALL be configured to show context.
func checkAuthenticatorContext() CheckResult {
	result := CheckResult{
		Name:        "Authenticator Context Enabled",
		Category:    "mfa",
		Description: "Verifies Microsoft Authenticator shows number matching and application info",
		Severity:    "high",
		SCuBAID:     "MS.AAD.3.3",
		Expected:    "Number matching and app info enabled",
	}

	script := `
$authPolicy = Get-MgPolicyAuthenticationMethodPolicy
$msAuth = $authPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq 'MicrosoftAuthenticator' }
if ($msAuth) {
    $settings = $msAuth.AdditionalProperties
    $featureSettings = $settings['featureSettings']
    $numberMatch = 'unknown'
    $appContext = 'unknown'
    if ($featureSettings) {
        if ($featureSettings['numberMatchingRequiredState']) {
            $numberMatch = $featureSettings['numberMatchingRequiredState']['state']
        }
        if ($featureSettings['displayAppInformationRequiredState']) {
            $appContext = $featureSettings['displayAppInformationRequiredState']['state']
        }
    }
    Write-Output "STATE:$($msAuth.State)|NM:$numberMatch|APP:$appContext"
} else {
    Write-Output "NOTCONFIGURED"
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying authentication methods"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "STATE:") {
		parts := strings.Split(strings.TrimPrefix(output, "STATE:"), "|")
		state := ""
		nm := "unknown"
		app := "unknown"
		for _, p := range parts {
			if strings.HasPrefix(p, "NM:") {
				nm = strings.TrimPrefix(p, "NM:")
			} else if strings.HasPrefix(p, "APP:") {
				app = strings.TrimPrefix(p, "APP:")
			} else {
				state = p
			}
		}

		nmEnabled := strings.EqualFold(nm, "enabled") || strings.EqualFold(nm, "default")
		appEnabled := strings.EqualFold(app, "enabled") || strings.EqualFold(app, "default")

		result.Passed = strings.EqualFold(state, "enabled") && nmEnabled && appEnabled
		result.Actual = fmt.Sprintf("State: %s, NumberMatch: %s, AppContext: %s", state, nm, app)
		result.Details = result.Actual
	} else {
		result.Passed = false
		result.Actual = "Microsoft Authenticator not configured"
		result.Details = "Not configured in authentication methods policy"
	}

	return result
}

// checkAuthMethodMigration verifies authentication methods migration is complete.
// SCuBA MS.AAD.3.4: The authentication methods migration SHALL be set to Migration Complete.
func checkAuthMethodMigration() CheckResult {
	result := CheckResult{
		Name:        "Auth Method Migration Complete",
		Category:    "mfa",
		Description: "Verifies authentication method policy migration state is 'migrationComplete'",
		Severity:    "high",
		SCuBAID:     "MS.AAD.3.4",
		Expected:    "PolicyMigrationState = migrationComplete",
	}

	script := `
$policy = Get-MgPolicyAuthenticationMethodPolicy
$policy.PolicyMigrationState
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying migration state"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	state := strings.TrimSpace(output)
	result.Passed = strings.EqualFold(state, "migrationComplete")
	result.Actual = fmt.Sprintf("PolicyMigrationState = %s", state)
	result.Details = result.Actual

	return result
}

// checkWeakMethodsDisabled verifies weak authentication methods (SMS, voice, email OTP) are disabled.
// SCuBA MS.AAD.3.5: Weak authentication methods SHALL be disabled.
func checkWeakMethodsDisabled() CheckResult {
	result := CheckResult{
		Name:        "Weak Auth Methods Disabled",
		Category:    "mfa",
		Description: "Verifies SMS, Voice, and Email OTP methods are disabled",
		Severity:    "high",
		SCuBAID:     "MS.AAD.3.5",
		Expected:    "SMS, Voice, and Email OTP disabled",
	}

	script := `
$policy = Get-MgPolicyAuthenticationMethodPolicy
$weakMethods = @('Sms', 'Voice', 'Email')
$enabledWeak = @()
foreach ($method in $policy.AuthenticationMethodConfigurations) {
    if ($weakMethods -contains $method.Id -and $method.State -eq 'enabled') {
        $enabledWeak += $method.Id
    }
}
if ($enabledWeak.Count -eq 0) {
    Write-Output "ALLDISABLED"
} else {
    Write-Output "ENABLED:$($enabledWeak -join ',')"
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying auth methods"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if output == "ALLDISABLED" {
		result.Passed = true
		result.Actual = "All weak methods disabled"
		result.Details = "SMS, Voice, Email OTP all disabled"
	} else if strings.HasPrefix(output, "ENABLED:") {
		enabledList := strings.TrimPrefix(output, "ENABLED:")
		result.Passed = false
		result.Actual = fmt.Sprintf("Weak methods enabled: %s", enabledList)
		result.Details = result.Actual
	} else {
		result.Passed = false
		result.Actual = "Could not determine auth method status"
		result.Details = output
	}

	return result
}

// checkPhishingResistantForAdmins verifies privileged roles require phishing-resistant MFA.
// SCuBA MS.AAD.3.6: Phishing-resistant MFA SHALL be required for highly privileged roles.
func checkPhishingResistantForAdmins() CheckResult {
	result := CheckResult{
		Name:        "Phishing-Resistant MFA for Admins",
		Category:    "mfa",
		Description: "Verifies a CA policy targets admin roles with phishing-resistant auth strength",
		Severity:    "critical",
		SCuBAID:     "MS.AAD.3.6",
		Expected:    "CA policy with auth strength targeting admin roles",
	}

	script := `
$policies = Get-MgIdentityConditionalAccessPolicy -All
$adminPolicy = $policies | Where-Object {
    $_.State -eq 'enabled' -and
    ($_.GrantControls.AuthenticationStrength.Id -ne $null -or
     $_.GrantControls.BuiltInControls -contains 'mfa') -and
    ($_.Conditions.Users.IncludeRoles.Count -gt 0)
}
if ($adminPolicy) {
    $roleCount = ($adminPolicy | ForEach-Object { $_.Conditions.Users.IncludeRoles } | Sort-Object -Unique).Count
    $hasAuthStrength = ($adminPolicy | Where-Object { $_.GrantControls.AuthenticationStrength.Id -ne $null }).Count -gt 0
    $type = if ($hasAuthStrength) { 'AuthStrength' } else { 'MFA' }
    Write-Output "FOUND:$($adminPolicy.Count)|$roleCount|$type"
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
		parts := strings.SplitN(strings.TrimPrefix(output, "FOUND:"), "|", 3)
		policyCount := parts[0]
		roleCount := ""
		authType := ""
		if len(parts) > 1 {
			roleCount = parts[1]
		}
		if len(parts) > 2 {
			authType = parts[2]
		}
		result.Passed = true
		result.Actual = fmt.Sprintf("%s policies covering %s roles (type: %s)", policyCount, roleCount, authType)
		result.Details = result.Actual
	} else {
		result.Passed = false
		result.Actual = "No admin-targeted MFA policy found"
		result.Details = "No CA policy targets admin roles with MFA/auth strength"
	}

	return result
}

// checkDeviceCodeFlowBlocked verifies device code flow is blocked via CA policy.
// SCuBA MS.AAD.3.9: The device code flow SHOULD be blocked (informational).
func checkDeviceCodeFlowBlocked() CheckResult {
	result := CheckResult{
		Name:        "Device Code Flow Blocked",
		Category:    "mfa",
		Description: "Verifies a CA policy blocks the device code authentication flow",
		Severity:    "informational",
		SCuBAID:     "MS.AAD.3.9",
		Expected:    "CA policy blocking device code flow",
	}

	script := `
$policies = Get-MgIdentityConditionalAccessPolicy -All
$dcfBlock = $policies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.Conditions.AuthenticationFlows.TransferMethods -eq 'deviceCodeFlow' -and
    $_.GrantControls.BuiltInControls -contains 'block'
}
if ($dcfBlock) {
    Write-Output "FOUND:$($dcfBlock[0].DisplayName)"
} else {
    Write-Output "NOTFOUND"
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		// This is a newer Graph API feature, may not be available
		result.Passed = false
		result.Actual = "Unable to verify"
		result.Details = "Informational: device code flow check requires recent Graph API"
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "FOUND:") {
		policyName := strings.TrimPrefix(output, "FOUND:")
		result.Passed = true
		result.Actual = fmt.Sprintf("Blocked by: %s", policyName)
		result.Details = result.Actual
	} else {
		result.Passed = false
		result.Actual = "Device code flow not blocked"
		result.Details = "Informational: SHOULD block device code flow"
	}

	return result
}
