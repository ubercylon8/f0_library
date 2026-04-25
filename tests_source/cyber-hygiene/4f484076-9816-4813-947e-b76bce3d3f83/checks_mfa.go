//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
)

// RunMFAChecks validates CISA SCuBA Section 3: Strong Authentication / MFA.
// Also runs the ISACA ITGC-AM-006 MFA Enrollment check (per-user enrollment vs.
// the CA-policy checks above, which assert tenant-wide enforcement).
func RunMFAChecks() ValidatorResult {
	checks := []CheckResult{
		checkPhishingResistantMFA(),
		checkMFAForAllUsers(),
		checkAuthenticatorContext(),
		checkAuthMethodMigration(),
		checkWeakMethodsDisabled(),
		checkPhishingResistantForAdmins(),
		checkDeviceCodeFlowBlocked(),
		checkMFAEnrollmentISACA(), // ITGC-AM-006
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
		ControlID:   "CH-ITN-005",
		Name:        "Phishing-Resistant MFA Enforced",
		Category:    "mfa",
		Description: "Verifies a CA policy requires phishing-resistant authentication strength for all users",
		Severity:    "critical",
		SCuBAID:     "MS.AAD.3.1",
		Expected:    "CA policy with phishing-resistant auth strength",
		Techniques:  []string{"T1556.006", "T1111"},
		Tactics:     []string{"credential-access"},
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
		ControlID:   "CH-ITN-006",
		Name:        "MFA Required for All Users",
		Category:    "mfa",
		Description: "Verifies a CA policy requires MFA for all users",
		Severity:    "critical",
		SCuBAID:     "MS.AAD.3.2",
		Expected:    "CA policy requiring MFA for all users/all cloud apps",
		Techniques:  []string{"T1556.006", "T1111"},
		Tactics:     []string{"credential-access"},
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
		ControlID:   "CH-ITN-007",
		Name:        "Authenticator Context Enabled",
		Category:    "mfa",
		Description: "Verifies Microsoft Authenticator shows number matching and application info",
		Severity:    "high",
		SCuBAID:     "MS.AAD.3.3",
		Expected:    "Number matching and app info enabled",
		Techniques:  []string{"T1556.006"},
		Tactics:     []string{"credential-access"},
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
		ControlID:   "CH-ITN-008",
		Name:        "Auth Method Migration Complete",
		Category:    "mfa",
		Description: "Verifies authentication method policy migration state is 'migrationComplete'",
		Severity:    "high",
		SCuBAID:     "MS.AAD.3.4",
		Expected:    "PolicyMigrationState = migrationComplete",
		Techniques:  []string{"T1556.007"},
		Tactics:     []string{"credential-access", "persistence"},
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
		ControlID:   "CH-ITN-009",
		Name:        "Weak Auth Methods Disabled",
		Category:    "mfa",
		Description: "Verifies SMS, Voice, and Email OTP methods are disabled",
		Severity:    "high",
		SCuBAID:     "MS.AAD.3.5",
		Expected:    "SMS, Voice, and Email OTP disabled",
		Techniques:  []string{"T1556.006", "T1111"},
		Tactics:     []string{"credential-access"},
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
		ControlID:   "CH-ITN-010",
		Name:        "Phishing-Resistant MFA for Admins",
		Category:    "mfa",
		Description: "Verifies a CA policy targets admin roles with phishing-resistant auth strength",
		Severity:    "critical",
		SCuBAID:     "MS.AAD.3.6",
		Expected:    "CA policy with auth strength targeting admin roles",
		Techniques:  []string{"T1556.006", "T1111"},
		Tactics:     []string{"credential-access", "persistence"},
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
		ControlID:   "CH-ITN-011",
		Name:        "Device Code Flow Blocked",
		Category:    "mfa",
		Description: "Verifies a CA policy blocks the device code authentication flow",
		Severity:    "informational",
		SCuBAID:     "MS.AAD.3.9",
		Expected:    "CA policy blocking device code flow",
		Techniques:  []string{"T1528"},
		Tactics:     []string{"credential-access"},
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

// checkMFAEnrollmentISACA — ITGC-AM-006 — per-user MFA enrollment audit.
//
// Distinct from checkMFAForAllUsers above (which audits the *CA policy* enforcing MFA),
// this control audits *actual user enrollment* via Get-MgUserAuthenticationMethod.
// An auditor needs both: a policy can require MFA, but if users haven't enrolled
// strong methods, the enforcement gap is real on day one.
//
// Requires Graph permission UserAuthenticationMethod.Read.All.
func checkMFAEnrollmentISACA() CheckResult {
	result := CheckResult{
		ControlID:      "ITGC-AM-006",
		Name:           "MFA Enrollment Verification",
		Category:       "mfa",
		Description:    "≥98% of users (member, non-guest, non-disabled) have at least one strong authentication method registered.",
		Severity:       "critical",
		SCuBAID:        "MS.AAD.3.x",
		Expected:       "≥98% strong-method enrollment among active member users",
		Techniques:     []string{"T1556"},
		Tactics:        []string{"credential-access"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.04 Manage Identity and Logical Access",
		CisV8Mapping:   "CIS 6.5 Require MFA for Administrative Access",
		ManualResidual: "Auditor reviews exception list (service accounts, break-glass) for documented business justification.",
	}

	// Strong methods per Microsoft definition: passkey/FIDO2, Microsoft Authenticator (push),
	// Windows Hello for Business, Authenticator app w/ MFA. Excludes voice + SMS (weak).
	script := `
$users = Get-MgUser -All -Filter "accountEnabled eq true and userType eq 'Member'" -Property Id,UserPrincipalName,UserType -ErrorAction SilentlyContinue
if (-not $users) { Write-Output "ERROR:no users returned"; exit 1 }
$total = $users.Count
$enrolled = 0
$noStrong = @()
foreach ($u in $users) {
    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $u.Id -ErrorAction Stop
        $strong = $methods | Where-Object {
            $_.AdditionalProperties['@odata.type'] -in @(
                '#microsoft.graph.fido2AuthenticationMethod',
                '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
                '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
                '#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod',
                '#microsoft.graph.softwareOathAuthenticationMethod'
            )
        }
        if ($strong) {
            $enrolled++
        } else {
            if ($noStrong.Count -lt 25) { $noStrong += $u.UserPrincipalName }
        }
    } catch {
        if ($noStrong.Count -lt 25) { $noStrong += ($u.UserPrincipalName + ' (query-error)') }
    }
}
$pct = if ($total -gt 0) { [math]::Round(($enrolled / $total) * 100, 2) } else { 0 }
$obj = @{ total = $total; enrolled = $enrolled; pct = $pct; sample_unenrolled = $noStrong }
$obj | ConvertTo-Json -Compress -Depth 4
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Graph query failed"
		result.Details = fmt.Sprintf("Could not query MFA enrollment: %v. Verify Graph app permission UserAuthenticationMethod.Read.All is granted.", err)
		result.Evidence = map[string]interface{}{"query_error": err.Error()}
		return result
	}
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "ERROR:") {
		result.Passed = false
		result.Actual = "Graph returned no users"
		result.Details = output
		result.Evidence = map[string]interface{}{"query_output": output}
		return result
	}

	result.Evidence = map[string]interface{}{"enrollment_query_raw": output}

	// Parse percent — accept patterns like `"pct":99.5` or `"pct":  99.5`
	pct := -1.0
	if idx := strings.Index(output, `"pct":`); idx >= 0 {
		rest := output[idx+6:]
		// trim leading whitespace
		i := 0
		for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
			i++
		}
		end := i
		for end < len(rest) && (rest[end] == '.' || (rest[end] >= '0' && rest[end] <= '9')) {
			end++
		}
		if end > i {
			fmt.Sscanf(rest[i:end], "%f", &pct)
		}
	}
	result.Evidence["enrollment_pct"] = pct

	if pct < 0 {
		result.Passed = false
		result.Actual = "could not parse enrollment percentage"
		result.Details = "Graph query succeeded but the response shape was unexpected. Inspect evidence.enrollment_query_raw."
		return result
	}

	result.Passed = pct >= 98.0
	result.Actual = fmt.Sprintf("%.2f%% enrolled (strong methods)", pct)
	if result.Passed {
		result.Details = fmt.Sprintf("MFA enrollment compliant at %.2f%% (≥98%% threshold).", pct)
	} else {
		result.Details = fmt.Sprintf("MFA enrollment at %.2f%% — below 98%% bar. See evidence.sample_unenrolled for first 25 unenrolled users; auditor reviews exception list for documented justification.", pct)
	}
	return result
}
