//go:build windows

package cyberhygiene

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type registryBaselineSpec struct {
	id, name, validator, path, value, severity, expected, source string
	minimum                                                      uint64
	equal                                                        bool
	techniques                                                   []string
	tactics                                                      []string
}

func registryBaselineCheck(spec registryBaselineSpec) ControlResult {
	control := NewControlResult(spec.id, spec.name, spec.validator, spec.severity, spec.expected, spec.source, spec.techniques)
	control.Tactics = spec.tactics
	value, err := WindowsRegistryUint(spec.path, spec.value)
	if err != nil {
		control.Actual = "Not configured"
		control.Details = err.Error()
		if IsWindowsNotExist(err) {
			control.Status = StatusFail
		} else {
			control.Status = StatusUnknown
			control.Actual = "Unable to read policy value"
		}
		return control
	}
	if spec.equal {
		control.Compliant = value == spec.minimum
	} else {
		control.Compliant = value >= spec.minimum
	}
	control.Actual = fmt.Sprintf("%s = %d", spec.value, value)
	control.Details = control.Actual
	return control
}

func registryBaselineControls() []ControlResult {
	specs := []registryBaselineSpec{
		{id: "CH-LSS-001", name: "LSASS Protected Process Light", validator: "LSASS Protection", path: `SYSTEM\CurrentControlSet\Control\Lsa`, value: "RunAsPPL", minimum: 1, severity: "high", expected: "RunAsPPL = 1 or 2", source: "local_registry", techniques: []string{"T1003.001"}, tactics: []string{"credential-access"}},
		{id: "CH-LSS-002", name: "Credential Guard Policy", validator: "LSASS Protection", path: `SYSTEM\CurrentControlSet\Control\Lsa`, value: "LsaCfgFlags", minimum: 1, severity: "high", expected: "LsaCfgFlags = 1 or 2", source: "local_registry", techniques: []string{"T1003.001"}, tactics: []string{"credential-access"}},
		{id: "CH-LSS-003", name: "Virtualization-Based Security Policy", validator: "LSASS Protection", path: `SYSTEM\CurrentControlSet\Control\DeviceGuard`, value: "EnableVirtualizationBasedSecurity", minimum: 1, equal: true, severity: "high", expected: "EnableVirtualizationBasedSecurity = 1", source: "local_registry", techniques: []string{"T1003.001"}, tactics: []string{"credential-access"}},
		{id: "CH-PWS-001", name: "PowerShell Script Block Logging", validator: "PowerShell Security", path: `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, value: "EnableScriptBlockLogging", minimum: 1, equal: true, severity: "high", expected: "Enabled", source: "local_registry", techniques: []string{"T1059.001"}, tactics: []string{"execution"}},
		{id: "CH-PWS-002", name: "PowerShell Module Logging", validator: "PowerShell Security", path: `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging`, value: "EnableModuleLogging", minimum: 1, equal: true, severity: "high", expected: "Enabled", source: "local_registry", techniques: []string{"T1059.001"}, tactics: []string{"execution"}},
		{id: "CH-PWS-003", name: "PowerShell Transcription", validator: "PowerShell Security", path: `SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`, value: "EnableTranscripting", minimum: 1, equal: true, severity: "medium", expected: "Enabled", source: "local_registry", techniques: []string{"T1059.001"}, tactics: []string{"execution"}},
		{id: "CH-PWS-004", name: "PowerShell Constrained Language Policy", validator: "PowerShell Security", path: `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, value: "__PSLockdownPolicy", minimum: 4, equal: true, severity: "medium", expected: "__PSLockdownPolicy = 4", source: "local_registry", techniques: []string{"T1059.001"}, tactics: []string{"execution"}},
		{id: "CH-SMB-002", name: "SMB Server Signing Required", validator: "SMB Hardening", path: `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, value: "RequireSecuritySignature", minimum: 1, equal: true, severity: "high", expected: "Required", source: "local_registry", techniques: []string{"T1021.002"}, tactics: []string{"lateral-movement"}},
		{id: "CH-SMB-003", name: "SMB Client Signing Required", validator: "SMB Hardening", path: `SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`, value: "RequireSecuritySignature", minimum: 1, equal: true, severity: "high", expected: "Required", source: "local_registry", techniques: []string{"T1021.002"}, tactics: []string{"lateral-movement"}},
		{id: "CH-SMB-004", name: "SMB Server Encryption Policy", validator: "SMB Hardening", path: `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, value: "EncryptData", minimum: 1, equal: true, severity: "medium", expected: "Enabled", source: "local_registry", techniques: []string{"T1021.002"}, tactics: []string{"lateral-movement"}},
		{id: "CH-SMB-005", name: "SMB Null Session Restriction", validator: "SMB Hardening", path: `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, value: "RestrictNullSessAccess", minimum: 1, equal: true, severity: "high", expected: "Enabled", source: "local_registry", techniques: []string{"T1021.002"}, tactics: []string{"lateral-movement"}},
		{id: "CH-NET-001", name: "LLMNR Disabled", validator: "Network Protocol Hardening", path: `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, value: "EnableMulticast", minimum: 0, equal: true, severity: "high", expected: "EnableMulticast = 0", source: "local_registry", techniques: []string{"T1557.001"}, tactics: []string{"credential-access"}},
		{id: "CH-PRT-002", name: "Printer Driver Installation Restricted", validator: "Print Spooler Hardening", path: `SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint`, value: "RestrictDriverInstallationToAdministrators", minimum: 1, equal: true, severity: "critical", expected: "Enabled", source: "local_registry", techniques: []string{"T1547.012"}, tactics: []string{"privilege-escalation"}},
		{id: "CH-PRT-003", name: "Point and Print Installation Warning", validator: "Print Spooler Hardening", path: `SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint`, value: "NoWarningNoElevationOnInstall", minimum: 0, equal: true, severity: "high", expected: "NoWarningNoElevationOnInstall = 0", source: "local_registry", techniques: []string{"T1547.012"}, tactics: []string{"privilege-escalation"}},
		{id: "CH-PRT-004", name: "Point and Print Update Prompt", validator: "Print Spooler Hardening", path: `SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint`, value: "UpdatePromptSettings", minimum: 0, equal: true, severity: "high", expected: "UpdatePromptSettings = 0", source: "local_registry", techniques: []string{"T1547.012"}, tactics: []string{"privilege-escalation"}},
	}
	controls := make([]ControlResult, 0, len(specs))
	for _, spec := range specs {
		controls = append(controls, registryBaselineCheck(spec))
	}
	return controls
}

func WindowsBaselineChecks(ctx EndpointContext) []ControlResult {
	controls := registryBaselineControls()
	controls = append(controls,
		checkSMBv1Baseline(),
		checkNetBIOSBaseline(),
		checkWPADBaseline(),
		checkIPv6TunnelBaseline(),
		checkLAPSBaseline(ctx),
		checkSpoolerBaseline(ctx),
	)
	controls = append(controls, auditBaselineControls()...)
	controls = append(controls, accountBaselineControls()...)
	return controls
}

func checkSMBv1Baseline() ControlResult {
	control := NewControlResult("CH-SMB-001", "SMBv1 Disabled", "SMB Hardening", "critical", "mrxsmb10 Start = 4 or feature absent", "local_registry", []string{"T1021.002"})
	control.Tactics = []string{"lateral-movement"}
	value, err := WindowsRegistryUint(`SYSTEM\CurrentControlSet\Services\mrxsmb10`, "Start")
	if err != nil {
		if IsWindowsNotExist(err) {
			control.Compliant = true
			control.Actual = "SMBv1 driver absent"
		} else {
			control.Status = StatusUnknown
			control.Actual = "Unable to query SMBv1 driver"
		}
		return control
	}
	control.Compliant = value == 4
	control.Actual = fmt.Sprintf("Start = %d", value)
	return control
}

func checkNetBIOSBaseline() ControlResult {
	control := NewControlResult("CH-NET-002", "NetBIOS over TCP/IP Disabled", "Network Protocol Hardening", "high", "TcpipNetbiosOptions = 2 on every IP-enabled adapter", "Win32_NetworkAdapterConfiguration", []string{"T1557.001"})
	control.Tactics = []string{"credential-access"}
	output, err := RunWindowsPowerShell(`$a = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'"); if ($a.Count -eq 0) { 'NO_ADAPTERS' } elseif (@($a | Where-Object { $_.TcpipNetbiosOptions -ne 2 }).Count -eq 0) { 'ALL_DISABLED' } else { 'NOT_DISABLED' }`)
	if err != nil {
		control.Status = StatusUnknown
		control.Actual = "Unable to query adapter configuration"
		return control
	}
	switch output {
	case "ALL_DISABLED":
		control.Compliant = true
		control.Actual = "Disabled on all adapters"
	case "NO_ADAPTERS":
		control.Status = StatusNotApplicable
		control.Applicability = "No IP-enabled adapters"
		control.Actual = "No IP-enabled adapters"
	case "NOT_DISABLED":
		control.Actual = "Enabled or default on at least one adapter"
	default:
		control.Status = StatusUnknown
		control.Actual = output
	}
	return control
}

func checkWPADBaseline() ControlResult {
	control := NewControlResult("CH-NET-003", "WPAD Override Enabled", "Network Protocol Hardening", "medium", "WpadOverride = 1", "local_registry", []string{"T1557.001"})
	control.Tactics = []string{"credential-access"}
	value, err := WindowsRegistryUint(`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp`, "WpadOverride")
	if err != nil {
		control.Actual = "Not configured"
		if IsWindowsNotExist(err) {
			control.Status = StatusFail
		} else {
			control.Status = StatusUnknown
		}
		return control
	}
	control.Compliant = value == 1
	control.Actual = fmt.Sprintf("WpadOverride = %d", value)
	return control
}

func checkIPv6TunnelBaseline() ControlResult {
	control := NewControlResult("CH-NET-004", "IPv6 Tunnel Interfaces Disabled", "Network Protocol Hardening", "medium", "DisabledComponents includes 0x21", "local_registry", []string{"T1572"})
	control.Tactics = []string{"command-and-control"}
	value, err := WindowsRegistryUint(`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`, "DisabledComponents")
	if err != nil {
		control.Actual = "Not configured"
		if IsWindowsNotExist(err) {
			control.Status = StatusFail
		} else {
			control.Status = StatusUnknown
		}
		return control
	}
	control.Compliant = value&0x21 != 0
	control.Actual = fmt.Sprintf("DisabledComponents = 0x%X", value)
	return control
}

func checkLAPSBaseline(ctx EndpointContext) ControlResult {
	control := NewControlResult("CH-LAP-001", "LAPS Configured", "Local Administrator Password Solution", "high", "Windows LAPS backup or legacy LAPS enabled", "local_registry", []string{"T1078.003"})
	control.Tactics = []string{"persistence", "privilege-escalation"}
	if !ctx.DomainJoined && !ctx.EntraJoined {
		control.Status = StatusNotApplicable
		control.Applicability = "Domain or Entra-joined device required for this baseline"
		control.Actual = "Device is not domain-joined"
		return control
	}
	backup, backupErr := WindowsRegistryUint(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS`, "BackupDirectory")
	legacy, legacyErr := WindowsRegistryUint(`SOFTWARE\Policies\Microsoft Services\AdmPwd`, "AdmPwdEnabled")
	if backupErr == nil && backup > 0 {
		control.Compliant = true
		control.Actual = fmt.Sprintf("Windows LAPS BackupDirectory = %d", backup)
		return control
	}
	if legacyErr == nil && legacy == 1 {
		control.Compliant = true
		control.Actual = "Legacy LAPS AdmPwdEnabled = 1"
		return control
	}
	if backupErr != nil && legacyErr != nil && (!IsWindowsNotExist(backupErr) || !IsWindowsNotExist(legacyErr)) {
		control.Status = StatusUnknown
		control.Actual = "Unable to read LAPS policy"
		return control
	}
	control.Actual = "Neither Windows LAPS nor legacy LAPS is enabled"
	return control
}

func checkSpoolerBaseline(ctx EndpointContext) ControlResult {
	control := NewControlResult("CH-PRT-001", "Print Spooler Service", "Print Spooler Hardening", "high", "Absent or disabled unless required by a documented print role", "Win32_Service", []string{"T1569.002"})
	control.Tactics = []string{"execution"}
	services, err := QueryWindowsServices([]string{"Spooler"})
	if err != nil {
		control.Status = StatusUnknown
		control.Actual = "Unable to query Spooler service"
		return control
	}
	service, exists := services["spooler"]
	if !exists {
		control.Compliant = true
		control.Actual = "Service not installed"
		return control
	}
	control.Actual = fmt.Sprintf("State=%s, StartMode=%s", service.State, service.StartMode)
	if service.State != "Running" && service.StartMode == "Disabled" {
		control.Compliant = true
		return control
	}
	if ctx.OSRole == RoleServer || ctx.OSRole == RoleMemberServer || ctx.OSRole == RoleDomainController {
		control.Status = StatusUnknown
		control.Applicability = "A server may have a documented print role"
		control.Details = "Confirm whether the print role is approved; do not assume a running spooler is a failure"
	}
	return control
}

type auditBaselineSpec struct {
	id, name, severity, required string
	techniques                   []string
}

func auditBaselineControls() []ControlResult {
	specs := []auditBaselineSpec{
		{id: "CH-AUD-001", name: "Logon", severity: "critical", required: "both", techniques: []string{"T1078"}},
		{id: "CH-AUD-002", name: "Logoff", severity: "high", required: "success", techniques: []string{"T1078"}},
		{id: "CH-AUD-003", name: "Account Lockout", severity: "high", required: "failure", techniques: []string{"T1110"}},
		{id: "CH-AUD-004", name: "Special Logon", severity: "high", required: "success", techniques: []string{"T1078"}},
		{id: "CH-AUD-005", name: "Process Creation", severity: "critical", required: "success", techniques: []string{"T1059"}},
		{id: "CH-AUD-006", name: "Audit Policy Change", severity: "high", required: "success", techniques: []string{"T1562.002"}},
		{id: "CH-AUD-007", name: "User Account Management", severity: "critical", required: "both", techniques: []string{"T1136"}},
		{id: "CH-AUD-008", name: "Computer Account Management", severity: "high", required: "success", techniques: []string{"T1136"}},
		{id: "CH-AUD-009", name: "Security Group Management", severity: "critical", required: "success", techniques: []string{"T1098"}},
	}
	controls := make([]ControlResult, 0, len(specs))
	for _, spec := range specs {
		control := NewControlResult(spec.id, "Audit "+spec.name, "Windows Audit Logging", spec.severity, "Required audit mode: "+spec.required, "auditpol", spec.techniques)
		control.Tactics = []string{"defense-evasion"}
		output, err := RunWindowsCommand("auditpol", "/get", "/subcategory:"+spec.name, "/r")
		if err != nil {
			control.Status = StatusUnknown
			control.Actual = "Unable to query audit policy"
			controls = append(controls, control)
			continue
		}
		records, parseErr := csv.NewReader(strings.NewReader(output)).ReadAll()
		setting := ""
		if parseErr == nil {
			for _, record := range records {
				if len(record) >= 5 && strings.EqualFold(strings.TrimSpace(record[2]), spec.name) {
					setting = strings.TrimSpace(record[4])
				}
			}
		}
		control.Actual = setting
		if parseErr != nil || setting == "" {
			control.Status = StatusUnknown
			control.Actual = "Audit inclusion setting was not reported"
			controls = append(controls, control)
			continue
		}
		lower := strings.ToLower(setting)
		success := strings.Contains(lower, "success")
		failure := strings.Contains(lower, "failure")
		switch spec.required {
		case "both":
			control.Compliant = success && failure
		case "success":
			control.Compliant = success
		case "failure":
			control.Compliant = failure
		}
		controls = append(controls, control)
	}
	return controls
}

func accountBaselineControls() []ControlResult {
	output, err := RunWindowsCommand("net", "accounts")
	values := make(map[string]string)
	if err == nil {
		for _, line := range strings.Split(output, "\n") {
			key, value, ok := strings.Cut(line, ":")
			if ok {
				values[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
			}
		}
	}
	controls := []ControlResult{
		accountPolicyControl("CH-LOK-001", "Account Lockout Threshold", values, "lockout threshold", 1, 5, false, err),
		accountPolicyControl("CH-LOK-002", "Account Lockout Duration", values, "lockout duration (minutes)", 15, 0, true, err),
		accountPolicyControl("CH-LOK-003", "Reset Account Lockout Counter", values, "lockout observation window (minutes)", 15, 0, false, err),
		accountPolicyControl("CH-LOK-004", "Minimum Password Length", values, "minimum password length", 14, 0, false, err),
		passwordComplexityBaseline(),
	}
	return controls
}

func accountPolicyControl(id, name string, values map[string]string, key string, minimum, maximum int, neverAllowed bool, queryErr error) ControlResult {
	control := NewControlResult(id, name, "Account Policy", "high", fmt.Sprintf("minimum=%d maximum=%d", minimum, maximum), "net accounts", []string{"T1110"})
	control.Tactics = []string{"credential-access"}
	if queryErr != nil {
		control.Status = StatusUnknown
		control.Actual = "Unable to query account policy"
		return control
	}
	raw, exists := values[key]
	if !exists {
		control.Status = StatusUnknown
		control.Actual = "Setting was not reported"
		return control
	}
	control.Actual = raw
	if neverAllowed && strings.EqualFold(raw, "Never") {
		control.Compliant = true
		return control
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		control.Status = StatusUnknown
		return control
	}
	control.Compliant = value >= minimum && (maximum == 0 || value <= maximum)
	return control
}

func passwordComplexityBaseline() ControlResult {
	control := NewControlResult("CH-LOK-005", "Password Complexity", "Account Policy", "high", "PasswordComplexity = 1", "secedit security policy", []string{"T1110"})
	control.Tactics = []string{"credential-access"}
	tempPath := filepath.Join(`C:\F0`, "f0_cyberhygiene_secedit.inf")
	defer os.Remove(tempPath)
	script := fmt.Sprintf(`secedit /export /cfg '%s' /areas SECURITYPOLICY /quiet | Out-Null; $line = Select-String -Path '%s' -Pattern '^PasswordComplexity\s*='; if ($line) { ($line.Line -split '=')[1].Trim() }`, strings.ReplaceAll(tempPath, "'", "''"), strings.ReplaceAll(tempPath, "'", "''"))
	output, err := RunWindowsPowerShell(script)
	if err != nil {
		control.Status = StatusUnknown
		control.Actual = "Unable to export security policy"
		return control
	}
	control.Actual = output
	control.Compliant = output == "1"
	return control
}
