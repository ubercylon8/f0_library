// Stage 1 — T1518.001 Security Software Discovery + T1087 Account Discovery + T1082 System Discovery
// F0RT1KA Security Testing Framework
// The Gentlemen (GOLD SHERWOOD) — Objective 1: reconnaissance to tailor the intrusion
//
// The Gentlemen performs extensive reconnaissance BEFORE tailoring its
// evasion (Trend Micro 2025-09: "the threat actors shifted tactics and began
// conducting detailed reconnaissance of the endpoint protection mechanisms in
// place ... adapt their techniques to the particular security solutions they
// encountered"). This stage reproduces the actor's discovery primitives:
//
//   1. T1518.001 — enumerate installed security products:
//      - WMI root\SecurityCenter2 AntiVirusProduct query (wmic shape with
//        PowerShell Get-CimInstance fallback — wmic is removed on Win11 24H2)
//      - sc.exe query probes against known AV/EDR service names (Rule 6:
//        registry service names, query-only, never stopped)
//      - tasklist filter for known EDR process names
//   2. T1087 — the actor's 1.bat mass-enumeration shape (60+ accounts):
//      net user /domain, net user <account> /domain, net group "domain admins"
//      /domain, net group "Enterprise admins" /domain, net localgroup
//      administrators, net localgroup __vmware__*
//   3. T1082 — systeminfo, hostname, computer domain (AD context)
//   4. Encoded-PowerShell PDC probe (Trend Micro IO): powershell -noni -nop
//      -w 1 -enc <UTF16LE-B64 of "(Get-ADDomain).PDCEmulator">
//
// CLASSIFICATION (Rule 8): blocked only on positive evidence of a protection
// action — a launch refusal (os/exec ERROR_ACCESS_DENIED etc.) or an OS-emitted
// denial on an operation that normally succeeds in this context. On a
// non-domain-joined lab host, /domain and Get-ADDomain commands fail benignly
// (no domain) — that is a PREREQUISITE outcome, not a block; the command-shape
// telemetry is the point. Missing tools (wmic removed) degrade to the fallback.
//
// EXIT CODES: 0 = discovery executed without prevention, 126 = positive
// prevention evidence, 999 = prerequisite/test error.

//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	TEST_UUID      = "7cc45d21-9a6e-4128-9f75-06e5167a4b80"
	TECHNIQUE_ID   = "T1518.001"
	TECHNIQUE_NAME = "Discovery: Security Products, Accounts & Domain Context (T1518.001/T1087/T1082)"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	exitCode := performTechnique()

	switch exitCode {
	case StageSuccess:
		fmt.Printf("[STAGE %s] Discovery executed without prevention\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "Security-product, account and system discovery completed unimpeded")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Discovery primitives executed without prevention")
	case StageBlocked:
		fmt.Printf("[STAGE %s] Discovery prevented (positive evidence)\n", TECHNIQUE_ID)
		LogMessage("BLOCKED", TECHNIQUE_ID, "Discovery prevented with positive protection evidence")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Discovery command refused with positive protection evidence", StageBlocked)
	default:
		fmt.Printf("[STAGE %s] Stage error - prerequisites not met or inconclusive\n", TECHNIQUE_ID)
		LogMessage("ERROR", TECHNIQUE_ID, "Discovery stage inconclusive or prerequisite failure")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive")
	}
	os.Exit(exitCode)
}

// discoveryStep tracks one enumeration primitive (Rule 4: separate counters —
// discovery steps are all "simulation" steps; a refused LAUNCH is the only
// protection signal here).
type discoveryStep struct {
	name    string
	command string
	output  string
	ranOK   bool
	refused bool // process creation itself was denied (protection evidence)
	errMsg  string
}

func performTechnique() int {
	steps := []discoveryStep{}

	// ------------------------------------------------------------------
	// Step 1: Security software discovery (T1518.001)
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 1: Enumerating installed security products (T1518.001)\n", TECHNIQUE_ID)

	// 1a. SecurityCenter2 WMI query — wmic shape first (actor-era tradecraft),
	// PowerShell Get-CimInstance fallback when wmic is removed (Win11 24H2+).
	wmicPath, _ := exec.LookPath("wmic.exe")
	if wmicPath != "" {
		steps = append(steps, runStep("SecurityCenter2 (wmic)",
			`wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState`,
			"wmic.exe", "/namespace:\\\\root\\SecurityCenter2", "path", "AntiVirusProduct", "get", "displayName,productState"))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "wmic.exe not present (Win11 24H2 removal) - using PowerShell Get-CimInstance fallback")
	}
	steps = append(steps, runStep("SecurityCenter2 (PowerShell)",
		`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select displayName,productState`,
		"powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState"))

	// 1b. Known AV/EDR service probes (sc.exe query — registry service names,
	// Rule 6; read-only telemetry, services are never touched). Includes the
	// Sophos endpoint-defense service names: the 2026-11 win lab runs Sophos
	// Intercept X (Sophos CTU is also a primary source for this test).
	for _, svc := range []string{"WinDefend", "Sense", "CSFalconService", "SepMasterService", "SophosMMS", "Sophos Endpoint Defense", "SEDService", "WdNisSvc"} {
		steps = append(steps, runStep(fmt.Sprintf("sc query %s", svc),
			fmt.Sprintf("sc.exe query %s", svc), "sc.exe", "query", svc))
	}

	// 1c. Known EDR process hunt via tasklist (actor's tasklist findstr shape).
	steps = append(steps, runStep("EDR process hunt",
		`tasklist /v /fo csv | findstr /i "csagent sensedefend sophos sep"`,
		"cmd.exe", "/Q", "/c", `tasklist /v /fo csv | findstr /i "csagent sensedefend sophos sep"`))

	// ------------------------------------------------------------------
	// Step 2: Mass account enumeration (T1087) — the 1.bat shape
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 2: Mass account enumeration, 1.bat shape (T1087)\n", TECHNIQUE_ID)

	// 2a. Enumerate the enumeration script itself: the actor wrote 1.bat then
	// ran it. We emulate the visible command surface directly.
	netCommands := [][]string{
		{"user", "/domain"},                                   // domain account census (fails benignly on non-domain host)
		{"user", "administrator", "/domain"},                  // high-value account probe (actor: admin.it, fortigate)
		{"group", "domain admins", "/domain"},                 // domain admins
		{"group", "Enterprise admins", "/domain"},             // enterprise admins
		{"localgroup", "administrators"},                      // local administrators
		{"localgroup", `__vmware__*`},                         // virtualization groups (actor IO)
	}
	for _, args := range netCommands {
		display := "net " + strings.Join(args, " ")
		steps = append(steps, runStep(display, display, "net.exe", args...))
	}

	// 2b. Current privilege context (whoami).
	steps = append(steps, runStep("whoami /all", "whoami.exe /all", "whoami.exe", "/all"))

	// ------------------------------------------------------------------
	// Step 3: System & AD domain context (T1082)
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 3: System and domain context (T1082)\n", TECHNIQUE_ID)

	steps = append(steps, runStep("hostname", "hostname.exe", "hostname.exe"))
	steps = append(steps, runStep("systeminfo", "systeminfo.exe", "systeminfo.exe"))
	steps = append(steps, runStep("computer domain",
		`wmic computersystem get domain`, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-CimInstance -ClassName Win32_ComputerSystem).Domain"))

	// ------------------------------------------------------------------
	// Step 4: Encoded-PowerShell PDC probe (Trend Micro IO, T1059.001 shape)
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 4: Encoded PowerShell PDC probe (actor command shape)\n", TECHNIQUE_ID)

	encCmd := utf16leBase64("(Get-ADDomain).PDCEmulator")
	steps = append(steps, runStep("encoded PDC probe",
		fmt.Sprintf("powershell.exe -noni -nop -w 1 -enc <%d chars> -> (Get-ADDomain).PDCEmulator", len(encCmd)),
		"powershell.exe", "-noni", "-nop", "-w", "1", "-enc", encCmd))

	// ------------------------------------------------------------------
	// Classification (Rule 8 + Rule 4)
	// ------------------------------------------------------------------
	ran, refused, failed := 0, 0, 0
	for _, s := range steps {
		switch {
		case s.refused:
			refused++
			LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("Process creation refused for %q: %v", s.name, s.errMsg))
		case s.ranOK:
			ran++
		default:
			failed++
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("%q completed without output success (prerequisite-shaped failure): %v", s.name, s.errMsg))
		}
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Discovery step totals: ran=%d refused=%d benign-failure=%d (of %d)", ran, refused, failed, len(steps)))

	// The critical protection metric: a refused launch is positive evidence
	// of prevention (ASR/AppLocker/EDR blocking recon tooling). Benign
	// failures (missing AD, missing tools) are prerequisites, not blocks.
	if refused > 0 {
		return StageBlocked
	}
	if ran == 0 {
		// Nothing executed at all — test error, not a block (Rule 8).
		LogMessage("ERROR", TECHNIQUE_ID, "No discovery primitive executed - prerequisite failure")
		return StageError
	}
	return StageSuccess
}

// runStep executes one enumeration command, logs it, and records whether the
// process launched, was refused, or ran and failed benignly. Command output
// is truncated before logging.
func runStep(name, display string, argv0 string, args ...string) discoveryStep {
	cmd := exec.Command(argv0, args...)
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))

	status := 0
	success := err == nil
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			status = exitErr.ExitCode()
		} else {
			status = -1
		}
	}
	LogProcessExecution(argv0, display, 0, success, status, truncateOut(outStr))

	s := discoveryStep{name: name, command: display, output: truncateOut(outStr), ranOK: success, errMsg: ""}
	if err != nil {
		s.errMsg = err.Error()
		// Launch refusal (not an ExitError): the OS/EDR refused to create the
		// process for a built-in Windows binary — positive protection evidence.
		if _, ok := err.(*exec.ExitError); !ok {
			s.refused = true
		}
	}
	return s
}

// utf16leBase64 encodes s the way powershell -EncodedCommand expects
// (UTF-16LE code units, big-endian per unit, then std base64).
func utf16leBase64(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 0xFFFF || (r >= 0xD800 && r <= 0xDFFF) {
			r = '?'
		}
		b.WriteByte(byte(r))    // low byte first
		b.WriteByte(byte(r>>8)) // high byte second
	}
	return base64.StdEncoding.EncodeToString([]byte(b.String()))
}

func truncateOut(s string) string {
	if len(s) > 400 {
		return s[:400] + " ...[truncated]"
	}
	if s == "" {
		return "(no output)"
	}
	return s
}
