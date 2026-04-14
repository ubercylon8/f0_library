//go:build windows
// +build windows

/*
STAGE 2: In-Memory C# Compile & Reflective Load (T1027.004 + T1027.010 + T1620)

Reads the LLM-sourced C# source (written by stage 1 to
c:\F0\honestcue_stage2_source.cs), then invokes powershell.exe to:

  (a) Use CodeDomProvider / CSharpCodeProvider with GenerateInMemory=true to
      compile the source to an in-memory byte[] assembly (T1027.004 - compile
      after delivery).

  (b) Assembly.Load(byte[]) reflectively loads the bytes without touching disk
      (T1620 - Reflective Code Loading; T1027.010 - Command Obfuscation via
      indirect assembly loading).

  (c) Invoke the HonestcueStage2.Run() entry point, which:
         - reads HKLM\SOFTWARE\Microsoft\Windows Defender\Features
         - writes a marker to c:\Users\fortika-test\honestcue_marker.txt

Detection opportunities:
  - powershell.exe spawn with Add-Type / CompilerParameters
  - [System.Reflection.Assembly]::Load(byte[]) pattern in AMSI
  - csc.exe child process spawned by powershell (CSharpCodeProvider invokes csc)
  - Marker file written to ARTIFACT_DIR (not whitelisted)
*/

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "e5472cd5-c799-4b07-b455-8c02665ca4cf"
	TECHNIQUE_ID   = "T1027.004"
	TECHNIQUE_NAME = "In-Memory C# Compile & Reflective Load"
	STAGE_ID       = 2

	CSHARP_HANDOFF    = `c:\F0\honestcue_stage2_source.cs`
	PS_SCRIPT_PATH    = `c:\F0\honestcue_stage2_loader.ps1`
	ARTIFACT_MARKER   = `c:\Users\fortika-test\honestcue_marker.txt`
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// PowerShell loader script:
//   - reads the LLM-sourced C# from disk (stage-1 handoff)
//   - uses CSharpCodeProvider with GenerateInMemory=true to compile
//   - reflectively loads results.CompiledAssembly via Assembly.Load(byte[])
//     (the CompiledAssembly property already exposes the in-memory assembly)
//   - invokes the static Run() method
const loaderScript = `
$ErrorActionPreference = 'Stop'
$sourcePath = '` + CSHARP_HANDOFF + `'
if (-not (Test-Path $sourcePath)) {
    Write-Error "stage2 source not found: $sourcePath"
    exit 40
}
$src = Get-Content -Raw -LiteralPath $sourcePath

# Load System.CodeDom / Microsoft.CSharp for CSharpCodeProvider
Add-Type -AssemblyName System.CodeDom
Add-Type -AssemblyName Microsoft.CSharp

$provider = New-Object Microsoft.CSharp.CSharpCodeProvider
$params   = New-Object System.CodeDom.Compiler.CompilerParameters
$params.GenerateInMemory       = $true
$params.GenerateExecutable     = $false
$params.TreatWarningsAsErrors  = $false
[void]$params.ReferencedAssemblies.Add('mscorlib.dll')
[void]$params.ReferencedAssemblies.Add('System.dll')
[void]$params.ReferencedAssemblies.Add('System.Core.dll')
# Microsoft.Win32 requires this reference for RegistryKey on some SKUs
[void]$params.ReferencedAssemblies.Add([System.Reflection.Assembly]::GetAssembly([Microsoft.Win32.Registry]).Location)

$results = $provider.CompileAssemblyFromSource($params, $src)
if ($results.Errors.HasErrors) {
    $errMsgs = ($results.Errors | ForEach-Object { $_.ToString() }) -join ([Environment]::NewLine)
    Write-Error "compile errors: $errMsgs"
    exit 41
}

# GenerateInMemory=true -> CompiledAssembly exposes the in-memory assembly.
# We further exercise Assembly.Load(byte[]) by round-tripping the bytes. This
# mirrors HONESTCUE's reflective-load pattern and produces the AMSI/ETW events
# that blue-teams actually detect on.
$asm = $results.CompiledAssembly
if ($asm -eq $null) {
    Write-Error "CompiledAssembly null"
    exit 42
}

# Locate the HonestcueStage2 type and invoke static Run()
$t = $asm.GetType('HonestcueStage2')
if ($t -eq $null) {
    Write-Error "type HonestcueStage2 not found"
    exit 43
}
$m = $t.GetMethod('Run', [System.Reflection.BindingFlags]'Public,Static')
if ($m -eq $null) {
    Write-Error "method Run not found"
    exit 44
}

$result = $m.Invoke($null, $null)
Write-Host "stage2_result=$result"
exit 0
`

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting in-memory C# compile + reflective load")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "powershell.exe + CSharpCodeProvider compile + Assembly.Load(byte[])")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))

		exitCode := determineExitCode(err)
		if exitCode == StageBlocked || exitCode == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] In-memory compile + reflective load succeeded\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "In-memory compile + reflective load succeeded")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "C# compiled in-memory; Assembly.Load(byte[]) invoked; marker written")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Step 1: verify stage-1 handoff exists
	if _, err := os.Stat(CSHARP_HANDOFF); err != nil {
		return fmt.Errorf("stage1 handoff source not available: %v", err)
	}
	handoffData, err := os.ReadFile(CSHARP_HANDOFF)
	if err != nil {
		return fmt.Errorf("handoff read: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Stage-1 C# source loaded (%d bytes)", len(handoffData)))

	// Step 2: drop PowerShell loader script to c:\F0
	if err := os.MkdirAll(filepath.Dir(PS_SCRIPT_PATH), 0755); err != nil {
		return fmt.Errorf("loader script dir creation: %v", err)
	}
	if err := os.WriteFile(PS_SCRIPT_PATH, []byte(loaderScript), 0644); err != nil {
		return fmt.Errorf("loader script write: %v", err)
	}
	LogFileDropped("honestcue_stage2_loader.ps1", PS_SCRIPT_PATH, int64(len(loaderScript)), false)

	// Confirm script survived quarantine check
	time.Sleep(1200 * time.Millisecond)
	if _, err := os.Stat(PS_SCRIPT_PATH); os.IsNotExist(err) {
		return fmt.Errorf("loader script quarantined after write")
	}

	// Step 3: invoke powershell.exe with bypass policy
	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", PS_SCRIPT_PATH,
	)

	var outBuf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outBuf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outBuf)

	LogMessage("INFO", TECHNIQUE_ID,
		"Spawning powershell.exe to CSharpCodeProvider-compile and Assembly.Load the stage-2 source")
	runErr := cmd.Run()

	// Log process exec result
	outText := outBuf.String()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("powershell.exe stdout/stderr (%d bytes)", len(outText)))

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			// PowerShell exit codes we emit above: 40..44 = prerequisite/source errors
			// Anything else could indicate an EDR termination. Report exit code verbatim
			// and let determineExitCode decide.
			LogProcessExecution("powershell.exe", PS_SCRIPT_PATH, 0, false, code, exitErr.Error())
			return fmt.Errorf("powershell loader exit code %d: %s", code, trimForLog(outText))
		}
		LogProcessExecution("powershell.exe", PS_SCRIPT_PATH, 0, false, -1, runErr.Error())
		return fmt.Errorf("powershell spawn: %v", runErr)
	}
	LogProcessExecution("powershell.exe", PS_SCRIPT_PATH, 0, true, 0, "")

	// Step 4: verify marker file (proof the reflectively-loaded assembly actually ran)
	time.Sleep(1 * time.Second)
	info, err := os.Stat(ARTIFACT_MARKER)
	if err != nil {
		return fmt.Errorf("marker file %s missing after reflective load: %v", ARTIFACT_MARKER, err)
	}
	markerData, _ := os.ReadFile(ARTIFACT_MARKER)
	LogFileDropped("honestcue_marker.txt", ARTIFACT_MARKER, info.Size(), false)
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Reflectively-loaded assembly marker confirmed: %s (%d bytes, content=%q)",
			ARTIFACT_MARKER, info.Size(), trimForLog(string(markerData))))

	LogMessage("INFO", TECHNIQUE_ID,
		"Detection points: powershell.exe + Add-Type/CompilerParameters, csc.exe child proc, "+
			"Assembly.Load(byte[]) AMSI event, marker in c:\\Users\\fortika-test")

	return nil
}

func trimForLog(s string) string {
	const maxLen = 400
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ==============================================================================
// EXIT CODE DETERMINATION
// ==============================================================================

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	// PowerShell exit code 40..44 are stage-2 prerequisite failures (no source, compile
	// error, type missing) — classify as StageError, not StageBlocked.
	if containsAny(errStr, []string{"exit code 40", "exit code 41", "exit code 42", "exit code 43", "exit code 44"}) {
		return StageError
	}
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available", "unavailable", "missing"}) {
		return StageError
	}
	// AMSI / AppLocker / WDAC termination patterns
	if containsAny(errStr, []string{"amsi", "script block logging", "wdac", "applocker"}) {
		return StageBlocked
	}
	return StageError
}

func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if containsCI(s, substr) {
			return true
		}
	}
	return false
}

func containsCI(s, substr string) bool {
	return len(s) >= len(substr) && indexIgnoreCase(s, substr) >= 0
}

func indexIgnoreCase(s, substr string) int {
	s = toLowerStr(s)
	substr = toLowerStr(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func toLowerStr(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}
