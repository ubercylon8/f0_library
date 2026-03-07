//go:build windows
// +build windows

/*
STAGE 1: Server Software Component - Web Shell / IIS Backdoor (T1505.003)
Simulates APT34's CacheHttp.dll passive IIS backdoor module deployment.
Writes a benign DLL file to c:\F0 and simulates IIS module registration.
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "5691f436-e630-4fd2-b930-911023cf638f"
	TECHNIQUE_ID   = "T1505.003"
	TECHNIQUE_NAME = "Server Software Component: Web Shell"
	STAGE_ID       = 1
)

// Standardized stage exit codes
const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting IIS Backdoor Deployment simulation (CacheHttp.dll)")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Deploy simulated CacheHttp.dll IIS backdoor module")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique blocked/failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Blocked/Failed: %v", err))
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		exitCode := determineExitCode(err)
		os.Exit(exitCode)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, "IIS Backdoor deployment simulation completed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "CacheHttp.dll backdoor deployed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "c:\\F0"

	// Step 1: Create a benign DLL file simulating CacheHttp.dll
	// This is a benign file that mimics the artifact APT34 deploys as an IIS native module
	LogMessage("INFO", TECHNIQUE_ID, "Creating simulated CacheHttp.dll backdoor...")
	fmt.Printf("[STAGE %s] Creating simulated CacheHttp.dll IIS backdoor module\n", TECHNIQUE_ID)

	// Simulated DLL content - just a marker file, not actual malicious code
	dllContent := []byte("MZ" + strings.Repeat("\x00", 62) + // Minimal PE header marker
		"F0RT1KA_SIMULATION_APT34_CacheHttp.dll_IIS_Backdoor\x00" +
		"This is a simulation artifact for security testing.\x00" +
		"APT34/OilRig deploys CacheHttp.dll as a passive IIS module\x00" +
		"that intercepts HTTP requests containing specific patterns.\x00" +
		"The real backdoor processes requests with special headers to\x00" +
		"execute commands and exfiltrate data via HTTP responses.\x00")

	dllPath := filepath.Join(targetDir, "CacheHttp.dll")
	if err := os.WriteFile(dllPath, dllContent, 0755); err != nil {
		return fmt.Errorf("failed to write CacheHttp.dll: %v (access denied by security controls)", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Wrote CacheHttp.dll to %s (%d bytes)", dllPath, len(dllContent)))
	fmt.Printf("[STAGE %s] CacheHttp.dll written to %s (%d bytes)\n", TECHNIQUE_ID, dllPath, len(dllContent))

	// Allow EDR time to scan the file
	time.Sleep(2 * time.Second)

	// Verify file persists (not quarantined)
	if _, err := os.Stat(dllPath); os.IsNotExist(err) {
		return fmt.Errorf("CacheHttp.dll was quarantined immediately after creation")
	}

	// Step 2: Create IIS module registration simulation artifact
	// APT34 registers this DLL as a native IIS HTTP module
	LogMessage("INFO", TECHNIQUE_ID, "Creating IIS module registration artifact...")
	fmt.Printf("[STAGE %s] Simulating IIS native module registration\n", TECHNIQUE_ID)

	registrationContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!-- F0RT1KA SIMULATION: APT34 IIS Module Registration -->
<!-- Real APT34 operations use appcmd.exe to register native modules -->
<!-- Command: appcmd.exe install module /name:CacheHttp /image:%%windir%%\System32\inetsrv\CacheHttp.dll -->
<configuration>
  <system.webServer>
    <modules>
      <add name="CacheHttp" type="CacheHttp.CacheHttpModule" preCondition="managedHandler" />
    </modules>
    <globalModules>
      <add name="CacheHttp" image="%s" />
    </globalModules>
  </system.webServer>
</configuration>
`, dllPath)

	regPath := filepath.Join(targetDir, "iis_module_registration.xml")
	if err := os.WriteFile(regPath, []byte(registrationContent), 0644); err != nil {
		return fmt.Errorf("failed to write IIS registration artifact: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("IIS module registration artifact created: %s", regPath))
	fmt.Printf("[STAGE %s] IIS module registration artifact created: %s\n", TECHNIQUE_ID, regPath)

	// Step 3: Attempt IIS module registration via appcmd.exe (LOLBin)
	// APT34 uses appcmd.exe to register CacheHttp.dll as a native IIS HTTP module
	// appcmd.exe is a legitimate IIS management LOLBin used for module installation
	fmt.Printf("[STAGE %s] Attempting IIS module registration via appcmd.exe (LOLBin)\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Attempting IIS native module registration via appcmd.exe")

	appcmdPath := `C:\Windows\System32\inetsrv\appcmd.exe`
	if _, err := os.Stat(appcmdPath); err == nil {
		// appcmd.exe exists (IIS is installed) — attempt module registration
		LogMessage("INFO", TECHNIQUE_ID, "appcmd.exe found — IIS is installed, attempting module registration")

		installCmd := exec.Command(appcmdPath, "install", "module",
			"/name:CacheHttp",
			fmt.Sprintf("/image:%s", dllPath),
		)
		installOutput, installErr := installCmd.CombinedOutput()
		installOutputStr := strings.TrimSpace(string(installOutput))

		if installErr != nil {
			fmt.Printf("[STAGE %s] appcmd.exe module install result: %s (err: %v)\n", TECHNIQUE_ID, installOutputStr, installErr)
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("appcmd.exe blocked or failed: %s", installOutputStr))

			if strings.Contains(strings.ToLower(installOutputStr), "access") ||
				strings.Contains(strings.ToLower(installOutputStr), "denied") ||
				strings.Contains(strings.ToLower(installOutputStr), "blocked") {
				return fmt.Errorf("IIS module registration blocked via appcmd.exe: %s", installOutputStr)
			}
			// Non-blocking failure (e.g., module name conflict) — continue
			LogMessage("INFO", TECHNIQUE_ID, "appcmd.exe returned error but not blocked by EDR — continuing")
		} else {
			fmt.Printf("[STAGE %s] WARNING: IIS module registered without prevention: %s\n", TECHNIQUE_ID, installOutputStr)
			LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("CacheHttp.dll registered as IIS module without detection: %s", installOutputStr))

			// SAFETY: Immediately uninstall the module
			uninstallCmd := exec.Command(appcmdPath, "uninstall", "module", "CacheHttp")
			uninstallOutput, _ := uninstallCmd.CombinedOutput()
			fmt.Printf("[STAGE %s] SAFETY: Module uninstalled: %s\n", TECHNIQUE_ID, strings.TrimSpace(string(uninstallOutput)))
			LogMessage("INFO", TECHNIQUE_ID, "SAFETY: CacheHttp module uninstalled from IIS")
		}

		// Allow EDR reaction time
		time.Sleep(2 * time.Second)
	} else {
		// IIS not installed — log and continue
		fmt.Printf("[STAGE %s] appcmd.exe not found — IIS not installed, skipping module registration\n", TECHNIQUE_ID)
		LogMessage("INFO", TECHNIQUE_ID, "IIS not installed (appcmd.exe not found) — skipping LOLBin registration, continuing with artifact-only simulation")
	}

	// Step 4: Create HTTP request interception pattern file
	// Documents the specific HTTP patterns CacheHttp.dll looks for
	interceptPatterns := `# F0RT1KA SIMULATION: CacheHttp.dll HTTP Interception Patterns
# APT34's CacheHttp.dll monitors incoming HTTP requests for:

# Command delivery via custom HTTP headers:
X-Cache-Http: <base64-encoded-command>

# Response exfiltration via cookies:
Set-Cookie: CacheHttp=<base64-encoded-output>

# Backdoor activation URL patterns:
GET /ews/exchange.asmx?cache=<command-id>
POST /owa/auth/logon.aspx (with X-Cache-Http header)

# The module operates passively - it does not create new connections
# but piggybacks on legitimate IIS traffic to blend in.
`

	patternPath := filepath.Join(targetDir, "cachehttp_patterns.txt")
	if err := os.WriteFile(patternPath, []byte(interceptPatterns), 0644); err != nil {
		return fmt.Errorf("failed to write intercept patterns: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, "HTTP interception pattern documentation created")
	fmt.Printf("[STAGE %s] HTTP interception patterns documented at %s\n", TECHNIQUE_ID, patternPath)

	LogMessage("SUCCESS", TECHNIQUE_ID, "IIS backdoor simulation artifacts deployed successfully")
	return nil
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "access denied") ||
		strings.Contains(errStr, "access is denied") ||
		strings.Contains(errStr, "permission denied") ||
		strings.Contains(errStr, "blocked") ||
		strings.Contains(errStr, "prevented") {
		return StageBlocked
	}
	if strings.Contains(errStr, "quarantine") ||
		strings.Contains(errStr, "quarantined") ||
		strings.Contains(errStr, "virus") ||
		strings.Contains(errStr, "threat") {
		return StageQuarantined
	}
	return StageBlocked
}
