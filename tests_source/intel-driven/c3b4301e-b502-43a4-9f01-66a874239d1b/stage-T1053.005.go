//go:build windows
// +build windows

/*
STAGE 5: Scheduled Task Persistence (T1053.005)
Recreates the RedFlick persistence layer: the malicious MSI installs three
scheduled tasks masquerading as network components, using the exact task
names from the Microsoft disclosure:

  - "Internet Quality Test Connection"   (registration beacon + DLL execution)
  - "Network Configuration Manager"      (WebDAV enablement)
  - "System Health Monitor"              (CosmicPulse downloader via control.exe)

SAFETY: task actions point at inert decoy scripts in ARTIFACT_DIR (they only
append a line to a LOG_DIR log). Pre-existing tasks with identical names are
NEVER created over or deleted — each task is checked first and its
pre-existence recorded in the cleanup state file, so the embedded cleanup
utility restores exactly what this test created. The WebClient service
(WebDAV enablement performed by "Network Configuration Manager" in the real
chain) is intentionally NOT started — see the Realism Lift Proposals in
<uuid>_info.md.
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
	TEST_UUID      = "c3b4301e-b502-43a4-9f01-66a874239d1b"
	TECHNIQUE_ID   = "T1053.005"
	TECHNIQUE_NAME = "Scheduled Task Persistence Trio"
	STAGE_ID       = 5

	INVITE_SUBDIR = "StarBlizzardInvite"
	STATE_FILE    = "scheduled_task_state.txt"
)

// Exact task names from the RedFlick disclosure; trigger details are not
// specified in the source — daily-09:30 and logon triggers are used as the
// documented plausible defaults.
var persistenceTasks = []struct {
	Name     string
	Schedule string
	Extra    []string // extra schtasks args per schedule type
}{
	{Name: "Internet Quality Test Connection", Schedule: "DAILY", Extra: []string{"/ST", "09:30"}},
	{Name: "Network Configuration Manager", Schedule: "ONLOGON", Extra: nil},
	{Name: "System Health Monitor", Schedule: "ONLOGON", Extra: nil},
}

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Create the three RedFlick persistence tasks by their real names")

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

	fmt.Printf("[STAGE %s] Persistence task trio created\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "all three persistence tasks created and verified")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "RedFlick task trio present with inert decoy actions")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	dir := filepath.Join(ARTIFACT_DIR, INVITE_SUBDIR)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("artifact directory creation failed: %v", err)
	}

	// Inert decoy action targets — if a task ever fires before cleanup, it
	// only appends a timestamped line to the LOG_DIR fire log.
	var stateLines []string
	for i, task := range persistenceTasks {
		decoyAction := filepath.Join(dir, fmt.Sprintf("task%d_action.cmd", i+1))
		script := fmt.Sprintf("@echo off\r\necho %%date%% %%time%% task '%s' fired >> \"%s\"\r\n", task.Name, filepath.Join(LOG_DIR, "task_fire.log"))
		if err := os.WriteFile(decoyAction, []byte(script), 0755); err != nil {
			return fmt.Errorf("decoy action write failed for task %d: %v", i+1, err)
		}
		LogFileDropped(filepath.Base(decoyAction), decoyAction, int64(len(script)), false)
	}

	isSystem := isSystemContext()
	created := 0
	skipped := 0

	for _, task := range persistenceTasks {
		existed := scheduledTaskExists(task.Name)
		stateLines = append(stateLines, fmt.Sprintf("TASK=%s|EXISTED_BEFORE=%v", task.Name, existed))

		if existed {
			// Never touch a task we did not create
			LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("task '%s' already present on host — leaving untouched", task.Name))
			skipped++
			continue
		}

		args := []string{"/Create", "/TN", task.Name, "/TR", fmt.Sprintf("\"%s\"", filepath.Join(dir, fmt.Sprintf("task%d_action.cmd", indexOfTask(task.Name)+1))), "/SC", task.Schedule, "/F"}
		args = append(args, task.Extra...)
		if isSystem {
			args = append(args, "/RU", "SYSTEM")
		} else {
			args = append(args, "/RL", "LIMITED")
		}

		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("creating task '%s' (%s) -> %s", task.Name, task.Schedule, filepath.Join(dir, fmt.Sprintf("task%d_action.cmd", indexOfTask(task.Name)+1))))
		out, err := exec.Command("schtasks.exe", args...).CombinedOutput()
		outputStr := strings.TrimSpace(string(out))
		if err != nil {
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("schtasks output: %s", outputStr))
			return classifySchtasksFailure(task.Name, err, outputStr)
		}
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("schtasks output: %s", outputStr))
		created++
	}

	// Verify creation (only the tasks we created)
	time.Sleep(2 * time.Second)
	for _, task := range persistenceTasks {
		if !scheduledTaskExists(task.Name) {
			// A task we just created vanishing is affirmative quarantine evidence
			return fmt.Errorf("task '%s' not present immediately after reported creation (possible quarantine of task or action file)", task.Name)
		}
	}

	// Persist cleanup state before declaring success
	statePath := filepath.Join(LOG_DIR, STATE_FILE)
	if err := os.WriteFile(statePath, []byte(strings.Join(stateLines, "\n")+"\n"), 0644); err != nil {
		return fmt.Errorf("cleanup state write failed: %v", err)
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("persistence established: %d created, %d skipped (pre-existing), cleanup state saved", created, skipped))
	return nil
}

func indexOfTask(name string) int {
	for i, t := range persistenceTasks {
		if t.Name == name {
			return i
		}
	}
	return -1
}

// classifySchtasksFailure separates an OS-emitted denial (positive protection
// evidence) from schtasks usage errors (test errors) per Bug Prevention Rule 8.
func classifySchtasksFailure(taskName string, err error, output string) error {
	lower := strings.ToLower(output)
	if strings.Contains(lower, "access is denied") || strings.Contains(lower, "access denied") {
		return fmt.Errorf("schtasks.exe reported OS-emitted denial while creating task '%s': %s", taskName, output)
	}
	if strings.Contains(lower, "virus") || strings.Contains(lower, "threat") || strings.Contains(lower, "quarantine") {
		return fmt.Errorf("schtasks.exe reported security-engine intervention while creating task '%s': %s", taskName, output)
	}
	// Usage/privilege errors and empty outputs are ambiguous — never a block
	return fmt.Errorf("schtasks.exe failed for task '%s' with unclear outcome: %v (output: %s)", taskName, err, output)
}

func scheduledTaskExists(taskName string) bool {
	out, err := exec.Command("schtasks.exe", "/Query", "/TN", taskName).CombinedOutput()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(out))) > 0
}

func isSystemContext() bool {
	username := os.Getenv("USERNAME")
	return strings.HasSuffix(username, "$") || strings.EqualFold(username, "SYSTEM")
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"os-emitted denial", "access denied", "access is denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"security-engine intervention", "quarantined", "virus", "threat", "possible quarantine"}) {
		return StageQuarantined
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
