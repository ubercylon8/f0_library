//go:build windows

package cyberhygiene

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

type WindowsService struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	State       string `json:"State"`
	StartMode   string `json:"StartMode"`
	PathName    string `json:"PathName"`
}

func NewControlResult(id, name, validator, severity, expected, source string, techniques []string) ControlResult {
	return ControlResult{
		ControlID:      id,
		ControlName:    name,
		Validator:      validator,
		Severity:       severity,
		Expected:       expected,
		EvidenceSource: source,
		Techniques:     techniques,
		Tactics:        []string{"defense-evasion"},
	}
}

func CentralPolicyUnknown(control ControlResult, source string) ControlResult {
	control.Status = StatusUnknown
	control.Compliant = false
	control.Actual = "Not evaluated without central management evidence"
	control.Details = "Read-only central host and effective-policy evidence is required"
	control.EvidenceSource = source
	return control
}

func RunWindowsPowerShell(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("PowerShell query exceeded 30 seconds")
		}
		return "", fmt.Errorf("PowerShell query failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func RunWindowsCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("%s query exceeded 30 seconds", name)
		}
		return "", fmt.Errorf("%s query failed: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func QueryWindowsServices(names []string) (map[string]WindowsService, error) {
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		quoted = append(quoted, "'"+strings.ReplaceAll(name, "'", "''")+"'")
	}
	script := fmt.Sprintf(`Get-CimInstance Win32_Service | Where-Object { $_.Name -in @(%s) } | Select-Object Name, DisplayName, State, StartMode, PathName | ConvertTo-Json -Compress`, strings.Join(quoted, ","))
	output, err := RunWindowsPowerShell(script)
	if err != nil {
		return nil, err
	}
	return parseWindowsServices(output)
}

func parseWindowsServices(output string) (map[string]WindowsService, error) {
	result := make(map[string]WindowsService)
	output = strings.TrimSpace(output)
	if output == "" {
		return result, nil
	}
	var services []WindowsService
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &services); err != nil {
			return nil, err
		}
	} else {
		var service WindowsService
		if err := json.Unmarshal([]byte(output), &service); err != nil {
			return nil, err
		}
		services = []WindowsService{service}
	}
	for _, service := range services {
		result[strings.ToLower(service.Name)] = service
	}
	return result, nil
}

func WindowsFileVersion(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	escaped := strings.ReplaceAll(path, "'", "''")
	output, err := RunWindowsPowerShell(fmt.Sprintf("(Get-Item -LiteralPath '%s' -ErrorAction Stop).VersionInfo.FileVersion", escaped))
	if err != nil {
		return "", err
	}
	if output == "" {
		return "", fmt.Errorf("file version is empty")
	}
	return output, nil
}

func WindowsRegistryUint(path, value string) (uint64, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, err
	}
	defer key.Close()
	valueData, _, err := key.GetIntegerValue(value)
	return valueData, err
}

func WindowsRegistryKeyExists(path string) (bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if IsWindowsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	key.Close()
	return true, nil
}

func IsWindowsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, syscall.ERROR_PATH_NOT_FOUND)
}
