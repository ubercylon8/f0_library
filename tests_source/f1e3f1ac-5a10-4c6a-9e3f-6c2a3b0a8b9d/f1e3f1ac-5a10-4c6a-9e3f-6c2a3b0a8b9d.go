//go:build windows
// +build windows

/*
ID: f1e3f1ac-5a10-4c6a-9e3f-6c2a3b0a8b9d
NAME: FIREFLAME Ransomware Emulation (DRAGONFORCE RaaS)
TECHNIQUE: T1112,T1480.002,T1059.005,T1070.004,T1033,T1057,T1082,T1083
UNIT: response
CREATED: 2025-10-17
*/
package main

import (
    _ "embed"
    "bytes"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "syscall"
    "time"
    "unicode/utf16"
    "unsafe"

    Dropper "github.com/preludeorg/libraries/go/tests/dropper"
    Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed defender_evasion.ps1
var defenderScript []byte

func checkAdminPrivileges() bool {
    cmd := exec.Command("net", "session")
    err := cmd.Run()
    return err == nil
}

func utf16PtrFromString(s string) *uint16 {
    a := utf16.Encode([]rune(s + "\x00"))
    return &a[0]
}

func createNamedMutex(name string) (syscall.Handle, error) {
    k32 := syscall.NewLazyDLL("kernel32.dll")
    proc := k32.NewProc("CreateMutexW")
    namePtr := utf16PtrFromString(name)
    r1, _, e1 := proc.Call(0, 0, uintptr(unsafe.Pointer(namePtr)))
    if r1 == 0 {
        if e1 != nil {
            return 0, e1
        }
        return 0, fmt.Errorf("CreateMutexW failed")
    }
    return syscall.Handle(r1), nil
}

func dropPaddedBinary(path string, size int64) error {
    f, err := os.Create(path)
    if err != nil {
        return err
    }
    defer f.Close()
    // Minimal MZ header to simulate PE
    if _, err := f.Write([]byte{0x4D, 0x5A}); err != nil {
        return err
    }
    if err := f.Truncate(size); err != nil {
        return err
    }
    return nil
}

func createService(serviceName, displayName, binaryPath string) error {
    Endpoint.Say("Creating service: %s", serviceName)
    cmd := exec.Command("sc", "create", serviceName,
        "binPath=", binaryPath,
        "DisplayName=", displayName,
        "type=", "kernel",
        "start=", "demand")
    output, err := cmd.CombinedOutput()
    if err != nil {
        out := string(output)
        if strings.Contains(out, "already exists") {
            Endpoint.Say("Service %s already exists", serviceName)
            return nil
        }
        return fmt.Errorf("failed to create service %s: %v | %s", serviceName, err, out)
    }
    Endpoint.Say("Successfully created service: %s", serviceName)
    return nil
}

func deleteService(serviceName string) {
    cmd := exec.Command("sc", "delete", serviceName)
    _, _ = cmd.CombinedOutput()
}

func writeVBS(path string) error {
    // Hidden execution via WScript (benign)
    content := "Set WshShell = CreateObject(\"WScript.Shell\")\r\n" +
        "WshShell.Run \"cmd /c echo FIREFLAME_VBS\", 0, True\r\n"
    return os.WriteFile(path, []byte(content), 0644)
}

func runHiddenVBS(script string) error {
    cmd := exec.Command("wscript.exe", "//B", "//nologo", script)
    if out, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("wscript blocked: %v output: %s", err, string(out))
    }
    return nil
}

func runCommand(name string, args ...string) string {
    cmd := exec.Command(name, args...)
    out, _ := cmd.CombinedOutput()
    return strings.TrimSpace(string(out))
}

func executeDefenderEvasion(scriptPath string) error {
    cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", scriptPath)
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("PowerShell blocked: %v output: %s", err, string(out))
    }
    return nil
}

func test() {
    if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
        Endpoint.Say("Dropper initialization failed")
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }

    Endpoint.Say("Starting FIREFLAME ransomware emulation (DRAGONFORCE RaaS)")

    if !checkAdminPrivileges() {
        Endpoint.Say("Admin privileges required for registry tamper checks")
        Endpoint.Stop(Endpoint.NotRelevant)
    }

    targetDir := "c:\\F0"
    if err := os.MkdirAll(targetDir, 0755); err != nil {
        Endpoint.Say("Failed to create target directory: %v", err)
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }

    // ===============================
    // Guardrails: Mutex (T1480.002)
    // ===============================
    Endpoint.Say("Creating named mutex for execution guardrails")
    if _, err := createNamedMutex("Global\\FIREFLAME_MUTEX"); err != nil {
        Endpoint.Say("Mutex creation failed (non-fatal): %v", err)
    }

    // ======================================
    // Masquerade + Padding (T1036.001/T1027.001)
    // ======================================
    masqueradePath := filepath.Join(targetDir, "svchost.exe")
    if err := dropPaddedBinary(masqueradePath, 200*1024); err != nil {
        Endpoint.Say("Failed to drop masquerade binary: %v", err)
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }

    // Short window to detect quarantine
    Endpoint.Wait(2)
    if !Endpoint.Exists(masqueradePath) {
        Endpoint.Say("Masqueraded binary quarantined on extraction")
        Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
    }

    // ===============================
    // Hidden VBS (T1059.005 + T1564.003)
    // ===============================
    vbsPath := filepath.Join(targetDir, "ffl.vbs")
    if err := writeVBS(vbsPath); err != nil {
        Endpoint.Say("Failed to write VBS: %v", err)
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }
    if err := runHiddenVBS(vbsPath); err != nil {
        Endpoint.Say("VBS execution blocked: %v", err)
        Endpoint.Stop(Endpoint.ExecutionPrevented)
    }

    // ===============================
    // Discovery (T1033/T1057/T1082/T1083)
    // ===============================
    Endpoint.Say("Running discovery commands")
    who := runCommand("whoami")
    procs := runCommand("tasklist")
    sysinfo := runCommand("cmd", "/c", "ver")
    dirlist := runCommand("cmd", "/c", "dir", targetDir)
    // Log trimmed outputs
    Endpoint.Say("whoami: %s", who)
    if len(procs) > 0 {
        Endpoint.Say("processes: %d chars", len(procs))
    }
    Endpoint.Say("system: %s", sysinfo)
    Endpoint.Say("dir %s: %d chars", targetDir, len(dirlist))

    // ===============================
    // Indicator removal: create+delete (T1070.004)
    // ===============================
    tmpPath := filepath.Join(targetDir, "ff_cleanup.tmp")
    if err := os.WriteFile(tmpPath, []byte("ff"), 0644); err == nil {
        _ = os.Remove(tmpPath)
    }

    // ========================================
    // Service creation simulation (kernel type)
    // ========================================
    Endpoint.Say("Service registration simulation with decoy drivers")
    rwdrv := filepath.Join(targetDir, "rwdrv.sys")
    hlpdrv := filepath.Join(targetDir, "hlpdrv.sys")
    if err := dropPaddedBinary(rwdrv, 15360); err != nil {
        Endpoint.Say("Failed to drop rwdrv.sys: %v", err)
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }
    if err := dropPaddedBinary(hlpdrv, 24576); err != nil {
        Endpoint.Say("Failed to drop hlpdrv.sys: %v", err)
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }
    if err := createService("mgdsrv", "Malicious Guard Driver Service", rwdrv); err != nil {
        Endpoint.Say("Service creation blocked: %v", err)
        Endpoint.Stop(Endpoint.ExecutionPrevented)
    }
    if err := createService("KMHLPSVC", "Kernel Mode Helper Service", hlpdrv); err != nil {
        Endpoint.Say("Service creation blocked: %v", err)
        Endpoint.Stop(Endpoint.ExecutionPrevented)
    }

    // ===============================
    // Registry Tampering (T1112) – Defender keys
    // ===============================
    scriptPath := filepath.Join(targetDir, "defender_evasion.ps1")
    if err := os.WriteFile(scriptPath, bytes.TrimSpace(defenderScript), 0644); err != nil {
        Endpoint.Say("Failed to write PowerShell script: %v", err)
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }

    statusFile := filepath.Join(targetDir, "status.txt")
    // Ensure clean status
    _ = os.Remove(statusFile)

    if err := executeDefenderEvasion(scriptPath); err != nil {
        Endpoint.Say("PowerShell execution blocked: %v", err)
        Endpoint.Stop(Endpoint.ExecutionPrevented)
    }

    Endpoint.Say("Waiting for Defender registry tamper status")
    time.Sleep(5 * time.Second)

    data, _ := os.ReadFile(statusFile)
    status := strings.TrimSpace(string(data))
    Endpoint.Say("Status: %s", status)

    switch {
    case strings.Contains(status, "DEFENDER_DISABLED"):
        Endpoint.Say("Windows Defender policy modification succeeded")
        Endpoint.Stop(Endpoint.Unprotected)
    case strings.Contains(status, "ACCESS_DENIED"):
        Endpoint.Say("Registry access denied – protection in place")
        Endpoint.Stop(Endpoint.ExecutionPrevented)
    default:
        Endpoint.Say("Unexpected or empty status – assuming protection prevented action")
        Endpoint.Stop(Endpoint.ExecutionPrevented)
    }
}

func clean() {
    Endpoint.Say("Cleaning FIREFLAME artifacts")
    targetDir := "c:\\F0"
    files := []string{
        "svchost.exe",
        "ffl.vbs",
        "ff_cleanup.tmp",
        "defender_evasion.ps1",
        "status.txt",
        "rwdrv.sys",
        "hlpdrv.sys",
    }
    // delete services first
    deleteService("mgdsrv")
    deleteService("KMHLPSVC")
    for _, f := range files {
        _ = os.Remove(filepath.Join(targetDir, f))
    }
}

func main() { Endpoint.Start(test, clean) }
