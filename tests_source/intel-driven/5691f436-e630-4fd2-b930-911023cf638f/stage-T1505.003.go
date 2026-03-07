//go:build windows
// +build windows

/*
STAGE 1: Server Software Component - Web Shell / IIS Backdoor (T1505.003)
Simulates APT34's CacheHttp.dll passive IIS backdoor module deployment.
Writes a benign DLL file to c:\F0 and simulates IIS module registration.
*/

package main

import (
	"encoding/binary"
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

	// Build a proper PE-structured DLL with IIS module export table
	// Real CacheHttp.dll is a native IIS module exporting CHttpModule class methods
	// EDR heuristics inspect PE headers, export tables, and section names
	dllContent := buildCacheHttpPEDll()

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

// buildCacheHttpPEDll constructs a valid PE DLL binary with IIS module exports.
// The DLL has proper MZ/PE headers, .text and .edata sections, and an export table
// advertising CHttpModule class methods (RegisterModule, OnBeginRequest, etc.)
// that are all no-op stubs. This triggers EDR heuristics that inspect PE structure
// and IIS module exports without containing any executable payload.
func buildCacheHttpPEDll() []byte {
	buf := make([]byte, 4096) // Minimum PE section alignment

	// ── DOS Header (64 bytes) ──
	copy(buf[0:2], []byte("MZ"))                            // e_magic
	binary.LittleEndian.PutUint32(buf[60:64], 0x80)         // e_lfanew → PE signature at offset 0x80

	// ── DOS stub message ──
	copy(buf[64:], []byte("This program cannot be run in DOS mode.\r\n"))

	// ── PE Signature (offset 0x80) ──
	pe := 0x80
	copy(buf[pe:pe+4], []byte("PE\x00\x00"))

	// ── COFF Header (20 bytes at offset 0x84) ──
	coff := pe + 4
	binary.LittleEndian.PutUint16(buf[coff:], 0x14C)        // Machine: IMAGE_FILE_MACHINE_I386
	binary.LittleEndian.PutUint16(buf[coff+2:], 2)           // NumberOfSections (.text, .edata)
	binary.LittleEndian.PutUint32(buf[coff+4:], 0x67CA0000)  // TimeDateStamp (fake)
	binary.LittleEndian.PutUint16(buf[coff+16:], 0xE0)       // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(buf[coff+18:], 0x2102)     // Characteristics: DLL | EXECUTABLE_IMAGE | 32BIT_MACHINE

	// ── Optional Header PE32 (224 = 0xE0 bytes at offset 0x98) ──
	opt := coff + 20
	binary.LittleEndian.PutUint16(buf[opt:], 0x10B)          // Magic: PE32
	buf[opt+2] = 14                                           // MajorLinkerVersion
	binary.LittleEndian.PutUint32(buf[opt+16:], 0x1000)      // AddressOfEntryPoint (RVA)
	binary.LittleEndian.PutUint32(buf[opt+28:], 0x10000000)  // ImageBase
	binary.LittleEndian.PutUint32(buf[opt+32:], 0x1000)      // SectionAlignment
	binary.LittleEndian.PutUint32(buf[opt+36:], 0x200)       // FileAlignment
	binary.LittleEndian.PutUint16(buf[opt+40:], 6)           // MajorOSVersion
	binary.LittleEndian.PutUint16(buf[opt+44:], 6)           // MajorSubsystemVersion
	binary.LittleEndian.PutUint32(buf[opt+56:], 0x3000)      // SizeOfImage
	binary.LittleEndian.PutUint32(buf[opt+60:], 0x200)       // SizeOfHeaders
	binary.LittleEndian.PutUint16(buf[opt+68:], 2)           // Subsystem: GUI
	binary.LittleEndian.PutUint16(buf[opt+70:], 0x8160)      // DllCharacteristics: NX | DYNAMIC_BASE | HIGH_ENTROPY_VA | TERMINAL_SERVER_AWARE
	binary.LittleEndian.PutUint32(buf[opt+72:], 0x100000)    // SizeOfStackReserve
	binary.LittleEndian.PutUint32(buf[opt+76:], 0x1000)      // SizeOfStackCommit
	binary.LittleEndian.PutUint32(buf[opt+80:], 0x100000)    // SizeOfHeapReserve
	binary.LittleEndian.PutUint32(buf[opt+84:], 0x1000)      // SizeOfHeapCommit
	binary.LittleEndian.PutUint32(buf[opt+88:], 16)          // NumberOfRvaAndSizes

	// Data Directory[0] — Export Table (RVA=0x2000 in .edata, size filled below)
	dd := opt + 96
	binary.LittleEndian.PutUint32(buf[dd:], 0x2000)          // Export Table RVA
	binary.LittleEndian.PutUint32(buf[dd+4:], 0x200)         // Export Table Size

	// ── Section Table (at offset 0x178) ──
	secTable := opt + 0xE0 // = 0x178
	// Section 1: .text
	copy(buf[secTable:], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(buf[secTable+8:], 0x100)   // VirtualSize
	binary.LittleEndian.PutUint32(buf[secTable+12:], 0x1000) // VirtualAddress
	binary.LittleEndian.PutUint32(buf[secTable+16:], 0x200)  // SizeOfRawData
	binary.LittleEndian.PutUint32(buf[secTable+20:], 0x200)  // PointerToRawData
	binary.LittleEndian.PutUint32(buf[secTable+36:], 0x60000020) // Characteristics: CODE | EXECUTE | READ

	// Section 2: .edata
	secTable2 := secTable + 40
	copy(buf[secTable2:], []byte(".edata\x00\x00"))
	binary.LittleEndian.PutUint32(buf[secTable2+8:], 0x200)  // VirtualSize
	binary.LittleEndian.PutUint32(buf[secTable2+12:], 0x2000) // VirtualAddress
	binary.LittleEndian.PutUint32(buf[secTable2+16:], 0x200) // SizeOfRawData
	binary.LittleEndian.PutUint32(buf[secTable2+20:], 0x400) // PointerToRawData
	binary.LittleEndian.PutUint32(buf[secTable2+36:], 0x40000040) // Characteristics: INITIALIZED_DATA | READ

	// ── .text section (at file offset 0x200): DllMain stub (ret 1) ──
	// x86: mov eax,1; ret 0Ch  (standard DllMain returning TRUE)
	copy(buf[0x200:], []byte{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00})

	// ── .edata section (at file offset 0x400): Export Directory + names ──
	edata := 0x400
	// Export names — IIS CHttpModule interface methods
	exports := []string{
		"RegisterModule",
		"OnBeginRequest",
		"OnEndRequest",
		"OnAuthenticateRequest",
		"OnSendResponse",
		"GetHttpModule",
	}

	// Export Directory Table (40 bytes)
	binary.LittleEndian.PutUint32(buf[edata+12:], 0x2080)      // Name RVA (DLL name string)
	binary.LittleEndian.PutUint32(buf[edata+16:], 1)            // OrdinalBase
	binary.LittleEndian.PutUint32(buf[edata+20:], uint32(len(exports))) // NumberOfFunctions
	binary.LittleEndian.PutUint32(buf[edata+24:], uint32(len(exports))) // NumberOfNames
	binary.LittleEndian.PutUint32(buf[edata+28:], 0x2028)       // AddressOfFunctions RVA
	binary.LittleEndian.PutUint32(buf[edata+32:], 0x2040)       // AddressOfNames RVA
	binary.LittleEndian.PutUint32(buf[edata+36:], 0x2058)       // AddressOfNameOrdinals RVA

	// Export Address Table (EAT) — all point to DllMain stub at RVA 0x1000
	eat := edata + 0x28
	for i := 0; i < len(exports); i++ {
		binary.LittleEndian.PutUint32(buf[eat+i*4:], 0x1000)
	}

	// Export Name Pointer Table
	nameTable := edata + 0x40
	// Export Ordinal Table
	ordTable := edata + 0x58

	// DLL name at offset 0x80
	dllName := "CacheHttp.dll\x00"
	copy(buf[edata+0x80:], dllName)

	// Name strings start at offset 0x90 within .edata
	nameStrOffset := edata + 0x90
	for i, name := range exports {
		// Name pointer (RVA)
		nameRVA := uint32(0x2000 + (nameStrOffset - edata))
		binary.LittleEndian.PutUint32(buf[nameTable+i*4:], nameRVA)
		// Ordinal
		binary.LittleEndian.PutUint16(buf[ordTable+i*2:], uint16(i))
		// Name string
		copy(buf[nameStrOffset:], name+"\x00")
		nameStrOffset += len(name) + 1
	}

	// Pad to 4096 and append simulation marker in the .edata padding area
	marker := "F0RT1KA_SIMULATION_APT34_CacheHttp_IIS_Backdoor"
	if nameStrOffset+len(marker) < len(buf) {
		copy(buf[nameStrOffset:], marker)
	}

	return buf
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
