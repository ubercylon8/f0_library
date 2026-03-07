//go:build windows
// +build windows

/*
ID: 54a0bd24-d75a-4d89-8dce-c381d932ca97
NAME: Perfctl/Symbiote LD_PRELOAD Hijacking with PAM Credential Harvesting
TECHNIQUES: T1574.006, T1003.008, T1548.001, T1014, T1059.004
TACTICS: persistence, defense-evasion, credential-access, privilege-escalation
SEVERITY: critical
TARGET: linux-endpoint
COMPLEXITY: medium
THREAT_ACTOR: Perfctl/Symbiote
SUBCATEGORY: apt
TAGS: ld-preload, shared-library-hijacking, pam-hooking, credential-harvesting, userland-rootkit, financial-sector, linux, perfctl, symbiote, auto-color, wolfsbane
UNIT: response
CREATED: 2026-03-07
AUTHOR: sectest-builder
*/
package main

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "54a0bd24-d75a-4d89-8dce-c381d932ca97"
	TEST_NAME = "Perfctl/Symbiote LD_PRELOAD Hijacking with PAM Credential Harvesting"
	VERSION   = "1.0.0"
)

// XOR key used by Perfctl for string encryption (0xAC)
const PERFCTL_XOR_KEY = 0xAC

// Simulated malicious shared library (ELF-like header + benign content)
// This is NOT a real rootkit - it simulates the artifact pattern
var simulatedMaliciousSO = generateSimulatedSO()

// ============================================================================
// SIMULATION DATA STRUCTURES
// ============================================================================

// PAMCredentialEntry simulates a captured PAM credential (Perfctl pattern)
type PAMCredentialEntry struct {
	Timestamp   string `json:"timestamp"`
	Service     string `json:"service"`
	Username    string `json:"username"`
	AuthResult  string `json:"auth_result"`
	SourceIP    string `json:"source_ip"`
	CapturedBy  string `json:"captured_by"`
}

// ShadowEntry simulates a parsed /etc/shadow line
type ShadowEntry struct {
	Username     string `json:"username"`
	HashType     string `json:"hash_type"`
	HashPrefix   string `json:"hash_prefix"`
	LastChanged  string `json:"last_changed"`
	Discoverable bool   `json:"discoverable"`
}

// SUIDResult simulates SUID binary discovery
type SUIDResult struct {
	Path        string `json:"path"`
	Permissions string `json:"permissions"`
	Owner       string `json:"owner"`
	Exploitable bool   `json:"exploitable"`
	GTFOBins    bool   `json:"gtfobins_listed"`
}

// ProcNetTCPEntry simulates a /proc/net/tcp entry
type ProcNetTCPEntry struct {
	LocalAddress  string `json:"local_address"`
	RemoteAddress string `json:"remote_address"`
	State         string `json:"state"`
	Hidden        bool   `json:"hidden"`
	HiddenBy      string `json:"hidden_by"`
}

// ============================================================================
// PHASE IMPLEMENTATIONS
// ============================================================================

// Phase 1: LD_PRELOAD Injection Simulation
// Simulates writing a malicious .so to /etc/ld.preload (Perfctl/Auto-Color/WolfsBane pattern)
func phaseLD_PreloadInjection() (bool, string) {
	Endpoint.Say("[*] Phase 1: LD_PRELOAD Shared Library Hijacking Simulation")
	Endpoint.Say("    Technique: T1574.006 - Hijack Execution Flow: LD_PRELOAD")
	Endpoint.Say("    Source: Perfctl (libgcwrap.so), Auto-Color (/etc/ld.preload), WolfsBane (BEURK rootkit)")
	Endpoint.Say("")

	targetDir := "c:\\F0"

	// Step 1: Create simulated malicious shared library (libgcwrap.so - Perfctl naming)
	soPath := filepath.Join(targetDir, "libgcwrap.so")
	soContent := generateSimulatedSO()
	if err := os.WriteFile(soPath, soContent, 0755); err != nil {
		LogMessage("ERROR", "T1574.006", fmt.Sprintf("Failed to create simulated .so: %v", err))
		return false, fmt.Sprintf("Failed to create simulated .so: %v", err)
	}
	soHash := sha256.Sum256(soContent)
	LogFileDropped("libgcwrap.so", soPath, int64(len(soContent)), false)
	LogMessage("INFO", "T1574.006", fmt.Sprintf("Created simulated malicious .so: %s (SHA256: %s)", soPath, hex.EncodeToString(soHash[:])))
	Endpoint.Say("    [+] Created simulated malicious library: libgcwrap.so (%d bytes)", len(soContent))
	Endpoint.Say("        SHA256: %s", hex.EncodeToString(soHash[:]))

	// Step 2: Create simulated /etc/ld.preload content (Auto-Color pattern)
	ldPreloadContent := fmt.Sprintf(`# Simulated /etc/ld.preload - F0RT1KA Security Test
# AUTO-COLOR PATTERN: Malicious library injected into /etc/ld.preload
# WOLFSBANE PATTERN: Modified BEURK rootkit via /etc/ld.so.preload
# PERFCTL PATTERN: libgcwrap.so hooking pam_authenticate + pcap_loop
#
# In a real attack, this file would contain:
# /lib/x86_64-linux-gnu/libgcwrap.so
# /usr/lib/libsophos.so  (Pygmy Goat on Sophos XG)
#
# This is a SIMULATION - no actual library preloading occurs
/lib/x86_64-linux-gnu/libgcwrap.so
`)
	ldPreloadPath := filepath.Join(targetDir, "etc_ld.preload")
	if err := os.WriteFile(ldPreloadPath, []byte(ldPreloadContent), 0644); err != nil {
		LogMessage("ERROR", "T1574.006", fmt.Sprintf("Failed to create ld.preload simulation: %v", err))
		return false, fmt.Sprintf("Failed to create ld.preload: %v", err)
	}
	LogFileDropped("etc_ld.preload", ldPreloadPath, int64(len(ldPreloadContent)), false)
	Endpoint.Say("    [+] Created simulated /etc/ld.preload: %s", ldPreloadPath)

	// Step 3: Create simulated /etc/ld.so.preload (WolfsBane/BEURK pattern)
	ldSoPreloadContent := fmt.Sprintf(`# Simulated /etc/ld.so.preload - WolfsBane (Gelsemium APT)
# Modified BEURK userland rootkit hooks: open, stat, readdir
/usr/lib/libmodule.so
`)
	ldSoPreloadPath := filepath.Join(targetDir, "etc_ld.so.preload")
	if err := os.WriteFile(ldSoPreloadPath, []byte(ldSoPreloadContent), 0644); err != nil {
		LogMessage("WARNING", "T1574.006", fmt.Sprintf("Failed to create ld.so.preload simulation: %v", err))
	} else {
		LogFileDropped("etc_ld.so.preload", ldSoPreloadPath, int64(len(ldSoPreloadContent)), false)
		Endpoint.Say("    [+] Created simulated /etc/ld.so.preload: %s", ldSoPreloadPath)
	}

	// Step 4: Simulate systemd persistence (Perfctl pattern)
	systemdServiceContent := `[Unit]
Description=System Guard Daemon
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/lib/x86_64-linux-gnu/libgcwrap.so --daemon
Restart=always
RestartSec=5
Environment=LD_PRELOAD=/lib/x86_64-linux-gnu/libgcwrap.so

[Install]
WantedBy=multi-user.target
`
	systemdPath := filepath.Join(targetDir, "perfctl_systemd_service.txt")
	if err := os.WriteFile(systemdPath, []byte(systemdServiceContent), 0644); err != nil {
		LogMessage("WARNING", "T1574.006", fmt.Sprintf("Failed to create systemd simulation: %v", err))
	} else {
		LogFileDropped("perfctl_systemd_service.txt", systemdPath, int64(len(systemdServiceContent)), false)
		Endpoint.Say("    [+] Created simulated systemd service: perfctl_systemd_service.txt")
	}

	// Step 5: Simulate ~/.profile modification (Perfctl persistence fallback)
	profileContent := `# Simulated ~/.profile modification - Perfctl persistence
# Original content preserved above
# --- INJECTED BY PERFCTL ---
export LD_PRELOAD=/lib/x86_64-linux-gnu/libgcwrap.so
nohup /tmp/.hidden/wizlmsh >/dev/null 2>&1 &
# --- END INJECTION ---
`
	profilePath := filepath.Join(targetDir, "profile_modification.txt")
	if err := os.WriteFile(profilePath, []byte(profileContent), 0644); err != nil {
		LogMessage("WARNING", "T1574.006", fmt.Sprintf("Failed to create profile simulation: %v", err))
	} else {
		LogFileDropped("profile_modification.txt", profilePath, int64(len(profileContent)), false)
		Endpoint.Say("    [+] Created simulated ~/.profile injection: profile_modification.txt")
	}

	Endpoint.Say("")
	Endpoint.Say("    Detection Opportunities:")
	Endpoint.Say("    - File write to /etc/ld.preload or /etc/ld.so.preload")
	Endpoint.Say("    - New .so file in /lib/ or /usr/lib/ paths")
	Endpoint.Say("    - systemd service with LD_PRELOAD environment variable")
	Endpoint.Say("    - ~/.profile modifications with export LD_PRELOAD")
	Endpoint.Say("")

	LogMessage("INFO", "T1574.006", "LD_PRELOAD injection simulation completed - 5 artifacts created")
	return true, "LD_PRELOAD injection simulation completed successfully"
}

// Phase 2: PAM Credential Hooking Simulation (Perfctl pattern)
func phasePAMCredentialHooking() (bool, string) {
	Endpoint.Say("[*] Phase 2: PAM Credential Hooking Simulation")
	Endpoint.Say("    Technique: T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow")
	Endpoint.Say("    Source: Perfctl hooks pam_authenticate for credential capture + auth bypass")
	Endpoint.Say("")

	targetDir := "c:\\F0"

	// Step 1: Simulate hooked pam_authenticate capturing credentials
	credentialLog := []PAMCredentialEntry{
		{
			Timestamp:  time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
			Service:    "sshd",
			Username:   "admin",
			AuthResult: "success",
			SourceIP:   "10.0.1.50",
			CapturedBy: "libgcwrap.so::pam_authenticate_hook",
		},
		{
			Timestamp:  time.Now().Add(-3 * time.Minute).Format(time.RFC3339),
			Service:    "sudo",
			Username:   "developer",
			AuthResult: "success",
			SourceIP:   "127.0.0.1",
			CapturedBy: "libgcwrap.so::pam_authenticate_hook",
		},
		{
			Timestamp:  time.Now().Add(-1 * time.Minute).Format(time.RFC3339),
			Service:    "login",
			Username:   "root",
			AuthResult: "failed",
			SourceIP:   "192.168.1.100",
			CapturedBy: "libgcwrap.so::pam_authenticate_hook",
		},
		{
			Timestamp:  time.Now().Format(time.RFC3339),
			Service:    "sshd",
			Username:   "backup-user",
			AuthResult: "success",
			SourceIP:   "10.0.2.30",
			CapturedBy: "libgcwrap.so::pam_authenticate_hook",
		},
	}

	// Write credential log (simulated exfiltration staging)
	var credLogBuilder strings.Builder
	credLogBuilder.WriteString("# Simulated PAM credential capture log - Perfctl pattern\n")
	credLogBuilder.WriteString("# libgcwrap.so hooks pam_authenticate to intercept all auth attempts\n")
	credLogBuilder.WriteString("# Real malware XOR-encrypts this data with key 0xAC before exfiltration\n\n")
	for _, entry := range credentialLog {
		line := fmt.Sprintf("[%s] service=%s user=%s result=%s src=%s captured_by=%s\n",
			entry.Timestamp, entry.Service, entry.Username, entry.AuthResult,
			entry.SourceIP, entry.CapturedBy)
		credLogBuilder.WriteString(line)
	}

	credLogPath := filepath.Join(targetDir, "pam_credential_capture.log")
	credLogContent := credLogBuilder.String()
	if err := os.WriteFile(credLogPath, []byte(credLogContent), 0600); err != nil {
		LogMessage("ERROR", "T1003.008", fmt.Sprintf("Failed to create credential log: %v", err))
		return false, fmt.Sprintf("Failed to create credential log: %v", err)
	}
	LogFileDropped("pam_credential_capture.log", credLogPath, int64(len(credLogContent)), false)
	Endpoint.Say("    [+] Created simulated PAM credential capture log (%d entries)", len(credentialLog))
	Endpoint.Say("        Simulated services: sshd, sudo, login")

	// Step 2: Simulate /etc/shadow access and dumping
	shadowEntries := []ShadowEntry{
		{Username: "root", HashType: "$6$ (SHA-512)", HashPrefix: "$6$rOuNdS=5000$", LastChanged: "19824", Discoverable: true},
		{Username: "admin", HashType: "$6$ (SHA-512)", HashPrefix: "$6$sAlT1234$", LastChanged: "19810", Discoverable: true},
		{Username: "www-data", HashType: "*", HashPrefix: "*", LastChanged: "19500", Discoverable: false},
		{Username: "postgres", HashType: "$y$ (yescrypt)", HashPrefix: "$y$j9T$", LastChanged: "19815", Discoverable: true},
		{Username: "developer", HashType: "$6$ (SHA-512)", HashPrefix: "$6$xTr4Ct3d$", LastChanged: "19820", Discoverable: true},
		{Username: "backup-user", HashType: "$6$ (SHA-512)", HashPrefix: "$6$bKpUsr01$", LastChanged: "19805", Discoverable: true},
	}

	var shadowBuilder strings.Builder
	shadowBuilder.WriteString("# Simulated /etc/shadow dump - F0RT1KA Security Test\n")
	shadowBuilder.WriteString("# In a real attack, this contains password hashes for offline cracking\n")
	shadowBuilder.WriteString("# Perfctl + Akira use LaZagne/unshadow + John the Ripper\n\n")
	crackableCount := 0
	for _, entry := range shadowEntries {
		if entry.Discoverable && entry.HashType != "*" {
			shadowBuilder.WriteString(fmt.Sprintf("%s:%sSIMULATED_HASH_REDACTED:%s:0:99999:7:::\n",
				entry.Username, entry.HashPrefix, entry.LastChanged))
			crackableCount++
		} else {
			shadowBuilder.WriteString(fmt.Sprintf("%s:*:%s:0:99999:7:::\n", entry.Username, entry.LastChanged))
		}
	}

	shadowPath := filepath.Join(targetDir, "shadow_dump.txt")
	shadowContent := shadowBuilder.String()
	if err := os.WriteFile(shadowPath, []byte(shadowContent), 0600); err != nil {
		LogMessage("ERROR", "T1003.008", fmt.Sprintf("Failed to create shadow dump: %v", err))
		return false, fmt.Sprintf("Failed to create shadow dump: %v", err)
	}
	LogFileDropped("shadow_dump.txt", shadowPath, int64(len(shadowContent)), false)
	Endpoint.Say("    [+] Created simulated /etc/shadow dump: %d entries (%d crackable)", len(shadowEntries), crackableCount)

	// Step 3: Simulate /etc/passwd enumeration
	passwdContent := `# Simulated /etc/passwd enumeration - F0RT1KA Security Test
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
admin:x:1000:1000:System Admin:/home/admin:/bin/bash
developer:x:1001:1001:Developer:/home/developer:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
postgres:x:114:120:PostgreSQL administrator:/var/lib/postgresql:/bin/bash
backup-user:x:1002:1002:Backup Service:/home/backup-user:/bin/bash
# NOTE: Perfctl technique - trailing space on nologin entries bypasses login restriction
# ftp:x:115:121:FTP User:/srv/ftp:/usr/sbin/nologin   <-- note trailing space
`
	passwdPath := filepath.Join(targetDir, "passwd_enum.txt")
	if err := os.WriteFile(passwdPath, []byte(passwdContent), 0644); err != nil {
		LogMessage("WARNING", "T1003.008", fmt.Sprintf("Failed to create passwd dump: %v", err))
	} else {
		LogFileDropped("passwd_enum.txt", passwdPath, int64(len(passwdContent)), false)
		Endpoint.Say("    [+] Created simulated /etc/passwd enumeration")
	}

	Endpoint.Say("")
	Endpoint.Say("    Detection Opportunities:")
	Endpoint.Say("    - Access to /etc/shadow (abnormal for non-root processes)")
	Endpoint.Say("    - PAM module modifications or new PAM configs")
	Endpoint.Say("    - Credential log files in unusual locations")
	Endpoint.Say("    - Bulk authentication event correlation")
	Endpoint.Say("")

	LogMessage("INFO", "T1003.008", fmt.Sprintf("PAM credential hooking simulation completed - %d creds captured, %d shadow hashes", len(credentialLog), crackableCount))
	return true, "PAM credential hooking simulation completed"
}

// Phase 3: Network Artifact Hiding Simulation (Auto-Color pattern)
func phaseNetworkArtifactHiding() (bool, string) {
	Endpoint.Say("[*] Phase 3: Network Artifact Hiding Simulation")
	Endpoint.Say("    Technique: T1014 - Rootkit (Userland)")
	Endpoint.Say("    Source: Auto-Color hooks open() to scrub /proc/net/tcp; Symbiote hooks libc+libpcap")
	Endpoint.Say("")

	targetDir := "c:\\F0"

	// Step 1: Generate simulated /proc/net/tcp with hidden entries
	procNetEntries := []ProcNetTCPEntry{
		{LocalAddress: "0.0.0.0:22", RemoteAddress: "0.0.0.0:0", State: "LISTEN", Hidden: false, HiddenBy: ""},
		{LocalAddress: "0.0.0.0:80", RemoteAddress: "0.0.0.0:0", State: "LISTEN", Hidden: false, HiddenBy: ""},
		{LocalAddress: "0.0.0.0:443", RemoteAddress: "0.0.0.0:0", State: "LISTEN", Hidden: false, HiddenBy: ""},
		{LocalAddress: "10.0.1.5:45678", RemoteAddress: "185.141.27.99:4444", State: "ESTABLISHED", Hidden: true, HiddenBy: "auto-color::open_hook"},
		{LocalAddress: "10.0.1.5:55123", RemoteAddress: "91.215.85.142:8080", State: "ESTABLISHED", Hidden: true, HiddenBy: "symbiote::libc_hook"},
		{LocalAddress: "0.0.0.0:3306", RemoteAddress: "0.0.0.0:0", State: "LISTEN", Hidden: false, HiddenBy: ""},
		{LocalAddress: "10.0.1.5:43210", RemoteAddress: "45.77.65.211:443", State: "ESTABLISHED", Hidden: true, HiddenBy: "symbiote::libpcap_hook"},
		{LocalAddress: "127.0.0.1:6379", RemoteAddress: "0.0.0.0:0", State: "LISTEN", Hidden: false, HiddenBy: ""},
	}

	// Write original /proc/net/tcp (what the kernel actually shows)
	var originalBuilder strings.Builder
	originalBuilder.WriteString("# Simulated /proc/net/tcp - ORIGINAL (kernel view)\n")
	originalBuilder.WriteString("# This is what the kernel actually maintains\n")
	originalBuilder.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	for i, entry := range procNetEntries {
		originalBuilder.WriteString(fmt.Sprintf("  %2d: %-21s %-21s %s 00000000:00000000 00:00000000 00000000     0        0 %d\n",
			i, entry.LocalAddress, entry.RemoteAddress, entry.State, 10000+i))
	}
	originalPath := filepath.Join(targetDir, "proc_net_tcp_original.txt")
	originalContent := originalBuilder.String()
	if err := os.WriteFile(originalPath, []byte(originalContent), 0644); err != nil {
		LogMessage("ERROR", "T1014", fmt.Sprintf("Failed to create original proc/net/tcp: %v", err))
		return false, fmt.Sprintf("Failed to create original proc/net/tcp: %v", err)
	}
	LogFileDropped("proc_net_tcp_original.txt", originalPath, int64(len(originalContent)), false)
	Endpoint.Say("    [+] Created original /proc/net/tcp (%d entries)", len(procNetEntries))

	// Write scrubbed /proc/net/tcp (what the rootkit shows to userland)
	var scrubbedBuilder strings.Builder
	scrubbedBuilder.WriteString("# Simulated /proc/net/tcp - SCRUBBED (rootkit view)\n")
	scrubbedBuilder.WriteString("# Auto-Color hooks open() to filter C2 connections\n")
	scrubbedBuilder.WriteString("# Symbiote hooks libc read() and libpcap pcap_loop()\n")
	scrubbedBuilder.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	visibleCount := 0
	hiddenCount := 0
	for i, entry := range procNetEntries {
		if !entry.Hidden {
			scrubbedBuilder.WriteString(fmt.Sprintf("  %2d: %-21s %-21s %s 00000000:00000000 00:00000000 00000000     0        0 %d\n",
				visibleCount, entry.LocalAddress, entry.RemoteAddress, entry.State, 10000+i))
			visibleCount++
		} else {
			hiddenCount++
		}
	}
	scrubbedPath := filepath.Join(targetDir, "proc_net_tcp_scrubbed.txt")
	scrubbedContent := scrubbedBuilder.String()
	if err := os.WriteFile(scrubbedPath, []byte(scrubbedContent), 0644); err != nil {
		LogMessage("ERROR", "T1014", fmt.Sprintf("Failed to create scrubbed proc/net/tcp: %v", err))
		return false, fmt.Sprintf("Failed to create scrubbed proc/net/tcp: %v", err)
	}
	LogFileDropped("proc_net_tcp_scrubbed.txt", scrubbedPath, int64(len(scrubbedContent)), false)
	Endpoint.Say("    [+] Created scrubbed /proc/net/tcp (%d visible, %d HIDDEN by rootkit)", visibleCount, hiddenCount)

	// Step 2: Write hidden connections report
	var hiddenReport strings.Builder
	hiddenReport.WriteString("# ROOTKIT HIDDEN CONNECTIONS REPORT - F0RT1KA\n")
	hiddenReport.WriteString("# These connections are hidden from userland tools (netstat, ss, lsof)\n\n")
	for _, entry := range procNetEntries {
		if entry.Hidden {
			hiddenReport.WriteString(fmt.Sprintf("HIDDEN CONNECTION:\n"))
			hiddenReport.WriteString(fmt.Sprintf("  Local:  %s\n", entry.LocalAddress))
			hiddenReport.WriteString(fmt.Sprintf("  Remote: %s\n", entry.RemoteAddress))
			hiddenReport.WriteString(fmt.Sprintf("  State:  %s\n", entry.State))
			hiddenReport.WriteString(fmt.Sprintf("  Hidden by: %s\n\n", entry.HiddenBy))
		}
	}
	hiddenReportPath := filepath.Join(targetDir, "hidden_connections_report.txt")
	hiddenReportContent := hiddenReport.String()
	if err := os.WriteFile(hiddenReportPath, []byte(hiddenReportContent), 0644); err != nil {
		LogMessage("WARNING", "T1014", fmt.Sprintf("Failed to create hidden connections report: %v", err))
	} else {
		LogFileDropped("hidden_connections_report.txt", hiddenReportPath, int64(len(hiddenReportContent)), false)
		Endpoint.Say("    [+] Created hidden connections report: %d C2 connections concealed", hiddenCount)
	}

	// Step 3: Simulate Symbiote libpcap hook (pcap_loop filtering)
	pcapFilterContent := `# Simulated Symbiote pcap_loop hook - packet capture filtering
# Symbiote (2025 variants): IPv6 + 8-port support across TCP/UDP/SCTP
# Perfctl: hooks pcap_loop to hide traffic from packet capture tools

FILTER RULES (applied by libgcwrap.so::pcap_loop_hook):
  - DROP packets to/from 185.141.27.99 (C2 primary)
  - DROP packets to/from 91.215.85.142 (C2 fallback)
  - DROP packets to/from 45.77.65.211 (exfil endpoint)
  - DROP packets on port 4444 (reverse shell)
  - DROP packets on port 8080 (HTTP C2)
  - DROP ICMP magic packets (0x7f, Pygmy Goat activation)

SYMBIOTE 2025 VARIANT EXTENSIONS:
  - IPv6 filtering enabled
  - 8-port configuration: 4444,8080,443,8443,9090,1337,31337,53
  - Protocol support: TCP, UDP, SCTP
  - DNS query filtering for C2 domains

EFFECT: tcpdump, wireshark, and other packet capture tools will NOT
see any traffic to/from C2 infrastructure.
`
	pcapPath := filepath.Join(targetDir, "pcap_filter_rules.txt")
	if err := os.WriteFile(pcapPath, []byte(pcapFilterContent), 0644); err != nil {
		LogMessage("WARNING", "T1014", fmt.Sprintf("Failed to create pcap filter rules: %v", err))
	} else {
		LogFileDropped("pcap_filter_rules.txt", pcapPath, int64(len(pcapFilterContent)), false)
		Endpoint.Say("    [+] Created simulated pcap filter rules (Symbiote pattern)")
	}

	Endpoint.Say("")
	Endpoint.Say("    Detection Opportunities:")
	Endpoint.Say("    - Discrepancy between /proc/net/tcp and kernel-level connection data")
	Endpoint.Say("    - eBPF-based network monitoring (bypasses userland hooks)")
	Endpoint.Say("    - Integrity monitoring on /proc filesystem handlers")
	Endpoint.Say("    - Comparing netstat output with iptables conntrack")
	Endpoint.Say("")

	LogMessage("INFO", "T1014", fmt.Sprintf("Network artifact hiding simulation completed - %d connections hidden", hiddenCount))
	return true, fmt.Sprintf("Network artifact hiding completed - %d connections hidden from userland", hiddenCount)
}

// Phase 4: XOR-Encrypted C2 Configuration (Perfctl pattern)
func phaseXOREncryptedC2Config() (bool, string) {
	Endpoint.Say("[*] Phase 4: XOR-Encrypted C2 Configuration")
	Endpoint.Say("    Technique: T1059.004 - Command and Scripting Interpreter: Unix Shell")
	Endpoint.Say("    Source: Perfctl uses XOR encryption with key 0xAC for strings")
	Endpoint.Say("")

	targetDir := "c:\\F0"

	// Step 1: Create plaintext C2 config (what the malware decrypts at runtime)
	c2Config := `{
  "c2_primary": "185.141.27.99",
  "c2_fallback": "91.215.85.142",
  "c2_port": 4444,
  "c2_protocol": "tcp",
  "exfil_endpoint": "45.77.65.211",
  "exfil_port": 443,
  "xmrig_pool": "pool.supportxmr.com:443",
  "wallet": "4SIMULATED_WALLET_ADDRESS_REDACTED",
  "beacon_interval_ms": 30000,
  "jitter_percent": 20,
  "persistence_methods": ["ld_preload", "systemd", "crontab", "profile"],
  "watchdog_binary": "wizlmsh",
  "hooks": ["pam_authenticate", "pcap_loop", "open", "stat", "readdir"],
  "target_services": ["sshd", "httpd", "nginx", "mysql", "postgres"],
  "note": "SIMULATION - This is a F0RT1KA test artifact, not real malware configuration"
}`

	plaintextPath := filepath.Join(targetDir, "c2_config_plaintext.json")
	if err := os.WriteFile(plaintextPath, []byte(c2Config), 0600); err != nil {
		LogMessage("ERROR", "T1059.004", fmt.Sprintf("Failed to create C2 config: %v", err))
		return false, fmt.Sprintf("Failed to create C2 config: %v", err)
	}
	LogFileDropped("c2_config_plaintext.json", plaintextPath, int64(len(c2Config)), false)
	Endpoint.Say("    [+] Created plaintext C2 configuration (for reference)")

	// Step 2: XOR-encrypt the config with Perfctl's key (0xAC)
	encrypted := xorEncrypt([]byte(c2Config), PERFCTL_XOR_KEY)
	encryptedPath := filepath.Join(targetDir, "c2_config_encrypted.bin")
	if err := os.WriteFile(encryptedPath, encrypted, 0600); err != nil {
		LogMessage("ERROR", "T1059.004", fmt.Sprintf("Failed to create encrypted config: %v", err))
		return false, fmt.Sprintf("Failed to create encrypted config: %v", err)
	}
	encHash := sha256.Sum256(encrypted)
	LogFileDropped("c2_config_encrypted.bin", encryptedPath, int64(len(encrypted)), false)
	Endpoint.Say("    [+] Created XOR-encrypted C2 config (key: 0x%02X, %d bytes)", PERFCTL_XOR_KEY, len(encrypted))
	Endpoint.Say("        SHA256: %s", hex.EncodeToString(encHash[:]))

	// Step 3: Verify XOR round-trip (demonstrate the encryption scheme)
	decrypted := xorEncrypt(encrypted, PERFCTL_XOR_KEY)
	if string(decrypted) == c2Config {
		Endpoint.Say("    [+] XOR round-trip verified: decrypted content matches plaintext")
		LogMessage("INFO", "T1059.004", "XOR encryption round-trip verified successfully")
	} else {
		Endpoint.Say("    [!] XOR round-trip verification failed")
		LogMessage("WARNING", "T1059.004", "XOR encryption round-trip verification failed")
	}

	// Step 4: Create simulated trojanized crontab (Perfctl pattern)
	crontabContent := `# Simulated trojanized crontab binary - Perfctl pattern
# The real Perfctl replaces the system crontab binary with a trojanized version
# that hides malicious cron entries from 'crontab -l' output

# VISIBLE entries (shown by trojanized crontab -l):
0 */6 * * * /usr/sbin/logrotate /etc/logrotate.conf
15 3 * * 0 /usr/bin/apt-get update && /usr/bin/apt-get -y upgrade

# HIDDEN entries (filtered by trojanized binary, only visible in raw /var/spool/cron/):
*/5 * * * * /tmp/.hidden/perfctl --mine >/dev/null 2>&1
@reboot /usr/lib/x86_64-linux-gnu/libgcwrap.so --daemon >/dev/null 2>&1
*/10 * * * * /tmp/.hidden/wizlmsh --check-persist >/dev/null 2>&1
`
	crontabPath := filepath.Join(targetDir, "trojanized_crontab.txt")
	if err := os.WriteFile(crontabPath, []byte(crontabContent), 0644); err != nil {
		LogMessage("WARNING", "T1059.004", fmt.Sprintf("Failed to create crontab simulation: %v", err))
	} else {
		LogFileDropped("trojanized_crontab.txt", crontabPath, int64(len(crontabContent)), false)
		Endpoint.Say("    [+] Created simulated trojanized crontab output")
	}

	Endpoint.Say("")
	Endpoint.Say("    Detection Opportunities:")
	Endpoint.Say("    - XOR-encrypted binary blobs in /tmp or library paths")
	Endpoint.Say("    - Discrepancy between crontab -l and raw /var/spool/cron/ contents")
	Endpoint.Say("    - Entropy analysis of .so files (encrypted configs have high entropy)")
	Endpoint.Say("    - Process monitoring for XMRig-like mining pool connections")
	Endpoint.Say("")

	LogMessage("INFO", "T1059.004", "XOR-encrypted C2 configuration simulation completed")
	return true, "XOR-encrypted C2 config simulation completed"
}

// Phase 5: SUID Abuse for Privilege Escalation (T1548.001)
func phaseSUIDAbuse() (bool, string) {
	Endpoint.Say("[*] Phase 5: SUID Binary Enumeration and Abuse Simulation")
	Endpoint.Say("    Technique: T1548.001 - Abuse Elevation Control Mechanism: SUID/SGID")
	Endpoint.Say("    Source: Perfctl uses SUID manipulation; GTFOBins exploitation")
	Endpoint.Say("")

	targetDir := "c:\\F0"

	// Step 1: Simulate SUID binary discovery (find / -type f -perm -u=s)
	suidResults := []SUIDResult{
		{Path: "/usr/bin/passwd", Permissions: "-rwsr-xr-x", Owner: "root", Exploitable: false, GTFOBins: false},
		{Path: "/usr/bin/sudo", Permissions: "-rwsr-xr-x", Owner: "root", Exploitable: false, GTFOBins: true},
		{Path: "/usr/bin/find", Permissions: "-rwsr-xr-x", Owner: "root", Exploitable: true, GTFOBins: true},
		{Path: "/usr/bin/vim.basic", Permissions: "-rwsr-xr-x", Owner: "root", Exploitable: true, GTFOBins: true},
		{Path: "/usr/bin/nano", Permissions: "-rwsr-xr-x", Owner: "root", Exploitable: true, GTFOBins: true},
		{Path: "/usr/bin/nmap", Permissions: "-rwsr-xr-x", Owner: "root", Exploitable: true, GTFOBins: true},
		{Path: "/usr/bin/pkexec", Permissions: "-rwsr-xr-x", Owner: "root", Exploitable: true, GTFOBins: true},
		{Path: "/usr/bin/newgrp", Permissions: "-rwsr-xr-x", Owner: "root", Exploitable: false, GTFOBins: true},
		{Path: "/usr/sbin/mount.nfs", Permissions: "-rwsr-xr-x", Owner: "root", Exploitable: false, GTFOBins: false},
		{Path: "/usr/bin/bash", Permissions: "-rwsr-xr-x", Owner: "root", Exploitable: true, GTFOBins: true},
	}

	var suidBuilder strings.Builder
	suidBuilder.WriteString("# Simulated SUID Binary Enumeration - F0RT1KA Security Test\n")
	suidBuilder.WriteString("# Command: find / -type f -perm -u=s 2>/dev/null\n\n")

	exploitableCount := 0
	gtfobinsCount := 0
	for _, result := range suidResults {
		status := ""
		if result.Exploitable {
			exploitableCount++
			status = " [EXPLOITABLE]"
		}
		if result.GTFOBins {
			gtfobinsCount++
			if result.Exploitable {
				status += " [GTFOBins]"
			}
		}
		suidBuilder.WriteString(fmt.Sprintf("%s %s %s%s\n", result.Permissions, result.Owner, result.Path, status))
	}

	suidBuilder.WriteString(fmt.Sprintf("\n# Summary: %d SUID binaries found, %d exploitable, %d in GTFOBins\n",
		len(suidResults), exploitableCount, gtfobinsCount))
	suidBuilder.WriteString("\n# Exploitation Examples (Perfctl/GTFOBins patterns):\n")
	suidBuilder.WriteString("# find:  find ./ -exec whoami \\;\n")
	suidBuilder.WriteString("# find:  find ./ -exec /bin/sh -p \\;\n")
	suidBuilder.WriteString("# vim:   vim -c ':!/bin/sh'\n")
	suidBuilder.WriteString("# nano:  nano /etc/shadow  (direct edit)\n")
	suidBuilder.WriteString("# bash:  /bin/bash -p  (privileged mode)\n")
	suidBuilder.WriteString("# nmap:  nmap --interactive -> !sh\n")

	suidPath := filepath.Join(targetDir, "suid_enumeration.txt")
	suidContent := suidBuilder.String()
	if err := os.WriteFile(suidPath, []byte(suidContent), 0644); err != nil {
		LogMessage("ERROR", "T1548.001", fmt.Sprintf("Failed to create SUID enumeration: %v", err))
		return false, fmt.Sprintf("Failed to create SUID enumeration: %v", err)
	}
	LogFileDropped("suid_enumeration.txt", suidPath, int64(len(suidContent)), false)
	Endpoint.Say("    [+] SUID enumeration: %d binaries found, %d exploitable", len(suidResults), exploitableCount)

	// Step 2: Simulate SUID bash exploitation (chmod u+s /bin/bash pattern)
	suidExploitLog := fmt.Sprintf(`# Simulated SUID Exploitation Log - F0RT1KA Security Test
# Technique: chmod u+s /bin/bash followed by /bin/bash -p

[%s] SUID EXPLOITATION ATTEMPT:
  Target binary: /usr/bin/find
  Method: find ./ -exec /bin/sh -p \;
  Result: Simulated root shell obtained
  Effective UID: 0 (root)
  Real UID: 1000 (developer)

[%s] PRIVILEGE MAINTENANCE:
  Action: chmod u+s /bin/bash
  Purpose: Persistent root access via /bin/bash -p
  Detection: ls -la /bin/bash shows -rwsr-xr-x

[%s] CREDENTIAL HARVESTING (post-escalation):
  Action: cat /etc/shadow
  Result: Shadow file readable with root privileges
  Hash types found: SHA-512 ($6$), yescrypt ($y$)
  Crackable accounts: 4
`, time.Now().Add(-2*time.Minute).Format(time.RFC3339),
		time.Now().Add(-1*time.Minute).Format(time.RFC3339),
		time.Now().Format(time.RFC3339))

	exploitLogPath := filepath.Join(targetDir, "suid_exploit_log.txt")
	if err := os.WriteFile(exploitLogPath, []byte(suidExploitLog), 0644); err != nil {
		LogMessage("WARNING", "T1548.001", fmt.Sprintf("Failed to create SUID exploit log: %v", err))
	} else {
		LogFileDropped("suid_exploit_log.txt", exploitLogPath, int64(len(suidExploitLog)), false)
		Endpoint.Say("    [+] Created SUID exploitation log (find -> root shell simulation)")
	}

	Endpoint.Say("")
	Endpoint.Say("    Detection Opportunities:")
	Endpoint.Say("    - find commands with -perm -u=s (SUID enumeration)")
	Endpoint.Say("    - chmod u+s on system binaries (bash, sh)")
	Endpoint.Say("    - Processes running with different real/effective UIDs")
	Endpoint.Say("    - GTFOBins command patterns (find -exec, vim -c)")
	Endpoint.Say("")

	LogMessage("INFO", "T1548.001", fmt.Sprintf("SUID abuse simulation completed - %d exploitable binaries identified", exploitableCount))
	return true, fmt.Sprintf("SUID abuse simulation completed - %d exploitable binaries", exploitableCount)
}

// Phase 6: Cleanup utility creation
func phaseCreateCleanup() {
	Endpoint.Say("[*] Phase 6: Creating cleanup utility")
	targetDir := "c:\\F0"

	cleanupScript := `@echo off
REM F0RT1KA Test Cleanup - LD_PRELOAD Hijacking Simulation
REM Removes ALL simulation artifacts from c:\F0

echo Cleaning up LD_PRELOAD hijacking simulation artifacts...

del /q "c:\F0\libgcwrap.so" 2>nul
del /q "c:\F0\etc_ld.preload" 2>nul
del /q "c:\F0\etc_ld.so.preload" 2>nul
del /q "c:\F0\perfctl_systemd_service.txt" 2>nul
del /q "c:\F0\profile_modification.txt" 2>nul
del /q "c:\F0\pam_credential_capture.log" 2>nul
del /q "c:\F0\shadow_dump.txt" 2>nul
del /q "c:\F0\passwd_enum.txt" 2>nul
del /q "c:\F0\proc_net_tcp_original.txt" 2>nul
del /q "c:\F0\proc_net_tcp_scrubbed.txt" 2>nul
del /q "c:\F0\hidden_connections_report.txt" 2>nul
del /q "c:\F0\pcap_filter_rules.txt" 2>nul
del /q "c:\F0\c2_config_plaintext.json" 2>nul
del /q "c:\F0\c2_config_encrypted.bin" 2>nul
del /q "c:\F0\trojanized_crontab.txt" 2>nul
del /q "c:\F0\suid_enumeration.txt" 2>nul
del /q "c:\F0\suid_exploit_log.txt" 2>nul
del /q "c:\F0\test_execution_log.json" 2>nul
del /q "c:\F0\test_execution_log.txt" 2>nul
del /q "c:\F0\cleanup.bat" 2>nul

echo Cleanup complete.
`
	cleanupPath := filepath.Join(targetDir, "cleanup.bat")
	if err := os.WriteFile(cleanupPath, []byte(cleanupScript), 0755); err != nil {
		LogMessage("WARNING", "Cleanup", fmt.Sprintf("Failed to create cleanup script: %v", err))
	} else {
		LogFileDropped("cleanup.bat", cleanupPath, int64(len(cleanupScript)), false)
		Endpoint.Say("    [+] Created cleanup script: %s", cleanupPath)
	}
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// xorEncrypt applies XOR encryption/decryption with the given key byte
func xorEncrypt(data []byte, key byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key
	}
	return result
}

// generateSimulatedSO creates a simulated ELF shared library artifact
// This is NOT a real .so - it's a simulation artifact with ELF header magic bytes
func generateSimulatedSO() []byte {
	// ELF magic header (0x7f ELF) followed by simulation marker
	header := []byte{
		0x7f, 0x45, 0x4c, 0x46, // ELF magic
		0x02,                                     // 64-bit
		0x01,                                     // Little endian
		0x01,                                     // ELF version
		0x00,                                     // OS/ABI
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
	}

	// Simulation marker (so static analysis tools recognize this as a test)
	marker := []byte("F0RT1KA_SIMULATION_ARTIFACT_NOT_REAL_MALWARE")

	// Simulated function stubs matching Perfctl's hooked functions
	stubs := []byte(`
/* Simulated hooking stubs - F0RT1KA test artifact */
/* In real Perfctl, these replace libc/libpam functions: */

int pam_authenticate(pam_handle_t *pamh, int flags) {
    /* Hook: capture credentials before forwarding to real PAM */
    /* XOR-encrypt captured data with key 0xAC */
    return real_pam_authenticate(pamh, flags);
}

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) {
    /* Hook: filter packets to/from C2 before passing to callback */
    return real_pcap_loop(p, cnt, filtered_callback, user);
}

int open(const char *pathname, int flags, ...) {
    /* Hook: intercept /proc/net/tcp reads, return scrubbed version */
    if (strstr(pathname, "/proc/net/tcp")) {
        return open_scrubbed_tcp(pathname, flags);
    }
    return real_open(pathname, flags);
}

int stat(const char *pathname, struct stat *statbuf) {
    /* Hook: hide malicious files from stat queries */
    if (is_hidden_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return real_stat(pathname, statbuf);
}

struct dirent *readdir(DIR *dirp) {
    /* Hook: skip hidden entries in directory listings */
    struct dirent *entry;
    do {
        entry = real_readdir(dirp);
    } while (entry && is_hidden_entry(entry->d_name));
    return entry;
}
`)

	// Add random padding to create realistic file size (~4KB)
	padding := make([]byte, 2048)
	rand.Read(padding)

	// Concatenate all parts
	result := make([]byte, 0, len(header)+len(marker)+len(stubs)+len(padding))
	result = append(result, header...)
	result = append(result, marker...)
	result = append(result, stubs...)
	result = append(result, padding...)

	return result
}

// ============================================================================
// TEST ORCHESTRATION
// ============================================================================

func test() {
	// Phase 0: Initialization
	LogPhaseStart(0, "Test Initialization")
	Endpoint.Say("[*] Phase 0: Test Initialization")

	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		LogMessage("ERROR", "Initialization", fmt.Sprintf("Dropper initialization failed: %v", err))
		LogPhaseEnd(0, "failed", "Dropper initialization failed")
		SaveLog(Endpoint.UnexpectedTestError, "Dropper initialization failed")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Ensure target directory exists
	targetDir := "c:\\F0"
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		LogMessage("ERROR", "Initialization", fmt.Sprintf("Failed to create target directory: %v", err))
		LogPhaseEnd(0, "failed", "Failed to create target directory")
		SaveLog(Endpoint.UnexpectedTestError, "Failed to create target directory")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	LogPhaseEnd(0, "success", "Test initialized successfully")
	Endpoint.Say("    [+] Dropper initialized, target directory ready")
	Endpoint.Say("")

	// Track overall results
	phasesCompleted := 0
	phasesBlocked := 0
	totalPhases := 5
	var blockedPhase string

	// ================================================================
	// PHASE 1: LD_PRELOAD Injection
	// ================================================================
	LogPhaseStart(1, "LD_PRELOAD Injection (T1574.006)")
	success, detail := phaseLD_PreloadInjection()
	if !success {
		phasesBlocked++
		blockedPhase = "Phase 1: LD_PRELOAD Injection"
		LogPhaseEnd(1, "blocked", detail)
	} else {
		phasesCompleted++
		LogPhaseEnd(1, "success", detail)
	}

	// Check for defensive reaction after dropping artifacts
	Endpoint.Say("[*] Checking for defensive reaction (3s)...")
	Endpoint.Wait(3)

	// Check if the primary artifact was quarantined
	soPath := filepath.Join(targetDir, "libgcwrap.so")
	if _, err := os.Stat(soPath); os.IsNotExist(err) {
		LogMessage("INFO", "Detection", "libgcwrap.so was removed/quarantined by EDR")
		Endpoint.Say("    [!] libgcwrap.so was QUARANTINED by security controls!")
		Endpoint.Say("")
		Endpoint.Say("=================================================================")
		Endpoint.Say("RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("")
		Endpoint.Say("EDR/AV detected and quarantined the simulated malicious .so file.")
		Endpoint.Say("Protection Type: File Quarantine")
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		SaveLog(Endpoint.FileQuarantinedOnExtraction, "Simulated malicious .so quarantined by EDR")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}
	Endpoint.Say("    [+] Artifacts not quarantined - continuing simulation")
	Endpoint.Say("")

	// ================================================================
	// PHASE 2: PAM Credential Hooking
	// ================================================================
	LogPhaseStart(2, "PAM Credential Hooking (T1003.008)")
	success, detail = phasePAMCredentialHooking()
	if !success {
		phasesBlocked++
		blockedPhase = "Phase 2: PAM Credential Hooking"
		LogPhaseEnd(2, "blocked", detail)
	} else {
		phasesCompleted++
		LogPhaseEnd(2, "success", detail)
	}

	// ================================================================
	// PHASE 3: Network Artifact Hiding
	// ================================================================
	LogPhaseStart(3, "Network Artifact Hiding (T1014)")
	success, detail = phaseNetworkArtifactHiding()
	if !success {
		phasesBlocked++
		blockedPhase = "Phase 3: Network Artifact Hiding"
		LogPhaseEnd(3, "blocked", detail)
	} else {
		phasesCompleted++
		LogPhaseEnd(3, "success", detail)
	}

	// ================================================================
	// PHASE 4: XOR-Encrypted C2 Configuration
	// ================================================================
	LogPhaseStart(4, "XOR-Encrypted C2 Config (T1059.004)")
	success, detail = phaseXOREncryptedC2Config()
	if !success {
		phasesBlocked++
		blockedPhase = "Phase 4: XOR-Encrypted C2 Config"
		LogPhaseEnd(4, "blocked", detail)
	} else {
		phasesCompleted++
		LogPhaseEnd(4, "success", detail)
	}

	// ================================================================
	// PHASE 5: SUID Abuse
	// ================================================================
	LogPhaseStart(5, "SUID Abuse (T1548.001)")
	success, detail = phaseSUIDAbuse()
	if !success {
		phasesBlocked++
		blockedPhase = "Phase 5: SUID Abuse"
		LogPhaseEnd(5, "blocked", detail)
	} else {
		phasesCompleted++
		LogPhaseEnd(5, "success", detail)
	}

	// ================================================================
	// Create cleanup utility
	// ================================================================
	phaseCreateCleanup()

	// ================================================================
	// FINAL EVALUATION
	// ================================================================
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("Attack Simulation: Perfctl/Symbiote LD_PRELOAD Hijacking")
	Endpoint.Say("Phases Completed: %d/%d", phasesCompleted, totalPhases)
	Endpoint.Say("Phases Blocked:   %d/%d", phasesBlocked, totalPhases)
	Endpoint.Say("")

	if phasesBlocked > 0 {
		Endpoint.Say("RESULT: PROTECTED (partial)")
		Endpoint.Say("")
		Endpoint.Say("Security controls blocked %d out of %d simulation phases.", phasesBlocked, totalPhases)
		Endpoint.Say("First blocked phase: %s", blockedPhase)
		Endpoint.Say("")
		Endpoint.Say("Exit Code: 126 (Execution Prevented)")
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Blocked at: %s (%d/%d phases blocked)", blockedPhase, phasesBlocked, totalPhases))
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	// All phases completed - system is unprotected against these techniques
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: All %d simulation phases completed without prevention.", totalPhases)
	Endpoint.Say("")
	Endpoint.Say("Techniques Successfully Simulated:")
	Endpoint.Say("  1. T1574.006 - LD_PRELOAD shared library hijacking (Perfctl/Auto-Color/WolfsBane)")
	Endpoint.Say("  2. T1003.008 - PAM credential hooking and /etc/shadow dumping")
	Endpoint.Say("  3. T1014    - Userland rootkit network artifact hiding (Auto-Color/Symbiote)")
	Endpoint.Say("  4. T1059.004 - XOR-encrypted C2 config with trojanized crontab")
	Endpoint.Say("  5. T1548.001 - SUID binary enumeration and exploitation")
	Endpoint.Say("")
	Endpoint.Say("Threat Actors Using These Techniques:")
	Endpoint.Say("  - Perfctl (eCrime, cryptomining, 3+ years targeting millions of Linux servers)")
	Endpoint.Say("  - Symbiote (eCrime, financial sector, Latin America, 2025 variants)")
	Endpoint.Say("  - Auto-Color (universities, government targets)")
	Endpoint.Say("  - WolfsBane/Gelsemium APT (state-sponsored)")
	Endpoint.Say("")
	Endpoint.Say("Cleanup: Run c:\\F0\\cleanup.bat to remove all simulation artifacts")
	Endpoint.Say("")
	Endpoint.Say("Exit Code: 101 (Unprotected)")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d phases completed - system unprotected against LD_PRELOAD hijacking chain", totalPhases))
	Endpoint.Stop(Endpoint.Unprotected)
}

// ============================================================================
// MAIN - Standardized F0RT1KA Runner
// ============================================================================

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Security Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Version: %s", VERSION)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Initialize logger with Schema v2.0 metadata and execution context
	metadata := TestMetadata{
		Version:  VERSION,
		Category: "credential_access",
		Severity: "critical",
		Techniques: []string{
			"T1574.006", // Hijack Execution Flow: LD_PRELOAD
			"T1003.008", // OS Credential Dumping: /etc/passwd and /etc/shadow
			"T1548.001", // Abuse Elevation Control Mechanism: SUID/SGID
			"T1014",     // Rootkit
			"T1059.004", // Command and Scripting Interpreter: Unix Shell
		},
		Tactics: []string{"persistence", "defense-evasion", "credential-access", "privilege-escalation"},
		Score:   9.4,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8, // Based on Perfctl/Symbiote/Auto-Color real-world TTPs
			TechnicalSophistication: 2.8, // XOR encryption, ELF simulation, multi-technique
			SafetyMechanisms:        2.0, // Simulation-only, cleanup script, no actual rootkit
			DetectionOpportunities:  0.8, // 8+ distinct detection points across phases
			LoggingObservability:    1.0, // Full test_logger with phase tracking
		},
		Tags: []string{
			"ld-preload", "shared-library-hijacking", "pam-hooking",
			"credential-harvesting", "userland-rootkit", "financial-sector",
			"linux", "perfctl", "symbiote", "auto-color", "wolfsbane",
		},
	}

	// Resolve organization info
	orgInfo := ResolveOrganization("")

	// Define execution context
	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         300000, // 5 minutes
			CertificateMode:   "self-healing",
			MultiStageEnabled: false,
		},
	}

	// Initialize logger with v2.0 signature
	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	Endpoint.Say("Organization: %s", orgInfo.ShortName)
	Endpoint.Say("Execution ID: %s", executionContext.ExecutionID)
	Endpoint.Say("")

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}()

	// Run test with custom timeout runner
	done := make(chan bool, 1)
	go func() {
		test()
		done <- true
	}()

	// 5-minute timeout for multi-phase simulation
	timeout := 5 * time.Minute
	select {
	case <-done:
		Endpoint.Say("Test completed")
	case <-time.After(timeout):
		Endpoint.Say("Test timed out after %v", timeout)
		LogMessage("ERROR", "Test Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
		SaveLog(Endpoint.TimeoutExceeded, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		Endpoint.Stop(Endpoint.TimeoutExceeded)
	}
}
