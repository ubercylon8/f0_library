//go:build linux
// +build linux

/*
STAGE 2: SSH Lateral Movement & Privilege Escalation (T1021.004, T1068)
Simulates SSH-Snake lateral movement, CVE-2024-37085 ESXi auth bypass,
CVE-2024-1086 kernel exploit, and enabling SSH on ESXi hosts.
Based on RansomHub, Akira, and Black Basta ESXi attack patterns.
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
	TECHNIQUE_ID   = "T1021.004"
	TECHNIQUE_NAME = "SSH Lateral Movement & Privilege Escalation"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "SSH lateral movement and privilege escalation simulation")

	if err := performTechnique(); err != nil {
		if isBlockedError(err) {
			fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)
			LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
			os.Exit(StageBlocked)
		}

		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		os.Exit(StageError)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "SSH lateral movement and privilege escalation completed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "/tmp/F0"
	artifactDir := filepath.Join(targetDir, "esxi_lateral")

	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create lateral movement directory: %v", err)
	}

	// Phase 1: Simulate SSH-Snake self-modifying worm behavior
	fmt.Printf("[STAGE %s] Phase 1: Simulating SSH-Snake lateral movement...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating SSH-Snake self-modifying worm (Sysdig Jan 2024)")

	sshSnakeOutput := simulateSSHSnake()
	sshSnakePath := filepath.Join(artifactDir, "ssh_snake_output.txt")
	if err := os.WriteFile(sshSnakePath, []byte(sshSnakeOutput), 0644); err != nil {
		return fmt.Errorf("failed to write SSH-Snake output: %v", err)
	}
	fmt.Printf("[STAGE %s]   SSH-Snake discovered 4 reachable hosts via SSH key harvesting\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "SSH-Snake discovered 4 reachable hosts")

	// Phase 2: Simulate discovering and harvesting SSH keys
	fmt.Printf("[STAGE %s] Phase 2: Harvesting SSH keys from known_hosts and authorized_keys...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Harvesting SSH keys for lateral movement")

	keyHarvestOutput := simulateSSHKeyHarvest()
	keyHarvestPath := filepath.Join(artifactDir, "ssh_key_harvest.txt")
	if err := os.WriteFile(keyHarvestPath, []byte(keyHarvestOutput), 0644); err != nil {
		return fmt.Errorf("failed to write key harvest output: %v", err)
	}
	fmt.Printf("[STAGE %s]   Harvested 6 SSH keys from system credential stores\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Harvested 6 SSH private keys")

	// Phase 3: Simulate CVE-2024-37085 - ESXi Authentication Bypass
	fmt.Printf("[STAGE %s] Phase 3: Simulating CVE-2024-37085 (ESXi Authentication Bypass)...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating CVE-2024-37085: Creating 'ESX Admins' AD group for hypervisor admin rights")

	cve37085Output := simulateCVE202437085()
	cve37085Path := filepath.Join(artifactDir, "cve_2024_37085_exploit.txt")
	if err := os.WriteFile(cve37085Path, []byte(cve37085Output), 0644); err != nil {
		return fmt.Errorf("failed to write CVE-2024-37085 output: %v", err)
	}
	fmt.Printf("[STAGE %s]   CVE-2024-37085: ESX Admins group created, admin rights obtained\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "CVE-2024-37085 exploitation simulated - admin rights obtained")

	// Phase 4: Simulate CVE-2024-1086 - Linux kernel nf_tables exploit
	fmt.Printf("[STAGE %s] Phase 4: Simulating CVE-2024-1086 (Flipping Pages kernel exploit)...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating CVE-2024-1086: nf_tables use-after-free for root escalation")

	cve1086Output := simulateCVE20241086()
	cve1086Path := filepath.Join(artifactDir, "cve_2024_1086_exploit.txt")
	if err := os.WriteFile(cve1086Path, []byte(cve1086Output), 0644); err != nil {
		return fmt.Errorf("failed to write CVE-2024-1086 output: %v", err)
	}
	fmt.Printf("[STAGE %s]   CVE-2024-1086: Root privilege escalation achieved\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "CVE-2024-1086 exploitation simulated - root obtained")

	// Phase 5: Simulate enabling SSH on ESXi (LockBit pattern)
	fmt.Printf("[STAGE %s] Phase 5: Enabling SSH on ESXi hosts (vim-cmd hostsvc/enable_ssh)...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating: vim-cmd hostsvc/enable_ssh (LockBit pattern)")

	sshEnableOutput := simulateEnableSSH()
	sshEnablePath := filepath.Join(artifactDir, "enable_ssh.txt")
	if err := os.WriteFile(sshEnablePath, []byte(sshEnableOutput), 0644); err != nil {
		return fmt.Errorf("failed to write SSH enable output: %v", err)
	}
	fmt.Printf("[STAGE %s]   SSH enabled on all 4 ESXi hosts\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "SSH enabled on all ESXi hosts")

	// Write lateral movement summary
	summaryPath := filepath.Join(targetDir, "lateral_movement_summary.txt")
	summary := generateLateralSummary()
	if err := os.WriteFile(summaryPath, []byte(summary), 0644); err != nil {
		return fmt.Errorf("failed to write lateral movement summary: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, "Lateral movement and privilege escalation simulation complete")

	return nil
}

func simulateSSHSnake() string {
	var sb strings.Builder
	sb.WriteString("=== SSH-Snake Self-Modifying Worm Simulation ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02T15:04:05Z")))
	sb.WriteString("Reference: Sysdig TRT Analysis (January 2024)\n\n")

	sb.WriteString("[*] SSH-Snake initializing...\n")
	sb.WriteString("[*] Phase 1: Harvesting SSH credentials from current host\n")
	sb.WriteString("    [+] Searching ~/.ssh/id_rsa, id_ed25519, id_ecdsa\n")
	sb.WriteString("    [+] Parsing ~/.ssh/known_hosts for target discovery\n")
	sb.WriteString("    [+] Parsing ~/.ssh/config for connection profiles\n")
	sb.WriteString("    [+] Checking /etc/ssh/sshd_config for key locations\n")
	sb.WriteString("    [+] Scanning bash_history for ssh commands\n\n")

	sb.WriteString("[*] Phase 2: Lateral movement via discovered credentials\n")

	hosts := []struct {
		IP       string
		User     string
		KeyType  string
		Hostname string
	}{
		{"10.20.30.10", "root", "ed25519", "esxi-prod-01"},
		{"10.20.30.11", "root", "rsa", "esxi-prod-02"},
		{"10.20.30.12", "root", "rsa", "esxi-prod-03"},
		{"10.20.30.20", "root", "ed25519", "esxi-dr-01"},
	}

	for i, h := range hosts {
		sb.WriteString(fmt.Sprintf("    [+] Hop %d: Connecting to %s@%s (%s) via %s key\n", i+1, h.User, h.IP, h.Hostname, h.KeyType))
		sb.WriteString(fmt.Sprintf("         Connection established - self-replicating to %s\n", h.Hostname))
		sb.WriteString(fmt.Sprintf("         Harvested %d additional keys from %s\n", 2+i, h.Hostname))
	}

	sb.WriteString(fmt.Sprintf("\n[*] SSH-Snake completed: %d hosts compromised, %d total keys collected\n", len(hosts), 14))
	return sb.String()
}

func simulateSSHKeyHarvest() string {
	var sb strings.Builder
	sb.WriteString("=== SSH Key Harvest Results ===\n\n")

	keys := []struct {
		Path        string
		Type        string
		Fingerprint string
		Owner       string
	}{
		{"/root/.ssh/id_rsa", "RSA-4096", "SHA256:k1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0", "root@esxi-prod-01"},
		{"/root/.ssh/id_ed25519", "ED25519", "SHA256:x1y2z3a4b5c6d7e8f9g0h1i2j3k4l5m6n7o8p9q0", "root@esxi-prod-01"},
		{"/etc/vmware/.ssh/authorized_keys", "RSA-2048", "SHA256:r1s2t3u4v5w6x7y8z9a0b1c2d3e4f5g6h7i8j9k0", "vcenter-service"},
		{"/var/log/.ssh_backup/id_rsa", "RSA-4096", "SHA256:m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e9f0", "backup-svc"},
		{"/home/admin/.ssh/id_ecdsa", "ECDSA-384", "SHA256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0", "admin@vcenter"},
		{"/root/.ssh/authorized_keys", "RSA-4096", "SHA256:j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0", "ansible-automation"},
	}

	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("Key: %s\n", k.Path))
		sb.WriteString(fmt.Sprintf("  Type: %s\n", k.Type))
		sb.WriteString(fmt.Sprintf("  Fingerprint: %s\n", k.Fingerprint))
		sb.WriteString(fmt.Sprintf("  Owner: %s\n\n", k.Owner))
	}

	sb.WriteString(fmt.Sprintf("Total keys harvested: %d\n", len(keys)))
	return sb.String()
}

func simulateCVE202437085() string {
	var sb strings.Builder
	sb.WriteString("=== CVE-2024-37085 - ESXi Authentication Bypass ===\n")
	sb.WriteString("Severity: CVSS 9.8 (Critical)\n")
	sb.WriteString("Used by: Storm-0506, Black Basta\n\n")

	sb.WriteString("[*] Exploiting CVE-2024-37085: ESXi Active Directory integration bypass\n")
	sb.WriteString("[*] Step 1: Creating 'ESX Admins' group in Active Directory\n")
	sb.WriteString("    Command: net group \"ESX Admins\" /domain /add\n")
	sb.WriteString("    [SIMULATED] Group 'ESX Admins' created in AD domain\n\n")

	sb.WriteString("[*] Step 2: Adding attacker account to 'ESX Admins' group\n")
	sb.WriteString("    Command: net group \"ESX Admins\" attacker_user /domain /add\n")
	sb.WriteString("    [SIMULATED] User added to ESX Admins group\n\n")

	sb.WriteString("[*] Step 3: ESXi host automatically grants admin privileges\n")
	sb.WriteString("    - ESXi host checks AD group membership\n")
	sb.WriteString("    - 'ESX Admins' group triggers automatic admin role assignment\n")
	sb.WriteString("    - No ESXi-side authentication required\n\n")

	sb.WriteString("[+] Result: Full administrator access to all ESXi hosts\n")
	sb.WriteString("    - Can manage VMs, datastores, networking\n")
	sb.WriteString("    - Can enable SSH, modify firewall rules\n")
	sb.WriteString("    - Can access /vmfs/volumes/ directly\n")
	return sb.String()
}

func simulateCVE20241086() string {
	var sb strings.Builder
	sb.WriteString("=== CVE-2024-1086 - Flipping Pages (Linux Kernel nf_tables) ===\n")
	sb.WriteString("Severity: CVSS 7.8 (High)\n")
	sb.WriteString("Used by: RansomHub, Akira affiliates\n")
	sb.WriteString("Affects: Linux kernels 5.14 - 6.6 (nf_tables use-after-free)\n\n")

	sb.WriteString("[*] Exploiting CVE-2024-1086: nf_tables double-free in nft_verdict_init()\n")
	sb.WriteString("[*] Step 1: Setting up nftables rules to trigger use-after-free\n")
	sb.WriteString("    - Creating nftables chain with NF_DROP verdict\n")
	sb.WriteString("    - Triggering double-free via verdict rewrite\n")
	sb.WriteString("    [SIMULATED] Heap spray successful\n\n")

	sb.WriteString("[*] Step 2: Kernel page table manipulation ('Flipping Pages')\n")
	sb.WriteString("    - Overwriting PTE entries for privilege escalation\n")
	sb.WriteString("    - Patching kernel credential structure\n")
	sb.WriteString("    [SIMULATED] Page table entries modified\n\n")

	sb.WriteString("[*] Step 3: Root shell obtained\n")
	sb.WriteString("    Before: uid=1000(user) gid=1000(user)\n")
	sb.WriteString("    After:  uid=0(root) gid=0(root)\n\n")

	sb.WriteString("[+] Result: Root privileges obtained on ESXi host\n")
	sb.WriteString("    - Full control over hypervisor\n")
	sb.WriteString("    - Can modify VM configurations\n")
	sb.WriteString("    - Can access all datastores\n")
	return sb.String()
}

func simulateEnableSSH() string {
	var sb strings.Builder
	sb.WriteString("=== Enable SSH on ESXi Hosts (LockBit Pattern) ===\n\n")

	hosts := []struct {
		IP       string
		Hostname string
	}{
		{"10.20.30.10", "esxi-prod-01"},
		{"10.20.30.11", "esxi-prod-02"},
		{"10.20.30.12", "esxi-prod-03"},
		{"10.20.30.20", "esxi-dr-01"},
	}

	for _, h := range hosts {
		sb.WriteString(fmt.Sprintf("[*] Enabling SSH on %s (%s)\n", h.IP, h.Hostname))
		sb.WriteString(fmt.Sprintf("    Command: vim-cmd hostsvc/enable_ssh\n"))
		sb.WriteString(fmt.Sprintf("    [SIMULATED] SSH service started on %s\n", h.Hostname))
		sb.WriteString(fmt.Sprintf("    Command: esxcli network firewall ruleset set -e true -r sshServer\n"))
		sb.WriteString(fmt.Sprintf("    [SIMULATED] Firewall rule updated on %s\n\n", h.Hostname))
	}

	sb.WriteString(fmt.Sprintf("[+] SSH enabled on %d ESXi hosts\n", len(hosts)))
	return sb.String()
}

func generateLateralSummary() string {
	var sb strings.Builder
	sb.WriteString("=== Lateral Movement & Privilege Escalation Summary ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format("2006-01-02T15:04:05Z")))

	sb.WriteString("SSH-Snake Results:\n")
	sb.WriteString("  - Hosts compromised: 4\n")
	sb.WriteString("  - SSH keys collected: 14\n")
	sb.WriteString("  - Propagation method: Self-modifying worm\n\n")

	sb.WriteString("CVE-2024-37085 (ESXi Auth Bypass):\n")
	sb.WriteString("  - Status: EXPLOITED (simulated)\n")
	sb.WriteString("  - Access level: Full ESXi administrator\n")
	sb.WriteString("  - Method: Created 'ESX Admins' AD group\n\n")

	sb.WriteString("CVE-2024-1086 (Kernel Privesc):\n")
	sb.WriteString("  - Status: EXPLOITED (simulated)\n")
	sb.WriteString("  - Access level: root\n")
	sb.WriteString("  - Method: nf_tables use-after-free\n\n")

	sb.WriteString("SSH Service Status:\n")
	sb.WriteString("  - esxi-prod-01: SSH ENABLED\n")
	sb.WriteString("  - esxi-prod-02: SSH ENABLED\n")
	sb.WriteString("  - esxi-prod-03: SSH ENABLED\n")
	sb.WriteString("  - esxi-dr-01:   SSH ENABLED\n")

	return sb.String()
}

func isBlockedError(err error) bool {
	errStr := strings.ToLower(err.Error())
	// Only match EDR/AV-specific indicators, NOT standard OS errors.
	// "permission denied" and "operation not permitted" are standard POSIX errors
	// from filesystem operations — not EDR blocks. On Linux, EDR blocks manifest
	// as process kills (SIGKILL), file quarantine (file disappears), or security
	// policy enforcement — never as simple EACCES/EPERM on mkdir/write.
	blockedPatterns := []string{
		"quarantined", "blocked by security", "blocked by endpoint",
		"malware detected", "threat detected", "security policy",
	}
	for _, pattern := range blockedPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}
