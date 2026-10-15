# Kothamine Tailcat Encrypted C2 Channel and Data Exfiltration

**Test Score**: **8.7/10**

## Overview
Simulates the Kothamine malware family's use of Tailscale's `tailcat` utility (control-plane-less netcat over the WireGuard data plane) to establish an encrypted, internet-reachable C2 channel and exfiltrate data — as reported by Microsoft Threat Intelligence and Malwarebytes (2026-09-28). The test downloads the genuine pinned tailcat v0.7.0 binary from official GitHub releases (SHA256-verified), launches an unauthenticated SSH server over Tailscale DERP relays (`tailcat serve no-auth-ssh`), proves shell access back over the tunnel, then exfiltrates synthetic decoy data (canary-safe PII) to an in-test `tailcat recv` drop box with SHA256 content verification. Evaluates AV/EDR coverage of ingress tool transfer, protocol tunneling, SSH-over-tunnel remote access, and exfiltration over an encrypted C2 channel that bypasses traditional network inspection. Cross-platform: Windows and Linux.

## MITRE ATT&CK Mapping
- **Tactic**: Command and Control
- **Technique**: T1105 - Ingress Tool Transfer
- **Technique**: T1572 - Protocol Tunneling
- **Tactic**: Lateral Movement
- **Sub-technique**: T1021.004 - Remote Services: SSH
- **Tactic**: Collection
- **Technique**: T1005 - Data from Local System
- **Tactic**: Exfiltration
- **Technique**: T1041 - Exfiltration Over C2 Channel

## Test Execution
Multi-stage (3 stages, embedded as gzip-compressed signed binaries in a single orchestrator):

1. **Stage 1 (T1105)** — Downloads the pinned tailcat v0.7.0 static binary from `github.com/tailscale/tailcat` releases into `LOG_DIR`, verifies the archive SHA256 against authoring-time pinned checksums, extracts it (zip on Windows / tar.gz on Linux), and proves it executes via `tailcat --version`.
2. **Stage 2 (T1572 + T1021.004)** — Launches `tailcat serve no-auth-ssh` (an unauthenticated SSH server reachable over the internet via Tailscale DERP relays, WireGuard-encrypted, no Tailscale account or inbound port required), parses the ephemeral `tc…` address from stderr, proves shell access by connecting back as a client (`tailcat ssh <addr> whoami`) and comparing against the local identity, then kills the server (measured lifetime ~1s, guaranteed via defer).
3. **Stage 3 (T1005 + T1041)** — Creates a fictitious user profile with format-valid but never-issued decoy data (SSA ad-reserved SSNs, Luhn-valid 4242 test PANs, RFC 2606 `.invalid` emails) under `ARTIFACT_DIR`, spawns an in-test `tailcat recv` drop-box receiver, and exfiltrates the decoy files via `tailcat cp` (system scp routed through the WireGuard tunnel, egressing through Tailscale's internet DERP relays). Success is proven by SHA256 hash-set comparison at the receiver.

Exit codes: **101** = all stages completed unimpeded (C2 established, data exfiltrated); **126/105/127** = protection layer intervened with positive evidence (OS denial on execution, or `os.Stat`-confirmed quarantine); **102** = per-stage timeout (240 s budget); **999** = prerequisite/ambiguous failure (no internet egress, checksum mismatch, missing system ssh/scp client) — never a protection verdict.

## Expected Outcomes
- **Protected**: EDR/AV blocks or quarantines the tailcat binary or a stage binary, denies execution, or an egress control prevents GitHub/DERP-relay connectivity (exit 126/105/127 with positive evidence)
- **Unprotected**: All three stages complete — tailcat tooling transferred, encrypted C2 tunnel established, unauthenticated SSH shell proven, decoy data exfiltrated and hash-verified (exit 101)

## Lab Evidence (2026-10-14)
- **Windows 11 Pro (x86_64), CrowdStrike Falcon Sensor active** (CSFalconService running; Windows Defender in passive mode — WinDefend/Sense stopped, real-time protection off): exit **101 UNPROTECTED**, full killchain in ~16 s, all 3 stages succeeded. Falcon did not block or quarantine any stage: tailcat v0.7.0 download from GitHub, `tailcat serve no-auth-ssh` via DERP region 301 (New York City), shell proof (`whoami=win-81o55oa6lo0\jimx`), and 5-file exfiltration (2,479 bytes, SHA256-verified) all completed. `test_execution_log.json` validates against Schema v2.0.
- **Debian 13 (no EDR — behavior validation only)**: exit **101**, 3/3 stages in ~13 s.
- Note: the lab evidence proves end-to-end execution and telemetry generation on both platforms; it does **not** measure the bundled detection rules firing in a SIEM (tenant-defense property, out of scope for v2.1 test scoring).

## Build Instructions
```bash
# Build single self-contained binary (Windows + Linux orchestrators)
./tests_source/intel-driven/c37d6a01-3934-4e72-9cb1-3dae284b937b/build_all.sh

# Or manually:
./utils/gobuild build tests_source/intel-driven/c37d6a01-3934-4e72-9cb1-3dae284b937b/
./utils/codesign sign build/c37d6a01-3934-4e72-9cb1-3dae284b937b/c37d6a01-3934-4e72-9cb1-3dae284b937b.exe
```
