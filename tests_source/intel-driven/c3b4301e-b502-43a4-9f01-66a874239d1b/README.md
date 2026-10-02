# Star Blizzard RedFlick CosmicPulse Espionage Chain

**Test Score**: **8.7/10**

## Overview

Multi-stage Windows simulation of the **Star Blizzard** (SEABORGIUM/Callisto, FSB-linked) espionage chain disclosed by Microsoft Threat Intelligence on 2026-09-29: the **RedFlick** delivery technique (password-protected event-invite archive → LNK → hidden conhost/cmd/BAT chain → ssh.exe PermitLocalCommand download cradle that authenticates against an in-process loopback SSH sandbox and genuinely executes its client-side LocalCommand fetch → weaponized PDF with embedded base64 payload → silent msiexec install of a genuine persistence MSI whose CustomActions create three masquerading scheduled tasks → rundll32/control.exe CPL execution → AES-ECB config staged in `HKCU\Software\Classes\.mollis`) culminating in a **CosmicPulse**-style HTTP registration beacon that exfiltrates `hostname|username` as UTF-16LE + Base64 with a spoofed Edge User-Agent. Each of the 7 killchain stages is a separate signed binary mapped to exactly one ATT&CK technique, executed in disclosure order against a loopback-only (127.0.0.1) asset/C2 server, with per-stage watchdog and guaranteed cleanup.

## MITRE ATT&CK Mapping

- **Tactics**: Execution, Command and Control, Defense Evasion, Persistence
- **Platform**: Windows
- **Threat Actor**: Star Blizzard (SEABORGIUM/Callisto, FSB-linked)

| Stage | Technique | Name |
|-------|-----------|------|
| 1 | T1204.002 | User Execution: Malicious File (event-invite LNK → conhost → cmd → BAT) |
| 2 | T1105 | Ingress Tool Transfer (ssh.exe PermitLocalCommand cradle + curl.exe fetch) |
| 3 | T1059.001 | Command and Scripting Interpreter: PowerShell (cAB base64 extraction + Invoke-Expression) |
| 4 | T1218.007 | System Binary Proxy Execution: Msiexec (`/i /q /norestart` silent install of a genuine persistence MSI) |
| 5 | T1053.005 | Scheduled Task/Job: Scheduled Task (RedFlick persistence task trio) |
| 6 | T1218.011 | System Binary Proxy Execution: Rundll32 (Control_RunDLL + control.exe CPL launch, `.mollis` AES staging) |
| 7 | T1071.001 | Application Layer Protocol: Web Protocols (CosmicPulse HTTP beacon) |

## Test Execution

An Authenticode-signed Go orchestrator embeds 7 gzip-compressed signed stage binaries plus a cleanup utility, starts a loopback HTTP asset/C2 server on `127.0.0.1:<random port>` (passed to stages via `F0_LOOPBACK_PORT`) and an in-process loopback SSH sandbox on a separate random port (per-run Ed25519 host+client keys, passed via `F0_SSH_PORT`/`F0_SSH_KEY`), writes pre/post system snapshots (Defender status, AV exclusions, hotfixes), and detonates the stages in disclosure order under a 180-second per-stage watchdog. Every stage uses the real system binaries (`conhost.exe`, `cmd.exe`, `ssh.exe`, `curl.exe`, `powershell.exe`, `msiexec.exe`, `schtasks.exe`, `rundll32.exe`, `control.exe`) with the disclosure's exact command-line surfaces, so process-creation telemetry matches the real chain. All decoy artifacts stay under `c:\Users\fortika-test\StarBlizzardInvite`; all logs/binaries stay in `C:\F0`; no traffic ever leaves loopback. Safety bounds: scheduled-task actions are inert decoy scripts, pre-existing tasks/registry values are never touched (skip-if-exists + namespaced fallback), the genuine persistence MSI is uninstalled by the cleanup utility (pinned ProductCode), per-run SSH key material stays in `C:\F0` and is removed after the run, and the cleanup utility runs on every exit path (success, blocked, error, panic, watchdog).

Lab-verified on the win lab (Windows 11 Pro 26200, Defender real-time ON, MAPS suppressed = local-only baseline): exit 101 UNPROTECTED, all 7 stages completed in ~16s, zero Defender detections for this test. Verdict evidence confirms the SSH cradle authenticated and PermitLocalCommand executed client-side (stage 2), the genuine MSI installed silently (stage 4), and all three persistence tasks were created by its CustomActions (stage 5).

## Expected Outcomes

- **Protected**: EDR/AV detects and blocks any stage — orchestrator reports PROTECTED with the stopping stage, technique, and exit code (105 quarantine / 126 execution prevention / 127 detected-blocked)
- **Unprotected**: all 7 stages complete — full RedFlick delivery + CosmicPulse persistence chain succeeds without any protection layer firing (exit code 101)
- **Watchdog**: a stage exceeding the 180s budget is force-terminated and logged as `unexpected_hang` (exit code 102)
- **Error**: infrastructure/prerequisite failure (exit code 999)

## Build Instructions

```bash
# Build single self-contained binary (builds + signs each stage, gzips, embeds, links orchestrator)
./tests_source/intel-driven/c3b4301e-b502-43a4-9f01-66a874239d1b/build_all.sh

# Or manually:
./utils/gobuild build tests_source/intel-driven/c3b4301e-b502-43a4-9f01-66a874239d1b/
./utils/codesign sign build/c3b4301e-b502-43a4-9f01-66a874239d1b/c3b4301e-b502-43a4-9f01-66a874239d1b.exe
```
