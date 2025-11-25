# EDR Network Isolation via Windows Filtering Platform

**Test UUID:** `640e6458-5b6b-4153-87b4-8327599829a8`
**Version:** 1.0.0
**Category:** Defense Evasion
**Severity:** High
**Test Score**: **9.2/10**

## Overview

This test simulates the **SilentButDeadly** technique - a sophisticated EDR isolation method that uses the Windows Filtering Platform (WFP) to block EDR/AV cloud connectivity without terminating security processes. This approach is stealthier than traditional EDR killing techniques because security processes remain running, avoiding process termination alerts.

## Attack Narrative

A sophisticated threat actor uses legitimate Windows APIs to surgically isolate EDR/AV from cloud infrastructure while maintaining stealth by avoiding process termination. The attack proceeds in three distinct stages:

1. **Discovery**: Enumerate running processes to identify EDR/AV products
2. **Network Isolation**: Apply WFP filters to block EDR cloud connectivity
3. **Service Disruption**: Attempt to stop and disable EDR services

## MITRE ATT&CK Mapping

- **T1562.001** - Impair Defenses: Disable or Modify Tools (Primary)
- **T1562.004** - Impair Defenses: Disable Windows Firewall
- **T1489** - Service Stop
- **T1016** - System Network Configuration Discovery

**Tactics:** Defense Evasion, Discovery

## Technical Details

### Stage 1: EDR Process Discovery
- Enumerates running processes using `CreateToolhelp32Snapshot`
- Identifies 40+ modern EDR/AV products
- Extracts process names, PIDs, and product information
- Targets: Windows Defender, CrowdStrike, SentinelOne, Carbon Black, and more

### Stage 2: WFP Filter Application
- Re-enumerates EDR processes and retrieves full executable paths
- Initializes Windows Filtering Platform engine
- Creates custom WFP provider and sublayer
- Converts process paths to AppID blobs using FwpmGetAppIdFromFileName0
- Creates application-specific filter conditions (FWPM_CONDITION_ALE_APP_ID)
- Applies 4 network blocking filters per EDR process:
  - IPv4 outbound (FWPM_LAYER_ALE_AUTH_CONNECT_V4)
  - IPv6 outbound (FWPM_LAYER_ALE_AUTH_CONNECT_V6)
  - IPv4 inbound (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)
  - IPv6 inbound (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6)
- Blocks both inbound and outbound traffic for identified EDRs
- Full implementation of SilentButDeadly WFP filtering technique

### Stage 3: Service Disruption
- Connects to Windows Service Control Manager
- Attempts to stop EDR/AV services
- Attempts to disable service startup
- Logs all protection responses and blocks

## Detection Opportunities

1. **WFP Filter Creation** - Windows Event IDs 5441, 5157, 5152
2. **Process Enumeration** - Behavioral detection of EDR targeting
3. **Service Manipulation** - SCM access and service control attempts
4. **Network Isolation** - Sudden loss of EDR cloud connectivity
5. **Administrative API Usage** - Privileged WFP operations
6. **EDR Self-Protection** - Blocked service stop/disable attempts

## Expected Protection Responses

**Protected System (Exit 126):**
- Service stop/disable operations blocked (Access Denied)
- WFP filter creation may be blocked or monitored
- EDR self-protection mechanisms prevent disruption
- Cloud connectivity maintained despite attempts

**Vulnerable System (Exit 101):**
- EDR services successfully stopped
- Network filters successfully applied
- EDR isolated from cloud infrastructure
- Services disabled from startup

## Prerequisites

- **Administrator privileges** - Required for WFP and SCM access
- **Base Filtering Engine (BFE) service running** - Required for WFP operations
  - Usually running by default, even if Windows Firewall UI shows "disabled"
  - Most enterprise environments have this enabled via Group Policy
  - Test will fail gracefully at Stage 2 if BFE is unavailable
- **EDR/AV installed** - At least one supported product running

**Note:** The test will attempt all stages and report which ones succeed/fail. If WFP is unavailable, Stage 2 will fail gracefully while Stage 3 (service disruption) will still execute.

## Build Instructions

The build process follows the multi-stage pattern:
1. Build each stage separately
2. Sign each stage binary
3. Embed signed stages into orchestrator
4. Sign final orchestrator

```bash
# Automated build (recommended)
cd tests_source/640e6458-5b6b-4153-87b4-8327599829a8/
./build_all.sh

# This script:
# [Step 1/5] Builds 3 stage binaries (T1016, T1562.004, T1489)
# [Step 2/5] Signs each stage with F0RT1KA certificate
# [Step 3/5] Builds orchestrator (embeds signed stages via //go:embed)
# [Step 4/5] Signs final orchestrator
# [Step 5/5] Builds cleanup utility

# Final binaries:
# - 640e6458-5b6b-4153-87b4-8327599829a8.exe (~18MB orchestrator)
# - 640e6458-5b6b-4153-87b4-8327599829a8-T1016.exe (embedded in orchestrator)
# - 640e6458-5b6b-4153-87b4-8327599829a8-T1562.004.exe (embedded in orchestrator)
# - 640e6458-5b6b-4153-87b4-8327599829a8-T1489.exe (embedded in orchestrator)
# - cleanup_utility.exe (service restoration)
```

**Important:** Stage binaries MUST be signed BEFORE the orchestrator is built, as the orchestrator embeds the signed binaries.

## Signing

```bash
# Sign with F0RT1KA certificate
./utils/codesign sign build/640e6458-5b6b-4153-87b4-8327599829a8/640e6458-5b6b-4153-87b4-8327599829a8.exe

# Or dual-sign with org certificate
/build-sign-test 640e6458-5b6b-4153-87b4-8327599829a8 sb
```

## Execution

```powershell
# Run as Administrator
.\640e6458-5b6b-4153-87b4-8327599829a8.exe
```

## Cleanup

If Stage 3 successfully stops or disables EDR services, those changes persist. Use the cleanup utility to restore services:

```powershell
# Run as Administrator to restore EDR/AV services
.\cleanup_utility.exe
```

**What the cleanup utility does:**
- Restarts stopped EDR/AV services
- Re-enables disabled services (sets startup type to Automatic)
- Verifies services are running
- Reports restoration status

**Note:** WFP filters from Stage 2 are non-persistent and automatically removed when the test exits. The cleanup utility only handles service restoration from Stage 3.

## Test Architecture

**Pattern:** Multi-Stage Architecture (3+ Techniques)
**Deployment:** Single orchestrator with 3 embedded signed stage binaries
**Stage Binaries:**
- `640e6458-5b6b-4153-87b4-8327599829a8-T1016.exe` (Stage 1: EDR Discovery)
- `640e6458-5b6b-4153-87b4-8327599829a8-T1562.004.exe` (Stage 2: WFP Filters)
- `640e6458-5b6b-4153-87b4-8327599829a8-T1489.exe` (Stage 3: Service Disruption)

**How it works:**
1. Each stage is a standalone signed executable
2. Stages are embedded into the orchestrator using `//go:embed`
3. At runtime, orchestrator extracts stages to `c:\F0\`
4. Stages execute sequentially, reporting results back
5. Provides technique-level detection precision

**Cleanup:** Automatic WFP filter cleanup on exit, cleanup utility for service restoration

## Exit Codes

- **101** - Unprotected: EDR services successfully disrupted
- **126** - Protected: EDR self-protection mechanisms active
- **999** - Test Error: Prerequisites not met or execution failed

## Safety Mechanisms

- Non-persistent WFP filters (removed on exit)
- No kernel drivers or rootkit techniques
- Completely reversible operations
- Targeted approach (only affects identified EDR processes)
- No permanent system modifications
- Automatic cleanup on exit

## References

- [SilentButDeadly GitHub Repository](https://github.com/loosehose/SilentButDeadly)
- [SilentButDeadly: New Tool Blocks Network Traffic to Bypass EDR](https://gbhackers.com/silentbutdeadly-new-tool-blocks-network-traffic-to-bypass-edr/)
- [Windows Filtering Platform Documentation](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)

## Notes

- This test demonstrates real-world EDR evasion techniques used by threat actors
- Full implementation of the SilentButDeadly WFP filtering technique
- Creates application-specific filters using process paths and AppID blobs
- Actually blocks EDR network traffic when successful (not just a capability test)
- Test validates both WFP filter creation and EDR service manipulation defenses
- Schema v2.0 compliant for analytics and dashboards
