# CrowdStrike Falcon Configuration Checks

**Test ID:** `b2cd3532-701d-4700-bbb2-f7c10ef0d717`
**Category:** Cyber-Hygiene Baseline
**Architecture:** Multi-binary bundle (quarantine-resilient)
**Platform:** Windows

## Overview

The CrowdStrike validator performs **6 local-only checks** against the Falcon sensor installation. All checks use Windows registry reads and `sc.exe` queries — no CrowdStrike APIs or network calls are made. Status data is collected upfront into a `FalconStatus` struct, then each check evaluates against it.

### Compliance Logic

| Exit Code | Meaning | Condition |
|-----------|---------|-----------|
| **126** | Compliant | All 6 checks pass |
| **101** | Non-compliant | Any check fails |
| **999** | Error | Not admin, or CrowdStrike not installed |

Results are written to `c:\F0\validator_crowdstrike_output.json` for the orchestrator to collect and fan out as individual Elasticsearch documents.

---

## CH-CRW-001 — Falcon Sensor Service

| Field | Value |
|-------|-------|
| **Severity** | Critical |
| **MITRE Technique** | T1562.001 (Impair Defenses: Disable or Modify Tools) |
| **MITRE Tactic** | Defense Evasion |
| **Expected** | Running |

### What It Checks

Whether `CSFalconService` is running and its startup type.

### How It Works

1. Runs `sc query CSFalconService` and looks for `"RUNNING"` in the output.
2. Runs `sc qc CSFalconService` to determine startup type (`Automatic`, `Manual`, or `Disabled`).
3. Reports both running state and start type (e.g., "Running (Automatic start)").

### Why It Matters

If the service is not running, the sensor is completely inactive — no detection, no prevention, no telemetry. This is the most fundamental check in the entire validator.

---

## CH-CRW-002 — Sensor Operational Status

| Field | Value |
|-------|-------|
| **Severity** | High |
| **MITRE Technique** | T1562.001 (Impair Defenses: Disable or Modify Tools) |
| **MITRE Tactic** | Defense Evasion |
| **Expected** | Provisioned (State 1) |

### What It Checks

Whether the sensor is fully provisioned and connected to the CrowdStrike tenant.

### How It Works

1. Reads the `ProvisioningState` registry value from:
   - `HKLM\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default`
2. Falls back to `HKLM\SOFTWARE\CrowdStrike\Falcon`.
3. If `ProvisioningState` is not found, checks for the presence of the `AG` (Agent ID) value as a secondary indicator — if the agent ID exists, the sensor is assumed provisioned.

| State | Meaning |
|-------|---------|
| **1** | Fully provisioned |
| **0** | Not provisioned |
| **-1** | Undetermined |

### Why It Matters

A sensor can be installed and running but not provisioned to a tenant, meaning it has no policies, no cloud intelligence, and generates no alerts. This is a common misconfiguration during deployment rollouts.

---

## CH-CRW-003 — Prevention Mode

| Field | Value |
|-------|-------|
| **Severity** | Critical |
| **MITRE Technique** | T1562.001 (Impair Defenses: Disable or Modify Tools) |
| **MITRE Tactic** | Defense Evasion |
| **Expected** | Enabled |

### What It Checks

Whether the sensor is actively **blocking** threats versus merely **detecting** them (detect-only mode).

### How It Works (3-Layer Detection Strategy)

1. **Kernel container service** — checks if `CSFalconContainer` is running via `sc query`.
2. **Kernel driver** — checks if `CSAgent` driver is running via `sc query`.
3. **Registry policy** — reads `HKLM\SOFTWARE\CrowdStrike\Falcon\Prevention\Enabled` (value `1` = enabled).
4. **Fallback** — checks if `CSFalconService` is running as a minimal indicator.

The logic is: if either kernel component (`CSFalconContainer` OR `CSAgent`) is running, prevention is considered active. The kernel driver is what actually intercepts and blocks malicious operations at the OS level.

### Why It Matters

Detect-only mode is common during initial rollouts but leaves endpoints unprotected. An attacker on a detect-only host can execute freely — the SOC sees alerts but nothing is blocked. This is one of the most dangerous misconfigurations in any EDR deployment.

---

## CH-CRW-004 — Sensor Version

| Field | Value |
|-------|-------|
| **Severity** | High |
| **MITRE Technique** | T1562.001 (Impair Defenses: Disable or Modify Tools) |
| **MITRE Tactic** | Defense Evasion |
| **Expected** | >= 7.0 |

### What It Checks

Whether the installed sensor version meets the minimum requirement (`>= 7.0`).

### How It Works (Multi-Source Version Discovery)

**Registry approach** — tries 3 paths in order:
1. `HKLM\SOFTWARE\CrowdStrike\Falcon` → `Version`
2. `HKLM\SOFTWARE\CrowdStrike\Falcon\Sensor` → `Version`
3. `HKLM\SYSTEM\CrowdStrike\{9b03c1d9-...}\{16e0423f-...}\Default` → `Version`

**File version fallback** — if all registry paths fail, reads `VersionInfo.FileVersion` via PowerShell `Get-Item` from:
1. `C:\Program Files\CrowdStrike\CSFalconService.exe`
2. `C:\Windows\System32\drivers\CrowdStrike\CSAgent.sys`

Version comparison extracts major.minor and compares against the `MINIMUM_SENSOR_VERSION` constant.

### Why It Matters

Older sensor versions lack newer threat intelligence models, behavioral detections, and kernel-level protections. Version 7.x+ introduced significant improvements to fileless attack detection and process injection prevention.

---

## CH-CRW-005 — Cloud Connectivity

| Field | Value |
|-------|-------|
| **Severity** | High |
| **MITRE Technique** | T1562.004 (Impair Defenses: Disable or Modify System Firewall) |
| **MITRE Tactic** | Defense Evasion |
| **Expected** | Connected |

### What It Checks

Whether the sensor can reach CrowdStrike's cloud for threat intelligence updates and alert reporting.

### How It Works

1. Reads `ConnectionState` from the CrowdStrike registry key — value `1` means connected.
2. Checks for presence of `LastSeen` binary value — its existence means the sensor has previously connected.
3. **Fallback** — if the service is running AND provisioning state is `1`, assumes connected.

### Why It Matters

Without cloud connectivity, the sensor operates with stale threat intelligence, cannot report incidents to the Falcon console, and cannot receive policy updates. An adversary who blocks CrowdStrike's cloud domains (e.g., via firewall rules or DNS poisoning) effectively blinds the SOC while maintaining a running sensor that appears healthy on the surface.

---

## CH-CRW-006 — Tamper Protection

| Field | Value |
|-------|-------|
| **Severity** | Critical |
| **MITRE Technique** | T1562.001 (Impair Defenses: Disable or Modify Tools), T1070 (Indicator Removal) |
| **MITRE Tactic** | Defense Evasion |
| **Expected** | Enabled |

### What It Checks

Whether the sensor is protected against malicious modification, uninstallation, or service disruption.

### How It Works (3-Tier Detection)

1. **Registry value** — reads `HKLM\SOFTWARE\CrowdStrike\Falcon\Protection\TamperProtection` (value `1` = enabled).
2. **Kernel driver** — checks if `CSAgent` kernel driver is running via `sc query` (a running kernel driver inherently provides tamper protection).
3. **Driver enumeration** — runs `sc query type= driver state= all` and searches for `CrowdStrike`, `CSAgent`, or `csagent` strings in the output.

### Why It Matters

Without tamper protection, an attacker with local admin can stop the service, unload the driver, or uninstall the agent entirely. This is a standard step in ransomware playbooks — disabling CrowdStrike before deploying encryptors. With tamper protection enabled, even administrators cannot uninstall or disable the sensor without a valid maintenance token from the Falcon console.

---

## Summary Table

| Control ID | Name | Severity | MITRE | Detection Method |
|------------|------|----------|-------|-----------------|
| CH-CRW-001 | Falcon Sensor Service | Critical | T1562.001 | `sc query` / `sc qc` |
| CH-CRW-002 | Sensor Operational Status | High | T1562.001 | Registry (`ProvisioningState`, `AG`) |
| CH-CRW-003 | Prevention Mode | Critical | T1562.001 | `sc query` + Registry (`Prevention\Enabled`) |
| CH-CRW-004 | Sensor Version | High | T1562.001 | Registry (3 paths) + File version (2 paths) |
| CH-CRW-005 | Cloud Connectivity | High | T1562.004 | Registry (`ConnectionState`, `LastSeen`) |
| CH-CRW-006 | Tamper Protection | Critical | T1562.001, T1070 | Registry + Kernel driver enumeration |

## Registry Paths Reference

| Path | Values Used |
|------|-------------|
| `HKLM\SYSTEM\CrowdStrike\{9b03c1d9-...}\{16e0423f-...}\Default` | `Version`, `AG`, `ProvisioningState`, `ConnectionState`, `LastSeen` |
| `HKLM\SOFTWARE\CrowdStrike\Falcon` | `Version`, `CID` |
| `HKLM\SOFTWARE\CrowdStrike\Falcon\Sensor` | `Version` |
| `HKLM\SOFTWARE\CrowdStrike\Falcon\Prevention` | `Enabled` |
| `HKLM\SOFTWARE\CrowdStrike\Falcon\Protection` | `TamperProtection` |
| `HKLM\SYSTEM\CurrentControlSet\Services\CSAgent` | Service existence, `AG` |

## Windows Services Queried

| Service Name | Type | Purpose |
|-------------|------|---------|
| `CSFalconService` | User-mode service | Main Falcon sensor service |
| `CSFalconContainer` | Kernel-mode service | Kernel container for prevention |
| `CSAgent` | Kernel driver | Core kernel-level driver |
