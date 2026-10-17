# ScreenConnect Unsanctioned RMM Abuse for Third-Party Access

**Test Score**: **8.4/10**

## Overview
Validates whether AV/EDR flags the "living off trusted software" pattern used by Black Basta and access brokers: silently installing a **genuine, vendor-signed** ConnectWise ScreenConnect remote-monitoring-and-management (RMM) agent, confirming the resulting Windows service, and using that foothold to relay outbound and exfiltrate staged data. The embedded agent is not malware — it is the real MSI ScreenConnect ships to customers. The detection challenge is trust-inheritance: the agent's hash, signature, and vendor are all clean, so controls have to catch the *anomalous install + service + relay of an unsanctioned RMM*, not the software itself. This mirrors the mass exploitation that followed the ScreenConnect authentication-bypass vulnerability (CVE-2024-1709) and CISA/NSA/MS-ISAC's AA23-025A advisory on RMM abuse.

## MITRE ATT&CK Mapping
- **Tactic**: Initial Access / Persistence
  - **Technique**: T1199 - Trusted Relationship (framing technique — carried in metadata; the vendor-signed agent is the trust vector)
- **Tactic**: Command and Control
  - **Technique**: T1219 - Remote Access Software
- **Tactic**: Persistence
  - **Technique**: T1543 - Create or Modify System Process
  - **Sub-technique**: T1543.003 - Windows Service
- **Tactic**: Exfiltration
  - **Technique**: T1567 - Exfiltration Over Web Service
  - **Sub-technique**: T1567.002 - Exfiltration to Cloud Storage

## Test Execution
Simulates a 3-stage unsanctioned-RMM kill chain to evaluate defensive capabilities:

1. **Stage 1 (T1219)** — Silently installs the embedded, vendor-signed ScreenConnect MSI via `msiexec /qn /norestart`, dropped first to `LOG_DIR` so AV/EDR can observe the file write.
2. **Stage 2 (T1543.003)** — Confirms the `ScreenConnect Client (<instance-id>)` Windows service was created and is running, then generates the outbound relay telemetry (DNS resolution + TCP connect) an RMM agent produces on start, against an unreachable RFC 2606 `.invalid` placeholder host.
3. **Stage 3 (T1567.002)** — Stages synthetic decoy files in `ARTIFACT_DIR`, collects them into a zip archive in `LOG_DIR`, and attempts an HTTPS upload to a benign, unreachable `.invalid` endpoint.

No live C2 relay is stood up and no relay/instance secrets are shipped — both network destinations are guaranteed-unreachable placeholders that exist purely to generate realistic egress telemetry (DNS + TCP/HTTP attempt shapes) for detection engineering.

## Expected Outcomes
- **Protected**: EDR/AV blocks the MSI install (policy rejection or quarantine), blocks/quarantines the collected archive, or otherwise interrupts the chain on positive evidence
- **Unprotected**: The full chain completes — RMM installed, service running, relay attempted, decoy data collected and exfiltration attempted

## Manual Build Gate

This test embeds a real ConnectWise ScreenConnect Windows MSI, which is **not committed to the repository** (vendor licensing/redistribution restrictions). Before building:

1. Acquire the ScreenConnect Windows access-agent MSI (x64) from ConnectWise out-of-band.
2. Place it at `tests_source/intel-driven/208ef54b-06bc-4610-87b6-520aea57517e/screenconnect_embedded.msi` (git-ignored).
3. Run the build script — it stops with an explicit error if the MSI is missing.

Because this test genuinely installs software and creates a real Windows service, **snapshot the target VM before running and revert after**. Cleanup is provided via `cleanup_utility.exe` (uninstalls the agent, deletes the service, removes install directories, decoys, and dropped artifacts) — run it as Administrator after each execution.

## Build Instructions
```bash
# Stage the vendor MSI first (see Manual Build Gate above), then:
./tests_source/intel-driven/208ef54b-06bc-4610-87b6-520aea57517e/build_all.sh

# Or manually:
./utils/gobuild build tests_source/intel-driven/208ef54b-06bc-4610-87b6-520aea57517e/
./utils/codesign sign build/208ef54b-06bc-4610-87b6-520aea57517e/208ef54b-06bc-4610-87b6-520aea57517e.exe
```
