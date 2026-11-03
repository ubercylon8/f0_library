# CrowdStrike Falcon Configuration Checks

**Test ID:** `b2cd3532-701d-4700-bbb2-f7c10ef0d717`
**Category:** Cyber-Hygiene Baseline
**Architecture:** Multi-binary bundle (quarantine-resilient)
**Platform:** Windows

## Evidence model

The validator separates locally observable sensor state from tenant-controlled policy. A running service, provisioned sensor, or loaded driver is not accepted as proof of prevention, recent cloud connectivity, or tamper protection.

| Control | Local evidence | Result without central evidence |
|---|---|---|
| CH-CRW-001 — Falcon Sensor Service | `sc query` / `sc qc CSFalconService` | PASS or FAIL from observed service state; query failure is UNKNOWN |
| CH-CRW-002 — Sensor Provisioning Status | Local `ProvisioningState` and agent identifier registry evidence | PASS or FAIL when observed; unavailable state is UNKNOWN |
| CH-CRW-003 — Prevention Mode | Effective Falcon host/prevention policy | UNKNOWN until read-only central evidence is available |
| CH-CRW-004 — Sensor Version Detected | Registry or executable/driver file version | PASS when a version is readable; no support/currency claim |
| CH-CRW-005 — Recent Cloud Check-in | Falcon host inventory last-seen state | UNKNOWN until read-only central evidence is available |
| CH-CRW-006 — Tamper Protection | Effective Falcon tamper-protection policy | UNKNOWN until read-only central evidence is available |

The central controls are not inferred from `CSFalconService`, `CSFalconContainer`, or `CSAgent` being running. Local state is included as supporting evidence only.

## Bundle roll-up

- **126:** all controls passed and the assessment is complete.
- **101:** at least one genuine configuration failure was observed.
- **999:** the assessment is incomplete or could not evaluate any controls.

Individual control records distinguish `PASS`, `FAIL`, `UNKNOWN`, and `SKIPPED`, and carry `evidence_source`, expected/actual values, and the bundle's `assessment_complete` value.

## Local data sources

- `CSFalconService` service state and start type.
- Falcon sensor executable or `CSAgent.sys` file version when registry version values are unavailable.
- Local provisioning values under CrowdStrike registry locations, including the sensor-specific `SYSTEM\CrowdStrike\...\Default` key and `SOFTWARE\CrowdStrike\Falcon` fallbacks.

No write operations, maintenance-token operations, or sensor-control actions are performed.
