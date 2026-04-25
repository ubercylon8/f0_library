# ISACA ITGC Control Matrix

Authoritative control_id → source-file:line mapping for the F0RT1KA ISACA ITGC Validation Bundle suite.

Each control is implemented in exactly one place. Auditors and reviewers can verify the evidence schema and check logic by following the file:line reference.

---

## Bundle 1 — Windows Endpoint (`db0738eb-848e-442b-b43c-208029063fe9`)

31 controls across 7 multi-binary validators. Runs on each Windows endpoint as SYSTEM.

### Access Management

| ID | Control | File | Line |
|---|---|---|---|
| ITGC-AM-001 | Local Administrator Account Inventory | `db0738eb-.../checks_am.go` | 50 |
| ITGC-AM-002 | Password Policy Enforcement | `db0738eb-.../checks_am.go` | 121 |
| ITGC-AM-005 | Guest / Default Account Status | `db0738eb-.../checks_am.go` | 224 |

### Change Management

| ID | Control | File | Line |
|---|---|---|---|
| ITGC-CM-001 | Unauthorized Software Detection | `db0738eb-.../checks_cm.go` | 44 |
| ITGC-CM-002 | Patch Compliance (Critical/High >SLA) | `db0738eb-.../checks_cm.go` | 103 |
| ITGC-CM-003 | Windows Update Configuration | `db0738eb-.../checks_cm.go` | 173 |
| ITGC-CM-004 | GPO Modification Audit Trail | `db0738eb-.../checks_cm.go` | 245 |
| ITGC-CM-005 | Scheduled Task Inventory | `db0738eb-.../checks_cm.go` | 290 |

### Logging & Monitoring

| ID | Control | File | Line |
|---|---|---|---|
| ITGC-LM-001 | Event Log Configuration | `db0738eb-.../checks_lm.go` | 40 |
| ITGC-LM-002 | Advanced Audit Policy Settings | `db0738eb-.../checks_lm.go` | 103 |
| ITGC-LM-003 | Sysmon Deployment Validation | `db0738eb-.../checks_lm.go` | 193 |
| ITGC-LM-004 | Log Forwarding Agent Status | `db0738eb-.../checks_lm.go` | 241 |
| ITGC-LM-005 | Event Log Clearing Detection | `db0738eb-.../checks_lm.go` | 281 |

### Endpoint Protection

| ID | Control | File | Line |
|---|---|---|---|
| ITGC-EP-001 | AV/EDR Agent Status | `db0738eb-.../checks_ep.go` | 46 |
| ITGC-EP-002 | Windows Firewall (all profiles) | `db0738eb-.../checks_ep.go` | 120 |
| ITGC-EP-003 | BitLocker OS Drive Encryption | `db0738eb-.../checks_ep.go` | 180 |
| ITGC-EP-004 | SMBv1 Disabled | `db0738eb-.../checks_ep.go` | 229 |
| ITGC-EP-005 | PowerShell Security Configuration | `db0738eb-.../checks_ep.go` | 279 |
| ITGC-EP-006 | Attack Surface Reduction Rules | `db0738eb-.../checks_ep.go` | 339 |

### Backup & Recovery

| ID | Control | File | Line |
|---|---|---|---|
| ITGC-BR-001 | Volume Shadow Copy Service Status | `db0738eb-.../checks_br.go` | 40 |
| ITGC-BR-002 | Backup Agent Service Status | `db0738eb-.../checks_br.go` | 93 |
| ITGC-BR-003 | Controlled Folder Access | `db0738eb-.../checks_br.go` | 132 |

### Network Security

| ID | Control | File | Line |
|---|---|---|---|
| ITGC-NS-001 | Open Port Inventory | `db0738eb-.../checks_ns.go` | 40 |
| ITGC-NS-002 | RDP Security Configuration | `db0738eb-.../checks_ns.go` | 93 |
| ITGC-NS-004 | WinRM/Remote Management Exposure | `db0738eb-.../checks_ns.go` | 161 |

### Governance & Policy

| ID | Control | File | Line |
|---|---|---|---|
| ITGC-GV-001 | Domain Join + GPO Application | `db0738eb-.../checks_gv.go` | 41 |
| ITGC-GV-002 | System Time Synchronization (NTP) | `db0738eb-.../checks_gv.go` | 84 |
| ITGC-GV-003 | Asset Inventory Data Collection | `db0738eb-.../checks_gv.go` | 138 |
| ITGC-GV-004 | Legal Notice / Logon Banner | `db0738eb-.../checks_gv.go` | 189 |
| ITGC-GV-005 | Screen Lock Policy Enforcement | `db0738eb-.../checks_gv.go` | 235 |
| ITGC-GV-006 | Windows License and Activation | `db0738eb-.../checks_gv.go` | 282 |

---

## Bundle 2 — AD Identity (`a26a91b2-8d59-410b-9f5e-7ec5ffb6734c`)

3 controls. Single-binary. Runs on a domain-joined host with RSAT (DC or mgmt server).

| ID | Control | File | Line |
|---|---|---|---|
| ITGC-AM-003 | Dormant Account Detection | `a26a91b2-.../checks_identity.go` | 54 |
| ITGC-AM-004 | Service Account Permissions Audit | `a26a91b2-.../checks_identity.go` | 131 |
| ITGC-NS-003 | LAPS Deployment Validation | `a26a91b2-.../checks_identity.go` | 223 |

---

## Bundle 3 — Entra Tenant *(extends existing)* (`4f484076-9816-4813-947e-b76bce3d3f83`)

The existing CISA SCuBA / CIS Identity bundle, extended with one ITGC control.

| ID | Control | File | Line |
|---|---|---|---|
| ITGC-AM-006 | MFA Enrollment Verification | `4f484076-.../checks_mfa.go` | 458 |

Requires Graph permission `UserAuthenticationMethod.Read.All` on the existing app registration. See `4f484076-.../<uuid>_info.md` for setup.

---

## Coverage summary

| Family | In ISACA spec | Implemented | Bundle |
|---|---|---|---|
| Access Management (AM) | 6 | 6 | Endpoint (3) + AD (2) + Entra (1) |
| Change Management (CM) | 5 | 5 | Endpoint |
| Logging & Monitoring (LM) | 5 | 5 | Endpoint |
| Endpoint Protection (EP) | 6 | 6 | Endpoint |
| Backup & Recovery (BR) | 3 | 3 | Endpoint |
| Network Security (NS) | 4 | 4 | Endpoint (3) + AD (1) |
| Governance & Policy (GV) | 6 | 6 | Endpoint |
| **TOTAL** | **35** | **35** | — |

## Verification

For any ITGC control, an auditor can:

1. Look up the file:line in the table above
2. Read the Go function — it's self-contained (~30-100 LOC) and produces structured `Evidence{}` per the ISACA spec
3. Cross-check the runtime output at `c:\F0\itgc_evidence_<control_id>.json` against the function logic

The framework cross-references (CISA domain, COBIT objective, CIS v8 mapping, MITRE ATT&CK technique) are populated directly in each Go check function — they're maintained alongside the implementation rather than in an external spreadsheet, so they cannot drift.
