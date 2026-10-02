# References — LockBit 3.0 Double Extortion Kill Chain (SB-PC-2026-001)

Test UUID: `298cc137-ea39-4cf0-9b2d-b1c59a3cbacb` · Generated: 2026-10-01

## Primary Source

| Field | Value |
|-------|-------|
| **Title** | SB-PC-2026-001 [LOCKBIT] — Paquete de Escenario, Marco de Pruebas Continuas de Seguridad 2026 (Arquetipo A — Ransomware con doble extorsión), Versión 3.0 |
| **Author** | Superintendencia de Bancos — Dirección de Supervisión de Tecnología y Seguridad de la Información (República Dominicana) |
| **Date** | 2026-10-01 |
| **URL** | N/A (supervisory document delivered as PDF: `SB-PC-2026-001-LOCKBIT.pdf`) |
| **Type** | threat-report |

The primary source defines the five observable attacker objectives, the acceptable MITRE
ATT&CK TTP menus per objective (LB-tagged = documented for LockBit), the minimum coverage
requirements, execution clarifications (synthetic data, segregated environment, assume-breach
scope), and the supervisory JSON reporting format (`{meta, executions[]}` with
PREVENTED/DETECTED/MISSED/EXPOSED/NOT_RUN/ERROR outcomes).

## Supporting References

| # | Title | URL | Type |
|---|-------|-----|------|
| 1 | CISA / FBI / MS-ISAC — Advisory AA23-165A: Understanding Ransomware Threat Actors: LockBit (June 2023) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a | threat-report |
| 2 | CISA / FBI / MS-ISAC — Advisory AA23-075A: #StopRansomware: LockBit 3.0 (March 2023) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a | threat-report |
| 3 | MITRE ATT&CK — Software S1202: LockBit 3.0 | https://attack.mitre.org/software/S1202/ | threat-report |
| 4 | MITRE ATT&CK — Software S1199: LockBit 2.0 (predecessor) | https://attack.mitre.org/software/S1199/ | threat-report |
| 5 | Europol — Law enforcement disrupt world's biggest ransomware operation (Operation Cronos, February 2024) | https://www.europol.europa.eu/media-press/newsroom/news/law-enforcement-disrupt-worlds-biggest-ransomware-operation | news-article |

## MITRE ATT&CK Technique References

| Technique | Name | URL |
|-----------|------|-----|
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1562.001 | Impair Defenses: Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001/ |
| T1112 | Modify Registry | https://attack.mitre.org/techniques/T1112/ |
| T1003.001 | OS Credential Dumping: LSASS Memory | https://attack.mitre.org/techniques/T1003/001/ |
| T1003.002 | OS Credential Dumping: Security Account Manager | https://attack.mitre.org/techniques/T1003/002/ |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | https://attack.mitre.org/techniques/T1021/002/ |
| T1570 | Lateral Tool Transfer | https://attack.mitre.org/techniques/T1570/ |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | https://attack.mitre.org/techniques/T1567/002/ |
| T1486 | Data Encrypted for Impact | https://attack.mitre.org/techniques/T1486/ |
| T1490 | Inhibit System Recovery | https://attack.mitre.org/techniques/T1490/ |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | https://attack.mitre.org/techniques/T1070/001/ |

## Provenance Notes

- Scenario selection, TTP choices (LB-tagged options preferred), and safety clarifications
  (synthetic data for exfiltration/impact, segregated environment for propagation, assume-breach
  scope) are taken directly from the primary source's "Comportamientos Observables" and
  "Aclaraciones para la Ejecución" sections.
- LockBit 3.0 tradecraft details (comsvcs.dll MiniDump LOLBin usage, rclone/StealBit-style
  exfiltration, `.lockbit` extension, `Restore-My-Files.txt` note, vssadmin/bcdedit/wevtutil
  recovery tamper) are corroborated by supporting references 1–3.
