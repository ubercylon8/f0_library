# References — KslKatz LSASS Credential Dumping Framework

**Test UUID**: `7ba6c119-df44-4cda-8045-b3700c31ba5e`

## Primary Source

| Field | Value |
|-------|-------|
| **Title** | Ghost in LSASS: Detecting KslKatz Credential Dumping Framework |
| **Author** | Omar Tarek Zayed |
| **Publisher** | detect.fyi |
| **Type** | threat-report / detection-engineering blog post |
| **URL** | https://detect.fyi/ghost-in-lsass-detecting-kslkatz-credential-dumping-framework-8645f246aec9 |
| **Accessed** | 2026-06-01 |

The article analyzes the KslKatz framework and details the detection surface: the
`AllowedProcessName` registry write under the KslD service key (the driver's
plain-string actor check), the KslD service `ImagePath` reconfiguration, the
`\\.\KslD` device interaction, and the resulting PPL-bypassing LSASS reads via the
driver's `MmCopyMemory` (`SubCmd 12`) wrapper.

## Supporting References (projects cited / related)

| Title | URL | Type |
|-------|-----|------|
| KslKatz (combines KslDump + GhostKatz) | https://github.com/vergamota/KslKatz | tool-release |
| KslDump (KslD.sys BYOVD LSASS reader) | https://github.com/vergamota/KslDump | tool-release |
| GhostKatz (PPL-bypass credential extraction) | https://github.com/vergamota/GhostKatz | tool-release |
| Mimikatz (foundational LSASS credential extraction) | https://github.com/gentilkiwi/mimikatz | tool-release |

> Tool-release URLs are recorded for provenance and detection-engineering context.
> This test does **not** download, embed, or execute any of the referenced offensive
> tooling — it reproduces only the benign telemetry surface of the documented chain.

## MITRE ATT&CK

| Technique | ID | URL |
|-----------|----|-----|
| Create or Modify System Service: Windows Service | T1543.003 | https://attack.mitre.org/techniques/T1543/003/ |
| Modify Registry | T1112 | https://attack.mitre.org/techniques/T1112/ |
| Exploitation for Privilege Escalation | T1068 | https://attack.mitre.org/techniques/T1068/ |
| OS Credential Dumping: LSASS Memory | T1003.001 | https://attack.mitre.org/techniques/T1003/001/ |

## Related Concepts

- **BYOVD (Bring Your Own Vulnerable Driver)** — abusing a legitimately signed but
  vulnerable kernel driver to gain kernel-mode primitives. KslD.sys is notable as a
  Microsoft-signed Defender driver with no fix available.
- **PPL (Protected Process Light)** — the user-mode protection on LSASS that BYOVD
  kernel reads bypass entirely, since `MmCopyMemory` physical reads occur in kernel mode.
