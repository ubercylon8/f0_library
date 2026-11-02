# References & Sources

## Primary Source

The original threat intelligence that initiated this test's development.

| Field | Value |
|---|---|
| **Title** | Qilin EDR killer infection chain |
| **Author/Organization** | Cisco Talos |
| **Date Published** | 2026-04-02 |
| **Document Type** | threat-report |
| **URL** | https://blog.talosintelligence.com/qilin-edr-killer/ |

The Talos analysis describes Qilin's malicious `msimg32.dll` loader and EDR-killer chain, including the `rwdrv.sys` and `hlpdrv.sys` helper drivers, callback removal, and security-process termination. This test borrows the observable chain but deliberately omits the functional vulnerable-driver load, kernel modification, malicious loader/payload, production-process interference, credential extraction, and real destructive impact.

## Supporting Resources

Additional reporting and local design material used to scope the emulation and its safety boundaries.

| # | Title | Type | URL / Path |
|---|---|---|---|
| 1 | Qilin and Warlock ransomware use vulnerable drivers to disable EDR tools | news-article | https://thehackernews.com/2026/04/qilin-and-warlock-ransomware-use.html |
| 2 | Qilin Ransomware Uses Malicious DLL to Kill Almost Every Vendor's EDR Solutions | research-paper | https://cybersecuritynews.com/qilin-ransomware-kill-edr/ |
| 3 | Local design brief — Qilin (Agenda) BYOVD EDR-Killer & svchost Injection Chain | verbal-briefing | `/home/jimx/F0RT1KA/tests-specs/2026-11-02-qilin-byovd-spec.md` |

The local brief defines the required safety invariants: no real vulnerable-driver load, no production EDR termination, no production svchost injection, no LSASS memory read/exfiltration, synthetic-only encryption, fail-harmless recovery commands, confined writes, watchdogs, and cleanup.

## MITRE ATT&CK References

| Technique | Name | URL |
|---|---|---|
| T1518.001 | Software Discovery: Security Software Discovery | https://attack.mitre.org/techniques/T1518/001/ |
| T1082 | System Information Discovery | https://attack.mitre.org/techniques/T1082/ |
| T1562.001 | Impair Defenses: Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001/ |
| T1211 | Exploitation for Defense Evasion | https://attack.mitre.org/techniques/T1211/ |
| T1055 | Process Injection | https://attack.mitre.org/techniques/T1055/ |
| T1003.001 | OS Credential Dumping: LSASS Memory | https://attack.mitre.org/techniques/T1003/001/ |
| T1490 | Inhibit System Recovery | https://attack.mitre.org/techniques/T1490/ |
| T1486 | Data Encrypted for Impact | https://attack.mitre.org/techniques/T1486/ |

Stage 1 additionally logs supporting [T1574.002 — DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/) telemetry, and stage 2 logs supporting [T1543.003 — Windows Service](https://attack.mitre.org/techniques/T1543/003/) telemetry. These supporting behaviors are not part of the test's declared metadata technique set.

## Related Advisories & News

- [Qilin and Warlock ransomware use vulnerable drivers to disable EDR tools](https://thehackernews.com/2026/04/qilin-and-warlock-ransomware-use.html) — Campaign reporting on vulnerable-driver use against endpoint defenses (2026-04).
- [Qilin Ransomware Uses Malicious DLL to Kill Almost Every Vendor's EDR Solutions](https://cybersecuritynews.com/qilin-ransomware-kill-edr/) — Additional technical reporting on the malicious DLL and broad security-vendor target set (2026-04).

## Provenance and Validation Boundary

The final score is based on these sources, implementation review, local rule validation, and the 2026-11-02 Sophos lab run. YAML/NDJSON parsing and YARA compilation plus an exact-driver match passed. All five stages executed; `test_execution_log.json`, `bundle_results.json`, stage output, and Sophos System Protection event 42 evidence are staged under `staging/8f68dda1-94be-430f-8f35-d8af3f9b5d2e/`. Sophos logged `RWEverything Driver` and `Evade_22a (T1036.005)`; LSASS denial was independently recorded by the stage. References establish threat-intel provenance, while those lab artifacts provide execution and detection evidence.
