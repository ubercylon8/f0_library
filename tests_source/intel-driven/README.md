# Intel-Driven — Threat Intelligence Test Suite

Security tests derived from **real-world threat intelligence**: APT campaign reports, ransomware analysis, CVE proof-of-concepts, and malware research. Each test simulates an attack technique observed in the wild and is mapped to MITRE ATT&CK.

**33 tests** across 8 subcategories. All tests follow Schema v2.0 and are scored under [Rubric v2.1](../../docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md).

## Quick stats

| Subcategory | Count | Examples |
|---|---:|---|
| **apt** | 12 | Iranian APT suite (APT33/34/42, TA453, Agrius), DPRK BlueNoroff, Nightmare-Eclipse triad, LLM-abuse research |
| **ransomware** | 8 | SafePay (3 variants), Akira BYOVD, Gunra, ESXi RansomHub, BitLocker abuse |
| **edr-evasion** | 7 | EDRSilencer, EDR-Freeze, SilentButDeadly, TrollDisappearKey AMSI, MDE bypass (×2), CyberEye |
| **c2** | 2 | Sliver, Tailscale exfil |
| **defender-evasion** | 1 | UnDefend (Nightmare-Eclipse) |
| **defense-evasion** | 1 | SafePay UAC bypass |
| **credential-dumping** | 1 | NativeDump (NimDump) |
| **infostealer** | 1 | AMOS/Banshee macOS |

## Featured suites

- **Iranian APT Multi-Stage Suite** — 5 multi-stage campaigns (APT33 Tickler, APT34 Exchange weaponization, APT42 TAMECAT, TA453 NICECURL, Agrius wiper). See [`iranian-apt-attack-flows.md`](iranian-apt-attack-flows.md) for kill-chain diagrams.
- **Nightmare-Eclipse Triad** — `5e59dd6a` BlueHammer + `0d7e7571` RedSun + `6a2351ac` UnDefend. CVE-2024-30088 oplock IOCTL race, Cloud Files reparse, Defender update DoS. Lab-verified Phase A/B uplifts under v2.1 (final scores: BH 9.2 / UD 9.0 / RS 8.7).
- **LLM-Abuse Research** — `0a749b39` PROMPTFLUX (LLM-assisted VBS dropper) + `e5472cd5` HONESTCUE (runtime C# compilation). Detection focus on prompt-template artifacts and just-in-time compile signals.

---

## Tests by subcategory

### APT (12)

| UUID | Name | Threat Actor | Severity | Key Techniques |
|---|---|---|---|---|
| [`13c2d073-…408ce9`](13c2d073-8e33-4fca-ab27-68f20c408ce9/) | APT33 Tickler Backdoor DLL Sideloading | APT33 | high | T1574.002, T1547.001, T1053.005 |
| [`5691f436-…1023cf638f`](5691f436-e630-4fd2-b930-911023cf638f/) | APT34 Exchange Server Weaponization with Email-Based C2 | APT34 | critical | T1505.003, T1071.003, T1556.002, T1048.003 |
| [`92b0b4f6-…461f804c`](92b0b4f6-a09b-4c7b-b593-31ce461f804c/) | APT42 TAMECAT Fileless Backdoor with Browser Credential Theft | APT42 | critical | T1059.001, T1547.001, T1555.003, T1102 |
| [`7d39b861-…aae527a130`](7d39b861-644d-4f8b-bb19-4faae527a130/) | Agrius Multi-Wiper Deployment Against Banking Infrastructure | Agrius | critical | T1505.003, T1543.003, T1485, T1070.001 |
| [`244dfb88-…dbc49517f63d`](244dfb88-9068-4db4-9fa8-dbc49517f63d/) | DPRK BlueNoroff Financial Sector Attack Chain | BlueNoroff/Lazarus | critical | T1553.001, T1543.004, T1071.001, T1041 |
| [`e5472cd5-…02665ca4cf`](e5472cd5-c799-4b07-b455-8c02665ca4cf/) | HONESTCUE LLM-Assisted Runtime C# Compilation (v2) | research | high | T1027.004, T1027.010, T1620, T1059.001 |
| [`5e59dd6a-…ea9b5e054cb9`](5e59dd6a-6c87-4377-942c-ea9b5e054cb9/) | Nightmare-Eclipse BlueHammer Early-Stage Behavioral Pattern | Nightmare-Eclipse | high | T1211, T1562.001, T1003.002, T1134.001 |
| [`0d7e7571-…bdb000439761`](0d7e7571-45e2-426a-ac8e-bdb000439761/) | Nightmare-Eclipse RedSun Cloud Files Rewrite Primitive Chain | Nightmare-Eclipse | high | T1211, T1006, T1574, T1559.001 |
| [`54a0bd24-…c381d932ca97`](54a0bd24-d75a-4d89-8dce-c381d932ca97/) | Perfctl/Symbiote LD_PRELOAD Hijacking with PAM Credential Harvesting | Perfctl/Symbiote | critical | T1574.006, T1003.008, T1548.001, T1014 |
| [`0a749b39-…e886b439cfa`](0a749b39-409e-46f5-9338-ee886b439cfa/) | PROMPTFLUX v1 — LLM-Assisted VBScript Dropper | research | high | T1071.001, T1027.001, T1547.001, T1091 |
| [`8e2cf534-…0f23d248db93`](8e2cf534-857b-4d29-a1ac-0f23d248db93/) | TA453 NICECURL VBScript Backdoor Detection | TA453 | high | T1059.005, T1518.001, T1071.001, T1105 |
| [`414a4c61-…d5e91a29a878`](414a4c61-019f-48ba-934d-d5e91a29a878/) | UNK_RobotDreams Rust Backdoor Execution Chain | UNK_RobotDreams | high | T1105, T1071.001, T1573.001, T1036.005 |

### Ransomware (8)

| UUID | Name | Family | Severity | Key Techniques |
|---|---|---|---|---|
| [`c3634a9c-…faeca14f612`](c3634a9c-e8c9-44a8-992b-0faeca14f612/) | Akira Ransomware BYOVD Attack Chain | Akira | critical | T1068, T1562.001 |
| [`94b248c0-…3d45028c407d`](94b248c0-a104-48c3-b4a5-3d45028c407d/) | Gunra Ransomware Simulation | Gunra | critical | T1486, T1490 |
| [`109266e2-…b97e4b7fda61`](109266e2-2310-40ea-9f63-b97e4b7fda61/) | SafePay Enhanced Ransomware Simulation & Mass Data Operations | SafePay | critical | T1486, T1560.001, T1490 |
| [`6717c98c-…7b3bd3fb02ee`](6717c98c-b3db-490e-b03c-7b3bd3fb02ee/) | SafePay Go-Native Ransomware Simulation | SafePay | critical | T1486, T1560.001, T1490 |
| [`25aafe2c-…c3d7cf35620c`](25aafe2c-ec57-4a85-a26a-c3d7cf35620c/) | ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira) | RansomHub/Akira | critical | T1046, T1489, T1529, T1486 |
| [`581e0f20-…be3abd110ae0`](581e0f20-13f0-4374-9686-be3abd110ae0/) | Ransomware Encryption via BitLocker | generic | critical | T1486, T1490, T1562.004 |
| [`5ed12ef2-…269d8e9edcea`](5ed12ef2-5e29-49a2-8f26-269d8e9edcea/) | Multi-Stage Ransomware Killchain | generic | critical | T1486, T1491.001, T1134.001 |
| [`4b4bd24c-…6d0fa5e22284`](4b4bd24c-fff5-4de8-982e-6d0fa5e22284/) | Data Exfiltration and Encryption Simulation | generic | critical | T1020, T1041, T1486 |

### EDR Evasion (7)

| UUID | Name | Severity | Key Techniques |
|---|---|---|---|
| [`bcba14e7-…718fdeb39b65`](bcba14e7-6f87-4cbd-9c32-718fdeb39b65/) | EDRSilencer Detection | high | T1562.001 |
| [`87b7653b-…73ec94d5e18e`](87b7653b-2cee-44d4-9d80-73ec94d5e18e/) | EDR-Freeze Defense Evasion | high | T1562.001, T1055, T1574 |
| [`e5577355-…f7d1c8b864f1`](e5577355-f8e4-4e52-b1b2-f7d1c8b864f1/) | SilentButDeadly WFP EDR Network Isolation | high | T1562.001 |
| [`c1f0fe6f-…47e0a39abe54`](c1f0fe6f-6907-4f95-820d-47e0a39abe54/) | TrollDisappearKey AMSI Bypass Detection | high | T1562.001 |
| [`b6c73735-…3c24af39671b`](b6c73735-0c24-4a1e-8f0a-3c24af39671b/) | MDE Authentication Bypass Command Interception | high | T1562.001, T1090.003, T1140 |
| [`fec68e9b-…98ec98428444`](fec68e9b-af59-40c1-abbd-98ec98428444/) | MDE Process Injection and API Authentication Bypass | high | T1055.001, T1562.001, T1557 |
| [`ecd2514c-…32cabe5cf206`](ecd2514c-512a-4251-a6f4-eb3aa834d401/) | CyberEye RAT — Windows Defender Disabling via PowerShell | high | T1562.001 |

### Command & Control (2)

| UUID | Name | Severity | Key Techniques |
|---|---|---|---|
| [`09efee46-…dded024cd1e7`](09efee46-f098-4948-8e35-dded024cd1e7/) | Sliver C2 Client Detection | high | T1219 |
| [`eafce2fc-…32cabe5cf206`](eafce2fc-75fd-4c62-92dc-32cabe5cf206/) | Tailscale Remote Access and Data Exfiltration | high | T1219, T1543.003, T1041 |

### Other

| UUID | Name | Subcategory | Severity | Key Techniques |
|---|---|---|---|---|
| [`6a2351ac-…6919beef70d`](6a2351ac-654a-4112-b378-e6919beef70d/) | UnDefend — Defender Signature/Engine Update DoS via File-Lock Race | defender-evasion | high | T1562.001, T1083 |
| [`2cf59d3e-…4a5ba5bd9c11`](2cf59d3e-ae82-48bb-9779-4a5ba5bd9c11/) | SafePay UAC Bypass & Defense Evasion | defense-evasion | high | T1548.002, T1562.001, T1547.001 |
| [`b83616c2-…d2d57eebecec`](b83616c2-84ee-4738-b398-d2d57eebecec/) | NativeDump (NimDump) Detection | credential-dumping | critical | T1003.001 |
| [`3e985e9e-…6c7f5e3282f5`](3e985e9e-8141-49d3-a23c-6c7f5e3282f5/) | AMOS/Banshee macOS Infostealer Credential Harvesting Simulation | infostealer | critical | T1555.001, T1056.002, T1041 |

---

## Path conventions

| Artifact | Path | Reason |
|---|---|---|
| Test binary (`.exe`) | `c:\F0` (Win) / `/tmp/F0` (Linux/macOS) | LOG_DIR — process-allowed |
| Embedded tools / stages | Same as above | Single-binary deployment |
| Log files (`*.json`, `bundle_results.json`) | Same as above | Standard collection point |
| Simulation artifacts (decoy docs, exfil targets) | `c:\Users\fortika-test` (Win) / `/home/fortika-test` (Linux) / `/Users/fortika-test` (macOS) | ARTIFACT_DIR — **NOT** whitelisted, allows EDR detection |

## Build & sign

```bash
# Build a single test
./utils/gobuild build tests_source/intel-driven/<uuid>/

# Build all
for dir in tests_source/intel-driven/*/; do
    ./utils/gobuild build "$dir"
done

# Sign all binaries (Windows; macOS uses ad-hoc codesign)
./utils/codesign sign-all
```

Multi-stage tests (Iranian APT suite, Nightmare-Eclipse triad) require `build_all.sh` for the per-stage build → sign → gzip → embed → orchestrator-sign sequence. See [`docs/MULTISTAGE_QUICK_REFERENCE.md`](../../docs/MULTISTAGE_QUICK_REFERENCE.md).

## Expected results

| Exit Code | Meaning |
|---|---|
| **101** | Attack succeeded — endpoint **unprotected** |
| **105** | File quarantined on extraction |
| **126** | Execution **blocked** by AV/EDR |
| **999** | Test prerequisites not met (missing tooling, wrong context) |

Exit codes are **always computed from observed protection layers**, never hardcoded. See [`CLAUDE.md`](../../CLAUDE.md) "Bug Prevention Rules" for the rationale (avoiding blame-keyword poisoning of `determineExitCode()`).

## Related documentation

- [Iranian APT attack flow diagrams](iranian-apt-attack-flows.md)
- [Multi-stage build reference](../../docs/MULTISTAGE_QUICK_REFERENCE.md)
- [Rubric v2.1 scoring](../../docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md)
- [Test results schema v2.0](../../docs/TEST_RESULTS_SCHEMA_GUIDE.md)
- [Top-level README](../../README.md)
