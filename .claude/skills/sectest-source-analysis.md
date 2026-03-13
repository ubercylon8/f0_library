---
name: sectest-source-analysis
description: Analyze threat intelligence sources and propose testing scenarios. Extracts TTPs, selects platform, determines architecture (standard vs multi-stage), generates UUID, and selects highest-scoring scenario for implementation.
---

# Source Analysis & Scenario Selection

This skill handles Phase 1 of security test creation: analyzing threat intelligence and selecting the implementation approach.

## Step 1: Source Analysis

When provided with threat intelligence, security articles, or incident reports:

1. **Extract all technical details**:
   - IOCs (file hashes, IPs, domains, URLs)
   - Attack techniques with specific commands, tools, file paths
   - Registry keys, services, scheduled tasks modified
   - Network indicators (C2 protocols, ports, exfiltration methods)
   - Behavioral patterns (timing, volume, sequences)

2. **Map to MITRE ATT&CK**:
   - Identify all tactics and techniques used
   - Use official T-codes with sub-techniques (e.g., T1055.001, not just T1055)
   - Note the attack flow sequence

3. **Identify detection opportunities**:
   - File system artifacts
   - Process creation events
   - Registry modifications
   - Network communications
   - Windows Event IDs generated

## Step 2: Propose 3 Scenarios

Always propose exactly **3 distinct testing scenarios** covering different aspects:

| Scenario | Focus | Typical Techniques |
|----------|-------|--------------------|
| **Scenario 1** | Initial access / execution | T1059.x, T1204, T1566.x |
| **Scenario 2** | Persistence / privilege escalation | T1053.x, T1543.x, T1068, T1548.x |
| **Scenario 3** | Defense evasion / impact | T1562.x, T1486, T1490, T1055.x |

For each scenario provide:
- Brief title and description
- Primary MITRE ATT&CK techniques covered (with T-codes)
- Expected detection opportunities (count them)
- Estimated complexity level (low/medium/high)
- **Score estimate** (0-10, using the scoring rubric)

## Step 3: Autonomous Selection

**Automatically select the highest-scoring scenario** for implementation.
- Proceed immediately — do not wait for user input
- If user has a preference, they will interrupt and specify
- Briefly announce: "Selected Scenario N (score X.X) — [title]"

## Step 4: Generate UUID

Generate a new lowercase UUID for the test directory:
```bash
uuidgen | tr '[:upper:]' '[:lower:]'
```

## Step 5: Determine Platform

**Automatically determine target platform** based on the threat intelligence:

| Threat Target | Build Tag | LOG_DIR | ARTIFACT_DIR | Extension |
|--------------|-----------|---------|--------------|-----------|
| Windows endpoint | `//go:build windows` | `C:\F0` | `c:\Users\fortika-test` | `.exe` |
| Linux endpoint/server | `//go:build linux` | `/tmp/F0` | `/home/fortika-test` | (none) |
| macOS endpoint | `//go:build darwin` | `/tmp/F0` | `/Users/fortika-test` | (none) |

**Decision logic:**
- ESXi/Linux server attacks → `//go:build linux`
- macOS infostealers, DPRK/BlueNoroff macOS campaigns → `//go:build darwin`
- Windows ransomware, credential theft, AD attacks → `//go:build windows`

## Step 6: Determine Architecture

Count the distinct ATT&CK techniques in the selected scenario:

| Technique Count | Architecture | Rationale |
|----------------|-------------|-----------|
| **1-2 techniques** | Standard single-binary | Simpler, adequate for focused tests |
| **3+ techniques** | Multi-stage | Technique-level detection precision, isolation of detection points |

If multi-stage, briefly note: "Using multi-stage architecture for [X] techniques: [list them]"

## Step 7: Determine Severity

Use the **highest severity** among all techniques in the scenario:

| Severity | CVSS-Equivalent | Example Techniques |
|----------|-----------------|-------------------|
| **critical** (9.0-10.0) | Immediate system/domain compromise | T1486, T1003.001, T1068, T1558, T1542 |
| **high** (7.0-8.9) | Significant access or lateral movement | T1562.001, T1055.x, T1550.x, T1021.x, T1071.x, T1041 |
| **medium** (4.0-6.9) | Reconnaissance or persistence foothold | T1087.x, T1083, T1053.x, T1543.x, T1548.002 |
| **low** (0.1-3.9) | Information disclosure, minimal impact | T1082, T1057 |
| **informational** (0.0) | No security impact | Connectivity tests |

**Multi-technique rule**: Use the highest severity among all techniques.

## Output

After completing this skill, the orchestrator context should contain:
- `uuid` — new test UUID
- `test_name` — human-readable name derived from threat intel
- `techniques` — list of MITRE ATT&CK technique IDs
- `tactics` — list of tactics (kebab-case)
- `platform` — windows/linux/darwin
- `severity` — critical/high/medium/low/informational
- `architecture` — standard/multi-stage
- `threat_actor` — APT attribution or "N/A"
- `subcategory` — ransomware/apt/c2/baseline/etc.
- `complexity` — low/medium/high
- `tags` — free-form keywords
- `stage_details` — (multi-stage only) list of {technique, name, description} per stage
- `test_dir` — full path: `tests_source/intel-driven/<uuid>/`

Proceed immediately to the `sectest-implementation` skill.
