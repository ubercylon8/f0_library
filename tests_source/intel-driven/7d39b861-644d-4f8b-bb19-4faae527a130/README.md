# Agrius Multi-Wiper Deployment Against Banking Infrastructure

**Test Score**: **9.4/10**

## Overview
Simulates the full Agrius (Pink Sandstorm / Agonizing Serpens / BlackShadow) destructive attack chain targeting banking infrastructure. This 5-stage multi-stage test models the confirmed active wiper campaigns against Israeli financial sector (Anomali, March 2026), covering ASPXSpy webshell deployment, IPsec Helper service persistence, EDR tampering via GMER64.sys driver loading, simultaneous multi-wiper deployment (MultiLayer + PartialWasher + BFG Agonizer), and anti-forensics via event log clearing and self-deletion. Tests business continuity and disaster recovery capabilities for core banking systems.

## MITRE ATT&CK Mapping
- **Tactic**: Persistence - T1505.003 (Web Shell: ASPXSpy)
- **Tactic**: Persistence - T1543.003 (Windows Service: IPsec Helper)
- **Tactic**: Defense Evasion - T1562.001 (Disable or Modify Tools: GMER64.sys)
- **Tactic**: Impact - T1485 (Data Destruction: Multi-Wiper)
- **Tactic**: Defense Evasion - T1070.001 (Clear Windows Event Logs)

## Threat Actor
- **Name**: Agrius / Pink Sandstorm / Agonizing Serpens / BlackShadow
- **Attribution**: Iranian state-sponsored (MOIS-linked)
- **Targets**: Israeli financial sector, banking infrastructure, payment processing
- **Activity**: Active wiper campaigns (2023-2026)

## Architecture
Multi-stage test with 5 embedded stage binaries:
1. `stage-T1505.003.exe` - ASPXSpy webshell deployment
2. `stage-T1543.003.exe` - IPsec Helper service persistence
3. `stage-T1562.001.exe` - EDR tampering via GMER64.sys
4. `stage-T1485.exe` - Multi-wiper deployment (3 variants)
5. `stage-T1070.001.exe` - Anti-forensics and evidence destruction

## Expected Outcomes
- **Protected** (exit 126): EDR detects and blocks at least one stage
- **Unprotected** (exit 101): All 5 stages complete without detection
- **Error** (exit 999): Prerequisites not met (admin privileges required for some stages)

## Safety Mechanisms
- All wiper operations target ONLY test files created in `c:\F0\wiper_test\`
- NO actual boot sector modification (simulation marker only)
- EDR services are immediately re-enabled if successfully disabled
- Created Windows services are deleted after testing
- Self-deletion script only targets test artifacts in `c:\F0`

## Build Instructions
```bash
# Build with organization dual-signing
./tests_source/intel-driven/7d39b861-644d-4f8b-bb19-4faae527a130/build_all.sh --org sb

# Build with F0RT1KA-only signing
./tests_source/intel-driven/7d39b861-644d-4f8b-bb19-4faae527a130/build_all.sh
```

## Detection Opportunities
1. ASPXSpy webshell file creation (.aspx files in staging directory)
2. Windows service creation with unknown binary path (sc.exe create)
3. GMER64.sys driver file deployment and kernel service creation
4. EDR service modification attempts (sc.exe config/stop on Defender/CrowdStrike)
5. Mass file overwrite patterns (simultaneous multi-wiper operations)
6. Event log clearing via wevtutil.exe
7. Self-deletion batch script execution (remover.bat pattern)
8. Simultaneous multiple suspicious process executions
