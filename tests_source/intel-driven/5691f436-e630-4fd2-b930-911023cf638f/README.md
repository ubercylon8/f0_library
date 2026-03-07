# APT34 Exchange Server Weaponization with Email-Based C2

**Test Score**: **9.4/10**

## Overview
Simulates APT34 (OilRig / Helix Kitten / Hazel Sandstorm) techniques for weaponizing compromised Exchange servers as command-and-control infrastructure and data exfiltration channels. This multi-stage test evaluates EDR detection capabilities against four distinct attack techniques used by this Iranian threat group to target financial institutions and government organizations.

## Threat Actor
**APT34 / OilRig / Helix Kitten / Hazel Sandstorm** - Iranian state-sponsored threat group known for targeting banking, financial services, and government sectors across the Middle East and beyond. APT34 specializes in exploiting Exchange server infrastructure for persistent access and covert communications.

## MITRE ATT&CK Mapping
- **T1505.003** - Server Software Component: Web Shell (CacheHttp.dll IIS backdoor)
- **T1071.003** - Application Layer Protocol: Mail Protocols (PowerExchange email C2)
- **T1556.002** - Modify Authentication Process: Password Filter DLL (LSA credential interception)
- **T1048.003** - Exfiltration Over Alternative Protocol: Unencrypted Non-C2 (STEALHOOK email exfil)

## Test Architecture
Multi-stage architecture with 4 sequential stages. Each technique is compiled as a separate signed binary, embedded in a single orchestrator. If EDR blocks any stage, the test stops and reports PROTECTED with technique-level precision.

## Expected Outcomes
- **Protected (Exit 126/105)**: EDR detects and blocks one or more techniques in the attack chain
- **Unprotected (Exit 101)**: All four attack stages complete without prevention

## Build Instructions
```bash
# Build with organization signing
./tests_source/intel-driven/5691f436-e630-4fd2-b930-911023cf638f/build_all.sh --org sb

# Build without org signing
./tests_source/intel-driven/5691f436-e630-4fd2-b930-911023cf638f/build_all.sh
```

## Financial Sector Relevance
Banks rely heavily on Exchange/Outlook for internal communications. Compromise of Exchange infrastructure enables access to:
- Deal flow and M&A communications
- Compliance alerts and regulatory correspondence
- Client communications and portfolio data
- Internal credential rotation events
