# Mini Shai-Hulud npm Supply Chain Kill Chain (@redhat-cloud-services)

**Test Score**: **9.3/10**

## Overview

Simulates the complete 6-stage kill chain of the "mini Shai-Hulud" software-supply-chain campaign that compromised `@redhat-cloud-services` npm packages (e.g. `@redhat-cloud-services/chrome@2.3.1`), as documented by the Socket Research Team. The campaign leverages publicly released Shai-Hulud worm tooling: a malicious npm `preinstall` hook executes during `npm install` on developer workstations and CI runners, deobfuscates a staged payload, silently acquires the Bun JS runtime, applies sandbox/locale/CI execution guardrails, harvests cloud/SSH/Git/npm secrets, exfiltrates them over an encrypted channel (with a GitHub-commit fallback), and carries a self-propagating worm capability.

This test evaluates Linux endpoint (developer workstation / CI runner) detection capability against the full attack flow. **Every behavior is simulated benignly** — decoy credentials only, loopback-only beacon, no real downloads, and log-only worm propagation.

## MITRE ATT&CK Mapping

| Stage | Tactic | Primary Technique | Also Maps | Description |
|-------|--------|-------------------|-----------|-------------|
| 1 | Initial Access / Execution | T1195.002 | T1059.007 | npm `preinstall` hook (`node index.js`) + staged deobfuscation (char-code map -> AES-128-GCM blobs) of a benign payload |
| 2 | Defense Evasion | T1480.001 | T1497.001 | Execution guardrails: locale evasion (skip on `ru-*`), CI/CD detection, daemonization decision, lock-file canary |
| 3 | Command and Control | T1105 | T1059.004 | JS runtime (Bun) acquisition staging via `curl`/`unzip` — **stubbed**, no network |
| 4 | Credential Access | T1552.001 | T1552.004, T1552.005 | Discovery/read of cloud creds, SSH/Git keys, npm/docker/k8s tokens — **decoys only** |
| 5 | Command and Control / Exfiltration | T1071.001 | T1041 | gzip + AES-256-GCM + RSA-OAEP-wrap synthetic envelope, POST to loopback sink |
| 6 | Exfiltration / Lateral Movement | T1567.001 | T1080 | Worm: repo/workflow modification, downstream npm publish, GitHub-commit exfil — **log-only** |

## Architecture

Multi-stage test with 6 gzip-embedded stage binaries. Each stage maps to a distinct phase of the supply-chain kill chain and executes as a separate process for technique-level detection precision. Linux ELF binaries are not Authenticode-signed (signing is a no-op on Linux).

```
Main Orchestrator (single Linux binary)
  |-- Stage 1: T1195.002  (npm Install-Hook Execution & Staged Deobfuscation)
  |-- Stage 2: T1480.001  (Execution Guardrails & Sandbox Evasion)
  |-- Stage 3: T1105      (JS Runtime Acquisition - Stubbed)
  |-- Stage 4: T1552.001  (Credential & Secret Discovery - Decoys)
  |-- Stage 5: T1071.001  (C2 Beacon & Synthetic Exfiltration - Loopback)
  |-- Stage 6: T1567.001  (Worm Propagation - Log-Only)
```

## Test Execution

```bash
# Deploy single binary to Linux target
./ae9002e4-3d82-4fcd-8b45-f7e0628f7375

# Artifacts: /tmp/F0 (logs/binaries) and /home/fortika-test (decoy tree)
```

## Expected Outcomes

- **Protected (Exit 126)**: EDR detects and blocks one of the 6 stages — the specific blocked technique is logged
- **Unprotected (Exit 101)**: All 6 stages complete without detection — full supply-chain chain succeeded
- **Error (Exit 999)**: Test prerequisites not met (e.g., `ARTIFACT_DIR` `/home/fortika-test` absent) or execution error

## Build Instructions

```bash
# Linux build (signing is a no-op for ELF)
GOOS=linux GOARCH=amd64 ./tests_source/intel-driven/ae9002e4-3d82-4fcd-8b45-f7e0628f7375/build_all.sh
# Output: build/ae9002e4-3d82-4fcd-8b45-f7e0628f7375/ae9002e4-3d82-4fcd-8b45-f7e0628f7375
```

## Safety Model (Simulation-Only)

- **Decoy credentials only** — Stage 4 plants a synthetic credential tree under `/home/fortika-test/shaihulud_decoys/` and reads ONLY that tree. Real paths (`~/.aws`, `~/.ssh`, `~/.npmrc`, `gh auth token`, cloud metadata at `169.254.169.254`) are logged as detection targets but never opened/contacted.
- **No real exfiltration** — Stage 5 beacons only to an in-process loopback sink (`127.0.0.1`, ephemeral port). The real C2 URL and GitHub-fallback marker are recorded as telemetry but never used as a destination. Envelope content is synthetic.
- **No real download/execution** — Stage 3 constructs and logs the `curl`/`unzip` Bun acquisition commands but performs no network I/O and executes nothing.
- **No self-propagation** — Stage 6 is purely log-only: no tokens used, no GitHub/npm contact, no real repository, workflow, or developer-tool config modified.
- **Benign embedded payload** — Stage 1's "obfuscated loader" is inert text; the deobfuscation chain operates on a benign marker string.

## Detection Opportunities

1. **npm install-time process tree** — `npm`/`node` spawning during `npm install` with a `preinstall` hook
2. **node -> curl/unzip** — runtime acquisition pattern (download + extract to `/tmp/b-*`)
3. **Credential path access** — process reading `~/.aws`, `~/.ssh/id*`, `~/.npmrc`, `.git-credentials`, `.env`
4. **`gh auth token` invocation** — live GitHub token theft
5. **Cloud metadata access** — outbound to `169.254.169.254` / cloud secret endpoints
6. **Encrypted beacon** — POST with `python-requests/2.31.0` User-Agent to non-standard endpoints
7. **GitHub-commit exfil** — commit messages containing `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner`
8. **Worm artifacts** — writes to `.github/workflows/codeql.yml`, `.github/setup.js`
9. **Anti-forensic temp writes** — `/tmp/p<random>.js` write-then-unlink
10. **Lock-file canary** — `tmp.0987654321.lock`

## References

- [Socket — Mini Shai-Hulud Campaign Hits Red Hat Cloud Services npm Packages](https://socket.dev/blog/mini-shai-hulud-campaign-hits-red-hat-cloud-services-npm-packages)
- [MITRE ATT&CK T1195.002 - Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK T1059.007 - JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK T1480.001 - Environmental Keying](https://attack.mitre.org/techniques/T1480/001/)
- [MITRE ATT&CK T1552.001 - Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [MITRE ATT&CK T1071.001 - Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1567.001 - Exfiltration to Code Repository](https://attack.mitre.org/techniques/T1567/001/)
