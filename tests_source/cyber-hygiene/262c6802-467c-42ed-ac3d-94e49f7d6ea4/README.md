# eMudhra Compromised CA Trust Exposure Assessment

**Test Score**: **9.4/10**

## Overview

This cross-platform cyber-hygiene assessment determines whether native and application-specific trust paths still accept certificate chains rooted in the compromised eMudhra intermediate CAs. It uses the incident's real intermediate certificates and publicly recovered CA key material at build time to create fresh, harmless validation artifacts, then performs offline chain validation and real loopback TLS handshakes on the endpoint.

The test is read-only with respect to endpoint trust configuration: it does not install or remove roots, change certificate policy, contact external hosts, execute the signed validation PEs, or intercept traffic. Its purpose is to expose residual trust that could enable adversary-in-the-middle TLS impersonation (T1557) or malicious code-signing trust (T1553.002), not to perform either attack.

## MITRE ATT&CK Mapping

- **Tactic**: Credential Access
  - **Technique**: **T1557 — Adversary-in-the-Middle**
  - **Relevance**: Acceptance of a compromised TLS CA chain demonstrates residual exposure to certificate-backed endpoint impersonation. No network interception is performed.
- **Tactic**: Defense Evasion
  - **Technique**: **T1553 — Subvert Trust Controls**
  - **Sub-technique**: **T1553.002 — Code Signing**
  - **Relevance**: Windows Authenticode validation checks whether harmless PEs signed through either compromised code-signing key, through both direct eMudhra and Sectigo AAA chains, are still trusted. The PEs are no-op programs and are never launched.

## Test Execution

- **Linux native validation**: OpenSSL evaluates seven direct eMudhra G3 chains, seven Sectigo AAA cross-signed chains, and two key-rollover chains offline, using a historical verification time derived from each leaf. `-verify_hostname` precedes certificate operands; operational `Could not open` or `no such file` output is classified as inconclusive rather than rejection.
- **Windows native validation**: Schannel performs loopback TLS 1.2/1.3 handshakes for six fresh TLS leaf keys through direct and AAA chains; `X509Chain.Build` evaluates two rollover chains; `WinVerifyTrust` with `WTD_REVOKE_NONE` evaluates **four** harmless signed no-op PEs covering both compromised CS keys through both direct and AAA paths, without revocation-network retrieval.
- **Independent runtime validation**: When discovered on `PATH`, Node.js, Java JSSE, Python default trust, Python certifi, pip-vendored certifi, and curl each attempt 12 real TLS validations against an ephemeral `127.0.0.1` listener. Python child processes run with bytecode writes disabled.
- **Evidence integrity**: Acceptance requires a successful validation/handshake. Certificate-based rejection is distinguished from timeouts, missing facilities, operational errors, and inconclusive results. An absent optional runtime is skipped.
- **Containment**: Extracted chains, helper code, and decompressed validation PEs are written only beneath `LOG_DIR` in an `emudhra-assessment-*` workspace and removed after normal assessment completion. Runtime networking is loopback-only. Panic and timeout paths finalize phase and result logs.

## Expected Outcomes

| Result | Meaning |
|---|---|
| **101 — Exposed / non-compliant** | At least one assessed validation path accepted a compromised chain. This verdict takes precedence over errors in other paths. |
| **126 — Compliant / protected for assessed paths** | At least one path was assessed, every executed probe rejected its chain with certificate-validation evidence, and no assessed path was inconclusive. This does **not** mean the assessment binary itself was blocked. |
| **999 — Incomplete or test error** | No chain was accepted, but at least one assessed path was inconclusive, initialization/result generation failed, a panic occurred, or no path could be assessed. |
| **102 — Timeout** | The four-minute assessment deadline expired. This is neither compliance nor exposure evidence. |
| **Skipped control** | The optional runtime or validation facility was not discovered; skipped controls do not cause failure and are excluded from aggregate assessment counts. |

The generic logger recognizes 105/127 quarantine outcomes, but the assessment logic does not emit them as trust verdicts.

## Lab Verification

| Platform | Status | Evidence |
|---|---|---|
| **Linux** | **Verified locally on 2026-11-14** | Standard-user Omarchy AMD64 run, execution ID `5d02ca07-4e90-404c-a592-9688d5173ccb`; completed in **5.202 seconds** with phase status `success` and all nine discovered controls reached. Native OpenSSL, Node.js, Java, Python default trust, and curl rejected all tested chains. Python certifi accepted six direct chains; pip-vendored certifi accepted all 12. Overall exit **101**, demonstrating independent-store exposure. MCP Schema v2.0 validation returned `ok=true` with zero schema/check errors. |
| **Windows** | **Verified on `win` on 2026-11-14** | Windows 11 Pro, Sophos Intercept X active and Defender passive; elevated `jimx` context. Execution ID `6a458166-7460-45e9-9893-9dbd3bf9277d` completed in **14.399 seconds**. All five assessed paths rejected every chain: six direct and six AAA Schannel cases, two rollover cases, four Authenticode cases, and 12 curl cases. Absent Node.js, Java, and Python runtimes were skipped. Overall exit **126**; Schema v2.0 validation returned `ok=true`. |
| **Debian** | **Verified on `debian` on 2026-11-14** | Debian 13, no EDR; execution ID `4dda286f-132b-4474-8723-2fc8e84946ab` completed in **9.999 seconds**. All six available paths accepted compromised chains: native direct, AAA, rollover, Python default, certifi, and curl. Node.js, Java, and pip-vendored certifi were absent. Overall exit **101**; Schema v2.0 validation returned `ok=true`. |

Execution evidence is retained under `staging/262c6802-467c-42ed-ac3d-94e49f7d6ea4/` in the development worktree. These runs verify control reachability and result accuracy, not live SIEM tenant firing. The initial Windows run also identified and led to correction of a PowerShell DER-constructor issue and Microsoft Store Python-alias handling; the table above records the subsequent corrected run.

All five detection artifact formats are bundled. Independent validation parsed five Elastic NDJSON rules, four Sigma documents, and the LimaCharlie YAML, and compiled the YARA rules with yara-python. YARA matching covered all incident/source/generated chains and all four decompressed Authenticode samples. No live tenant rule-firing claim is made.

## Scope and Limitations

- Discovery is limited to executables available on `PATH` and certifi locations importable by the selected Python interpreter.
- Custom application stores, browsers, containers, alternate runtime installations, and undiscovered trust stores are **not implicitly certified** by a 126 result.
- The assessment is a point-in-time trust evaluation. It does not prove that every application uses the validated system store or that revocation, Certificate Transparency policy, and TLS behavior are identical across applications.
- Offline tests intentionally use embedded material and historical validation times. They do not query live OCSP/CRL services or external incident hosts.
- Windows Authenticode coverage checks signature trust only; it does not execute a signed binary or claim SmartScreen/reputation coverage.
- Optional runtime coverage varies by endpoint. The Windows lab did not have Node.js, Java, or a real Python interpreter on `PATH`; those controls were skipped, not counted as protected.

## Build Instructions

From the repository root:

```bash
# Generate fresh validation material, compile both binaries, and sign Windows.
./tests_source/cyber-hygiene/262c6802-467c-42ed-ac3d-94e49f7d6ea4/build_all.sh

# Optional organization-specific dual signing:
./tests_source/cyber-hygiene/262c6802-467c-42ed-ac3d-94e49f7d6ea4/build_all.sh --org sb
```

Build prerequisites are Go, `javac`, `osslsigncode`, and `gzip`. Outputs are:

```text
build/262c6802-467c-42ed-ac3d-94e49f7d6ea4/262c6802-467c-42ed-ac3d-94e49f7d6ea4
build/262c6802-467c-42ed-ac3d-94e49f7d6ea4/262c6802-467c-42ed-ac3d-94e49f7d6ea4.exe
```

The build generator verifies that each recovered CA scalar matches the corresponding public key before signing fresh leaves. Deployed binaries contain only newly generated leaf keys, not the compromised CA private keys. Each stripped no-op PE is signed and gzip-compressed for embedding; runtime extraction decompresses it only into `LOG_DIR` for validation.

## Execution and Results

Run the native binary for the target OS. No arguments are required.

```bash
# Linux
build/262c6802-467c-42ed-ac3d-94e49f7d6ea4/262c6802-467c-42ed-ac3d-94e49f7d6ea4

# Windows (from an elevated or standard-user context, as applicable)
C:\F0\262c6802-467c-42ed-ac3d-94e49f7d6ea4.exe
```

Result files are written beneath `C:\F0` on Windows or `/tmp/F0` on Linux:

- `bundle_results.json` — authoritative per-control verdicts and per-probe evidence.
- `test_execution_log.json` — Schema v2.0 metadata, execution context, process activity, timing, and outcome.
- `test_execution_log.txt` — human-readable execution record.

Both platforms have a **240,000 ms (four-minute) overall budget**. The latest observed local Linux runtime was **5.202 seconds**; no Windows runtime has been measured.

## Binary Size — Green Tier

- **Linux**: 9,003,168 bytes (8.59 MiB)
- **Windows**: 9,299,792 bytes (8.87 MiB)

The Green size includes embedded direct, cross-signed, no-CT, and rollover incident chains; 12 fresh runtime probe chains; a Java 8-compatible JSSE helper; the Windows validation helper; and four harmless Authenticode validation artifacts. Stripping and gzip-compressing the signed PEs before embedding reduces their size contribution while preserving real signature validation after confined runtime decompression. Embedded assets keep fleet execution deterministic and independent of downloads or external network access.

See [`262c6802-467c-42ed-ac3d-94e49f7d6ea4_info.md`](262c6802-467c-42ed-ac3d-94e49f7d6ea4_info.md) for the rubric v2.1 scorecard and detection audit, and [`262c6802-467c-42ed-ac3d-94e49f7d6ea4_references.md`](262c6802-467c-42ed-ac3d-94e49f7d6ea4_references.md) for source provenance.
