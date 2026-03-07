# Iranian APT Multi-Stage Attack Flow Diagrams

## 1. APT34 (OilRig) — Exchange Server Weaponization with Email-Based C2
**UUID**: `5691f436-e630-4fd2-b930-911023cf638f` | **Score**: 8.7/10

```mermaid
flowchart TD
    subgraph INIT["ORCHESTRATOR"]
        START([Deploy to c:\F0]) --> EXTRACT[Extract 4 embedded<br/>stage binaries]
    end

    subgraph S1["STAGE 1 — IIS Backdoor (T1505.003)"]
        S1A[Write CacheHttp.dll<br/>to c:\F0] --> S1B[Create IIS module<br/>registration XML]
        S1B --> S1C[Document HTTP<br/>interception patterns]
        S1C --> S1D{EDR<br/>blocked?}
    end

    subgraph S2["STAGE 2 — Email-Based C2 (T1071.003)"]
        S2A[Deploy PowerExchange<br/>PS1 script] --> S2B["Generate 4 C2 emails<br/>with @@ subject markers"]
        S2B --> S2C[Simulate bidirectional<br/>Exchange C2 channel]
        S2C --> S2D{EDR<br/>blocked?}
    end

    subgraph S3["STAGE 3 — Password Filter DLL (T1556.002)"]
        S3A[Create benign<br/>password filter DLL] --> S3B["Write LSA registry key<br/>HKLM\...\Lsa\Notification Packages"]
        S3B --> S3C[Register f0rt1ka_credfilter<br/>for credential interception]
        S3C --> S3D{EDR<br/>blocked?}
    end

    subgraph S4["STAGE 4 — STEALHOOK Exfiltration (T1048.003)"]
        S4A[Stage simulated<br/>financial data] --> S4B[Compress to<br/>ZIP archive]
        S4B --> S4C[Create multi-part<br/>exfil emails]
        S4C --> S4D{EDR<br/>blocked?}
    end

    EXTRACT --> S1A
    S1D -->|No| S2A
    S1D -->|Yes| PROT1([EXIT 126 — PROTECTED<br/>IIS backdoor detected])
    S2D -->|No| S3A
    S2D -->|Yes| PROT2([EXIT 126 — PROTECTED<br/>Email C2 detected])
    S3D -->|No| S4A
    S3D -->|Yes| PROT3([EXIT 126 — PROTECTED<br/>LSA registry blocked])
    S4D -->|No| UNPROT([EXIT 101 — UNPROTECTED<br/>Full APT34 chain succeeded])
    S4D -->|Yes| PROT4([EXIT 126 — PROTECTED<br/>Exfiltration blocked])

    style INIT fill:#1a1a2e,color:#e0e0e0,stroke:#0f3460
    style S1 fill:#0a2647,color:#e0e0e0,stroke:#2c74b3
    style S2 fill:#0a2647,color:#e0e0e0,stroke:#2c74b3
    style S3 fill:#0a2647,color:#e0e0e0,stroke:#2c74b3
    style S4 fill:#0a2647,color:#e0e0e0,stroke:#2c74b3
    style PROT1 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style PROT2 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style PROT3 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style PROT4 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style UNPROT fill:#6a040f,color:#ffd6a5,stroke:#9d0208
```

---

## 2. Agrius (Pink Sandstorm) — Multi-Wiper Deployment Against Banking Infrastructure
**UUID**: `7d39b861-644d-4f8b-bb19-4faae527a130` | **Score**: 9.0/10

```mermaid
flowchart TD
    subgraph INIT["ORCHESTRATOR"]
        START([Deploy to c:\F0]) --> EXTRACT[Extract 5 embedded<br/>stage binaries]
    end

    subgraph S1["STAGE 1 — ASPXSpy Webshell (T1505.003)"]
        S1A[Write ASPXSpy<br/>.aspx webshell to c:\F0] --> S1B[Simulate webshell<br/>command interface]
        S1B --> S1D{EDR<br/>blocked?}
    end

    subgraph S2["STAGE 2 — Service Persistence (T1543.003)"]
        S2A["sc.exe create IPsec Helper<br/>with non-standard binary path"] --> S2B[Verify service<br/>installation]
        S2B --> S2C[Cleanup: delete<br/>service after test]
        S2C --> S2D{EDR<br/>blocked?}
    end

    subgraph S3["STAGE 3 — EDR Tampering (T1562.001)"]
        S3A[Deploy GMER64.sys<br/>driver file] --> S3B[Attempt kernel<br/>driver service creation]
        S3B --> S3C["sc.exe config/stop<br/>Defender & CrowdStrike"]
        S3C --> S3R[Safety: re-enable<br/>EDR services]
        S3R --> S3D{EDR<br/>blocked?}
    end

    subgraph S4["STAGE 4 — Multi-Wiper Deployment (T1485)"]
        direction LR
        S4A[Create test files in<br/>c:\F0\wiper_test\] --> S4W
        subgraph S4W["CONCURRENT GOROUTINES"]
            W1["MultiLayer<br/>.NET wiper sim"]
            W2["PartialWasher<br/>C++ wiper sim"]
            W3["BFG Agonizer<br/>disk wiper sim"]
        end
        S4W --> S4B[Verify file<br/>overwrite results]
    end

    subgraph S5["STAGE 5 — Anti-Forensics (T1070.001)"]
        S5A["wevtutil.exe cl<br/>clear event logs"] --> S5B[Create remover.bat<br/>self-deletion script]
        S5B --> S5C[Execute cleanup<br/>of test artifacts]
        S5C --> S5D{EDR<br/>blocked?}
    end

    EXTRACT --> S1A
    S1D -->|No| S2A
    S1D -->|Yes| PROT1([EXIT 126 — PROTECTED<br/>Webshell detected])
    S2D -->|No| S3A
    S2D -->|Yes| PROT2([EXIT 126 — PROTECTED<br/>Service creation blocked])
    S3D -->|No| S4A
    S3D -->|Yes| PROT3([EXIT 126 — PROTECTED<br/>EDR tamper blocked])
    S4B --> S4D{EDR<br/>blocked?}
    S4D -->|No| S5A
    S4D -->|Yes| PROT4([EXIT 126 — PROTECTED<br/>Wiper activity blocked])
    S5D -->|No| UNPROT([EXIT 101 — UNPROTECTED<br/>Full Agrius chain succeeded])
    S5D -->|Yes| PROT5([EXIT 126 — PROTECTED<br/>Anti-forensics blocked])

    style INIT fill:#1a1a2e,color:#e0e0e0,stroke:#0f3460
    style S1 fill:#3d0000,color:#e0e0e0,stroke:#8b0000
    style S2 fill:#3d0000,color:#e0e0e0,stroke:#8b0000
    style S3 fill:#3d0000,color:#e0e0e0,stroke:#8b0000
    style S4 fill:#4a0000,color:#e0e0e0,stroke:#b30000
    style S4W fill:#5c0000,color:#ffa07a,stroke:#ff4500
    style S5 fill:#3d0000,color:#e0e0e0,stroke:#8b0000
    style PROT1 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style PROT2 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style PROT3 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style PROT4 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style PROT5 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style UNPROT fill:#6a040f,color:#ffd6a5,stroke:#9d0208
```

---

## 3. APT42 (Magic Hound) — TAMECAT Fileless Backdoor with Browser Credential Theft
**UUID**: `92b0b4f6-a09b-4c7b-b593-31ce461f804c` | **Score**: 8.7/10

```mermaid
flowchart TD
    subgraph INIT["ORCHESTRATOR"]
        START([Deploy to c:\F0]) --> EXTRACT[Extract 5 embedded<br/>stage binaries]
    end

    subgraph S1["STAGE 1 — LNK + VBScript Delivery (T1204.002 / T1059.005)"]
        S1A[Create malicious .lnk<br/>targeting cscript.exe] --> S1B[Deploy VBScript<br/>downloader]
        S1B --> S1C["WMI query SecurityCenter2<br/>enumerate AV products"]
        S1C --> S1D{EDR<br/>blocked?}
    end

    subgraph S2["STAGE 2 — TAMECAT PowerShell Backdoor (T1059.001)"]
        S2A["conhost.exe --headless →<br/>powershell -EncodedCommand"] --> S2B[AMSI detection<br/>probe]
        S2B --> S2C[In-memory TAMECAT<br/>environment fingerprint]
        S2C --> S2D{EDR<br/>blocked?}
    end

    subgraph S3["STAGE 3 — Dual Persistence (T1547.001 / T1037.001)"]
        direction LR
        S3A["Registry Run key<br/>''Renovation'' → payload"] --> S3V[Verify &<br/>cleanup]
        S3B["UserInitMprLogonScript<br/>→ logon persistence"] --> S3V
    end

    subgraph S4["STAGE 4 — Browser Credential Theft (T1555.003)"]
        S4A["Activate Edge remote<br/>debugging port 9222"] --> S4B["Access Chrome/Edge<br/>Login Data SQLite DB"]
        S4B --> S4C["Runs.dll simulation:<br/>4KB data chunking"]
        S4C --> S4D{EDR<br/>blocked?}
    end

    subgraph S5["STAGE 5 — Multi-Channel Exfiltration (T1102)"]
        direction LR
        S5T["Telegram API<br/>api.telegram.org"]
        S5F["FTP upload<br/>staging"]
        S5H["HTTPS POST<br/>exfiltration"]
    end

    EXTRACT --> S1A
    S1D -->|No| S2A
    S1D -->|Yes| PROT1([EXIT 126 — PROTECTED<br/>LNK/VBS execution blocked])
    S2D -->|No| S3A
    S2D -->|Yes| PROT2([EXIT 126 — PROTECTED<br/>PowerShell/AMSI blocked])
    S3V --> S3D{EDR<br/>blocked?}
    S3D -->|No| S4A
    S3D -->|Yes| PROT3([EXIT 126 — PROTECTED<br/>Persistence blocked])
    S4D -->|No| S5T
    S4D -->|Yes| PROT4([EXIT 126 — PROTECTED<br/>Credential theft blocked])
    S5T --> S5D{EDR<br/>blocked?}
    S5F --> S5D
    S5H --> S5D
    S5D -->|No| UNPROT([EXIT 101 — UNPROTECTED<br/>Full APT42 chain succeeded])
    S5D -->|Yes| PROT5([EXIT 126 — PROTECTED<br/>Exfil channel blocked])

    style INIT fill:#1a1a2e,color:#e0e0e0,stroke:#0f3460
    style S1 fill:#1b2838,color:#e0e0e0,stroke:#3a7ca5
    style S2 fill:#1b2838,color:#e0e0e0,stroke:#3a7ca5
    style S3 fill:#1b2838,color:#e0e0e0,stroke:#3a7ca5
    style S4 fill:#2a1a3e,color:#e0e0e0,stroke:#7b2d8e
    style S5 fill:#2a1a3e,color:#e0e0e0,stroke:#7b2d8e
    style PROT1 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style PROT2 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style PROT3 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style PROT4 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style PROT5 fill:#1b4332,color:#95d5b2,stroke:#2d6a4f
    style UNPROT fill:#6a040f,color:#ffd6a5,stroke:#9d0208
```

---

## Legend

| Color | Meaning |
|-------|---------|
| Dark blue/red | Stage subgraphs (blue = espionage, red = destructive) |
| Green terminals | PROTECTED outcomes (EDR detection success) |
| Red terminal | UNPROTECTED outcome (full chain execution) |
| Orange highlight | High-risk concurrent operations |

## Combined MITRE ATT&CK Coverage

```mermaid
flowchart LR
    subgraph IA["Initial Access"]
        T1190[T1190<br/>Exploit Public App]
        T1204[T1204.002<br/>Malicious File]
    end

    subgraph EX["Execution"]
        T1059_1[T1059.001<br/>PowerShell]
        T1059_5[T1059.005<br/>VBScript]
    end

    subgraph PE["Persistence"]
        T1505[T1505.003<br/>Web Shell]
        T1543[T1543.003<br/>Windows Service]
        T1547[T1547.001<br/>Registry Run Keys]
        T1037[T1037.001<br/>Logon Script]
    end

    subgraph DE["Defense Evasion"]
        T1562[T1562.001<br/>Disable Tools]
        T1070[T1070.001<br/>Clear Event Logs]
    end

    subgraph CA["Credential Access"]
        T1556[T1556.002<br/>Password Filter DLL]
        T1555[T1555.003<br/>Browser Credentials]
    end

    subgraph CC["Command & Control"]
        T1071[T1071.003<br/>Mail Protocols]
        T1102[T1102<br/>Web Service]
    end

    subgraph XF["Exfiltration"]
        T1048[T1048.003<br/>Alt Protocol]
    end

    subgraph IM["Impact"]
        T1485[T1485<br/>Data Destruction]
        T1561[T1561.001<br/>Disk Content Wipe]
    end

    IA --> EX --> PE --> DE --> CA --> CC --> XF --> IM

    style IA fill:#264653,color:#e9c46a,stroke:#2a9d8f
    style EX fill:#264653,color:#e9c46a,stroke:#2a9d8f
    style PE fill:#264653,color:#e9c46a,stroke:#2a9d8f
    style DE fill:#264653,color:#e9c46a,stroke:#2a9d8f
    style CA fill:#264653,color:#e9c46a,stroke:#2a9d8f
    style CC fill:#264653,color:#e9c46a,stroke:#2a9d8f
    style XF fill:#264653,color:#e9c46a,stroke:#2a9d8f
    style IM fill:#264653,color:#e9c46a,stroke:#2a9d8f
```
