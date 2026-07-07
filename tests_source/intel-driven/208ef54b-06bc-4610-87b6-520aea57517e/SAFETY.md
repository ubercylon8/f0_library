# SAFETY — ScreenConnect Unsanctioned RMM Abuse Test

- **Test UUID:** `208ef54b-06bc-4610-87b6-520aea57517e`
- **Classification:** DESTRUCTIVE / STATE-CHANGING — this test **really installs software**.

> [!WARNING]
> Unlike simulation-only tests, this test performs a **real silent install** of the
> ConnectWise ScreenConnect access agent and **creates a real Windows service**.
> **Snapshot the target VM before running and revert after.**

---

## 1. What this test actually does on the host

| Action | Real / Simulated | Reversible by cleanup? |
|--------|------------------|------------------------|
| Drops the embedded vendor MSI to `C:\F0\screenconnect-setup.msi` | Real file write | Yes |
| `msiexec /qn` silent install of ScreenConnect | **Real install** | Yes (uninstall) |
| Creates the `ScreenConnect Client (<instance-id>)` Windows service | **Real service** | Yes (stop + delete) |
| Outbound relay attempt (DNS + TCP 443) | Real network attempt to an **unreachable** `.invalid` placeholder | N/A (no session) |
| Stages synthetic `*_DECOY` files in `c:\Users\fortika-test\shared_finance_export` | Real file writes (synthetic content) | Yes |
| Zips decoys to `C:\F0\collected_export.zip` | Real file write | Yes |
| Exfil upload attempt | Real HTTPS attempt to an **unreachable** benign `.invalid` endpoint | N/A |

**No live remote-control session is ever established** — the relay is pointed at an
unreachable, controlled placeholder host and no relay/instance secrets are shipped.

---

## 2. Mandatory pre-run steps

1. **Snapshot the `win` lab VM** (Defender ON). This test overwrites host state.
2. Provision the artifact directory (decoy source): `c:\Users\fortika-test`. On the
   lab this is created by the deploy step; the stage will create the
   `shared_finance_export` subdir and decoys itself.
3. Ensure the **manual build gate** is satisfied — the vendor MSI must be staged as
   `screenconnect_embedded.msi` in the test directory before building (see README).

## 3. Mandatory post-run steps

1. Run the bundled cleanup **as Administrator**: `C:\F0\screenconnect_cleanup.exe`
   (stops + uninstalls the agent, deletes the service, removes install dirs, decoys,
   and dropped artifacts).
2. **Revert the VM snapshot** to guarantee a clean baseline (recommended over relying
   on cleanup alone, since a real MSI install touches Program Files / ProgramData /
   registry / services).

---

## 3b. If the test aborts mid-run

- Exit **999** (prerequisite/benign) — the agent may or may not have installed.
  Run cleanup, then check for a residual `ScreenConnect Client (*)` service.
- Exit **126 / 105** (blocked/quarantined) — a protection layer intervened with
  positive evidence; the agent likely did not fully install. Run cleanup anyway.
- Panic — the orchestrator recovers, saves a 999 result, and prints the cleanup path.

---

## 4. Secrets & redistribution hygiene

- **No relay/instance config or key is committed.** Relay + exfil endpoints are
  unreachable RFC 2606 `.invalid` placeholders.
- The **vendor MSI is a LOCAL build asset only** — it is git-ignored (`.gitignore`)
  and must never be committed if ConnectWise licensing disallows redistribution.
  Stage it out-of-band; do not push it to the repo.

---

## 5. Authorization

Run only on lab endpoints you own/control (the `win` lab), under the F0RT1KA
authorized security-testing program. Do not deploy the real agent to production or
third-party hosts.
