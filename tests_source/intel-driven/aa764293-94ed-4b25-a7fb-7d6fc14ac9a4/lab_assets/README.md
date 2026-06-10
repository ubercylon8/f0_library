# RoguePlanet — Lab Asset (prebuilt payload)

This test is a **prebuilt-binary deployment**: the orchestrator embeds an existing
prebuilt `RoguePlanet.exe` via `//go:embed` (gzip-compressed at build time). The
payload binary is **NOT committed to git** — the repo `.gitignore` excludes all `*.exe`,
and large/sensitive PoC binaries follow the `lab_assets/` out-of-band convention.

## Required asset

| File | Place at | Purpose |
|------|----------|---------|
| `RoguePlanet.exe` | `tests_source/intel-driven/aa764293-94ed-4b25-a7fb-7d6fc14ac9a4/RoguePlanet.exe` | The prebuilt PoC payload embedded by the orchestrator |

The build step (`build_all.sh`) signs this binary with the F0RT1KA cert, gzip-compresses
it to `RoguePlanet.exe.gz`, embeds it, then removes the `.gz`. The committed Go source
references `RoguePlanet.exe.gz` in its `//go:embed` directive; that `.gz` is produced at
build time and is also gitignored.

## Provenance & integrity

| Field | Value |
|-------|-------|
| Origin | RoguePlanet PoC (attributed to "Nightmare-Eclipse"), supplied for authorized defensive research |
| File type | PE32+ x64 console, ~1.07 MB |
| **Pristine (unsigned) SHA256** | `08295dfde704bccce015af683ca95312d45564f7321bd64cc63c034b64e08080` |
| Reference analysis | `/home/jimx/F0RT1KA/RoguePlanet/ROGUEPLANET_ANALYSIS.md` |
| Source-of-truth copy | `/home/jimx/F0RT1KA/RoguePlanet/RoguePlanet.exe` |

Do **not** recompile from `RoguePlanet.cpp` (5.7 MB / 79k lines, needs MSVC + Windows
SDK). Ship the prebuilt exe.

## Restore before building (fresh clone)

```bash
cp /home/jimx/F0RT1KA/RoguePlanet/RoguePlanet.exe \
   tests_source/intel-driven/aa764293-94ed-4b25-a7fb-7d6fc14ac9a4/RoguePlanet.exe

# verify integrity
sha256sum tests_source/intel-driven/aa764293-94ed-4b25-a7fb-7d6fc14ac9a4/RoguePlanet.exe
# expect: 08295dfde704bccce015af683ca95312d45564f7321bd64cc63c034b64e08080

cd tests_source/intel-driven/aa764293-94ed-4b25-a7fb-7d6fc14ac9a4
./build_all.sh
```

## Safety

`RoguePlanet.exe` is a **real LPE exploit**, not a simulation. It overwrites
`C:\Windows\System32\wermgr.exe` and spawns a SYSTEM console. Detonate only on a
disposable / snapshot Windows VM with Defender enabled, logged in as a standard user.
See the test README and info card.
