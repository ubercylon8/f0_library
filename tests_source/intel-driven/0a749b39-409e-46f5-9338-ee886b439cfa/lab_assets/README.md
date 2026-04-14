# PROMPTFLUX v1 — Local Lab-Asset Manifest

This directory is intentionally empty. The **canonical** lab assets for this
test live in ProjectAchilles, hosted from `raw.githubusercontent.com`, so
that stage 1 and stage 2 produce genuine TLS / DNS / SNI IOCs observable by
EDR and NDR products.

## Canonical location

Source of truth:
[`projectachilles/ProjectAchilles/lab-assets/promptflux/v1/`](https://github.com/projectachilles/ProjectAchilles/tree/main/lab-assets/promptflux/v1)

## Raw URLs consumed by this test

- Stage 1 (T1071.001): `https://raw.githubusercontent.com/projectachilles/ProjectAchilles/main/lab-assets/promptflux/v1/gemini_response.json`
- Stage 2 (T1027.001): `https://raw.githubusercontent.com/projectachilles/ProjectAchilles/main/lab-assets/promptflux/v1/variant_thinging.vbs`

## Why host them there instead of embedding?

- Genuine TLS handshake against GitHub's fleet certificate (real JA3/JA4)
- Genuine DNS EventID 22 observable by Sysmon
- Genuine SNI observable by NDR / SSL inspection
- Rotation of the VBS payload shape requires only a ProjectAchilles push —
  no signed-binary rebuild needed on the f0_library side

## Why NOT the third (stage 3) Startup VBS?

The third benign obfuscated VBS — `ScreenRecUpdater.vbs` dropped into the
user Startup folder — is **embedded** into the stage-3 binary via `//go:embed`
from `embedded_startup_payload.vbs`. It is not hosted externally because:

1. Stage 3's detection signal is the **file appearing in a Startup folder**
   at test time. An external fetch would create an extra network IOC that
   dilutes the persistence-write signal we want to measure.
2. It never executes at test time; the orchestrator removes it on exit
   before it can fire at next logon. There is no scenario where rotating
   its body at runtime adds test value.

## Do NOT remove from ProjectAchilles

If the stage 1 or stage 2 lab asset is removed or renamed from
ProjectAchilles, this test will return exit **999**
(`Endpoint.UnexpectedTestError`) from whichever stage's fetch fails,
**not** exit 126 (`Endpoint.ExecutionPrevented`). Lab-asset outages are
never confused with EDR protection.

See the upstream manifest for SHA256 integrity hashes and the safety
statement for both files.
