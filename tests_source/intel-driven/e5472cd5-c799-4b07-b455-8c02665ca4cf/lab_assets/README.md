# HONESTCUE v2 — Lab Asset Setup

The v2 HONESTCUE test fetches two static assets from GitHub raw-hosting to
produce **real** TLS/DNS/CDN IOCs that EDR and NDR products can observe.
The test ships with reference copies of both assets here; operators must
upload them (once) to a GitHub repo they control, then update the
constants in the Go source.

## Assets to Host

| File | Purpose | Source in this directory |
|------|---------|--------------------------|
| `gemini_response.json` | Pre-staged Gemini-API-shaped response hosting the C# source code for stage 2 | `gemini_response.json` |
| `stage2_payload.exe` | F0RT1KA-signed benign marker PE that stage 3 drops to `%TEMP%` and executes | Build from `stage2_payload_src/` |

## Target Constants (update after upload)

Edit these in the test's Go source, then rebuild via `build_all.sh`:

| Constant | Go File | Default Value |
|----------|---------|---------------|
| `STAGE1_LLM_RESPONSE_URL` | `stage-T1071.001.go` | `https://raw.githubusercontent.com/F0RT1KA/lab-assets/main/honestcue/v2/gemini_response.json` |
| `STAGE3_PAYLOAD_URL` | `stage-T1105.go` | `https://raw.githubusercontent.com/F0RT1KA/lab-assets/main/honestcue/v2/stage2_payload.exe` |

Any GitHub repo + path works — the only hard requirement is that the URL
resolves to `raw.githubusercontent.com` over HTTPS.

## Build & Sign `stage2_payload.exe`

Requires .NET 8 SDK + `osslsigncode` + the F0RT1KA signing cert.

```bash
cd lab_assets/stage2_payload_src
dotnet publish -c Release -r win-x64 --self-contained true \
    -p:PublishSingleFile=true \
    -o ../publish

# Sign with F0RT1KA cert (adjust path to your signing repo)
SIGN_CERT=/path/to/signing-certs/F0RT1KA.pfx
SIGN_PASS_FILE=/path/to/signing-certs/.F0RT1KA.pfx.txt
PASSWORD=$(tr -d '\n\r' < "$SIGN_PASS_FILE")

osslsigncode sign \
    -pkcs12 "$SIGN_CERT" \
    -pass "$PASSWORD" \
    -in ../publish/stage2_payload.exe \
    -out ../stage2_payload.exe

# Verify
osslsigncode verify ../stage2_payload.exe
```

## Upload to GitHub

```bash
# Example layout in your hosting repo:
#   /honestcue/v2/gemini_response.json
#   /honestcue/v2/stage2_payload.exe

git clone https://github.com/F0RT1KA/lab-assets.git  # or your own repo
cp gemini_response.json lab-assets/honestcue/v2/
cp stage2_payload.exe   lab-assets/honestcue/v2/
cd lab-assets
git add honestcue/v2/
git commit -m "honestcue v2 lab assets"
git push
```

Wait up to 5 minutes for raw.githubusercontent.com to propagate, then:

```bash
curl -I https://raw.githubusercontent.com/<owner>/<repo>/main/honestcue/v2/gemini_response.json
# Expect: HTTP/2 200
```

## Failure Modes (Graceful by Design)

If either asset is unreachable at test time (404, DNS failure, TLS
failure), the corresponding stage exits **999 (UnexpectedTestError)**
with a descriptive message — **never** 126 (blocked). This ensures lab
asset propagation issues are never confused with EDR protection.

## Why GitHub Raw (and not Discord CDN)?

v1 used `cdn.discordapp.com` with a host-header/hosts-file spoof. v2
switches to `raw.githubusercontent.com` because:

1. No hosts-file mutation required — simpler, safer, no system config change
2. Real TLS handshake against GitHub's real fleet certificate — genuine JA3/JA4 IOC
3. Real DNS query observable via Sysmon EventID 22
4. Real SNI (`raw.githubusercontent.com`) observable by NDR / SSL inspection
5. Corporate egress filters often allow GitHub raw (developer productivity) — mirrors real TA tradecraft
6. No risk of tripping Discord-CDN egress filters during testing

## Rotation

Update the URL constants and rebuild. The test otherwise does not care
where the assets live. Moving them across repos rotates all wire-level
IOCs (SNI path, URL path, certificate chain if you use a custom domain).
