#!/usr/bin/env bash
# Optional interim mitigation for the compromised eMudhra intermediate CAs.
# Prefer supported distribution, runtime, application, and container updates.
# Check mode is read-only and performs no external network calls.
# No change is made unless --apply is present; --undo also requires --apply.
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
MODE="check"
APPLY_PRESENT=0
INCLUDE_AAA=0
ACKNOWLEDGE_AAA=0
REBUILD_JAVA=0
STATE_DIR="${EMUDHRA_STATE_DIR:-/var/lib/emudhra-ca-trust-hardening}"
BACKUP_ROOT="${EMUDHRA_BACKUP_DIR:-/var/backups/emudhra-ca-trust-hardening}"
MANIFEST="$STATE_DIR/manifest"
RUN_BACKUP=""
FAMILY=""
BLOCKLIST_DIR=""
CA_CONFIG="/etc/ca-certificates.conf"
JAVA_CACERTS="/etc/ssl/certs/java/cacerts"
TEMP_REGISTRY=""

info() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[ OK ] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERR ] %s\n' "$*" >&2; exit 1; }
cleanup() {
    local path
    if [[ -n "$TEMP_REGISTRY" && -f "$TEMP_REGISTRY" ]]; then
        while IFS= read -r path; do
            if [[ -n "$path" ]]; then
                rm -f -- "$path"
            fi
        done < "$TEMP_REGISTRY"
        rm -f -- "$TEMP_REGISTRY"
    fi
}
trap cleanup EXIT

usage() {
    cat <<EOF
Usage:
  sudo $SCRIPT_NAME --check
  sudo $SCRIPT_NAME --apply
  sudo $SCRIPT_NAME --apply --include-aaa --acknowledge-aaa-impact
  sudo $SCRIPT_NAME --apply --rebuild-java-cacerts
  sudo $SCRIPT_NAME --undo --apply

Modes:
  --check                     Audit local trust configuration and runtime versions.
  --apply                     Apply the supported interim mitigation.
  --undo --apply              Roll back only changes recorded by this script.

Debian/Ubuntu options:
  --include-aaa               Also distrust AAA Certificate Services. This can
                              break unrelated sites and services using that root.
  --acknowledge-aaa-impact    Required with --include-aaa.
  --rebuild-java-cacerts      Back up and recreate /etc/ssl/certs/java/cacerts
                              using update-ca-certificates --fresh.

p11-kit systems use exact intermediate blocklists and do not remove AAA or any
other root. Without --apply the script makes no trust configuration changes.
EOF
}

while (($#)); do
    case "$1" in
        --check)
            [[ "$MODE" == "check" ]] || die '--check cannot be combined with apply or undo'
            MODE="check"
            ;;
        --apply)
            APPLY_PRESENT=1
            [[ "$MODE" == "check" ]] && MODE="apply"
            ;;
        --undo)
            [[ "$MODE" != "apply" ]] || die 'Specify --undo before --apply'
            MODE="undo"
            ;;
        --include-aaa) INCLUDE_AAA=1 ;;
        --acknowledge-aaa-impact) ACKNOWLEDGE_AAA=1 ;;
        --rebuild-java-cacerts) REBUILD_JAVA=1 ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
    shift
done

[[ "$MODE" != "undo" || "$APPLY_PRESENT" -eq 1 ]] || die '--undo requires the explicit --apply switch'
[[ "$MODE" != "check" || "$INCLUDE_AAA" -eq 0 ]] || die '--include-aaa requires --apply'
[[ "$MODE" != "check" || "$REBUILD_JAVA" -eq 0 ]] || die '--rebuild-java-cacerts requires --apply'
[[ "$MODE" != "undo" || "$INCLUDE_AAA" -eq 0 ]] || die 'Undo uses recorded state; omit --include-aaa'
[[ "$MODE" != "undo" || "$REBUILD_JAVA" -eq 0 ]] || die 'Undo uses recorded state; omit --rebuild-java-cacerts'
[[ "$INCLUDE_AAA" -eq 0 || "$ACKNOWLEDGE_AAA" -eq 1 ]] || die 'AAA distrust requires --acknowledge-aaa-impact'
[[ "$EUID" -eq 0 ]] || die 'Root privileges are required for check, apply, and undo'

for command_name in openssl base64 sha256sum; do
    command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done

CERT_DATA=$(cat <<'CERTIFICATES'
42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493|A4AEE678F23362B4C0E460B772F214|tls|EM DV TLS CA - G3B|emSign Root TLS CA - G3|MIIDaDCCAu6gAwIBAgIQAKSu5njyM2K0wORgt3LyFDAKBggqhkjOPQQDAzBWMQswCQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTU1NDA4WhcNNDAwNDI4MTgzMDAwWjA/MQswCQYDVQQGEwJOTDETMBEGA1UECgwKZU11ZGhyYSBCVjEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0gRzNCMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE557ZwEqXc8RzXlERHahawr1eZKs3S4DhLLwgOOweTw47gS/JhZ4eZ6+wTi+LyX90hbplqpEe6KTkW2LVzAPVa+Z4s8OMtNyTfKJGDiOEU8iSk10p1E+R4VYGtjzO2rRoo4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0OBBYEFOIeL+ccGTkOVUtiwSAkVzUkiiUUMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCowKAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYBBAGDjiEBAmQwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AtYi5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRFZUTFNDQUczQi5wN2MwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5jcmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwMDaAAwZQIwLmsGXi6oFMJ2klkcEMXMug6gvxQWZWkewiDWVzQyl2L6z6DuQfPOIbh1grvdULDCAjEAxZvLlxUavG69J6wnSjC8XBbqNIQsJ6CE2QdNOe84Ptxb6VG8gt2TlfJbHii+KNvK
45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE|A024FDF4BA665C785CE4A020483858B7|tls|EM DV TLS CA - G3B|AAA Certificate Services|MIIDzjCCAragAwIBAgIRAKAk/fS6Zlx4XOSgIEg4WLcwDQYJKoZIhvcNAQELBQAwezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0yODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJWMRswGQYDVQQDDBJFTSBEViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATnntnASpdzxHNeUREdqFrCvV5kqzdLgOEsvCA47B5PDjuBL8mFnh5nr7BOL4vJf3SFumWqkR7opORbYtXMA9Vr5nizw4y03JN8okYOI4RTyJKTXSnUT5HhVga2PM7atGijggE1MIIBMTAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQU4h4v5xwZOQ5VS2LBICRXNSSKJRQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMDEGA1UdIAQqMCgwCAYGZ4EMAQIBMA0GCysGAQQBg44hAQABMA0GCysGAQQBg44hAQJkMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQBzQ1IoqpdotM6gFrR4Q3YrKifOLeaj5XXunldpVE/vZn2TxC2y0s8oYiLR5ICEwqVXSB7N6BM1Mp+Nif7Jbhb2IswAfSR4Iik8+B0iRmi7lYoNlycCgHjmsjOmZaxMQkPmjXAJbG5f4V41OsvJZmS7lI3r0IuvEDVX3GAZ13on6IImSs9ybNpHQ7NCqkMQ7wH4uAO1dtpFycgJSdHaCOhHjrox2BTYGLdpUrYwY3EOAjlZ8UGgsxs7mG+xquMlbN1LFURwfnkVMP3T/DBIZ/ys2+lNFyxK3FlArrV4/000uTnVB1lO8oGORYdXoT5VGUyRCEIDhF5TBUuKF4E3kf1h
98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B|6CADA367FB1C100088120EA202D568|tls|EM OV TLS CA - G3B|emSign Root TLS CA - G3|MIIDZjCCAu2gAwIBAgIPbK2jZ/scEACIEg6iAtVoMAoGCCqGSM49BAMDMFYxCzAJBgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVkMSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNjAwMTJaFw00MDA0MjgxODMwMDBaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJWMRswGQYDVQQDDBJFTSBPViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARziXqg6zz9yosSQC/68KvE4SErr43ud4rJ7i1tuD+sKAxeBWOK56Ks1xwyKo42HN659pxDArndjXPRzGyqsswK7k4hbOl53VGKSvS2JuVoTN1lgDftDIVOTMEvTPhkbQ2jggGWMIIBkjAfBgNVHSMEGDAWgBThOqshfPHjTVSu1HK3/YtZQiCQVDAdBgNVHQ4EFgQUm9hlUa/n5yw3rQjuaRnZvzeErgowHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMF0GA1UdIARWMFQwOQYLKwYBBAGDjiEBAAEwKjAoBggrBgEFBQcCARYcaHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbTANBgsrBgEEAYOOIQECbjAIBgZngQwBAgIwdQYIKwYBBQUHAQEEaTBnMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC1iLmVtc2lnbi5jb20wPwYIKwYBBQUHMAKGM2h0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20vY2VydHMvRU1PVlRMU0NBRzNCLnA3YzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmVtc2lnbi5jb20vP3Jvb3R0bHNjYWczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqhkjOPQQDAwNnADBkAjBAk+5BizdJhrED3wb7F2Gm7bWI60dlNd075nghT2TrR4NWKZtJZcbc28xxIY/NONICMF6mPdsjosaqmvEMWqKcBh4vsIvXSKnQj5o8zrFB4oKS+accjYTe8Dz3bQjauvy9uw==
5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699|E94223BDE92F914E5AB9ACABFDAC3710|tls|EM OV TLS CA - G3B|AAA Certificate Services|MIIDzjCCAragAwIBAgIRAOlCI73pL5FOWrmsq/2sNxAwDQYJKoZIhvcNAQELBQAwezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0yODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJWMRswGQYDVQQDDBJFTSBPViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARziXqg6zz9yosSQC/68KvE4SErr43ud4rJ7i1tuD+sKAxeBWOK56Ks1xwyKo42HN659pxDArndjXPRzGyqsswK7k4hbOl53VGKSvS2JuVoTN1lgDftDIVOTMEvTPhkbQ2jggE1MIIBMTAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQUm9hlUa/n5yw3rQjuaRnZvzeErgowDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMDEGA1UdIAQqMCgwCAYGZ4EMAQICMA0GCysGAQQBg44hAQABMA0GCysGAQQBg44hAQJuMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQALRoOSvkzRa+tN5Rje9W5GiXd/qsicd9N6Gnh0SWC7VyWH+HycIqAnFCMYZznjCeGusomFYHE42SHWr85JDIbgzy6y3dO4i9n9w0Bx7yrXWBbDzFS8VgA3+EY4Cg7ymtoC3RPOJVtaXXPZ+68X804g1Mj+3vCSHj2lNPVgco0OzSIOJ/KMg1R9MLBkiKzbbERAGZHejY0HBhYd76IINZN8z6bBNah2UdFYxsOisLynPQUkol6gRLum024/FzVlCCDfnUusrkr+mAfPAvD/Vb8bhpA7jYtepuU+2mIdShj5lLlvAwZphn+ypWycuo2x0k9mldz2dqI9nhCiY+TTIOOR
E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838|C7C41EFE92D825F05EAE841A4A82C1|tls|EM EV TLS CA - G3B|emSign Root TLS CA - G3|MIIDaDCCAu2gAwIBAgIQAMfEHv6S2CXwXq6EGkqCwTAKBggqhkjOPQQDAzBWMQswCQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTYwMzMxWhcNNDAwNDI4MTgzMDAwWjA/MQswCQYDVQQGEwJOTDETMBEGA1UECgwKZU11ZGhyYSBCVjEbMBkGA1UEAwwSRU0gRVYgVExTIENBIC0gRzNCMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEJduoWmTTl9oLEFLp6lRuSHvv6pydnWigxerc/u91ppu11vwB9Cv7ym60C81kwHZ+Nv/QXZeoE8WqDGyVMOec9fCGZGjxOAZCCqXIUYQLHiUlQOeQ5LZUw4Uu1krx6GV9o4IBlTCCAZEwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0OBBYEFD7cINmJRpiHe4c/2IFHslwV2EcGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBcBgNVHSAEVTBTMDkGCysGAQQBg44hAQABMCowKAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYBBAGDjiEBAngwBwYFZ4EMAQEwdQYIKwYBBQUHAQEEaTBnMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC1iLmVtc2lnbi5jb20wPwYIKwYBBQUHMAKGM2h0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20vY2VydHMvRU1FVlRMU0NBRzNCLnA3YzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmVtc2lnbi5jb20vP3Jvb3R0bHNjYWczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqhkjOPQQDAwNpADBmAjEA9Jq999oaOUKhFwopw33iCmt0OHIn3gjT43GfuOHR/YckXdwoNdDAlIEhz0NgRO3/AjEAvY/a3OMvktIZLYjn+WLKmp0QhrIMV+e6EpS7j4GVeOKouNp6MN/P+ByGeiRMghzB
579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512|D8F8685E4F2BD9D82402A85A1C1EB731|tls|EM EV TLS CA - G3B|AAA Certificate Services|MIIDzTCCArWgAwIBAgIRANj4aF5PK9nYJAKoWhwetzEwDQYJKoZIhvcNAQELBQAwezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0yODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJWMRswGQYDVQQDDBJFTSBFViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQl26haZNOX2gsQUunqVG5Ie+/qnJ2daKDF6tz+73Wmm7XW/AH0K/vKbrQLzWTAdn42/9Bdl6gTxaoMbJUw55z18IZkaPE4BkIKpchRhAseJSVA55DktlTDhS7WSvHoZX2jggE0MIIBMDAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQUPtwg2YlGmId7hz/YgUeyXBXYRwYwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMDAGA1UdIAQpMCcwBwYFZ4EMAQEwDQYLKwYBBAGDjiEBAAEwDQYLKwYBBAGDjiEBAngwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQELBQADggEBAJNFuAFW9Gnw/8+kCO4KIlZdnM1Sh2u+8cK0EYAHhXpb5FlGvYkcARigo5oS7VoM7FOYlTueV6yICZKNAYawZPJPhNCGK+rp3cQBEz6d0n8OZEYZov9lb3ll8ORgSDufFVIW6Gagg/UnOamLBTOR8eD5V73SCme/B2cHUDw+m5E8cc+0Ujzz3Cn3ex5JrhXk2T3s8PoVzEmhTgGboFfcWO1EYhPPrYwdxPYRQIXAXUXhLEOVNL9ASbZJLFI8E1IMm7NwxVN2s38jWpaCUaaF0tg7hfiy7oe13rzJfHsdqldJVTTUTPWVx8TC4ju0VLetbAlwhwFT6AP8uIVMGUHNw24=
0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19|588B2E3C2BB8CDA13E1A1209254321|tls|EM DV TLS CA - G3C|emSign Root TLS CA - G3|MIIDaDCCAu6gAwIBAgIPWIsuPCu4zaE+GhIJJUMhMAoGCCqGSM49BAMDMFYxCzAJBgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVkMSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNTM1MDlaFw00MDA0MjgxODMwMDBaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIEluYzEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOnp4YsjETTJN3WkDOmeCwO/u/kBV5ooSP6A3G6O9kZRRTuFypDPjYw8CvRiAN9nlFJ+bd9uUooHfmHsv6oiLdL3+j9pMEJnubKGVZv4+8OX2sJpVbMyLpQVh3xsqRB0Bo4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0OBBYEFK5+EFw8KZbBqEcnBVnx4D3U5QrzMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCowKAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYBBAGDjiEBAmQwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRFZUTFNDQUczQy5wN2MwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5jcmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwMDaAAwZQIxAMEN2HWMocbuWdy1d33pH6JpMvP/V/DIS5PtZbv1Q7TXEbxrcyxgyuddOJscYDJJlAIwB4sH1BpbScDzkdD4tJBSwrG/1Mx82vb8YaySehNuu1+1oXNdAEKwaJ0mVzScy2+6
62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72|91F347F1A5B7D39962B95E0EE4E299D1|tls|EM DV TLS CA - G3C|AAA Certificate Services|MIIDzzCCAregAwIBAgIRAJHzR/Glt9OZYrleDuTimdEwDQYJKoZIhvcNAQELBQAwezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0yODEyMzEyMzU5NTlaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIEluYzEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOnp4YsjETTJN3WkDOmeCwO/u/kBV5ooSP6A3G6O9kZRRTuFypDPjYw8CvRiAN9nlFJ+bd9uUooHfmHsv6oiLdL3+j9pMEJnubKGVZv4+8OX2sJpVbMyLpQVh3xsqRB0Bo4IBNTCCATEwHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYDVR0OBBYEFK5+EFw8KZbBqEcnBVnx4D3U5QrzMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAxBgNVHSAEKjAoMAgGBmeBDAECATANBgsrBgEEAYOOIQEAATANBgsrBgEEAYOOIQECZDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAr7b6Mx11TIJgVzHt6EH5qGNWeiiqoMrp8E5/k8s+jvupx1n083pZ5XOzUzNDwEUe0W4C4FIGUHNQ4XDwqOw0yK42xqm2dvCKgsko2UvDlT0haZVtTCeWMQOe5J/JziaMfZwsZNfZ3aaI6XPtWDZtwY8AaNfyaeCpbtm5GcGnyNWk4jSNpbtpo6NjfXuPCFOm3rTjJ4zytP7Tso6iMm0L01cYFOlTmoPv4515R2r3SPnKDtijoB/D/vgxzojvDafgyG9afX8+laO9NbMMz4sqC1vZx3984i/sBNFiugm3Vvdq5OdJRjuGC1QILIs6dg/K3i8VQqRpbfaM9kIlMzZ3dQ==
CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F|296926C227A3A1526392B19482A504|tls|EM OV TLS CA - G3C|emSign Root TLS CA - G3|MIIDaDCCAu6gAwIBAgIPKWkmwiejoVJjkrGUgqUEMAoGCCqGSM49BAMDMFYxCzAJBgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVkMSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNTM3NDFaFw00MDA0MjgxODMwMDBaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIEluYzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZfjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+N7ulaVSfHAKycO1no4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCowKAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYBBAGDjiEBAm4wCAYGZ4EMAQICMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNT1ZUTFNDQUczQy5wN2MwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5jcmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwMDaAAwZQIxAMSZt2xsPeumRdeSMSQ3CbzIZeQ/q7GDCWfeE1Pq+mhgA6gRM44cNVF3xJ+wsxJk+wIwFJbaDMokD8Ei6eNOiA8yUMYvfzQyngmrhZQMdPCK1SewrR794rSb9vGqxZzelQth
7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489|8D5A4811939EF447D77111CDD9849AE9|tls|EM OV TLS CA - G3C|AAA Certificate Services|MIIDzzCCAregAwIBAgIRAI1aSBGTnvRH13ERzdmEmukwDQYJKoZIhvcNAQELBQAwezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0yODEyMzEyMzU5NTlaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIEluYzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZfjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+N7ulaVSfHAKycO1no4IBNTCCATEwHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAxBgNVHSAEKjAoMAgGBmeBDAECAjANBgsrBgEEAYOOIQEAATANBgsrBgEEAYOOIQECbjBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAHlbhZpjhkPEAQVhPHRtBDaHqiisVD20pQ1TUeSx3l62Qe7NQ0b7vWQy7DN0iKOu7BGpP5EnIjvXbz9FhpfPJ4FhKEt3tQ51rqXz2oD8vRaryvExWPobDUz3j7HN6OzBsVMIe3PD7AAkpky0x8zMSi/ep5R9OMzybmNptbtppyuB5ytgq+h7lQdRIP+CQTaJX3qTgfMqzntYre5GljmEB5hU2/rSn8zoSU2APkJidlZFpghtgbD4I2VRHZvCwFFr/SrFM9pwrgbJNZ1MtyTSVgI5NlNb0aMfLR+/r6jJt3ROeY2yh2QQ2dx+YqgdbuL5ChFWOQU+ErSDnUq7yr+pjBQ==
432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3|8009928A64107601AF05FA2F19F109|tls|EM EV TLS CA - G3C|emSign Root TLS CA - G3|MIIDaDCCAu6gAwIBAgIQAIAJkopkEHYBrwX6LxnxCTAKBggqhkjOPQQDAzBWMQswCQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTUzOTMxWhcNNDAwNDI4MTgzMDAwWjBAMQswCQYDVQQGEwJVUzEUMBIGA1UECgwLZU11ZGhyYSBJbmMxGzAZBgNVBAMMEkVNIEVWIFRMUyBDQSAtIEczQzB2MBAGByqGSM49AgEGBSuBBAAiA2IABC1W6Cmm+4LGSkaX2WCvlR6QZ66R+SbTQwbaSKiq63hptqZ+bSdCbgRCqgOzbhmI3/Y2UU7hzwf1uks/8qBmRa59MdWGatMao9JG6wsxd+6Zy3VmxRbOdICKZo+R8MR/yqOCAZUwggGRMB8GA1UdIwQYMBaAFOE6qyF88eNNVK7Ucrf9i1lCIJBUMB0GA1UdDgQWBBSmJV6AqU2385Z8G8eR35K87kvrXzAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwXAYDVR0gBFUwUzA5BgsrBgEEAYOOIQEAATAqMCgGCCsGAQUFBwIBFhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMA0GCysGAQQBg44hAQJ4MAcGBWeBDAEBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRVZUTFNDQUczQy5wN2MwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5jcmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwMDaAAwZQIwBy1wTnzH4lXDTy2PD91ysLjvnlVN3JbJmc1BIMEU8TOLkYVHibMc9HeyonikFSfmAjEA6uE3QRxlrZTz/1/lXPTEMUhoauAtycagtlNFp79kjhvNa2/fAal1GNxsOutLnr0Y
FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F|05F078752DECE7A1BB8595D303167171|tls|EM EV TLS CA - G3C|AAA Certificate Services|MIIDzTCCArWgAwIBAgIQBfB4dS3s56G7hZXTAxZxcTANBgkqhkiG9w0BAQsFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTI1MDUxNDAwMDAwMFoXDTI4MTIzMTIzNTk1OVowQDELMAkGA1UEBhMCVVMxFDASBgNVBAoMC2VNdWRocmEgSW5jMRswGQYDVQQDDBJFTSBFViBUTFMgQ0EgLSBHM0MwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQtVugppvuCxkpGl9lgr5UekGeukfkm00MG2kioqut4abamfm0nQm4EQqoDs24ZiN/2NlFO4c8H9bpLP/KgZkWufTHVhmrTGqPSRusLMXfumct1ZsUWznSAimaPkfDEf8qjggE0MIIBMDAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQUpiVegKlNt/OWfBvHkd+SvO5L618wDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMDAGA1UdIAQpMCcwBwYFZ4EMAQEwDQYLKwYBBAGDjiEBAAEwDQYLKwYBBAGDjiEBAngwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQELBQADggEBAIFfHiaMSjnrdZygRYV4ekRBmG7ybcFk4hGQWMMyMFi0cAEk2+dGfz5bl8IaIbLqz+uVJzhOgVEX7WqIfgbWfFsfPYHYjPHBmy7SlZ3BwA86IQ6qF/etpX2/qL9A5yRNN3nVowUpaqV6H3aCpkAh3wR2ZNkvAbLDvPz3J0l+sEWjWv+ZISOV4R+hXDTdPXV01lKxnbwqEsdo/sE2QkCDKwFrZh/0uKjWspydJj+jSaDLTrGNx50Dgmn7VEcD1ZI5FXjknVUiO25YlmS1dtVZSBbyUKSjlrP/yDwPcZunoAsmCAAtCKsFLviLaymzvsKIeSSDGxpSySp2VCxompGDk8g=
9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4|7818933F8F85B4619A2B35FBA83D0A|code-signing|EM OV CS CA - G3B|emSign Root CS CA - G3|MIIDWzCCAuCgAwIBAgIPeBiTP4+FtGGaKzX7qD0KMAoGCCqGSM49BAMDMFUxCzAJBgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVkMR8wHQYDVQQDDBZlbVNpZ24gUm9vdCBDUyBDQSAtIEczMB4XDTI1MDQzMDE2MDgyN1oXDTQwMDQyODE4MzAwMFowPjELMAkGA1UEBhMCTkwxEzARBgNVBAoMCmVNdWRocmEgQlYxGjAYBgNVBAMMEUVNIE9WIENTIENBIC0gRzNCMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqrsPsGZqz88B+tUr/P1MK/LLPDSX3nOVDlgZth/mlQmHQcjEkUObNKBDHK/+W/m0wcjorgAB+fTcitgsWfNjnpbNbD1NsM7+wmw9YlF7N3YTcnQ/jordd7EAZPKr5eBQo4IBizCCAYcwHwYDVR0jBBgwFoAUaHQD+IXKjVRQVx0W4MjeRQ2rzS0wHQYDVR0OBBYEFHn66OzP2w11jaRY1p+27dx8Sd7mMBMGA1UdJQQMMAoGCCsGAQUFBwMDMF4GA1UdIARXMFUwOQYLKwYBBAGDjiEBAAEwKjAoBggrBgEFBQcCARYcaHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbTAOBgwrBgEEAYOOIQECgUgwCAYGZ4EMAQQBMHQGCCsGAQUFBwEBBGgwZjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AtYi5lbXNpZ24uY29tMD4GCCsGAQUFBzAChjJodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNT1ZDU0NBRzNCLnA3YzA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmVtc2lnbi5jb20vP3Jvb3Rjc2NhZzMuY3JsMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMAoGCCqGSM49BAMDA2kAMGYCMQC/zr03YEELsNKqzUtH2dVFi4BaKFdyrr/6G1dIWp8KAVgsw2/u4lyyboUDaC9jDvICMQC9HTxku84tNX9dmHOtH7aC2Nu/JM0jTf6KjZAvovCJzzv1IFWSZpVLZibynMLXOrM=
A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8|41E32B73AC185D6CE0D7480BACF84E69|code-signing|EM OV CS CA - G3B|AAA Certificate Services|MIIDwzCCAqugAwIBAgIQQeMrc6wYXWzg10gLrPhOaTANBgkqhkiG9w0BAQsFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTI1MDUxNDAwMDAwMFoXDTI4MTIzMTIzNTk1OVowPjELMAkGA1UEBhMCTkwxEzARBgNVBAoMCmVNdWRocmEgQlYxGjAYBgNVBAMMEUVNIE9WIENTIENBIC0gRzNCMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqrsPsGZqz88B+tUr/P1MK/LLPDSX3nOVDlgZth/mlQmHQcjEkUObNKBDHK/+W/m0wcjorgAB+fTcitgsWfNjnpbNbD1NsM7+wmw9YlF7N3YTcnQ/jordd7EAZPKr5eBQo4IBLDCCASgwHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYDVR0OBBYEFHn66OzP2w11jaRY1p+27dx8Sd7mMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMDIGA1UdIAQrMCkwCAYGZ4EMAQQBMA0GCysGAQQBg44hAQABMA4GDCsGAQQBg44hAQKBSDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAIh0OzWsdBYhY7+yxPGyosRL+uUSN6/Mrd30fBuougs5FVWQ3cRgLhImnUUgXADY9buugWhMmfT3cyU5T1MFXZXClCILm5mfg+oqm/ikUWJl3Ayf2GvYf2O++6vzqvkn418nI5Lpdt0O7Li524YS/3CZHDA+zZQ7rrHpZXgQ9Hmp8AUQ4FneaGjNanFoYxiZxwCyW5z4u7AoK0bmOVqKtcDFoVNz5++G9TYDJdhWOXmKKgzqRo1MK0PjazNT7MGHqknP93SqMVJ1gmX/qNWxYteAjlvFanQxBNX/+TRxDjuFsEHO/7BvqSpIIck0UEEfizhN8zNpWLbclEqVgl0g39A==
4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1|544B7F922C31AE220A4A922916F6E6|code-signing|EM OV CS CA - G3C|emSign Root CS CA - G3|MIIDWzCCAuGgAwIBAgIPVEt/kiwxriIKSpIpFvbmMAoGCCqGSM49BAMDMFUxCzAJBgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVkMR8wHQYDVQQDDBZlbVNpZ24gUm9vdCBDUyBDQSAtIEczMB4XDTI1MDQzMDE2Mzg0MFoXDTQwMDQyODE4MzAwMFowPzELMAkGA1UEBhMCVVMxFDASBgNVBAoMC2VNdWRocmEgSW5jMRowGAYDVQQDDBFFTSBPViBDUyBDQSAtIEczQzB2MBAGByqGSM49AgEGBSuBBAAiA2IABLnw4GNHAqacpqrdRDz9YsQbm6SyCSRpfXl052kaEm+5avs+NML9O8X0gwYfJl3CpYQ2NHMjUQQ2so8E84YjYwZ5gOJQPgJTLWVGI1pxZaJZoe9Jb3QbX97neHII5Lj676OCAYswggGHMB8GA1UdIwQYMBaAFGh0A/iFyo1UUFcdFuDI3kUNq80tMB0GA1UdDgQWBBTub3MpjW+/p7Mbw5U09hVWRHhmtzATBgNVHSUEDDAKBggrBgEFBQcDAzBeBgNVHSAEVzBVMDkGCysGAQQBg44hAQABMCowKAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDgYMKwYBBAGDjiEBAoFIMAgGBmeBDAEEATB0BggrBgEFBQcBAQRoMGYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLWMuZW1zaWduLmNvbTA+BggrBgEFBQcwAoYyaHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbS9jZXJ0cy9FTU9WQ1NDQUczQy5wN2MwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290Y3NjYWczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqhkjOPQQDAwNoADBlAjEA8yPg8sntOhLwV2QXJ5LEaKSpo/fnE3uOgTadK73fDhyjiqr0Io9GVuQTYqBPbQ2TAjBgeuApmBS486+iei03lRrp139dPw6k28jjGNvWsAU7A1N86J1zPJVDEyVH+nMAWC0=
84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD|D6A5EF613B390F32EF9CDF349F772841|code-signing|EM OV CS CA - G3C|AAA Certificate Services|MIIDxTCCAq2gAwIBAgIRANal72E7OQ8y75zfNJ93KEEwDQYJKoZIhvcNAQELBQAwezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0yODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIEluYzEaMBgGA1UEAwwRRU0gT1YgQ1MgQ0EgLSBHM0MwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAS58OBjRwKmnKaq3UQ8/WLEG5uksgkkaX15dOdpGhJvuWr7PjTC/TvF9IMGHyZdwqWENjRzI1EENrKPBPOGI2MGeYDiUD4CUy1lRiNacWWiWaHvSW90G1/e53hyCOS4+u+jggEsMIIBKDAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQU7m9zKY1vv6ezG8OVNPYVVkR4ZrcwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwMgYDVR0gBCswKTAIBgZngQwBBAEwDQYLKwYBBAGDjiEBAAEwDgYMKwYBBAGDjiEBAoFIMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQBgGbZ+NDkn2Fr5dCVs/51+6cT5iEPP1stglX4TI2UaNh9LmPdltxXw3crV8gK5L8i+d+ScGibFy0obtBHNTldXDgLnAHIzY3n+pceyKj7O2ae9CYnyuu5RBifeI3XYKowWE+oXnVGFOy0CvCJ/JsdP6aYgoCa9hGnAYicYQQL6MOMQZ5PuhcSM8t4giIzrpgrEkUP93GYEemDG5Z8BYwKs80lLeQNBnwg/VHJ3iEF/o84RXYwrlrKqJ+33C094o6LNikMJCqOK/WYHZSR8Xyhf8GXFAj5pZuI6Bcpug2V/E7i42j8OBhc25aNYDqK+B0qmb90sjNUBg3tJeSIb/599
CERTIFICATES
)

declare -A CERT_DER CERT_NAME CERT_ISSUER CERT_SERIAL
CERT_HASHES=()
while IFS='|' read -r hash serial _ name issuer der; do
    [[ -n "$hash" ]] || continue
    [[ "$hash" =~ ^[0-9A-F]{64}$ ]] || die 'Malformed certificate fingerprint in embedded data'
    [[ -z "${CERT_DER[$hash]:-}" ]] || die "Duplicate certificate fingerprint: $hash"
    CERT_HASHES+=("$hash")
    CERT_SERIAL[$hash]="$serial"
    CERT_NAME[$hash]="$name"
    CERT_ISSUER[$hash]="$issuer"
    CERT_DER[$hash]="$der"
done < <(printf '%s\n' "$CERT_DATA")
[[ "${#CERT_HASHES[@]}" -eq 16 ]] || die 'Expected exactly 16 affected certificate variants'

new_temp() {
    local path
    path=$(mktemp)
    printf '%s\n' "$path" >> "$TEMP_REGISTRY"
    printf '%s\n' "$path"
}

file_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

pem_fingerprint() {
    local output
    output=$(openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null) || return 1
    printf '%s\n' "${output#*=}" | tr -d ':'
}

decode_certificate() {
    local hash="$1" destination="$2" der_file actual serial
    der_file=$(new_temp)
    printf '%s' "${CERT_DER[$hash]}" | base64 --decode > "$der_file"
    openssl x509 -inform DER -in "$der_file" -out "$destination" || die "Could not decode $hash"
    actual=$(pem_fingerprint "$destination") || die "Could not fingerprint decoded certificate $hash"
    [[ "$actual" == "$hash" ]] || die "Decoded certificate fingerprint mismatch: $hash"
    serial=$(openssl x509 -in "$destination" -noout -serial)
    serial="${serial#serial=}"
    [[ "${serial^^}" == "${CERT_SERIAL[$hash]}" ]] || die "Decoded certificate serial mismatch: $hash"
}

detect_family() {
    local os_id="" os_like=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        os_id="${ID:-}"
        os_like="${ID_LIKE:-}"
    fi
    if command -v update-ca-trust >/dev/null 2>&1 && [[ -d /etc/pki/ca-trust/source ]]; then
        FAMILY="p11-kit-rhel"
        if [[ -d /etc/pki/ca-trust/source/blocklist || ! -d /etc/pki/ca-trust/source/blacklist ]]; then
            BLOCKLIST_DIR="/etc/pki/ca-trust/source/blocklist"
        else
            BLOCKLIST_DIR="/etc/pki/ca-trust/source/blacklist"
        fi
    elif command -v update-ca-trust >/dev/null 2>&1 && [[ -d /etc/ca-certificates/trust-source ]]; then
        FAMILY="p11-kit-arch"
        BLOCKLIST_DIR="/etc/ca-certificates/trust-source/blocklist"
    elif command -v update-ca-certificates >/dev/null 2>&1 && [[ -d /etc/pki/trust ]]; then
        FAMILY="p11-kit-suse"
        if [[ -d /etc/pki/trust/blocklist || ! -d /etc/pki/trust/blacklist ]]; then
            BLOCKLIST_DIR="/etc/pki/trust/blocklist"
        else
            BLOCKLIST_DIR="/etc/pki/trust/blacklist"
        fi
    elif command -v update-ca-certificates >/dev/null 2>&1 && [[ -f "$CA_CONFIG" ]] && [[ " $os_id $os_like " == *debian* || " $os_id $os_like " == *ubuntu* ]]; then
        FAMILY="debian"
    else
        FAMILY="unsupported"
    fi
}

refresh_trust() {
    case "$FAMILY" in
        p11-kit-rhel|p11-kit-arch) update-ca-trust ;;
        p11-kit-suse|debian) update-ca-certificates ;;
        *) return 0 ;;
    esac
}

manifest_has_path() {
    [[ -f "$MANIFEST" ]] && grep -F -- "$1|" "$MANIFEST" >/dev/null 2>&1
}

ensure_backup() {
    if [[ -z "$RUN_BACKUP" ]]; then
        mkdir -p "$STATE_DIR" "$BACKUP_ROOT"
        chmod 0700 "$STATE_DIR" "$BACKUP_ROOT"
        RUN_BACKUP=$(mktemp -d "$BACKUP_ROOT/backup-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
        if [[ -f "$MANIFEST" ]]; then
            cp -p "$MANIFEST" "$RUN_BACKUP/manifest.before"
        fi
        info "Rollback backup: $RUN_BACKUP"
    fi
}

update_manifest_expected() {
    local path="$1" expected="$2" temporary
    temporary=$(new_temp)
    awk -F'|' -v OFS='|' -v target="$path" -v hash="$expected" \
        '$1 == target {$4 = hash} {print}' "$MANIFEST" > "$temporary"
    install -m 0600 "$temporary" "$MANIFEST"
}

prepare_change() {
    local path="$1" action backup_name backup_path
    mkdir -p "$STATE_DIR"
    chmod 0700 "$STATE_DIR"
    if ! manifest_has_path "$path"; then
        ensure_backup
        if [[ -e "$path" ]]; then
            action="updated"
            backup_name=$(printf '%s' "$path" | sha256sum | awk '{print $1}')
            backup_path="$RUN_BACKUP/$backup_name"
            cp -p "$path" "$backup_path"
        else
            action="created"
            backup_path=""
        fi
        printf '%s|%s|%s|pending\n' "$path" "$action" "$backup_path" >> "$MANIFEST"
        chmod 0600 "$MANIFEST"
    fi
}

install_with_backup() {
    local source="$1" destination="$2" mode="${3:-0644}"
    prepare_change "$destination"
    install -m "$mode" "$source" "$destination"
    update_manifest_expected "$destination" "$(file_sha256 "$destination")"
}

remove_manifest_entry() {
    local path="$1" temporary
    temporary=$(new_temp)
    grep -Fv -- "$path|" "$MANIFEST" > "$temporary" || true
    install -m 0600 "$temporary" "$MANIFEST"
}

apply_p11_kit() {
    [[ "$INCLUDE_AAA" -eq 0 ]] || die 'Exact blocklists already cover AAA cross-signs without distrusting the AAA root; omit --include-aaa'
    [[ "$REBUILD_JAVA" -eq 0 ]] || die 'Automatic Java recreation is supported only for the Debian/Ubuntu cacerts path; update this Java runtime through its vendor'
    mkdir -p "$BLOCKLIST_DIR"
    local hash destination certificate
    for hash in "${CERT_HASHES[@]}"; do
        destination="$BLOCKLIST_DIR/emudhra-${hash,,}.pem"
        if [[ -f "$destination" ]] && [[ "$(pem_fingerprint "$destination" || true)" == "$hash" ]]; then
            info "Already blocklisted: ${CERT_NAME[$hash]} / ${CERT_ISSUER[$hash]}"
            continue
        fi
        certificate=$(new_temp)
        decode_certificate "$hash" "$certificate"
        install_with_backup "$certificate" "$destination" 0644
        ok "Blocklisted ${CERT_NAME[$hash]} / ${CERT_ISSUER[$hash]}"
    done
    if ! refresh_trust; then
        warn "Trust generation failed. Changes remain recorded in $MANIFEST; use --undo --apply after correcting the error."
        return 1
    fi
    ok "Refreshed the $FAMILY trust store using exact intermediate blocklists; no root was removed"
}

debian_line_disabled() {
    grep -q "^!$1$" "$CA_CONFIG"
}

debian_line_active() {
    grep -q "^$1$" "$CA_CONFIG"
}

disable_debian_root() {
    local line="$1" label="$2" temporary
    if debian_line_disabled "$line"; then
        info "Already distrusted in $CA_CONFIG: $label"
        return 0
    fi
    if ! debian_line_active "$line"; then
        warn "No active entry for $label in $CA_CONFIG; no line was added. It may already be absent from the distribution store."
        return 0
    fi
    temporary=$(new_temp)
    sed "s|^$line$|!&|" "$CA_CONFIG" > "$temporary"
    install_with_backup "$temporary" "$CA_CONFIG" 0644
    ok "Distrusted $label in $CA_CONFIG"
}

rebuild_debian_java() {
    [[ "$REBUILD_JAVA" -eq 1 ]] || return 0
    [[ -d "$(dirname "$JAVA_CACERTS")" ]] || die "Java trust directory is absent: $(dirname "$JAVA_CACERTS")"
    local empty_file
    warn "Java keystore rebuild: preserving $JAVA_CACERTS before update-ca-certificates --fresh. Reapply any local enterprise CA additions afterward."
    if [[ -e "$JAVA_CACERTS" ]]; then
        prepare_change "$JAVA_CACERTS"
    else
        empty_file=$(new_temp)
        install_with_backup "$empty_file" "$JAVA_CACERTS" 0644
    fi
    rm -f "$JAVA_CACERTS"
    if ! update-ca-certificates --fresh; then
        warn "Java/trust recreation failed. Restore recorded state with --undo --apply after correcting the error."
        return 1
    fi
    [[ -f "$JAVA_CACERTS" ]] || die 'Java cacerts was not recreated'
    if ! manifest_has_path "$JAVA_CACERTS"; then
        die 'Internal rollback-state error for Java cacerts'
    fi
    update_manifest_expected "$JAVA_CACERTS" "$(file_sha256 "$JAVA_CACERTS")"
    ok "Recreated $JAVA_CACERTS; restart Java consumers and preserve required local CAs"
}

apply_debian() {
    cat >&2 <<'WARNING'
[WARN] Debian/Ubuntu fallback: prefer the supported ca-certificates update.
[WARN] By default this blocks the emSign ECC rollover path only, not AAA cross-signs.
[WARN] Independent Java, Node, Python, pip, curl, Electron, and application stores still need updates.
WARNING
    if [[ "$INCLUDE_AAA" -eq 1 ]]; then
        cat >&2 <<'WARNING'
[WARN] AAA COMPATIBILITY WARNING: distrusting AAA Certificate Services can break
[WARN] unrelated websites, code signing, and services that still chain to that root.
[WARN] Continue only after compatibility testing and a rollback plan.
WARNING
    fi
    disable_debian_root 'mozilla/emSign_ECC_Root_CA_-_G3.crt' 'emSign ECC Root CA - G3'
    if [[ "$INCLUDE_AAA" -eq 1 ]]; then
        disable_debian_root 'mozilla/Comodo_AAA_Services_root.crt' 'AAA Certificate Services'
    fi
    rebuild_debian_java
    if ! refresh_trust; then
        warn "Trust generation failed. Changes remain recorded in $MANIFEST; use --undo --apply after correcting the error."
        return 1
    fi
    if [[ "$INCLUDE_AAA" -eq 0 ]]; then
        warn 'AAA cross-signed chains were not locally distrusted. Install vendor updates and validate that path separately.'
    fi
    ok 'Refreshed the Debian/Ubuntu trust store'
}

undo_changes() {
    if [[ ! -s "$MANIFEST" ]]; then
        info 'No script-owned changes are recorded; nothing to undo'
        return 0
    fi
    ensure_backup
    local -a lines
    mapfile -t lines < "$MANIFEST"
    local index line path action backup expected current failed=0
    for ((index=${#lines[@]}-1; index>=0; index--)); do
        line="${lines[$index]}"
        [[ -n "$line" ]] || continue
        IFS='|' read -r path action backup expected <<< "$line"
        if [[ ! -e "$path" ]]; then
            if [[ "$action" == "updated" && -n "$backup" && -f "$backup" ]]; then
                cp -p "$backup" "$path"
                ok "Restored missing file: $path"
            else
                info "Already absent: $path"
            fi
            remove_manifest_entry "$path"
            continue
        fi
        current=$(file_sha256 "$path")
        if [[ "$action" == "created" ]]; then
            if [[ "$expected" != "pending" && "$current" != "$expected" ]]; then
                warn "Refusing to delete drifted file: $path; reconcile it using $RUN_BACKUP"
                failed=1
                continue
            fi
            rm -f "$path"
            ok "Removed script-created file: $path"
        else
            if [[ "$expected" != "pending" && "$current" != "$expected" ]]; then
                if [[ -n "$backup" && -f "$backup" && "$current" == "$(file_sha256 "$backup")" ]]; then
                    info "Already restored: $path"
                    remove_manifest_entry "$path"
                    continue
                fi
                warn "Refusing to overwrite drifted file: $path; reconcile it from $backup"
                failed=1
                continue
            fi
            [[ -n "$backup" && -f "$backup" ]] || die "Backup is missing for $path"
            cp -p "$backup" "$path"
            ok "Restored original file: $path"
        fi
        remove_manifest_entry "$path"
    done
    if ! refresh_trust; then
        warn 'Trust generation failed during rollback; retained state permits another undo attempt'
        return 1
    fi
    [[ "$failed" -eq 0 ]] || die 'Rollback completed with drifted entries left in place; see warnings and retained backups'
    ok 'Rollback complete; pre-existing vendor and administrator entries were not removed'
}

check_java_store() {
    local store="$1" output normalized hash
    command -v keytool >/dev/null 2>&1 || return 0
    [[ -f "$store" ]] || return 0
    if ! output=$(keytool -list -keystore "$store" -storepass changeit 2>/dev/null); then
        warn "Could not read Java keystore with the standard default password: $store"
        return 0
    fi
    normalized="${output//:/}"
    for hash in "${CERT_HASHES[@]}"; do
        if [[ "$normalized" == *"$hash"* ]]; then
            warn "Affected identifier present in Java keystore $store: ${CERT_NAME[$hash]} / ${CERT_ISSUER[$hash]} / $hash"
        fi
    done
}

scan_bundle() {
    local bundle="$1" line pem="" fingerprint
    while IFS= read -r line; do
        if [[ "$line" == '-----BEGIN CERTIFICATE-----' ]]; then
            pem="$line"$'\n'
        elif [[ -n "$pem" ]]; then
            pem+="$line"$'\n'
            if [[ "$line" == '-----END CERTIFICATE-----' ]]; then
                fingerprint=$(printf '%s' "$pem" | openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)
                fingerprint="${fingerprint#*=}"
                fingerprint="${fingerprint//:/}"
                if [[ -n "${CERT_NAME[$fingerprint]:-}" ]]; then
                    warn "Affected identifier present in $bundle: ${CERT_NAME[$fingerprint]} / ${CERT_ISSUER[$fingerprint]} / $fingerprint"
                fi
                pem=""
            fi
        fi
    done < "$bundle"
}

check_runtimes() {
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f='ca-certificates package: ${Version}\n' ca-certificates 2>/dev/null || true
    elif command -v rpm >/dev/null 2>&1; then
        rpm -q ca-certificates 2>/dev/null || true
    fi
    if command -v node >/dev/null 2>&1; then info "Node: $(node --version 2>&1)"; fi
    if command -v nodejs >/dev/null 2>&1; then info "Node.js executable: $(nodejs --version 2>&1)"; fi
    if command -v python3 >/dev/null 2>&1; then
        info "Python: $(python3 --version 2>&1)"
        PYTHONDONTWRITEBYTECODE=1 python3 -c 'import certifi; print("certifi:", certifi.__version__, certifi.where())' 2>/dev/null || info 'certifi: not importable by python3'
        PYTHONDONTWRITEBYTECODE=1 python3 -m pip --version 2>/dev/null || info 'pip: not importable by python3'
        PYTHONDONTWRITEBYTECODE=1 python3 -c 'import pip._vendor.certifi as c; print("pip vendored certifi:", c.where())' 2>/dev/null || true
    fi
    if command -v curl >/dev/null 2>&1; then curl --version | awk 'NR==1 {print "[INFO] curl: " $0}'; fi
    if command -v java >/dev/null 2>&1; then java -version 2>&1 | awk 'NR<=2 {print "[INFO] Java: " $0}'; fi
    info 'Version output is inventory, not proof of chain rejection. Update each vendor-supported runtime and validate its actual trust path.'
}

check_state() {
    detect_family
    info "Detected trust family: $FAMILY"
    case "$FAMILY" in
        p11-kit-*)
            local hash destination found=0
            for hash in "${CERT_HASHES[@]}"; do
                destination="$BLOCKLIST_DIR/emudhra-${hash,,}.pem"
                if [[ -f "$destination" ]] && [[ "$(pem_fingerprint "$destination" || true)" == "$hash" ]]; then
                    ((found+=1))
                else
                    warn "Exact blocklist entry absent: ${CERT_NAME[$hash]} / ${CERT_ISSUER[$hash]} / $hash"
                fi
            done
            info "Exact local blocklist coverage: $found/16 in $BLOCKLIST_DIR (vendor mitigations may exist elsewhere)"
            ;;
        debian)
            if debian_line_disabled 'mozilla/emSign_ECC_Root_CA_-_G3.crt'; then
                ok 'emSign ECC Root CA - G3 is excluded in ca-certificates.conf'
            else
                warn 'emSign ECC Root CA - G3 is not explicitly excluded in ca-certificates.conf'
            fi
            if debian_line_disabled 'mozilla/Comodo_AAA_Services_root.crt'; then
                ok 'AAA Certificate Services is excluded; review compatibility impact'
            else
                warn 'AAA Certificate Services is not excluded; cross-signed coverage depends on vendor/runtime updates'
            fi
            ;;
        *)
            warn 'No supported local mitigation path was detected. Use the distribution vendor update and its documented trust-store procedure.'
            ;;
    esac

    local -a bundles=(
        /etc/ssl/certs/ca-certificates.crt
        /etc/pki/tls/certs/ca-bundle.crt
        /etc/pki/tls/certs/ca-bundle.trust.crt
        /etc/ssl/ca-bundle.pem
    )
    declare -A seen_bundles=()
    local bundle store
    for bundle in "${bundles[@]}"; do
        [[ -f "$bundle" && -z "${seen_bundles[$bundle]:-}" ]] || continue
        seen_bundles[$bundle]=1
        scan_bundle "$bundle"
    done
    check_java_store "$JAVA_CACERTS"
    if [[ -n "${JAVA_HOME:-}" ]]; then
        check_java_store "$JAVA_HOME/lib/security/cacerts"
        check_java_store "$JAVA_HOME/jre/lib/security/cacerts"
    fi
    check_runtimes
    info 'Presence in a legacy PEM bundle is an exposure cue, not a chain-acceptance verdict; blocklist semantics and runtime behavior require offline chain validation.'
}

if [[ "$MODE" != "check" ]]; then
    TEMP_REGISTRY=$(mktemp)
fi

detect_family
case "$MODE" in
    check) check_state ;;
    apply)
        case "$FAMILY" in
            p11-kit-*) apply_p11_kit ;;
            debian) apply_debian ;;
            *) die 'Unsupported trust-store family. Install the supported vendor ca-certificates update instead of editing generated bundles.'
        esac
        ;;
    undo) undo_changes ;;
esac
