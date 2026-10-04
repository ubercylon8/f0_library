#!/usr/bin/env python3
"""sb_report.py — Convert F0RT1KA per-stage bundle results into the
Superintendencia de Bancos continuous-testing report format.

The SB-PC-2026-001 [LOCKBIT] package (section 04, "Reporte de Resultados")
requires a JSON envelope `{meta, executions[]}` delivered over the SB SFTP,
with one row per technique executed per endpoint and outcomes from:
PREVENTED | DETECTED | MISSED | EXPOSED | NOT_RUN | ERROR.

F0RT1KA measures *prevention* (a stage binary either executed its primitive or
was blocked/quarantined); it cannot observe SOC-side *detection*. DETECTED is
therefore only emitted when declared explicitly via --detected.

Outcome mapping (F0 bundle row -> SB outcome). Bundle rows carry the
normalized exit_code (101 = stage succeeded, 126/105/127 = prevented,
999 = error) plus the skipped flag:
    exit 126/105/127                          -> PREVENTED
    exit 101/0, exfiltration or impact stage  -> EXPOSED
    exit 101/0, other stages                  -> MISSED
    skipped                                   -> NOT_RUN (reason in evidenceRef)
    anything else (999, unknown)              -> ERROR

Usage:
    python3 utils/sb_report.py \
        --bundle staging/<uuid>/bundle_results.json \
        --execution-log staging/<uuid>/test_execution_log.json \
        --org-code ENT-001 --window-from 2026-10-01 --window-to 2026-10-01 \
        --out sb_report.json

Stdlib only. See docs/ and the SB-PC-2026-001 package for the field contract.
"""

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone

OUTCOMES = {"PREVENTED", "DETECTED", "MISSED", "EXPOSED", "NOT_RUN", "ERROR"}

# ATT&CK tactic kebab-case -> TA identifier (SB format uses TA-codes).
TACTIC_TO_TA = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "command-and-control": "TA0011",
    "impact": "TA0040",
}

# SB-PC-2026-001 objective labels (section 02, "Comportamientos Observables").
# Keyed by bundle id; extend when new supervisory packages land.
SB_STAGE_LABELS = {
    "SB-PC-2026-001": {
        1: "Ejecución y degradación de defensas en los endpoints",
        2: "Acceso a credenciales privilegiadas",
        3: "Movimiento lateral y propagación hacia activos de valor",
        4: "Exfiltración de datos previa al cifrado",
        5: "Impacto por cifrado y bloqueo de recuperación",
    }
}
SB_BUNDLE_NAMES = {
    "SB-PC-2026-001": "Ransomware con doble extorsión — LockBit 3.0",
}

# Stages whose success maps to EXPOSED instead of MISSED (exfiltration/impact
# objectives where "the objective was achieved" is the exposure signal).
EXPOSED_TACTICS = {"exfiltration", "impact"}

# Exit code -> canonical name (mirrors ProjectAchilles ERROR_CODE_MAP). Used to
# build the default evidenceRef suffix, same as the PA reports endpoint.
EXIT_CODE_NAMES = {
    0: "NormalExit",
    101: "Unprotected",
    105: "FileQuarantinedOnExtraction",
    126: "ExecutionPrevented",
    127: "QuarantinedOnExecution",
    200: "NoOutput",
    259: "StillActive",
    260: "BlockedPreExecution",
    999: "UnexpectedTestError",
}


def parse_args():
    p = argparse.ArgumentParser(
        description="Convert F0RT1KA bundle_results.json to the SB {meta, executions[]} report format.")
    p.add_argument("--bundle", required=True, help="Path to bundle_results.json")
    p.add_argument("--execution-log", help="Optional test_execution_log.json (per-stage timestamps, hostname)")
    p.add_argument("--org-code", required=True, help="Entity code assigned by the SB (meta.organization)")
    p.add_argument("--vendor", default="F0RT1KA / ProjectAchilles",
                   help="Execution platform/method, declarative (meta.vendor)")
    p.add_argument("--window-from", help="Execution window start, YYYY-MM-DD (default: run date)")
    p.add_argument("--window-to", help="Execution window end, YYYY-MM-DD (default: run date)")
    p.add_argument("--bundle-id", default="SB-PC-2026-001",
                   help="SB package code (default: SB-PC-2026-001; inferred from bundle_name when present)")
    p.add_argument("--bundle-name", help="SB package name (default: built-in for the bundle id)")
    p.add_argument("--hostname", help="Endpoint name/pseudonym (default: from execution log)")
    p.add_argument("--prevented-by", default="",
                   help="Comma-separated control names for PREVENTED rows (e.g. 'Microsoft Defender for Endpoint')")
    p.add_argument("--detected", default="",
                   help="Stages the SOC detected, e.g. '2:Microsoft Defender for Endpoint,5:Sentinel'. "
                        "Only valid for stages that executed (success).")
    p.add_argument("--evidence-ref", default="",
                   help="Override evidenceRef for every row (default: per-row '<sourceEventId> (<error name>)', "
                        "mirroring the ProjectAchilles reports endpoint)")
    p.add_argument("-o", "--out", help="Output file (default: stdout)")
    return p.parse_args()


def iso_with_tz(ts):
    """Normalize an ISO timestamp to include a timezone (SB requires the zone)."""
    if not ts:
        return None
    ts = ts.strip()
    if ts.endswith("Z") or re.search(r"[+-]\d{2}:?\d{2}$", ts):
        return ts
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return ts  # leave unparseable strings untouched rather than inventing
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def stage_number(control, position):
    """Extract the stage number from the validator field ('Stage 2') or fall back to position."""
    m = re.search(r"(\d+)", str(control.get("validator", "")))
    return int(m.group(1)) if m else position


def map_outcome(control, detected_controls):
    # The written bundle schema carries exit_code/compliant/skipped, not the
    # in-memory status string: success is normalized to 101, blocks to
    # 126/105/127, errors to 999.
    exit_code = control.get("exit_code")
    status = str(control.get("status", "")).lower()
    tactics = set(control.get("tactics", []))
    stage = control.get("_stage")
    if control.get("skipped") or status == "skipped":
        return "NOT_RUN"
    if exit_code in (126, 105, 127) or status == "blocked":
        return "PREVENTED"
    if exit_code in (0, 101) or status == "success":
        if stage in detected_controls:
            return "DETECTED"
        if tactics & EXPOSED_TACTICS:
            return "EXPOSED"
        return "MISSED"
    return "ERROR"


def main():
    args = parse_args()

    with open(args.bundle, encoding="utf-8") as f:
        bundle = json.load(f)
    controls = bundle.get("controls")
    if not isinstance(controls, list) or not controls:
        sys.exit("error: bundle_results.json has no controls[] entries")

    exec_log = None
    if args.execution_log:
        with open(args.execution_log, encoding="utf-8") as f:
            exec_log = json.load(f)

    # SB package identity: explicit flags > inferred from F0 bundle name > defaults.
    bundle_id = args.bundle_id
    m = re.search(r"SB-PC-\d{4}-\d{3}", str(bundle.get("bundle_name", "")))
    if m:
        bundle_id = m.group(0)
    bundle_name = args.bundle_name or SB_BUNDLE_NAMES.get(bundle_id, bundle.get("bundle_name", ""))
    stage_labels = SB_STAGE_LABELS.get(bundle_id, {})

    # Per-stage timestamps + hostname from the execution log, when available.
    stage_times = {}
    hostname = args.hostname
    if exec_log:
        for s in exec_log.get("stages", []):
            if s.get("stageId") and s.get("startTime"):
                stage_times[s["stageId"]] = s["startTime"]
        hostname = hostname or exec_log.get("systemInfo", {}).get("hostname")
    hostname = hostname or "unknown"

    detected_controls = {}
    if args.detected:
        for item in args.detected.split(","):
            num, _, who = item.partition(":")
            detected_controls[int(num.strip())] = [w.strip() for w in who.split("+") if w.strip()]

    prevented_by = [w.strip() for w in args.prevented_by.split(",") if w.strip()]

    executions = []
    for pos, control in enumerate(controls, start=1):
        stage = stage_number(control, pos)
        control["_stage"] = stage
        outcome = map_outcome(control, detected_controls)
        if outcome == "DETECTED" and control.get("exit_code") not in (0, 101):
            sys.exit(f"error: stage {stage} declared detected but did not execute (exit_code={control.get('exit_code')})")

        techniques = control.get("techniques") or [control.get("control_id")]
        tactics = [TACTIC_TO_TA.get(t, t) for t in control.get("tactics", [])]

        source_event_id = str(uuid.uuid4())
        exit_code = control.get("exit_code")
        if outcome == "NOT_RUN":
            details = control.get("details", "")
            evidence_suffix = f"skipped: {details}" if details else "skipped"
        else:
            evidence_suffix = EXIT_CODE_NAMES.get(exit_code, f"Unknown ({exit_code})")

        row = {
            "sourceEventId": source_event_id,
            "timestamp": iso_with_tz(
                stage_times.get(stage) or bundle.get("started_at") or bundle.get("completed_at")),
            "bundleId": bundle_id,
            "bundleName": bundle_name,
            "testName": bundle.get("bundle_name", ""),
            "hostname": hostname,
            "stage": stage,
            "stageLabel": stage_labels.get(stage, control.get("control_name", "")),
            "techniques": techniques,
            "tactics": tactics,
            "outcome": outcome,
            "isProtected": outcome in ("PREVENTED", "DETECTED"),
            "preventedBy": prevented_by if outcome == "PREVENTED" else [],
            "detectedBy": detected_controls.get(stage, []) if outcome == "DETECTED" else [],
            "evidenceRef": args.evidence_ref or f"{source_event_id} ({evidence_suffix})",
        }
        if row["timestamp"] is None:
            sys.exit(f"error: no timestamp available for stage {stage} — provide --execution-log")
        executions.append(row)

    run_date = None
    for key in ("started_at", "completed_at"):
        if bundle.get(key):
            run_date = bundle[key][:10]
            break
    window_from = args.window_from or run_date
    window_to = args.window_to or run_date
    if not window_from or not window_to:
        sys.exit("error: no run date in bundle — provide --window-from/--window-to")

    report = {
        "meta": {
            "organization": args.org_code,
            "vendor": args.vendor,
            "window": {"from": window_from, "to": window_to},
            "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "executions": executions,
    }

    # Contract sanity check (section 04): required fields + outcome enum.
    required = ["sourceEventId", "timestamp", "bundleId", "bundleName", "testName",
                "hostname", "stage", "stageLabel", "techniques", "outcome", "isProtected"]
    for row in executions:
        missing = [k for k in required if row.get(k) in (None, "", [])]
        if missing:
            sys.exit(f"error: execution row stage {row['stage']} missing required fields: {missing}")
        if row["outcome"] not in OUTCOMES:
            sys.exit(f"error: invalid outcome {row['outcome']}")

    out = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out + "\n")

    covered = {r["stage"] for r in executions if r["outcome"] not in ("NOT_RUN", "ERROR")}
    print(f"SB report: {len(executions)} executions, bundle {bundle_id}, host {hostname}", file=sys.stderr)
    for r in executions:
        print(f"  stage {r['stage']}  {r['outcome']:<9} {'/'.join(r['techniques'])}", file=sys.stderr)
    print(f"objectives covered (non NOT_RUN/ERROR): {len(covered)}/5", file=sys.stderr)
    if args.out:
        print(f"written to {args.out}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
