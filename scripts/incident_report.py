#!/usr/bin/env python3
"""
incident_report.py - run every detection in ../detections against your Log Analytics
workspace (Microsoft Sentinel) and write an incident summary in Markdown.

It also compares the alerts with simulation/attack_log.csv (what you actually did),
so you can show your DETECTION COVERAGE: which attack steps were caught and which were missed.

Live (in Azure Cloud Shell, after the simulation):
    python3 scripts/incident_report.py --from-terraform --timespan P1D --out report/incident-summary.md

Offline (from saved query results, one JSON file per detection):
    python3 scripts/incident_report.py --from-json tests/fixtures/alerts

Uses the Azure CLI ("az monitor log-analytics query"), already installed in Cloud Shell.
Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = ROOT / "detections"
ATTACK_LOG = ROOT / "simulation" / "attack_log.csv"

SEVERITY_POINTS = {"informational": 0, "low": 1, "medium": 3, "high": 5}
SEVERITY_ORDER = ["high", "medium", "low", "informational"]

MITRE_NAMES = {
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1562.007": "Impair Defenses: Disable or Modify Cloud Firewall",
    "T1562.008": "Impair Defenses: Disable or Modify Cloud Logs",
    "T1530": "Data from Cloud Storage",
}

ISO_NAMES = {
    "A.5.15": "Access control", "A.5.18": "Access rights", "A.5.28": "Collection of evidence",
    "A.8.2": "Privileged access rights", "A.8.3": "Information access restriction",
    "A.8.5": "Secure authentication", "A.8.9": "Configuration management",
    "A.8.12": "Data leakage prevention", "A.8.15": "Logging", "A.8.16": "Monitoring activities",
    "A.8.20": "Networks security", "A.8.32": "Change management",
}

META_RE = re.compile(r"^//\s*([a-z0-9_]+):\s*(.+?)\s*$", re.MULTILINE)


@dataclass
class Detection:
    key: str
    meta: dict
    query: str


@dataclass
class Alert:
    time: datetime | None
    time_raw: str
    resource: str
    account: str
    detection: str
    detection_id: str
    mitre: list[str]
    severity: str
    details: str


# --------------------------------------------------------------------------- detections
def load_detections(folder: Path) -> dict[str, Detection]:
    out: dict[str, Detection] = {}
    for path in sorted(folder.glob("*.kql")):
        text = path.read_text(encoding="utf-8")
        meta = dict(META_RE.findall(text))
        out[meta.get("id", path.stem.split("_")[0])] = Detection(path.stem, meta, text)
    return out


def split_list(value: str) -> list[str]:
    return [v.strip() for v in re.split(r"[,;]", value or "") if v.strip()]


# --------------------------------------------------------------------------- input
def az_query(workspace: str, query: str, timespan: str) -> list[dict]:
    cmd = ["az", "monitor", "log-analytics", "query", "-w", workspace,
           "--analytics-query", query, "--timespan", timespan, "-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "az failed")
    return json.loads(result.stdout or "[]")


def workspace_from_terraform() -> str:
    result = subprocess.run(["terraform", f"-chdir={ROOT / 'terraform'}", "output", "-raw", "workspace_customer_id"],
                            capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout.strip():
        sys.exit("Could not read workspace_customer_id from Terraform. Did you run 'terraform apply'?")
    return result.stdout.strip()


def rows_live(workspace: str, timespan: str, detections: dict[str, Detection]) -> list[dict]:
    if not shutil.which("az"):
        sys.exit("Azure CLI 'az' not found. Run this in Azure Cloud Shell, or use --from-json.")
    rows: list[dict] = []
    for det_id, det in detections.items():
        try:
            found = az_query(workspace, det.query, timespan)
        except Exception as exc:  # keep going if one table does not exist yet
            print(f"[!] {det_id} failed: {exc}", file=sys.stderr)
            continue
        print(f"[+] {det_id} {det.meta.get('name', '')}: {len(found)} result(s)", file=sys.stderr)
        rows.extend(found)
    return rows


def rows_offline(folder: Path) -> list[dict]:
    rows: list[dict] = []
    files = sorted(folder.glob("*.json"))
    if not files:
        sys.exit(f"No .json files in {folder}")
    for path in files:
        data = json.loads(path.read_text(encoding="utf-8"))
        data = data if isinstance(data, list) else [data]
        print(f"[+] {path.name}: {len(data)} row(s)", file=sys.stderr)
        rows.extend(data)
    return rows


# --------------------------------------------------------------------------- normalise
def parse_time(value: str) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    value = value.replace("Z", "+00:00")
    # Log Analytics can return 7 fractional digits; Python accepts at most 6.
    value = re.sub(r"(\.\d{6})\d+", r"\1", value)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.astimezone()


def to_alert(row: dict) -> Alert:
    detection = str(row.get("Detection") or "unknown")
    return Alert(
        time=parse_time(str(row.get("TimeGenerated") or "")),
        time_raw=str(row.get("TimeGenerated") or ""),
        resource=str(row.get("Resource") or "unknown"),
        account=str(row.get("Account") or "unknown"),
        detection=detection,
        detection_id=detection.split()[0],
        mitre=split_list(str(row.get("Mitre") or "")),
        severity=str(row.get("Severity") or "medium").lower(),
        details=str(row.get("Details") or ""),
    )


def short(resource: str) -> str:
    """Last part of an Azure resource ID, for readable tables."""
    return resource.rstrip("/").split("/")[-1] if resource.startswith("/") else resource


# --------------------------------------------------------------------------- coverage
def load_ground_truth(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def coverage(steps: list[dict], alerts: list[Alert]) -> list[tuple[dict, list[str]]]:
    result = []
    for step in steps:
        wanted = set(split_list(step.get("mitre", "")))
        hits = sorted({a.detection_id for a in alerts if wanted & set(a.mitre)})
        result.append((step, hits))
    return result


# --------------------------------------------------------------------------- report
def build_report(alerts: list[Alert], detections: dict[str, Detection], source: str,
                 steps: list[dict]) -> str:
    alerts.sort(key=lambda a: (a.time is None, a.time.timestamp() if a.time else 0))
    out: list[str] = ["# Cloud incident summary", "",
                      f"_Generated {datetime.now().astimezone():%Y-%m-%d %H:%M %Z} by `scripts/incident_report.py` "
                      f"from {source}._", ""]

    if steps:
        out += ["## Detection coverage (simulated steps vs alerts)", "",
                "| Step | ATT&CK | What was done | Detected by |", "|---|---|---|---|"]
        cov = coverage(steps, alerts)
        for step, hits in cov:
            out.append(f"| {step.get('step')} | {step.get('mitre')} | {step.get('description')} | "
                       f"{', '.join(hits) if hits else '❌ not detected'} |")
        caught = sum(1 for _, hits in cov if hits)
        out += ["", f"**Coverage: {caught}/{len(cov)} simulated steps detected.**", ""]

    if not alerts:
        out.append("No alerts returned for this time window.")
        return "\n".join(out) + "\n"

    sev = Counter(a.severity for a in alerts)
    out += ["## Overview", "",
            f"- **Alerts:** {len(alerts)} ({', '.join(f'{sev[s]} {s}' for s in SEVERITY_ORDER if sev[s])})",
            f"- **Resources involved:** {len({a.resource for a in alerts})}",
            f"- **Accounts / sources involved:** {len({a.account for a in alerts})}", ""]

    per_res: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        per_res[short(a.resource)].append(a)
    out += ["## Resource risk", "", "| Resource | Alerts | Risk points |", "|---|---|---|"]
    for res, items in sorted(per_res.items(), key=lambda kv: -sum(SEVERITY_POINTS.get(a.severity, 1) for a in kv[1])):
        out.append(f"| {res} | {len(items)} | {sum(SEVERITY_POINTS.get(a.severity, 1) for a in items)} |")
    out += ["", "_Points: low=1, medium=3, high=5._", ""]

    out += ["## Timeline (UTC)", "", "| Time | Detection | Severity | Resource | Account | Details |",
            "|---|---|---|---|---|---|"]
    for a in alerts:
        when = a.time.strftime("%Y-%m-%d %H:%M:%S") if a.time else a.time_raw
        details = a.details.replace("|", "\\|")
        out.append(f"| {when} | {a.detection} | {a.severity} | {short(a.resource)} | {a.account} | `{details}` |")
    out.append("")

    out += ["## MITRE ATT&CK techniques", "", "| Technique | Name | Alerts |", "|---|---|---|"]
    for tech, count in Counter(t for a in alerts for t in a.mitre).most_common():
        out.append(f"| [{tech}](https://attack.mitre.org/techniques/{tech.replace('.', '/')}/) | "
                   f"{MITRE_NAMES.get(tech, '')} | {count} |")
    out.append("")

    out += ["## Related ISO/IEC 27001:2022 controls", "", "| Detection | Controls |", "|---|---|"]
    for det_id in sorted({a.detection_id for a in alerts}):
        det = detections.get(det_id)
        if det:
            controls = ", ".join(f"{c} {ISO_NAMES.get(c, '')}".strip() for c in split_list(det.meta.get("iso27001", "")))
            out.append(f"| {det_id} {det.meta.get('name', '')} | {controls} |")
    out += ["", "## Analyst notes", "",
            "- _Which alerts are expected (your own simulation, deployment noise) and which are real Internet traffic?_",
            "- _Containment: remove extra role assignments, close the opened port, make the container private, restore logging._",
            "- _Root cause: which Terraform misconfiguration made each step possible? (see posture_check.py report)_", ""]
    return "\n".join(out)


# --------------------------------------------------------------------------- main
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-terraform", action="store_true", help="read the workspace ID from terraform output")
    src.add_argument("--workspace", help="Log Analytics workspace (customer) ID")
    src.add_argument("--from-json", type=Path, metavar="DIR", help="offline: folder of saved query results")
    parser.add_argument("--timespan", default="P1D", help="ISO 8601 duration, e.g. PT4H, P1D (default P1D)")
    parser.add_argument("--attack-log", type=Path, default=ATTACK_LOG, help="ground-truth CSV from simulate.sh")
    parser.add_argument("--out", type=Path, help="write Markdown here")
    args = parser.parse_args()

    detections = load_detections(DETECTIONS_DIR)
    if args.from_json:
        rows = rows_offline(args.from_json)
        source = f"saved results in `{args.from_json}`"
    else:
        workspace = workspace_from_terraform() if args.from_terraform else args.workspace
        rows = rows_live(workspace, args.timespan, detections)
        source = f"Log Analytics workspace `{workspace}` (last {args.timespan})"

    alerts = [to_alert(r) for r in rows]
    report = build_report(alerts, detections, source, load_ground_truth(args.attack_log))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"[+] Report written to {args.out}", file=sys.stderr)
    else:
        print(report)


if __name__ == "__main__":
    main()
