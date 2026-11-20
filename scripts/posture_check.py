#!/usr/bin/env python3
"""
posture_check.py - find security misconfigurations in an Azure Terraform plan/state
BEFORE (or after) it is deployed. A small, readable "policy-as-code" checker.

Input: the JSON from Terraform
    terraform -chdir=terraform plan -out tfplan
    terraform -chdir=terraform show -json tfplan > plan.json      # planned resources
or  terraform -chdir=terraform show -json > state.json            # deployed resources

Usage:
    python3 scripts/posture_check.py plan.json
    python3 scripts/posture_check.py plan.json --format json
    python3 scripts/posture_check.py plan.json --fail-on high      # exit 1 if any High finding (for CI)

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

ANY_SOURCE = {"*", "0.0.0.0/0", "0.0.0.0", "internet", "any", "::/0"}
MGMT_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM-HTTPS"}
PRIVILEGED_ROLES = {"owner", "contributor", "user access administrator"}
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}
SUBSCRIPTION_SCOPE = re.compile(r"^/subscriptions/[^/]+/?$", re.IGNORECASE)


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    resource: str
    evidence: str
    fix: str
    benchmark: str
    iso27001: str


# --------------------------------------------------------------------------- loading
def load_resources(doc: dict) -> list[dict]:
    """Return every resource from a plan (planned_values) or state (values), modules included."""
    root = (doc.get("planned_values") or doc.get("values") or {}).get("root_module", {})
    resources: list[dict] = []

    def walk(module: dict) -> None:
        resources.extend(r for r in module.get("resources", []) if r.get("mode", "managed") == "managed")
        for child in module.get("child_modules", []):
            walk(child)

    walk(root)
    return resources


# --------------------------------------------------------------------------- helpers
def port_matches(port_spec, wanted: int) -> bool:
    """True if a port spec like '22', '20-25' or '*' includes the wanted port."""
    if port_spec is None:
        return False
    spec = str(port_spec).strip()
    if spec == "*":
        return True
    if "-" in spec:
        low, high = spec.split("-", 1)
        return low.isdigit() and high.isdigit() and int(low) <= wanted <= int(high)
    return spec.isdigit() and int(spec) == wanted


def as_list(*values) -> list:
    out: list = []
    for value in values:
        if value is None or value == "":
            continue
        out.extend(value if isinstance(value, list) else [value])
    return out


def check_rule_dict(rule: dict, address: str) -> list[Finding]:
    """Check one NSG rule (standalone resource or inline security_rule block)."""
    if str(rule.get("direction", "")).lower() != "inbound" or str(rule.get("access", "")).lower() != "allow":
        return []
    sources = [str(s).lower() for s in as_list(rule.get("source_address_prefix"), rule.get("source_address_prefixes"))]
    if not any(s in ANY_SOURCE for s in sources):
        return []
    ports = as_list(rule.get("destination_port_range"), rule.get("destination_port_ranges"))
    exposed = sorted({name for p in ports for port, name in MGMT_PORTS.items() if port_matches(p, port)})
    if not exposed:
        return []
    return [Finding(
        rule="AZ-NET-01", severity="high",
        title="Management port open to the whole Internet",
        resource=address,
        evidence=f"rule '{rule.get('name')}' allows {', '.join(exposed)} from {', '.join(sources)}",
        fix="Restrict source to your own IP (/32), or use Azure Bastion / Just-In-Time VM access.",
        benchmark="CIS Azure Foundations: Networking - restrict SSH/RDP from the Internet",
        iso27001="A.8.20 Networks security, A.8.22 Segregation of networks",
    )]


# --------------------------------------------------------------------------- checks
def check(resources: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    has_subscription_activity_log = False
    workspace_present = False

    for res in resources:
        rtype, addr, v = res.get("type"), res.get("address", "?"), res.get("values") or {}

        if rtype == "azurerm_storage_account":
            if v.get("allow_nested_items_to_be_public") is True:
                findings.append(Finding(
                    "AZ-STG-01", "high", "Storage account allows public (anonymous) blob access", addr,
                    "allow_nested_items_to_be_public = true",
                    "Set allow_nested_items_to_be_public = false.",
                    "CIS Azure Foundations: Storage Accounts - disable anonymous blob access",
                    "A.5.15 Access control, A.8.3 Information access restriction"))
            if v.get("https_traffic_only_enabled") is False:
                findings.append(Finding(
                    "AZ-STG-02", "medium", "Storage account accepts unencrypted HTTP", addr,
                    "https_traffic_only_enabled = false", "Set https_traffic_only_enabled = true.",
                    "CIS Azure Foundations: Storage Accounts - secure transfer required",
                    "A.8.24 Use of cryptography"))
            tls = v.get("min_tls_version")
            if tls and tls != "TLS1_2" and tls != "TLS1_3":
                findings.append(Finding(
                    "AZ-STG-03", "medium", "Storage account allows old TLS versions", addr,
                    f"min_tls_version = {tls}", "Set min_tls_version = \"TLS1_2\".",
                    "CIS Azure Foundations: Storage Accounts - minimum TLS 1.2",
                    "A.8.24 Use of cryptography"))

        elif rtype == "azurerm_storage_container":
            access = str(v.get("container_access_type", "private")).lower()
            if access in ("blob", "container"):
                findings.append(Finding(
                    "AZ-STG-04", "high", "Blob container is publicly readable", addr,
                    f"container_access_type = {access}", "Set container_access_type = \"private\".",
                    "CIS Azure Foundations: Storage Accounts - no public containers",
                    "A.5.15 Access control, A.8.12 Data leakage prevention"))

        elif rtype == "azurerm_network_security_rule":
            findings.extend(check_rule_dict(v, addr))

        elif rtype == "azurerm_network_security_group":
            for inline in v.get("security_rule") or []:
                findings.extend(check_rule_dict(inline, addr))

        elif rtype in ("azurerm_linux_virtual_machine",):
            if v.get("disable_password_authentication") is False:
                findings.append(Finding(
                    "AZ-VM-01", "high", "VM allows SSH password login", addr,
                    "disable_password_authentication = false",
                    "Use SSH keys only: disable_password_authentication = true.",
                    "CIS Azure Foundations: Virtual Machines - use SSH keys",
                    "A.8.5 Secure authentication"))

        elif rtype == "azurerm_role_assignment":
            role = str(v.get("role_definition_name") or "").lower()
            scope = v.get("scope")
            if role in PRIVILEGED_ROLES:
                at_subscription = bool(scope) and bool(SUBSCRIPTION_SCOPE.match(str(scope)))
                findings.append(Finding(
                    "AZ-IAM-01", "high" if at_subscription else "medium",
                    "Privileged role assigned" + (" on the whole subscription" if at_subscription else ""), addr,
                    f"role = {v.get('role_definition_name')}, scope = {scope or '(known after apply)'}",
                    "Least privilege: give the narrowest role (e.g. Reader, or a custom role) on the smallest scope.",
                    "CIS Azure Foundations: Identity - least privilege for identities",
                    "A.8.2 Privileged access rights, A.5.15 Access control, A.5.18 Access rights"))

        elif rtype == "azurerm_monitor_diagnostic_setting":
            target = v.get("target_resource_id")
            if target and SUBSCRIPTION_SCOPE.match(str(target)):
                has_subscription_activity_log = True

        elif rtype == "azurerm_log_analytics_workspace":
            workspace_present = True
            if (v.get("retention_in_days") or 30) < 30:
                findings.append(Finding(
                    "AZ-LOG-02", "low", "Log retention shorter than 30 days", addr,
                    f"retention_in_days = {v.get('retention_in_days')}", "Keep logs at least 30 days (often 90+).",
                    "CIS Azure Foundations: Logging and Monitoring - log retention",
                    "A.8.15 Logging"))

    if workspace_present and not has_subscription_activity_log:
        findings.append(Finding(
            "AZ-LOG-01", "medium", "Subscription Activity Log is not sent to the workspace", "(subscription)",
            "no azurerm_monitor_diagnostic_setting with a /subscriptions/<id> target",
            "Add a diagnostic setting on the subscription (Administrative, Security, Policy categories).",
            "CIS Azure Foundations: Logging and Monitoring - export Activity Log",
            "A.8.15 Logging, A.8.16 Monitoring activities"))

    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.rule, f.resource))
    return findings


# --------------------------------------------------------------------------- output
def to_markdown(findings: list[Finding], source: str, resource_count: int) -> str:
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("high", "medium", "low")}
    lines = [
        "# Azure posture check",
        "",
        f"_Source: `{source}` · {resource_count} resources checked_",
        "",
        f"**Findings: {len(findings)}** — {counts['high']} high, {counts['medium']} medium, {counts['low']} low",
        "",
    ]
    if not findings:
        lines.append("✅ No misconfigurations found by these rules.")
        return "\n".join(lines) + "\n"
    lines += ["| Rule | Severity | Finding | Resource | Evidence |", "|---|---|---|---|---|"]
    for f in findings:
        lines.append(f"| {f.rule} | {f.severity.upper()} | {f.title} | `{f.resource}` | {f.evidence} |")
    lines += ["", "## How to fix", ""]
    for f in findings:
        lines.append(f"- **{f.rule} {f.title}** (`{f.resource}`): {f.fix}  ")
        lines.append(f"  _Benchmark:_ {f.benchmark} · _ISO 27001:2022:_ {f.iso27001}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("plan_json", type=Path, help="output of: terraform show -json [tfplan]")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--out", type=Path, help="write the report to this file")
    parser.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="never",
                        help="exit with code 1 if a finding of this severity or worse exists")
    args = parser.parse_args()

    doc = json.loads(args.plan_json.read_text(encoding="utf-8"))
    resources = load_resources(doc)
    if not resources:
        print("No resources found. Is this the output of 'terraform show -json'?", file=sys.stderr)
        return 2
    findings = check(resources)

    if args.format == "json":
        report = json.dumps([asdict(f) for f in findings], indent=2)
    else:
        report = to_markdown(findings, str(args.plan_json), len(resources))

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"[+] {len(findings)} finding(s) written to {args.out}", file=sys.stderr)
    else:
        print(report)

    if args.fail_on != "never":
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
