# Incident Report — [INC-2026-001] [Short title, e.g. "Public customer file and privilege escalation in rg-csl-xxxx"]

> Fill every [bracket] with YOUR real data (Sentinel incidents, `simulation/attack_log.csv`,
> `report/incident-summary.md`). 2 pages max. Summary for a manager first, details for an analyst after.

| Field | Value |
|---|---|
| Date | [date] |
| Analyst | [your name] |
| Severity | [High] — [one-line reason] |
| Status | Closed — lab simulation |
| Affected resources | [storage account], [VM], [subscription / resource group] |
| Detected by | Microsoft Sentinel rules [C0x…] |

## 1. Executive summary (5 lines, no jargon)

[What happened, when, what was exposed, how it was contained, what changes now.]

## 2. Timeline (UTC)

| Time | Event | Source |
|---|---|---|
| [hh:mm] | [first SSH attempts from Internet scanners] | Syslog / C01 |
| [hh:mm] | [anonymous download of fake-customer-list.csv] | StorageBlobLogs / C04 |
| [hh:mm] | [role assignment User Access Administrator] | AzureActivity / C02 |
| [hh:mm] | [NSG rule Lab-Open-RDP created] | AzureActivity / C03 |
| [hh:mm] | Incident triaged | Sentinel |
| [hh:mm] | Containment done (cleanup.sh / secure_mode) | — |

## 3. Root cause

| Attack step | Made possible by (misconfiguration) | posture_check rule |
|---|---|---|
| Data download without login | Public container + account allows public access | AZ-STG-01, AZ-STG-04 |
| SSH attempts from the whole Internet | NSG source `*` | AZ-NET-01 |
| Role escalation / firewall change | Over-privileged identities | AZ-IAM-01 |

## 4. Detection coverage

[x / y steps detected — paste the coverage table from incident-summary.md. For each miss: why? (delay, threshold, missing log)]

## 5. Containment, eradication, recovery

- [ ] Role assignment removed  - [ ] RDP rule removed  - [ ] Container made private
- [ ] Logging restored  - [ ] Redeployed in secure mode  - [ ] Re-scan clean (posture-secure.md)

## 6. Lessons learned & recommendations

| # | Finding | Recommendation | ISO 27001 | Priority |
|---|---|---|---|---|
| 1 | [e.g. Terraform allowed public containers] | [Azure Policy "deny public blob access" + posture check in CI] | A.8.9 | High |
| 2 | | | | |
