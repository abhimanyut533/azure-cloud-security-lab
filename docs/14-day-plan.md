# 14-day plan (about 2–3 hours a day)

Each day ends with something you can show. Tick the boxes as you go.

## Week 1 — Build, break, watch

- [ ] **Day 1** — Azure for Students, budget alert, Cloud Shell, providers, SSH key. `terraform validate` + tests pass. ([01-setup](01-setup.md))
- [ ] **Day 2** — Read every `.tf` file and write one line per resource in `docs/notes.md` ("what it is, why it's insecure"). Phase A: posture scan + Checkov on the insecure plan. 📸
- [ ] **Day 3** — Phase B: deploy. Prove the data exposure with `curl`. Check the 3 log tables fill up. Count real SSH scanners. 📸
- [ ] **Day 4** — Phase C + D: enable Sentinel rules, run `simulate.sh`. Keep `attack_log.csv`.
- [ ] **Day 5** — Phase E: find each attack step by hand in **Logs** with your own KQL before looking at the rules.
- [ ] **Day 6** — Check every rule fired. Fix the ones that didn't. Write each fix in `docs/notes.md` (real detection-engineering lessons).
- [ ] **Day 7** — `incident_report.py` → coverage report. Fill in the incident report template with your real timeline. **Destroy the lab.**

## Week 2 — Fix, prove, show

- [ ] **Day 8** — Phase F: secure mode. Before/after posture reports. Re-run the simulation; record what is now blocked. 📸
- [ ] **Day 9** — Add **one rule of your own** to `posture_check.py` (ideas: VM without managed disk encryption setting, storage without soft delete, NSG allowing all ports) **with a unit test**. This is your code to talk about in interviews.
- [ ] **Day 10** — Add **one detection of your own** (`C06_*.kql`), e.g. *storage account keys listed* (`MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION`). Deploy it with Terraform and trigger it.
- [ ] **Day 11** — GRC: complete [`../grc/control-mapping.md`](../grc/control-mapping.md) with the exact CIS benchmark IDs from the version you download, and the risk register.
- [ ] **Day 12** — Optional: GitHub Actions workflow that runs the unit tests and `posture_check.py --fail-on high` on every push.
- [ ] **Day 13** — README: results tables, screenshots, "What I learned". Push to GitHub. Double-check no state/tfvars/keys are committed.
- [ ] **Day 14** — 2-minute demo video (architecture → public data exposed → attack → Sentinel incident → fix → re-scan clean). LinkedIn post. Add to CV. **Destroy the lab.**

## CV line (only what you actually did)

> **Azure Cloud Security Lab (personal project, 2026)** — Deployed insecure and hardened Azure environments with
> Terraform; built a Python policy-as-code checker for Terraform plans (and compared it with Checkov); collected
> Activity, storage and VM auth logs into Microsoft Sentinel and wrote 5 KQL analytics rules deployed as code,
> mapped to MITRE ATT&CK; simulated cloud attacks (SSH brute force, public blob exfiltration, role escalation,
> firewall and logging tampering) and measured detection coverage; mapped controls to the CIS Azure Benchmark and
> ISO/IEC 27001:2022. GitHub: <link>

## Certifications to pair with it

AZ-900 (Azure Fundamentals) → SC-900 (Security, Compliance & Identity Fundamentals) → AZ-500 (Azure Security
Engineer). Microsoft Learn has free learning paths for all three.
