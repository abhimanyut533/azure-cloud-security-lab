# 02 — Run the lab

Run everything from the repo root in Cloud Shell. Take screenshots at every 📸.

> ⚠️ Only run this in your own subscription. Destroy the lab at the end of every session
> (`terraform -chdir=terraform destroy`) so it does not use your credit.

---

## Phase A — Scan the insecure design BEFORE deploying (Day 2)

```bash
terraform -chdir=terraform plan -out tfplan            # secure_mode = false in terraform.tfvars
terraform -chdir=terraform show -json tfplan > plan_insecure.json
python3 scripts/posture_check.py plan_insecure.json --out report/posture-insecure.md
pip install --user checkov && ~/.local/bin/checkov -d terraform --compact > report/checkov-insecure.txt
```

📸 the posture report. Compare: which problems did **your** tool find that Checkov missed, and the reverse?
(Checkov reads the code without evaluating `secure_mode`, so it reports some things differently — explain why
in your README: that is a good interview talking point.)

## Phase B — Deploy the insecure lab (Day 3)

```bash
terraform -chdir=terraform apply tfplan
terraform -chdir=terraform output
```

Check it works:

```bash
ssh labadmin@$(terraform -chdir=terraform output -raw vm_public_ip) "hostname"   # your key works
curl -s "$(terraform -chdir=terraform output -raw public_blob_url)"                # fake data readable by anyone ⚠️
```

📸 the `curl` output: this is the data exposure.

Wait ~20 minutes, then check logs arrive (Portal → your Log Analytics workspace → **Logs**):

```kql
AzureActivity | summarize count() by OperationNameValue | top 10 by count_
Syslog | where Facility in ("auth","authpriv") | take 20
StorageBlobLogs | take 20
```

> Even before you attack anything, you will probably see **real Internet scanners** trying SSH in `Syslog`.
> Count them: `Syslog | where SyslogMessage has "Invalid user" | extend ip=extract(@"(\d+\.\d+\.\d+\.\d+)",1,SyslogMessage) | summarize count() by ip | order by count_ desc`
> 📸 — this is a great slide for your demo.

## Phase C — Turn on the Sentinel rules (detection-as-code)

In `terraform/terraform.tfvars` set `enable_sentinel_rules = true`, then:

```bash
terraform -chdir=terraform apply
```

Portal → **Microsoft Sentinel → Analytics**: you should see the 5 rules C01–C05. 📸

## Phase D — Simulate the attacks (Day 4)

```bash
bash simulation/simulate.sh               # S1–S4
# bash simulation/simulate.sh --log-tamper   # also S5 (then cleanup.sh restores logging)
```

Keep `simulation/attack_log.csv` — it is your ground truth. Logs take 5–20 minutes to arrive.

## Phase E — Detect and report (Days 5–7)

1. Portal → **Sentinel → Incidents**: open each incident, read the evidence. 📸
2. Run each `.kql` file by hand in **Logs** to understand it. If a rule does not fire, debug it
   (field names, time window, ingestion delay) and write the fix in `docs/notes.md`.
3. Generate the report:

```bash
python3 scripts/incident_report.py --from-terraform --timespan P1D --out report/incident-summary.md
```

It shows **detection coverage**: which simulated steps were caught. Fill `report/incident-report-template.md`
with your real timeline.

## Phase F — Fix and re-scan (Days 8–9)

```bash
bash simulation/cleanup.sh
curl -s ifconfig.me    # your IP
```

In `terraform.tfvars`: `secure_mode = true` and `admin_ip = "<your-ip>/32"` (the Cloud Shell IP changes between
sessions — if SSH stops working, update it).

```bash
terraform -chdir=terraform plan -out tfplan
terraform -chdir=terraform show -json tfplan > plan_secure.json
python3 scripts/posture_check.py plan_secure.json --out report/posture-secure.md
terraform -chdir=terraform apply tfplan
curl -s -o /dev/null -w "%{http_code}\n" "$(terraform -chdir=terraform output -raw public_blob_url)"   # now 404/409, not 200
```

📸 the before/after posture reports and the failed `curl`. Run `simulate.sh` again: S2 (anonymous read) should now
fail. Note which detections still fire (C02/C03 detect *actions*, so they still alert — that is expected).

## Phase G — Destroy

```bash
terraform -chdir=terraform destroy
```

Check the portal: the `rg-csl-…` resource group is gone.
