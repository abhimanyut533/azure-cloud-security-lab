# Cost and safety rules

## Cost

- The lab is small (1 small VM, 1 public IP, 1 storage account, 1 Log Analytics workspace with Sentinel).
- The workspace has a **daily ingestion cap** (`log_daily_cap_gb = 0.5`) so logs cannot run up a big bill.
- Check current prices yourself in the Azure Pricing Calculator: Sentinel and Log Analytics charge per GB ingested;
  new workspaces may get a free trial period for Sentinel — check the Sentinel pricing page.
- **Destroy after every session:** `terraform -chdir=terraform destroy`. Re-creating takes ~10 minutes.
- Set a budget alert (docs/01-setup.md step 2) and look at **Cost Management → Cost analysis** once a week.

## Safety

- The VM accepts **SSH keys only** — no password — even in insecure mode. Internet scanners will fail, but you
  will see their attempts. Do not change `disable_password_authentication`.
- The storage file is **fake** data. Never put real personal data in this lab.
- In insecure mode the app identity is Contributor on your subscription. Nothing on the VM uses it, but
  **destroy the lab when you are not using it.**
- Never commit `terraform.tfvars`, `*.tfstate`, `tfplan`, `plan_*.json` or keys to GitHub (`.gitignore` blocks them).
  Terraform state can contain secrets.
- The simulation only targets resources created by this project. Testing systems you do not own or have no written
  permission to test is illegal (France: Code pénal, art. 323-1).
