# 01 — Setup (Day 1)

Everything runs in **Azure Cloud Shell** in your browser: Terraform, the Azure CLI, Python, ssh, curl
and git are already installed there. Nothing to install on your PC.

## 1. Get Azure for Students (free, no credit card)

1. Go to the Azure for Students page (azure.microsoft.com → Free account → Students).
2. Sign up with your **school email** (@edu.ece.fr). Verify it.
3. You get $100 of credit for 12 months plus free services. One account per person.

> If your school email is refused, ask ECE IT whether the school is registered, or use the standard
> Azure free account (it asks for a card for identity check only).

## 2. Set a cost alert now (2 minutes)

Portal → **Cost Management → Budgets → Add** → amount €20 → email alert at 50% and 90%.
(If budgets are not available on your offer, check **Cost Management → Cost analysis** after each session.)

## 3. Open Cloud Shell

Portal → the `>_` icon at the top → **Bash**. If asked about storage, choose **"No storage account required"**
(ephemeral session) or create the small storage it proposes. With ephemeral sessions, files disappear when
the session ends — keep your work in GitHub.

## 4. Register the services this lab uses (one time)

```bash
for p in Microsoft.OperationalInsights Microsoft.OperationsManagement Microsoft.SecurityInsights \
         Microsoft.Insights Microsoft.Storage Microsoft.Network Microsoft.Compute Microsoft.ManagedIdentity; do
  az provider register --namespace "$p"
done
az provider show -n Microsoft.SecurityInsights --query registrationState -o tsv   # wait for "Registered"
```

## 5. Get the project into Cloud Shell

Push this folder to your GitHub first (recommended), then:

```bash
git clone https://github.com/<your-username>/azure-cloud-security-lab.git
cd azure-cloud-security-lab
```

(Or upload the zip with the Cloud Shell **Manage files → Upload** button and `unzip` it.)

## 6. SSH key and subscription

```bash
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519      # skip if you already have one
export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
echo "export ARM_SUBSCRIPTION_ID=$ARM_SUBSCRIPTION_ID" >> ~/.bashrc
```

## 7. First check

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
terraform -chdir=terraform init
terraform -chdir=terraform validate
python3 -m unittest discover -s tests -v
```

✅ **Done when** `terraform validate` says *Success* and the 8 tests pass.
Write any error you hit (and the fix) in `docs/notes.md`.

### Common problems

| Problem | Fix |
|---|---|
| `RequestDisallowedByPolicy` / region not allowed | Student subscriptions limit regions. Set `location = "westeurope"` or `"swedencentral"` in `terraform.tfvars`. |
| `SkuNotAvailable` for the VM | Set `vm_size = "Standard_B2ats_v2"` (or another small B-series size). |
| `MissingSubscriptionRegistration` | Run step 4 again and wait until "Registered". |
| `subscription ID could not be determined` | Run the `export ARM_SUBSCRIPTION_ID=...` line again. |
