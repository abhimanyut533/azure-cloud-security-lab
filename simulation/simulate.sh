#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Attack simulation for the Azure Cloud Security Lab.
# Run in Azure Cloud Shell (Bash), from the repo root, AFTER:
#   terraform -chdir=terraform apply    (with secure_mode = false)
#
# LAB ONLY: it acts only on resources this project created in YOUR subscription.
# Every step is logged to simulation/attack_log.csv (your ground truth).
#
# Usage:  bash simulation/simulate.sh            # steps S1-S4
#         bash simulation/simulate.sh --log-tamper   # also S5 (deletes a log setting)
# -----------------------------------------------------------------------------
set -euo pipefail

LOG_TAMPER=false
if [[ "${1:-}" == "--log-tamper" ]]; then LOG_TAMPER=true; fi

TF="terraform -chdir=terraform"
RG=$($TF output -raw resource_group)
VM_IP=$($TF output -raw vm_public_ip)
NSG=$($TF output -raw nsg_name)
BLOB_URL=$($TF output -raw public_blob_url)
SA=$($TF output -raw storage_account)
DIAG=$($TF output -raw blob_diagnostic_setting)
APP_PRINCIPAL=$($TF output -raw app_identity_principal_id)
SUB_ID=$(az account show --query id -o tsv)
LOG_FILE="simulation/attack_log.csv"

echo "Resource group: $RG   VM: $VM_IP"
read -r -p "This simulates attacks on YOUR lab resources only. Type LAB to continue: " CONFIRM
[[ "$CONFIRM" == "LAB" ]] || { echo "Cancelled."; exit 1; }

[[ -f "$LOG_FILE" ]] || echo "time_utc,step,mitre,description" > "$LOG_FILE"
step() {
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$1,$2,$3" >> "$LOG_FILE"
  echo ">>> [$1] $2  $3"
}

# S1 ---------------------------------------------------------------- brute force
step S1 "T1110.001" "20 SSH logins with invalid user names against the VM"
for i in $(seq 1 20); do
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 "fakeuser${i}@${VM_IP}" exit >/dev/null 2>&1 || true
done

# S2 ---------------------------------------------------------------- data exposure
step S2 "T1530" "Download the fake customer file without logging in (5 times)"
for i in $(seq 1 5); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$BLOB_URL")
  echo "    anonymous GET -> HTTP $code"
done

# S3 ---------------------------------------------------------------- privilege escalation
step S3 "T1098.003" "Give the app identity User Access Administrator on the resource group"
az role assignment create \
  --assignee-object-id "$APP_PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role "User Access Administrator" \
  --scope "/subscriptions/${SUB_ID}/resourceGroups/${RG}" -o none

# S4 ---------------------------------------------------------------- firewall change
step S4 "T1562.007" "Open RDP (3389) to the whole Internet on the NSG"
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n "Lab-Open-RDP" \
  --priority 200 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes '*' --destination-port-ranges 3389 -o none

# S5 ---------------------------------------------------------------- log tampering (optional)
if $LOG_TAMPER; then
  step S5 "T1562.008" "Delete the blob diagnostic setting (stops storage logging)"
  az monitor diagnostic-settings delete --name "$DIAG" \
    --resource "/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.Storage/storageAccounts/${SA}/blobServices/default"
  echo "    Logging is now OFF for storage. Restore it with: terraform -chdir=terraform apply"
fi

echo
echo "Done. Ground truth: $LOG_FILE"
echo "Logs take 5-20 minutes to reach Sentinel. Then run: python3 scripts/incident_report.py --from-terraform"
echo "Clean up afterwards: bash simulation/cleanup.sh"
