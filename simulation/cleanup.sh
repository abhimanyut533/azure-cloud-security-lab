#!/usr/bin/env bash
# Removes what simulate.sh added (the role assignment and the RDP rule).
# Everything else is removed by: terraform -chdir=terraform destroy
set -uo pipefail

TF="terraform -chdir=terraform"
RG=$($TF output -raw resource_group)
NSG=$($TF output -raw nsg_name)
APP_PRINCIPAL=$($TF output -raw app_identity_principal_id)
SUB_ID=$(az account show --query id -o tsv)

echo "Removing the User Access Administrator assignment..."
az role assignment delete --assignee "$APP_PRINCIPAL" --role "User Access Administrator" \
  --scope "/subscriptions/${SUB_ID}/resourceGroups/${RG}" 2>/dev/null || true

echo "Removing the Lab-Open-RDP rule..."
az network nsg rule delete -g "$RG" --nsg-name "$NSG" -n "Lab-Open-RDP" 2>/dev/null || true

echo "Re-applying Terraform to restore anything else (e.g. the blob diagnostic setting)..."
$TF apply -auto-approve

echo "Clean-up done."
