output "mode" {
  value = var.secure_mode ? "SECURE" : "INSECURE (deliberately misconfigured)"
}

output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "vm_public_ip" {
  value = azurerm_public_ip.vm.ip_address
}

output "ssh_command" {
  value = "ssh ${var.admin_username}@${azurerm_public_ip.vm.ip_address}"
}

output "nsg_name" {
  value = azurerm_network_security_group.vm.name
}

output "storage_account" {
  value = azurerm_storage_account.data.name
}

output "public_blob_url" {
  description = "Readable without login only in insecure mode."
  value       = "${azurerm_storage_account.data.primary_blob_endpoint}${azurerm_storage_container.reports.name}/${azurerm_storage_blob.fake_customers.name}"
}

output "blob_diagnostic_setting" {
  value = azurerm_monitor_diagnostic_setting.blob.name
}

output "app_identity_principal_id" {
  value = azurerm_user_assigned_identity.app.principal_id
}

output "workspace_name" {
  value = azurerm_log_analytics_workspace.law.name
}

output "workspace_customer_id" {
  description = "GUID used by: az monitor log-analytics query -w <this>"
  value       = azurerm_log_analytics_workspace.law.workspace_id
}
