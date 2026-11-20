# ----------------------------------------------------------------------------
# Storage account with a container holding FAKE "customer" data
# Insecure: anonymous public read access is allowed on the container.
# ----------------------------------------------------------------------------
resource "azurerm_storage_account" "data" {
  name                     = "${var.prefix}data${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = azurerm_resource_group.lab.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = local.insecure # MISCONFIG when true
  shared_access_key_enabled       = true

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }

  tags = local.tags
}

resource "azurerm_storage_container" "reports" {
  name                  = "reports"
  storage_account_id    = azurerm_storage_account.data.id
  container_access_type = local.insecure ? "blob" : "private" # MISCONFIG when "blob"
}

resource "azurerm_storage_blob" "fake_customers" {
  name                   = "fake-customer-list.csv"
  storage_account_name   = azurerm_storage_account.data.name
  storage_container_name = azurerm_storage_container.reports.name
  type                   = "Block"
  content_type           = "text/csv"
  source_content         = <<-CSV
    id,name,email,note
    1,Test Person A,a@example.invalid,FAKE DATA FOR A SECURITY LAB
    2,Test Person B,b@example.invalid,FAKE DATA FOR A SECURITY LAB
  CSV
}

# Blob access logs -> workspace (table: StorageBlobLogs)
resource "azurerm_monitor_diagnostic_setting" "blob" {
  name                       = "diag-blob-${local.name}"
  target_resource_id         = "${azurerm_storage_account.data.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }
}
