###############################################################################
# Azure Cloud Security Lab
#
# secure_mode = false  -> deploys a deliberately MISCONFIGURED environment
# secure_mode = true   -> deploys the same environment, HARDENED
#
# Run it only in your own Azure for Students subscription. Destroy it after
# each session:  terraform destroy
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.9"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# Subscription comes from the ARM_SUBSCRIPTION_ID environment variable
# (see docs/01-setup.md).
provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

data "azurerm_subscription" "current" {}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

locals {
  insecure = !var.secure_mode
  name     = "${var.prefix}-${random_string.suffix.result}"
  tags = {
    project = "azure-cloud-security-lab"
    mode    = var.secure_mode ? "secure" : "insecure"
    owner   = "student-lab"
  }
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

# ----------------------------------------------------------------------------
# Logging: Log Analytics workspace + Microsoft Sentinel
# ----------------------------------------------------------------------------
resource "azurerm_log_analytics_workspace" "law" {
  name                = "law-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  daily_quota_gb      = var.log_daily_cap_gb # cost protection
  tags                = local.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.law.id
}

# Subscription Activity Log (who changed what) -> workspace (table: AzureActivity)
resource "azurerm_monitor_diagnostic_setting" "activity" {
  name                       = "diag-activity-${local.name}"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Policy"
  }
}
