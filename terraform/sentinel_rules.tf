# ----------------------------------------------------------------------------
# Detection-as-code: every ../detections/*.kql file becomes a Sentinel
# scheduled analytics rule. Metadata comes from the "// key: value" header
# lines at the top of each file (id, name, severity, tactics, techniques...).
# ----------------------------------------------------------------------------
locals {
  detection_files = fileset("${path.module}/../detections", "*.kql")

  detections = {
    for f in local.detection_files :
    trimsuffix(f, ".kql") => {
      query = file("${path.module}/../detections/${f}")
      meta = {
        for m in regexall("(?m)^// *([a-z0-9_]+): *(.+?) *$", file("${path.module}/../detections/${f}")) :
        m[0] => m[1]
      }
    }
  }
}

resource "azurerm_sentinel_alert_rule_scheduled" "detections" {
  # Turned on in a second apply, once logs are flowing (see docs/02-run-the-lab.md)
  for_each = var.enable_sentinel_rules ? local.detections : {}

  name                       = each.key
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = "${each.value.meta["id"]} ${each.value.meta["name"]}"
  description                = each.value.meta["description"]
  severity                   = each.value.meta["severity"]
  query                      = each.value.query
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = split(",", replace(each.value.meta["tactics"], " ", ""))
  techniques                 = split(",", replace(each.value.meta["techniques"], " ", ""))
  enabled                    = true
}
