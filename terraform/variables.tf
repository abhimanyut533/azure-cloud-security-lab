variable "secure_mode" {
  description = "false = deploy the deliberately misconfigured lab; true = deploy the hardened version."
  type        = bool
  default     = false
}

variable "prefix" {
  description = "Short lowercase prefix for resource names (letters/numbers only, max 6)."
  type        = string
  default     = "csl"
  validation {
    condition     = can(regex("^[a-z0-9]{2,6}$", var.prefix))
    error_message = "prefix must be 2-6 lowercase letters or digits."
  }
}

variable "location" {
  description = "Azure region. If your student subscription refuses it, try westeurope or swedencentral."
  type        = string
  default     = "francecentral"
}

variable "vm_size" {
  description = "VM size. Standard_B1s is in the 12-month free services for new accounts; if unavailable try Standard_B2ats_v2."
  type        = string
  default     = "Standard_B1s"
}

variable "admin_username" {
  type    = string
  default = "labadmin"
}

variable "ssh_public_key_path" {
  description = "Path to your SSH public key (create one with: ssh-keygen -t ed25519)."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "admin_ip" {
  description = "Your public IP in CIDR form (x.x.x.x/32). Required when secure_mode = true."
  type        = string
  default     = ""
}

variable "log_daily_cap_gb" {
  description = "Daily ingestion cap for the Log Analytics workspace (cost protection)."
  type        = number
  default     = 0.5
}

variable "enable_sentinel_rules" {
  description = "Create the Sentinel analytics rules from ../detections. Turn on after logs have started arriving (Sentinel checks that each table exists)."
  type        = bool
  default     = false
}
