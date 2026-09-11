variable "aws_region" {
  type        = string
  default     = "ap-southeast-2"
  description = "Region for the isolated demo and scanner."
}

variable "project_name" {
  type        = string
  default     = "security-drift-demo"
  description = "Short prefix for disposable demo resources."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}$", var.project_name))
    error_message = "Use 3-25 lowercase letters, digits or hyphens, starting with a letter."
  }
}

variable "trusted_admin_cidr" {
  type        = string
  default     = null
  nullable    = true
  description = "Optional narrow IPv4 SSH source (/24 to /32). Null means no SSH rule."
  validation {
    condition = var.trusted_admin_cidr == null ? true : (
      can(cidrnetmask(var.trusted_admin_cidr)) &&
      try(tonumber(split("/", var.trusted_admin_cidr)[1]) >= 24, false)
    )
    error_message = "Use a valid narrow IPv4 CIDR (/24 to /32), or null. Public SSH is not a baseline option."
  }
}

variable "allow_public_https" {
  type        = bool
  default     = false
  description = "Explicitly allow expected TCP/443 IPv4 ingress; no service is deployed."
}

variable "enable_cloudtrail" {
  type        = bool
  default     = false
  description = "Enable optional event-history enrichment and include LookupEvents in scanner policy. Creates no trail or log bucket."
}
