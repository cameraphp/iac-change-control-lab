# Provider-free, resource-free sample module.
# It exists only as the target of the optional `terraform fmt -check` in
# scripts/terraform-safe-check.ps1. It declares no providers, backends or managed objects, so
# nothing here can reach any infrastructure.

terraform {
  required_version = ">= 1.6.0"
}

locals {
  lab_notice = "synthetic sample for formatting checks only"
}

output "lab_notice" {
  value = local.lab_notice
}
