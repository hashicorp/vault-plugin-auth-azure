# Copyright IBM Corp. 2018, 2025
# SPDX-License-Identifier: MPL-2.0

variable "project" {
  type = string
  description = "Vault Azure auth method test with Azure Function"
  default     = "vlt-auth-func"
}

variable "env" {
  type    = string
  default = "test"
}

variable "region" {
  type        = string
  description = "The region to create Azure resources in"
  default     = "westus2"
}
