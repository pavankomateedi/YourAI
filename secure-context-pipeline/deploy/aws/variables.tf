variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  type    = string
  default = "secure-context-pipeline"
}

variable "image_tag" {
  type    = string
  default = "2.0.0"
}

variable "desired_count" {
  type        = number
  default     = 1
  description = "Keep at 1 with the sqlite vault (per-task in-memory keys). Use postgres + a shared backend before scaling out."
}

# --- Non-secret config (becomes task env) ---
variable "llm_model" {
  type    = string
  default = "claude-3-5-sonnet-20241022"
}

variable "vault_backend" {
  type    = string
  default = "sqlite" # set "postgres" and provide database_url for HA
}

variable "key_wrapping" {
  type    = string
  default = "none" # "local" (with scp_kek) or "kms" (with kms_key_id)
}

# --- Secrets (sensitive; written to AWS Secrets Manager) ---
variable "service_api_key" {
  type      = string
  sensitive = true
}

variable "store_encryption_key_b64" {
  type        = string
  sensitive   = true
  description = "base64 of the 32-byte master key (wrapped if key_wrapping != none). Generate with scripts/gen_keys.py."
}

variable "anthropic_api_key" {
  type      = string
  sensitive = true
  default   = "" # empty -> service uses the offline mock
}

variable "scp_kek" {
  type      = string
  sensitive = true
  default   = "" # base64 KEK when key_wrapping = local
}

variable "database_url" {
  type      = string
  sensitive = true
  default   = "" # postgres DSN when vault_backend = postgres
}
