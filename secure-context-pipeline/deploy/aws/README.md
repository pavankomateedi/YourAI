# Launch on AWS (ECS Fargate)

Provisions ECR, an ECS Fargate service behind an ALB, CloudWatch logs, IAM, and
Secrets Manager — no cluster to pre-create. Synthetic-data launch by default.

## Prerequisites (yours)
- AWS account + credentials configured (`aws sts get-caller-identity` works)
- Terraform >= 1.5, Docker, and the AWS CLI installed
- A default VPC in the chosen region (most accounts have one)

## One-time: generate the master key + service key

```bash
# 32-byte master key as base64 (raw, since KEY_WRAPPING defaults to none):
python - <<'PY'
import os, base64; print(base64.b64encode(os.urandom(32)).decode())
PY
# Pick a strong SERVICE_API_KEY (any long random string).
```

(To wrap the master key under a KEK instead: `KEK=$(python scripts/gen_keys.py kek)`,
set `key_wrapping=local`, pass `scp_kek=$KEK`, and base64 the wrapped key.)

## Launch (the command you run)

```bash
cd deploy/aws
terraform init
terraform apply \
  -var="region=us-east-1" \
  -var="service_api_key=YOUR_LONG_RANDOM_KEY" \
  -var="store_encryption_key_b64=BASE64_MASTER_KEY" \
  -var="anthropic_api_key=sk-ant-...     # optional; omit for offline mock"

# Push the image into the ECR repo Terraform just created:
ECR_URL=$(terraform output -raw ecr_repository_url)
REGION=us-east-1 TAG=2.0.0 ../../deploy/aws/push_image.sh

# Get the public URL once the service is healthy (~1-2 min):
terraform output -raw service_url
curl "$(terraform output -raw service_url)/health"
```

## Notes
- **Synthetic data only** for this default launch. Before real PHI: switch
  `vault_backend=postgres` (+ an RDS `database_url`), enable `key_wrapping=kms`,
  validate recall on a real corpus, add TLS at the ALB, and complete a security
  review + provider BAA.
- `desired_count` stays at 1 because the sqlite vault keeps session keys in-process;
  scaling out requires the postgres backend and shared key management.
- Tear down with `terraform destroy`.
