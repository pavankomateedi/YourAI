# Deployment

## Production entrypoint

The service is ASGI. In production run it under gunicorn with uvicorn workers:

```bash
pip install -e .[api]
gunicorn secure_context_pipeline.api.app:app \
  -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 --workers 4 --timeout 60
```

## Required production configuration

| Variable | Why |
|---|---|
| `SCP_ENV=production` | Fails closed if no persistent master key is configured |
| `STORE_ENCRYPTION_KEY_PATH` | Persistent document-store master key (mount as a secret) |
| `KEY_WRAPPING=local` + `SCP_KEK` | Envelope-encrypt the master key under a KEK (or `kms` + `KMS_KEY_ID` with `boto3`) |
| `SERVICE_API_KEY` | Enforces the `X-API-Key` header on all non-health routes |
| `VAULT_BACKEND=postgres` + `DATABASE_URL` | Use the HA Postgres vault instead of SQLite |
| `ANTHROPIC_API_KEY` | Live Claude calls (offline mock if absent) |

## Kubernetes

`deploy/k8s.yaml` provides a Deployment (2 replicas, gunicorn/uvicorn, health
probes, non-root), a Service, a ConfigMap, and a Secret stub. Fill secrets from
your secret manager (never commit real values), build/push the image, set the
`image:` field, then `kubectl apply -f deploy/k8s.yaml`.

## Checklist before going live

- [ ] `SCP_ENV=production` and a persistent, KEK/KMS-wrapped master key mounted
- [ ] `VAULT_BACKEND=postgres` with a managed Postgres (encrypted at rest, backups)
- [ ] `SERVICE_API_KEY` set; TLS terminated at the ingress
- [ ] Run the recall benchmark on a representative corpus; tune detector thresholds
- [ ] CI green (tests, mypy, recall, 100-run leak scan, in-container Presidio suite)
