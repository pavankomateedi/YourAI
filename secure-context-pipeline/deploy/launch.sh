#!/usr/bin/env bash
# One-command launch for a Kubernetes target.
#
# Prereqs (export these or set in your shell/CI):
#   IMAGE     container image ref, e.g. ghcr.io/yourorg/secure-context-pipeline:2.0.0
#   KUBECTL   kubectl context already pointed at the target cluster
#   secrets   filled into deploy/k8s.yaml's Secret (via your secret manager)
#
# Usage:  IMAGE=... ./deploy/launch.sh
set -euo pipefail

: "${IMAGE:?Set IMAGE to your registry path, e.g. ghcr.io/org/scp:2.0.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Preflight"
SCP_ENV=production python scripts/preflight.py

echo "==> Build image: $IMAGE"
docker build -t "$IMAGE" .

echo "==> Push image"
docker push "$IMAGE"

echo "==> Apply manifests (image: $IMAGE)"
sed "s#secure-context-pipeline:2.0.0#${IMAGE//\#/\\#}#" deploy/k8s.yaml | kubectl apply -f -

echo "==> Wait for rollout"
kubectl rollout status deployment/secure-context-pipeline --timeout=180s

echo "==> Service:"
kubectl get svc secure-context-pipeline
echo "Done. Probe /health through your ingress."
