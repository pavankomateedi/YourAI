# Secure Context Pipeline — Onboarding / Continuation Context

PII/PHI/privilege **obfuscation pipeline** that lets YourAI call external LLMs on
sensitive documents without raw personal data leaving infra:
`detect → obfuscate → leak gate → call LLM → de-obfuscate → restore`. A per-session
AES-256-GCM vault holds the token↔original map and is destroyed on logout.

**Status (2026-05-22): built, tested, and DEPLOYED LIVE on AWS.** 80 tests pass,
mypy clean, 95% detection recall, 0 leaks/100 runs.

> Secrets are intentionally NOT in this file. The live `SERVICE_API_KEY` and master
> key live in `secure-context-pipeline/deploy/aws/secrets.auto.tfvars` (git-ignored).

---

## Where things are
- **Code:** `secure-context-pipeline/` (Python 3.11+ async). Package:
  `secure_context_pipeline/` — `store/ detection/ obfuscation/ vault/ deobfuscation/
  audit/ pipeline/ security/ api/`.
- **Tests:** `secure-context-pipeline/tests/` (+ golden fixtures in `tests/fixtures/golden/`).
- **Spec (read-only):** `PRD_SecureContextPipeline.md`, `GOLDEN_DATASET_RULES.md`,
  `EVALS_SecureContextPipeline.md`, `test_harness.py` (the grader contract) — repo root.
- **Deploy:** `secure-context-pipeline/deploy/` (`aws/` = ECS Fargate Terraform;
  `k8s.yaml` = EKS; `launch.sh`). `scripts/` has `preflight.py`, `gen_keys.py`,
  `recall_benchmark.py`, `pii_leakage_scan.py`.

## Run locally
```
cd secure-context-pipeline
python -m venv .venv && .\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .[api]
.\.venv\Scripts\python.exe -m pytest tests/ -q          # 80 passed, 1 skipped
.\.venv\Scripts\python.exe demo.py                       # end-to-end demo (mock LLM)
```
Full NER stack (Presidio + spaCy) only installs cleanly on 3.11 → use Docker
(`docker compose run --rm app pytest tests/ -q`). Local 3.14 uses the regex/heuristic
detector fallback (everything still passes).

## Live deployment (AWS, acct 119112823258, us-east-1)
- ECS Fargate + ALB + ECR + Secrets Manager + IAM + CloudWatch (16 TF resources).
- URL: `http://secure-context-pipeline-1965755421.us-east-1.elb.amazonaws.com`
  - Use **http** (no TLS listener) and a real path. Root `/` is 404 by design.
  - Swagger UI: **`/docs`** · status: **`/health`** · `/sessions`, `/run`, `/documents`.
  - **Demo UX: `/ui`** — self-contained single-page trust-boundary demo (no build
    step; HTML lives in `api/ui.py`, served same-origin so there's no CORS). Shows
    Original → Sent-to-LLM (obfuscated) → LLM raw reply → Restored, with samples.
  - `/run` returns two zero-PII observability fields used by the UI:
    `obfuscated_preview` (exactly what crosses the boundary) and `llm_raw_response`.
  - Auth: `X-API-Key` header (value in `deploy/aws/secrets.auto.tfvars`).
- LLM backend = **offline mock** (no Anthropic key set); **synthetic data** only.
- **Teardown (stops billing ~$0.07/hr):**
  `terraform -chdir=secure-context-pipeline/deploy/aws destroy`

## Architecture notes / gotchas
- Token format `[PREFIX_8hex]`; 3-segment types collapse to 2 segments
  (`PHI_INSURANCE_ID`→`PHI_INSURANCEID`) so they match the harness `TOKEN_PATTERN`.
- Obfuscation engine: replace at valid offset; value-replace only when offset is
  out of range; skip in-range-stale spans (makes the harness's fabricated-offset
  tests pass at once).
- `FIN_ACCOUNT` is card-style only (keeps F-003 idempotency exact); medical patterns
  need a qualifier (dose/value/"Mellitus") so clean docs don't false-fire.
- `PHI_MRN` matches hyphen-, space-, colon- and hash-separated labels (`MRN-7293847`,
  `MRN 884211`, `MRN: …`, `MRN# …`), capturing the `MRN` label into the token (matches
  the golden contract); space form requires 3+ digits to avoid false fires. The
  `/run` `obfuscated_preview` surfaced the original hyphen-only gap during the UI demo.
- Two leak gates before any LLM call: vault-based + `residual_scan` (raw identifiers
  in payload). Fail closed (HTTP 422).
- Key mgmt fails closed in production without a persistent master key
  (`security/keys.py`); supports file, `STORE_ENCRYPTION_KEY_B64` env, KEK envelope,
  or AWS KMS wrapping (`KEY_WRAPPING=none|local|kms`).
- Heuristic name detector (local fallback) over-segments some Title-Case labels
  (e.g. "Patient Dr") — cosmetic, no leak; Presidio path avoids it.
- Provided `test_harness.py` has 3 perf tests that fail for ANY impl
  (`benchmark(asyncio.run, run())` reuses an awaited coroutine); repo's own
  `tests/test_performance.py` covers the same SLAs. 49/52 of the grader harness pass.

## Open items / next steps
- **SECURITY:** rotate/delete the AWS access key pasted during deploy
  (IAM → YourAIAWSCLIUser → Security credentials).
- In-container Presidio/spaCy suite green (CI `docker` job; Docker daemon was down locally).
- Before REAL PHI: Anthropic key + BAA, `VAULT_BACKEND=postgres` (RDS),
  `KEY_WRAPPING=kms`, TLS on ALB, recall validation on a real corpus, security review.
- Co-reference resolution (only true v1 functional gap); multi-chunk + streaming are
  built (`obfuscation/chunking.py`, `DeobfuscationEngine.deobfuscate_stream`).
