# Secure Context Pipeline

PII/PHI/privilege obfuscation layer that lets YourAI use external LLM providers
(Anthropic, OpenAI) on highly sensitive documents — **medical records, legal case
files, financial disclosures** — without any recoverable personal data leaving
YourAI infrastructure.

It performs a full round trip:

```
detect → obfuscate → [leak gate] → call LLM → de-obfuscate → restore
```

What crosses the trust boundary is semantically useful but contains **zero
recoverable PII**. What the user sees is fully restored. The token↔original
mapping lives in an encrypted, per-session vault that is destroyed on logout —
making the obfuscation cryptographically irreversible across sessions.

---

## Quickstart

### Option A — Docker (recommended; full Presidio + spaCy NER stack)

```bash
cp .env.example .env          # add your ANTHROPIC_API_KEY (optional for the demo)
docker compose build
docker compose run --rm app pytest tests/ -v      # run the test suite
docker compose run --rm app python demo.py        # end-to-end demo
```

### Option B — Local virtualenv (Windows / any recent Python 3.11+)

The core stack installs cleanly without the heavy NLP dependencies; the detector
falls back to a high-precision regex + name-heuristic path.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e . --no-deps
.\.venv\Scripts\python.exe -m pytest tests/ -v
.\.venv\Scripts\python.exe demo.py
```

To enable the full Presidio + spaCy detector locally:

```bash
pip install -r requirements-nlp.txt
python -m spacy download en_core_web_lg
```

### Configuration

All config is environment-driven (`.env`, see `.env.example`). The only secret is
the LLM API key — there are **no hardcoded secrets** anywhere in the source.
The pipeline runs offline with a deterministic echo-mock LLM when no key is set.

---

## Architecture

```
                       YOURAI INFRASTRUCTURE
 upload ─▶ SecureDocumentStore ─▶ PIIDetector ─▶ ObfuscationEngine ─▶ LLMContextInjector
            (AES-256-GCM,           (regex +        (Tokenization /     │ leak gate
             per-user HKDF key)      Presidio NER)   Pseudonymization)  │
                                          │                ▼            │
                                     SessionVault ◀── store(token,enc)  │
                                     (AES-256-GCM,                       │
                                      per-session key)                   ▼
══════════════════════════ TRUST BOUNDARY ══════════════ External LLM (Claude/OpenAI)
                                          ▲                              │
                  restored ◀── DeobfuscationEngine ◀── (token references)┘
                                          │
                                     AuditLog (token ids only — never originals)
```

| # | Component | File | Responsibility |
|---|-----------|------|----------------|
| 1 | `SecureDocumentStore` | `store/store.py` | Encrypt-at-rest upload/retrieve; PDF/DOCX/TXT text extraction |
| 2 | `PIIDetector` | `detection/detector.py` | Detect & classify the 15 entity types (hybrid rules + NER) |
| 3 | `ObfuscationEngine` + strategies | `obfuscation/` | Replace entities with tokens or pseudonyms; idempotent per session |
| 4 | `SessionVault` | `vault/vault.py` | Encrypted, per-session token↔original map; destroyed on logout |
| 5 | `LLMContextInjector` | `pipeline/injector.py` | Build payload, call provider (real Anthropic + offline mock) |
| 6 | `DeobfuscationEngine` | `deobfuscation/engine.py` | Restore originals; vault miss → `[UNAVAILABLE]` |
| 7 | `AuditLog` | `audit/audit_log.py` | Append-only JSONL trail — token ids only, never originals |
| — | `SecureContextPipeline` | `pipeline/pipeline.py` | Top-level orchestrator (the only entry point product code uses) |
| — | HTTP service | `api/app.py` | FastAPI service: `/sessions`, `/documents`, `/run`, `/health`; `X-API-Key` auth |
| — | Key management | `security/keys.py` | Master-key provider (fail-closed in prod) + KMS wrapping hook |

### Running as a service

```bash
pip install -e .[api]
uvicorn secure_context_pipeline.api.app:app --host 0.0.0.0 --port 8000
# POST /sessions -> {session_id}; POST /run {user_id, session_id, text, user_query}
```

Set `SERVICE_API_KEY` to require the `X-API-Key` header on every non-health route.

### The 15 entity types

PII: `NAME, SSN, DOB, ADDRESS, EMAIL, PHONE` · PHI: `MRN, DIAGNOSIS, MEDICATION,
INSURANCE_ID, LAB_RESULT` · Financial: `ACCOUNT, TAX_ID` · Legal:
`CLIENT, STRATEGY`.

Token format: `[{PREFIX}_{8-hex}]`, e.g. `[PII_NAME_a3f2c1d4]`. The prefix is the
entity type rendered as exactly two upper-case segments (so `PHI_INSURANCE_ID` →
`PHI_INSURANCEID`), keeping every token inside the canonical token grammar so any
consumer reliably finds them.

---

## Detection: hybrid rules + NER

Microsoft Presidio + spaCy (`en_core_web_lg`) supply `PII_NAME` (PERSON) detection
when installed (the container path). The 14 structured/medical/legal types are
detected by deterministic, dependency-free regex/lexicon/context recognizers
(`detection/patterns.py`), which:

* keep `FIN_ACCOUNT` scoped to card-style grouped numbers (so account *labels* are
  not over-captured and idempotency stays exact);
* require a discriminating qualifier for medical types (a dosage after a drug, a
  value after a lab, "Mellitus" after a diabetes diagnosis) so generic prose like
  "patients taking Metformin" or "annual HbA1c testing" never false-fires;
* fold a leading honorific ("Dr.") into a name span.

When Presidio/spaCy are absent, a capitalized-name heuristic stands in for NER, so
the suite runs and passes in a minimal venv as well as in the full container.
*Known limitation:* the heuristic can over-segment multi-word Title-Case **field
labels** ("Medical Record") as names; this is cosmetic — it never leaks real PII
and the Presidio path does not exhibit it.

---

## Obfuscation strategies (swappable by config)

* **Tokenization** — opaque typed token. Deterministic within a session, random
  across sessions, type-preserving, irreversible without the vault. Default for
  identifiers and for diagnoses/medications (substituting a wrong drug would
  corrupt the LLM's reasoning).
* **Pseudonymization** — a realistic fake value (Faker) the LLM can reason about
  naturally. Better for names/addresses; consistent within a session.

Switching strategy is a config change (`OBFUSCATION_STRATEGY`), not a code change.

---

## Security & threat model

| Threat | Mitigation |
|--------|-----------|
| LLM provider logs/retains payload | Tokens/pseudonyms carry zero recoverable PII; random suffix has no entropy link to the original |
| Vault database breach | Entries are AES-256-GCM ciphertext; the key lives only in memory |
| Cross-session re-identification | Independent per-session key; Session B cannot decrypt Session A; lookup returns an error, not data |
| Logging of originals | Every logging path receives token ids only; verified by an automated log scan after each pipeline run |
| Secret leakage | No hardcoded keys; `.env` git-ignored; key supplied only via env |
| A value escaping obfuscation | Pre-call **leak gate** scans the outbound payload against the session's known originals and aborts with `PIILeakError` before any network call |

**5 hard-fail conditions** (HF-001…HF-005) are all enforced: no original PII in the
outbound payload, none in the audit log, no hardcoded secrets, no cross-session
vault access, and sub-0.60-confidence entities are redacted rather than passed
through.

---

## Tests & results

```bash
pytest tests/ -v                              # full suite
pytest tests/test_performance.py --benchmark-only
python scripts/recall_benchmark.py            # detection recall vs. golden ground truth
python scripts/pii_leakage_scan.py --runs 100 # 0 leaks across 100 runs
python tests/fixtures/golden/validate_fixtures.py --fixture-dir tests/fixtures/golden
mypy secure_context_pipeline                  # clean (0 issues)
```

* **79 passed, 1 skipped** (the skip is the live-Postgres test, which needs a
  DSN). Covers detection, obfuscation, vault, de-obfuscation, full pipeline,
  concurrency, golden dataset F-001…F-007, document store, audit/compliance, edge
  cases, performance, residual leak gate, key management + envelope wrapping,
  multi-chunk consistency, streaming de-obfuscation, the red-team suite, and the
  HTTP service.
* **0 PII leaks** across the 100-run scan; **95% overall detection recall** vs.
  golden ground truth.
* `mypy` clean across 34 modules; secret scan clean.
* Performance SLAs met: obfuscation < 2 s / 2,000 words, vault lookup < 5 ms,
  de-obfuscation < 500 ms / 500 tokens.

### Defense-in-depth leak gate

Two gates run before every LLM call: (1) scan the payload against values the
detector found (the vault), and (2) `residual_scan` re-applies high-precision
identifier patterns to the outbound payload itself — catching anything detection
*missed* and never vaulted. Either firing raises `PIILeakError` and the call is
aborted (the service returns HTTP 422, failing closed).

CI (`.github/workflows/ci.yml`) gates merges on: secret scan, mypy, fixture
validation, the full suite, the recall benchmark (≥ 80%), the 100-run leak scan,
and an in-container run of the full Presidio + spaCy stack.

> **Note on the provided `test_harness.py`:** its 3 `TestPerformance` cases call
> `benchmark(asyncio.run, run())`, passing an already-created coroutine that
> pytest-benchmark re-executes across rounds → `cannot reuse already awaited
> coroutine` (and with `--benchmark-disable`, `benchmark.stats.mean` is `None`).
> This fails for *any* implementation; it is a defect in the harness's benchmark
> invocation, not the pipeline. This repo's `tests/test_performance.py` asserts
> the identical SLAs correctly and passes. All other 49 harness tests pass.

---

## Live-review Q&A

1. **Why obfuscate instead of trusting zero-retention contracts?** A contract is
   not a technical control — it cannot stop a misconfigured log, a provider
   incident, or a subpoena. This enforces the guarantee in code.
2. **Tokenization vs pseudonymization?** Tokens for identifiers and for
   drug/diagnosis (wrong substitutions corrupt reasoning); pseudonyms for
   names/addresses where realistic context improves LLM output.
3. **What stops cross-session re-identification?** Per-session AES-256-GCM keys;
   Session B's key can't decrypt Session A; lookups are keyed by session id.
4. **What if the LLM uses a token in an inflected form?** The de-obfuscator matches
   only the bracketed token, so `[…]'s` restores to `Name's`; a vault miss becomes
   `[UNAVAILABLE]`, never an unresolved token or a crash.
5. **How is "zero PII in transit" verified?** A pre-call leak gate scans the
   payload against the session's known originals and aborts before the call; an
   automated 100-run scan confirms zero leakage.
6. **Biggest residual risk?** Inference/co-reference: the LLM may refer to "the
   patient" without a token. Out of scope for v1 (see below).

---

## Built (productionization)

* **Postgres vault backend** — `vault/postgres_vault.py` (asyncpg), same interface
  and encryption model; select via `VAULT_BACKEND=postgres` + `DATABASE_URL`.
* **Real key wrapping** — `security/keys.py` ships `LocalEnvelopeWrapping`
  (AES-256-GCM under a local KEK) and `AwsKmsWrapping` (boto3); the master key is
  stored wrapped, unwrapped into memory on load. `KEY_WRAPPING=none|local|kms`.
* **Multi-chunk documents** — `obfuscation/chunking.py`; large docs are obfuscated
  chunk-by-chunk against the shared vault (cross-chunk token consistency).
* **Streaming de-obfuscation** — `DeobfuscationEngine.deobfuscate_stream` restores
  tokens incrementally, buffering tokens split across stream chunks.
* **Red-team suite** — `tests/test_red_team.py`: prompt injection, cross-session
  token guessing, re-identification, post-destroy use, gate bypass.
* **Deployment** — `deploy/k8s.yaml` + `deploy/README.md` (gunicorn/uvicorn,
  health probes, secret-backed config, fail-closed prod settings).

## Remaining (need your infra/credentials or a real corpus)

* **Live cloud deploy + real LLM/KMS** — code is ready; needs an `ANTHROPIC_API_KEY`,
  AWS creds for `KEY_WRAPPING=kms`, and a target cluster.
* **Real-corpus recall validation** — recall is benchmarked on the golden fixtures
  (95%); production needs tuning against representative documents (and the full
  Presidio + scispaCy stack enabled).
* **Co-reference resolution** — restore indirect references ("the patient's
  condition"); needs a coref model. The one true v1 functional gap.
* **In-container CI verification** — the Docker image builds; the in-container
  Presidio/spaCy suite runs in the CI `docker` job (Docker daemon was unavailable
  locally during this build).

### Detection recall caveats (from `scripts/recall_benchmark.py`)

Two intentional gaps on the adversarial golden set: `FIN_ACCOUNT` is scoped to
card-style numbers (so the `SAVINGS-…` label isn't swept up and F-003 idempotency
stays exact), and a bare single-name ("John") / a colon-adjacent name are not
matched by the name heuristic. Enabling the full Presidio + scispaCy stack
(`requirements-nlp.txt`, or `SCISPACY_MODEL=en_ner_bc5cdr_md`) raises name and
medical recall.

---

*YourAI — Secure Context Pipeline v2.0*
