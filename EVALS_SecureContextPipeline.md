# Evaluation Framework
## Secure Context Pipeline — Scoring Rubric & Test Specifications
**Version:** 2.0  
**Aligned with:** YourAI Engineering Interview Rubric  
**Date:** 2026-05-21

---

## Quick Eval Reference

### Eval ID → pytest Test Map

| Eval ID | pytest Class | pytest Method | Marker |
|---|---|---|---|
| EVAL-SEC-001 | `TestSessionVault` | `test_per_session_key_uniqueness` | `security` |
| EVAL-SEC-002 | `TestSessionVault` | `test_cross_session_isolation` | `security` |
| EVAL-SEC-003 | `TestSessionVault` | `test_at_rest_encryption_correctness` | `security` |
| EVAL-SEC-004 | `TestSessionVault` | `test_session_key_lifecycle_and_destruction` | `security` |
| EVAL-SEC-005 | `TestLLMPayloadSafety` | `test_llm_payload_pii_leak_unit` | `security` |
| EVAL-SEC-006 | `TestLLMPayloadSafety` | `test_pre_call_leak_gate_enforcement` | `security` |
| EVAL-SEC-007 | `TestAuditLog` | `test_audit_log_pii_scan` | `security` |
| EVAL-SEC-008 | `TestEncryptionImpl` | `test_aes256gcm_correctness` | `security` |
| EVAL-SEC-009 | `TestSecretsHygiene` | `test_no_secrets_in_code_or_git` | `security` |
| EVAL-OBF-001 | `TestTokenization` | `test_within_session_determinism` | `obfuscation` |
| EVAL-OBF-002 | `TestTokenization` | `test_cross_session_nondeterminism` | `obfuscation` |
| EVAL-OBF-003 | `TestTokenization` | `test_token_format_compliance` | `obfuscation` |
| EVAL-OBF-004 | `TestPseudonymization` | `test_semantic_type_preservation` | `obfuscation` |
| EVAL-OBF-005 | `TestPseudonymization` | `test_pseudonym_consistency_within_session` | `obfuscation` |
| EVAL-OBF-006 | `TestEntityDetection` | `test_all_entity_types_detected` | `obfuscation` |
| EVAL-OBF-007 | `TestEntityDetection` | `test_graceful_degradation_low_confidence` | `obfuscation` |
| EVAL-DEOB-001 | `TestDeobfuscation` | `test_complete_token_restoration` | `deobfuscation` |
| EVAL-DEOB-002 | `TestDeobfuscation` | `test_inflected_token_handling` | `deobfuscation` |
| EVAL-DEOB-003 | `TestDeobfuscation` | `test_vault_miss_handling` | `deobfuscation` |
| EVAL-DEOB-004 | `TestDeobfuscation` | `test_non_pii_text_preservation` | `deobfuscation` |
| EVAL-DEOB-005 | `TestDeobfuscation` | `test_pseudonym_reverse_lookup` | `deobfuscation` |
| EVAL-DEOB-006 | `TestPipeline` | `test_end_to_end_round_trip_fidelity` | `deobfuscation` |
| EVAL-CODE-001 | `TestCodeQuality` | `test_mypy_strict_compliance` | `quality` |
| EVAL-CODE-002 | `TestCodeQuality` | `test_strategy_pattern_implementation` | `quality` |
| EVAL-CODE-003 | `TestCodeQuality` | `test_detector_extensibility` | `quality` |
| EVAL-CODE-004 | `TestCodeQuality` | `test_no_blocking_io_in_async_context` | `quality`, `performance` |
| EVAL-CODE-005 | `TestCodeQuality` | `test_test_completeness` | `quality` |
| EVAL-THINK-001 | — | Manual reviewer check | `manual` |
| EVAL-THINK-002 | — | Manual reviewer check | `manual` |
| EVAL-THINK-003 | — | Manual reviewer check | `manual` |

### pytest Commands by Eval Group

```bash
# Security evals only
pytest tests/ -v -m security

# Obfuscation evals only
pytest tests/ -v -m obfuscation

# De-obfuscation evals only
pytest tests/ -v -m deobfuscation

# Code quality evals only
pytest tests/ -v -m quality

# Performance / async correctness
pytest tests/ -v -m performance

# All automated evals (excludes manual)
pytest tests/ -v -m "not manual"

# Run everything with line-level coverage report
pytest tests/ -v --cov=secure_context_pipeline --cov-report=term-missing

# Run everything with HTML coverage report (opens in browser)
pytest tests/ -v --cov=secure_context_pipeline --cov-report=html && open htmlcov/index.html
```

---

## Overview

This document defines the full evaluation framework for the Secure Context Pipeline submission. It maps directly to the five rubric dimensions in the challenge brief, and expands each with specific, verifiable pass/fail criteria, scoring gradations, automated test hooks, and concrete implementation hints for each eval item.

**Total weight: 100 points**

| Dimension | Weight | Points |
|---|---|---|
| Security Architecture | 30% | 30 pts |
| Obfuscation Quality | 25% | 25 pts |
| De-obfuscation Correctness | 20% | 20 pts |
| Code Quality | 15% | 15 pts |
| Critical Thinking | 10% | 10 pts |

---

## Dimension 1: Security Architecture (30 points)

### 1.1 Vault Design (12 pts)

**What we test:** Is the vault cryptographically sound and correctly isolated?

#### EVAL-SEC-001: Per-session key uniqueness (3 pts)
```
GIVEN: Two sessions created for the same user
WHEN:  Session keys are extracted (in test context, not in production)
THEN:  Key(session_A) != Key(session_B) with probability ≥ 1 - 2^-128
```
- **3 pts:** Keys are cryptographically distinct (derived via os.urandom(32), not seeded from user_id)
- **1 pt:** Keys are distinct but derivation is weak (e.g., seeded from timestamp)
- **0 pts:** Same key reused across sessions
- **Implementation Hint:** In `SessionVault.__init__` or `create_session()`, set `self._key = os.urandom(32)`. Never compute the key from `user_id`, `session_id`, a timestamp, or any deterministic value. The key must be generated fresh on each call and stored only in memory (and optionally in a KMS-backed secrets store), never derived.

---

#### EVAL-SEC-002: Cross-session vault isolation (3 pts)
```
GIVEN: Token [PII_NAME_a3f2] exists in Session A's vault
WHEN:  Session A's vault is destroyed and Session B attempts lookup of [PII_NAME_a3f2]
THEN:  Raises VaultMissError or equivalent; never returns Session A's data
```
- **3 pts:** Cryptographic isolation — Session B key cannot decrypt Session A ciphertext; test verifies
- **2 pts:** Logical isolation (row-level filter) but no cryptographic separation
- **0 pts:** Cross-session lookup succeeds or error is swallowed silently
- **Implementation Hint:** Store vault rows with a `session_id` column and always scope all queries with `WHERE session_id = ?`. More importantly, each session uses its own AES key (from EVAL-SEC-001), so even if Session B somehow retrieves Session A's ciphertext row, decryption will fail with an `InvalidTag` exception — providing cryptographic isolation on top of logical isolation. In tests, assert that `vault_b.lookup(token_from_a)` raises `VaultMissError` and that no plaintext from session A is reachable.

---

#### EVAL-SEC-003: Vault at-rest encryption correctness (3 pts)
```
GIVEN: A vault entry for original value "John Smith"
WHEN:  The encrypted_original column is read directly from the database
THEN:  The raw bytes contain no recognizable substring of "John Smith"
       AND decryption with the wrong key raises an authentication error (GCM tag failure)
```
- **3 pts:** AES-256-GCM with fresh nonce per entry; authenticated decryption; wrong-key test passes
- **2 pts:** AES-256 but CBC mode (no authentication); or fixed nonce
- **1 pt:** Base64 encoding called "encryption"
- **0 pts:** Plaintext storage
- **Implementation Hint:** Use `cryptography.hazmat.primitives.ciphers.aead.AESGCM`. In `vault.store(token, plaintext)`: generate `nonce = os.urandom(12)`, call `ciphertext = AESGCM(self._key).encrypt(nonce, plaintext.encode(), None)`, then store `nonce + ciphertext` as a single `BLOB` column named `encrypted_original`. In `vault.lookup(token)`: slice `blob[:12]` as nonce and `blob[12:]` as ciphertext, call `AESGCM(self._key).decrypt(nonce, ciphertext, None)` — this raises `InvalidTag` automatically if the key or ciphertext is wrong.

---

#### EVAL-SEC-004: Session key lifecycle (3 pts)
```
GIVEN: An active session with a key in memory
WHEN:  destroy_session() is called
THEN:  The in-memory key is zeroed (ctypes.memset or equivalent)
       AND the vault store entries for that session are deleted
       AND subsequent lookup of any token from that session fails irreversibly
```
- **3 pts:** Key zeroing + store deletion + irreversibility confirmed by test
- **2 pts:** Store deletion but no key zeroing (GC-dependent)
- **1 pt:** Session marked "expired" but data not deleted
- **0 pts:** Vault persists after logout
- **Implementation Hint:** In `destroy_session()`, use `ctypes.memset(ctypes.c_char_p(self._key), 0, len(self._key))` (or the `bytearray` + `memoryview` pattern: store the key as a `bytearray`, then do `self._key[:] = b'\x00' * len(self._key)`) to zero the key before Python's GC can handle it. Then execute `DELETE FROM vault WHERE session_id = ?` against the DB. Finally, set `self._key = None` and `self._active = False`. In tests, assert that `vault.lookup(any_token)` raises `SessionDestroyedError` after `destroy_session()` is called.

---

### 1.2 Zero PII in Transit (10 pts)

#### EVAL-SEC-005: LLM payload PII leak check — unit (4 pts)
```
GIVEN: A document with 10 known PII entities (from golden dataset fixture)
WHEN:  The LLM Context Injector assembles the outbound payload
THEN:  For every entity in the detected entity list:
         entity.original_value NOT IN payload.obfuscated_context
         entity.original_value NOT IN payload.user_query
         entity.original_value NOT IN payload.system_prompt
```
- **4 pts:** Automated scan verifies zero occurrences; test runs 100 times across varied fixtures
- **2 pts:** Manual inspection only; no automated scan
- **0 pts:** Any original value found in payload
- **Implementation Hint:** Before assembling the final `LLMPayload`, iterate over `detected_entities` and for each `entity.original_value` assert it does not appear in any string field of the payload. Implement a helper `_scan_for_pii(payload: LLMPayload, originals: list[str]) -> list[str]` that returns any leaked values, and call it inside `verify_no_pii_leak()`. In tests, use `@pytest.mark.parametrize` with 10+ fixture documents to reach the 100-run coverage requirement.

---

#### EVAL-SEC-006: Pre-call leak gate enforcement (3 pts)
```
GIVEN: An obfuscation engine with a simulated bug that leaves one PII value unmasked
WHEN:  verify_no_pii_leak() is called before the LLM call
THEN:  PIILeakError is raised
       AND the LLM call is NOT made (verify via mock call count = 0)
       AND the error is logged with token ID only (not the leaked value)
```
- **3 pts:** Gate raises exception; call aborted; no leaked value in log
- **1 pt:** Gate detects leak but call proceeds anyway
- **0 pts:** No leak gate exists
- **Implementation Hint:** In the pipeline's `send_to_llm()` method, call `verify_no_pii_leak(payload, detected_entities)` before `await llm_client.complete(payload)`. Inside `verify_no_pii_leak`, if a leak is found, log `logger.error("PIILeakDetected token_id=%s", token_id)` — log only the token ID, never the original value — then `raise PIILeakError(token_id=token_id)`. In tests, monkeypatch the obfuscation engine to leave one value unmasked, then assert `mock_llm.complete.call_count == 0` and that `PIILeakError` is raised.

---

#### EVAL-SEC-007: Audit log PII scan (3 pts)
```
GIVEN: A full pipeline run on a document with 15 PII entities
WHEN:  The audit log is scanned for all 15 original values
THEN:  Zero occurrences found in any audit log field
```
- **3 pts:** Automated scan passes with zero hits across all log fields
- **0 pts:** Any original value found in any log field (this is a hard fail)
- **Implementation Hint:** Every audit log write must pass through a `sanitize_for_log(value: str) -> str` function that replaces any detected PII with its token ID. Never log `entity.original_value`; instead log `entity.token_id`. After each pipeline run in tests, read back all audit log rows and assert that none of the 15 original values appear anywhere: `for original in originals: assert original not in json.dumps(log_row)`.

---

### 1.3 Encryption Implementation (8 pts)

#### EVAL-SEC-008: Correct AES-256-GCM usage (4 pts)
```
Code review checks:
□ Uses Python cryptography library (not PyCrypto, not hashlib)
□ AES-GCM mode (authenticated encryption — prevents tampering)
□ Fresh nonce (96-bit minimum) generated per encryption operation
□ Authentication tag is verified on decryption (GCM tag check)
□ Key is 256 bits (32 bytes) — not 128 or 192
```
- **4 pts:** All five checks pass
- **3 pts:** Four checks pass
- **2 pts:** Three checks pass (acceptable if GCM is used)
- **0 pts:** AES-CBC without authentication, or any homebrew crypto
- **Implementation Hint:** The only import you need is `from cryptography.hazmat.primitives.ciphers.aead import AESGCM`. Instantiate with a 32-byte key: `aesgcm = AESGCM(key)` — passing a key of wrong length raises `ValueError` immediately. Use `nonce = os.urandom(12)` before every `aesgcm.encrypt(...)` call. The `cryptography` library automatically appends and verifies the 16-byte GCM authentication tag; decryption raises `cryptography.exceptions.InvalidTag` on tampering or wrong key, which satisfies the authentication requirement without any extra code.

---

#### EVAL-SEC-009: No secrets in code or git history (4 pts)
```
□ grep -r "sk-" . → no matches
□ grep -r "OPENAI_API_KEY\s*=" . | grep -v ".env" → no matches  
□ git log --all -p | grep -i "api_key\|secret\|password" → no matches
□ All keys loaded via os.environ or pydantic Settings
□ .env is in .gitignore
```
- **4 pts:** All checks pass
- **0 pts:** Any secret found in code or git history (this is a hard fail for a security role)
- **Implementation Hint:** Use `pydantic_settings.BaseSettings` for all configuration: define `class Settings(BaseSettings): openai_api_key: str = Field(..., env="OPENAI_API_KEY")`. Access via `settings = Settings()` at startup — Pydantic reads from environment variables and `.env` automatically. Add `.env` and `*.env` to `.gitignore` before your first commit. If you accidentally committed a secret, remove it with `git filter-branch` or BFG Repo Cleaner and force-push before submission; the eval script checks full git history with `git log --all -p`.

---

## Dimension 2: Obfuscation Quality (25 points)

### 2.1 Tokenization Properties (10 pts)

#### EVAL-OBF-001: Determinism within session (3 pts)
```
GIVEN: "John Smith" appears 3 times in a document
WHEN:  The obfuscation engine processes the document in a single session
THEN:  All 3 occurrences are replaced with the SAME token [PII_NAME_XXXXXXXX]
       AND vault contains exactly 1 entry for "John Smith" (not 3)
```
- **3 pts:** Idempotent obfuscation; dedup verified via vault entry count
- **1 pt:** Each occurrence gets a different token (breaks de-obfuscation)
- **0 pts:** Token map not stored at all
- **Implementation Hint:** In `TokenizationStrategy.obfuscate(entity, session)`, before generating a new token, first query the vault for an existing token for this `(session_id, original_value, entity_type)` tuple: `existing = await vault.lookup_by_original(session_id, original_value)`. If found, return `existing.token`. Only call `_generate_token(entity_type)` if no existing entry is found, then immediately store the new mapping. This lookup-or-create pattern ensures deduplication within a session.

---

#### EVAL-OBF-002: Non-determinism across sessions (4 pts)
```
GIVEN: "John Smith" obfuscated in Session A → [PII_NAME_a3f2c1d4]
WHEN:  "John Smith" is obfuscated in Session B (different session, same user)
THEN:  Token B != Token A (with probability 1 - 2^-32 given 8-byte suffix)
       AND Token B cannot be used to look up "John Smith" in Session A's vault
```
- **4 pts:** Cross-session non-determinism verified; isolation confirmed
- **2 pts:** Non-deterministic but same vault (isolation failure)
- **0 pts:** Deterministic across sessions (global token map)
- **Implementation Hint:** Generate the token suffix using `secrets.token_hex(4)` (8 hex chars = 4 random bytes = 2^32 possibilities), producing tokens like `[PII_NAME_a3f2c1d4]`. Since there is no global token map and each session has its own vault scoped to `session_id`, the same original value in two sessions will always receive different tokens. In tests, create sessions A and B, obfuscate the same value in each, and assert `token_a != token_b` and that `vault_a.lookup(token_b)` raises `VaultMissError`.

---

#### EVAL-OBF-003: Token format compliance (3 pts)
```
GIVEN: Any detected entity
WHEN:  Tokenization strategy is applied
THEN:  Token matches regex \[([A-Z]+_[A-Z]+_[0-9a-f]{8})\]
       AND token prefix matches entity type (e.g., PHI_ for PHI entities)
       AND token suffix is random (not derived from original value)
```
- **3 pts:** All format checks pass across all entity types
- **2 pts:** Format correct but entity type prefix missing
- **1 pt:** Token exists but format is non-standard
- **Implementation Hint:** Implement `_generate_token(entity_type: str) -> str` as: `prefix = ENTITY_TYPE_PREFIX_MAP[entity_type]` (e.g., `{"PII_NAME": "PII_NAME", "PHI_MRN": "PHI_MRN"}`), `suffix = secrets.token_hex(4)`, return `f"[{prefix}_{suffix}]"`. Validate the output against `re.fullmatch(r'\[[A-Z]+_[A-Z]+_[0-9a-f]{8}\]', token)` in the test. Critically, never hash or derive the suffix from the original value — doing so would make tokens linkable across sessions.

---

### 2.2 Pseudonymization Properties (8 pts)

#### EVAL-OBF-004: Semantic type preservation (4 pts)
```
For each entity type, verify replacement is plausible in the same role:
□ NAME: Pseudonym is a real-sounding full name (not "PERSON_001")
□ ADDRESS: Pseudonym is a valid-format US address
□ DOB: Pseudonym is within ±10 years of original (age-range preservation)
□ MEDICATION: Pseudonym is a real medication name (from approved list)
□ NAME → pseudonym is NOT of the original person's specific name (no overlap)
```
- **4 pts:** All five checks pass
- **2 pts:** Three checks pass
- **0 pts:** Pseudonyms are meaningless (same as tokenization without the bracket format)
- **Implementation Hint:** Use `faker.Faker()` for NAME (call `fake.name()`) and ADDRESS (call `fake.address()`). For DOB, parse the original date, compute `original_year`, then pick `pseudonym_year = random.randint(original_year - 10, original_year + 10)` and reconstruct a plausible date. For MEDICATION, maintain a static curated list (`MEDICATION_PSEUDONYMS = ["Lisinopril", "Metformin", ...]`) and pick randomly. Add a guard: if `fake.name() == original_name`, re-draw. Store all pseudonyms in the vault the same way as tokens so reverse lookup (EVAL-DEOB-005) works.

---

#### EVAL-OBF-005: Pseudonym consistency within session (4 pts)
```
GIVEN: "John Smith" → "Michael Torres" in Session A, turn 1
WHEN:  "John Smith" appears again in Session A, turn 2
THEN:  "John Smith" → "Michael Torres" (same mapping, not a new pseudonym)
```
- **4 pts:** Pseudonym consistency enforced via same vault lookup as tokenization
- **0 pts:** New pseudonym generated on each encounter (breaks de-obfuscation)
- **Implementation Hint:** `PseudonymizationStrategy.obfuscate()` must follow the same lookup-or-create pattern as `TokenizationStrategy` (see EVAL-OBF-001): call `vault.lookup_by_original(session_id, original_value)` first. If the vault already has a pseudonym for this value, return it. Only generate a new pseudonym if no entry exists. Because both strategies share the same vault interface, this consistency is automatic if you reuse the pattern correctly. Store pseudonyms as the "token" value in the vault row.

---

### 2.3 Entity Detection Coverage (7 pts)

#### EVAL-OBF-006: Entity type coverage (4 pts)
```
GIVEN: Golden dataset fixture containing one entity of each required type:
  PII_NAME, PII_SSN, PII_DOB, PII_ADDRESS, PII_EMAIL, PII_PHONE,
  PHI_MRN, PHI_DIAGNOSIS, PHI_MEDICATION, PHI_INSURANCE_ID, PHI_LAB_RESULT,
  FIN_ACCOUNT, FIN_TAX_ID, LEGAL_CLIENT
WHEN:  PIIDetector.detect() runs on the fixture
THEN:  All 14 entity types are detected with confidence ≥ 0.60
       AND each detected span matches the ground-truth span (within 2 chars)
```
- **4 pts:** All 14 detected; spans match
- **3 pts:** 11-13 detected
- **2 pts:** 8-10 detected
- **1 pt:** 5-7 detected
- **0 pts:** <5 detected
- **Implementation Hint:** Use Microsoft Presidio (`presidio_analyzer.AnalyzerEngine`) as the base detector. For entity types not natively supported by Presidio (e.g., `PHI_MRN`, `FIN_TAX_ID`, `LEGAL_CLIENT`), implement custom `PatternRecognizer` subclasses using regex patterns and register them with `engine.registry.add_recognizer(...)` at startup. Each custom recognizer should define `PATTERNS` and `CONTEXT` words to boost confidence scores. Store all recognizer configs in a YAML file (for extensibility, per EVAL-CODE-003) and load them in a loop.

---

#### EVAL-OBF-007: Graceful degradation for low-confidence entities (3 pts)
```
GIVEN: An entity that is ambiguous (e.g., "John" in a sentence where it may be a name or a common noun)
       Injected with confidence = 0.45 via mock
WHEN:  ObfuscationEngine processes it
THEN:  The output contains [REDACTED] at the entity span
       AND the entity is NOT passed through unmasked
       AND the redaction is logged in the audit log
```
- **3 pts:** Redaction applied; no passthrough; audit logged
- **1 pt:** Redaction applied but not logged
- **0 pts:** Low-confidence entity passed through unmasked (hard fail)
- **Implementation Hint:** In `ObfuscationEngine.process_entity(entity)`, add a confidence threshold check at the top: `if entity.confidence < self.confidence_threshold:` (default `self.confidence_threshold = 0.60`). If below threshold, replace the span with the literal string `[REDACTED]` and write an audit event `{"event": "LOW_CONFIDENCE_REDACTION", "token_id": entity.span_id, "entity_type": entity.type, "confidence": entity.confidence}` — never include `entity.original_value` in this log entry. Then `return RedactedResult(span=entity.span, replacement="[REDACTED]")`.

---

## Dimension 3: De-obfuscation Correctness (20 points)

### 3.1 Token Restoration (10 pts)

#### EVAL-DEOB-001: Complete token restoration (4 pts)
```
GIVEN: LLM mock response containing 10 tokens from the session vault
WHEN:  DeobfuscationEngine.deobfuscate() runs
THEN:  All 10 tokens are replaced with their original values
       tokens_restored == 10
       tokens_missed == 0
       No token strings remain in the output
```
- **4 pts:** 100% restoration on golden dataset
- **3 pts:** 90-99% (1 token missed per 10)
- **2 pts:** 80-89%
- **0 pts:** <80%
- **Implementation Hint:** In `DeobfuscationEngine.deobfuscate(response_text, session)`, use `re.finditer(r'\[([A-Z]+_[A-Z]+_[0-9a-f]{8})\]', response_text)` to find all tokens. For each match, call `original = await session.vault.lookup(match.group(0))`. Build the output string by iterating matches and replacing in order (use `re.sub` with a callable for cleanliness). Track `tokens_restored` and `tokens_missed` in a `DeobfuscationResult` dataclass. After substitution, assert no tokens remain with a final `re.search(TOKEN_PATTERN, output)` check.

---

#### EVAL-DEOB-002: Grammatically inflected token handling (4 pts)
```
GIVEN: LLM response containing:
  - "[PII_NAME_a3f2]'s diagnosis"   (possessive)
  - "[PHI_DIAGNOSIS_x7a]s"          (plural — unlikely but possible)
  - "the [PII_NAME_a3f2] patient"   (adjective use)
WHEN:  DeobfuscationEngine processes the response
THEN:  All three are correctly resolved to their original values
       Grammatical context is preserved (possessive "'s" remains after name)
```
- **4 pts:** All three inflected forms handled correctly
- **2 pts:** Two of three handled
- **0 pts:** Inflected tokens not recognized (left as token strings in output)
- **Implementation Hint:** Use a regex that captures optional suffix characters after the closing bracket: `re.finditer(r'(\[[A-Z]+_[A-Z]+_[0-9a-f]{8}\])(\'s|s\b)?', response_text)`. Extract the base token (`match.group(1)`) for vault lookup, then reattach any captured suffix (`match.group(2) or ""`) to the resolved original value. For the possessive case `"[PII_NAME_a3f2]'s"`, this produces `"Jane Doe's"`. For the plural suffix, produce `"diagnosis" + "s" = "diagnosiss"` (log a warning, as LLMs rarely pluralize tokens, but handle it gracefully rather than breaking).

---

#### EVAL-DEOB-003: Vault miss handling (2 pts)
```
GIVEN: LLM response containing [PII_NAME_FFFFFFFF] (token not in vault)
WHEN:  DeobfuscationEngine.deobfuscate() runs
THEN:  [PII_NAME_FFFFFFFF] is replaced with [UNAVAILABLE] in the output
       AND tokens_missed == 1 in the result
       AND a VAULT_MISS event is written to the audit log
       AND the pipeline does NOT raise an exception
```
- **2 pts:** All conditions met
- **1 pt:** Handled but not logged
- **0 pts:** Unresolved token passed to user as-is
- **Implementation Hint:** In the vault lookup loop, wrap each `vault.lookup(token)` in a `try/except VaultMissError`: on `VaultMissError`, substitute `[UNAVAILABLE]`, increment `tokens_missed`, and write `audit_log.write({"event": "VAULT_MISS", "token_id": token})`. Never re-raise the exception — the pipeline must continue processing remaining tokens. Return the completed `DeobfuscationResult` with `tokens_missed > 0` so the caller can decide whether to surface a warning to the user.

---

### 3.2 Response Integrity (10 pts)

#### EVAL-DEOB-004: Non-PII text preservation (4 pts)
```
GIVEN: LLM response: "The patient [PII_NAME_a3f2] has shown improvement. 
        Their blood pressure is now normal. Follow-up in 3 weeks."
WHEN:  De-obfuscation runs with vault entry: [PII_NAME_a3f2] → "Jane Doe"
THEN:  Output: "The patient Jane Doe has shown improvement. 
        Their blood pressure is now normal. Follow-up in 3 weeks."
       Non-entity text is bit-for-bit identical to the input (no corruption)
```
- **4 pts:** Non-PII text identical; only tokens replaced
- **2 pts:** Minor formatting changes introduced
- **0 pts:** Non-PII text corrupted or truncated
- **Implementation Hint:** Implement de-obfuscation using `re.sub` with a replacement callable rather than repeated `str.replace()` calls, which can corrupt text if original values contain regex special characters. Pattern: `output = re.sub(TOKEN_PATTERN, lambda m: lookup(m.group(0)), response_text)`. Never split on whitespace or re-join — work purely at the character level to guarantee bit-for-bit identity of surrounding text. In tests, assert `output.replace("Jane Doe", "[PII_NAME_a3f2]") == original_response_text`.

---

#### EVAL-DEOB-005: Pseudonym reverse lookup (3 pts)
```
GIVEN: "John Smith" was pseudonymized to "Michael Torres" in the session
WHEN:  LLM response contains "Michael Torres recommended..."
THEN:  The de-obfuscation engine recognizes "Michael Torres" as a pseudonym
       AND replaces it with "John Smith" in the output
```
- **3 pts:** Pseudonym reverse lookup implemented and tested
- **0 pts:** Pseudonyms are not tracked for reverse lookup (user sees "Michael Torres")
- **Implementation Hint:** Store pseudonyms in the vault with a secondary index: alongside the forward mapping `token → original` (or `pseudonym → original`), also store a reverse index `pseudonym_value → original_value` in a separate `pseudonym_reverse` table (columns: `session_id`, `pseudonym`, `original`). In `DeobfuscationEngine.deobfuscate()`, after token substitution, run a second pass: for each known pseudonym in `vault.list_pseudonyms(session_id)`, use `output = output.replace(pseudonym, original)`. Order replacements longest-first to avoid partial substitutions (e.g., "Michael Torres Jr." before "Michael Torres").

---

#### EVAL-DEOB-006: End-to-end round-trip fidelity (3 pts)
```
GIVEN: Original text with 10 known PII entities (from golden dataset)
WHEN:  Full pipeline runs: detect → obfuscate → mock LLM echoes all tokens → deobfuscate
THEN:  All 10 original values appear in the restored output
       The restored output is semantically equivalent to what the user expects
       Measured by: exact match on entity values + no extra token strings
```
- **3 pts:** 100% round-trip fidelity on all golden dataset fixtures
- **2 pts:** 90-99% fidelity
- **0 pts:** <90% fidelity
- **Implementation Hint:** Write a parametrized test `test_end_to_end_round_trip_fidelity(fixture)` that: (1) runs the full pipeline with a mock LLM that echoes the obfuscated payload back verbatim, (2) runs de-obfuscation, (3) asserts `all(original in restored_output for original in golden_entities)`, and (4) asserts `re.search(TOKEN_PATTERN, restored_output) is None` (no dangling tokens). Use `pytest.mark.parametrize` over all fixture files in `tests/fixtures/golden_*.txt`. This test is the definitive integration gate.

---

## Dimension 4: Code Quality (15 points)

### 4.1 Type Safety (4 pts)

#### EVAL-CODE-001: mypy strict compliance
```
Command: mypy --strict secure_context_pipeline/
Expected: Exit code 0, zero errors
```
- **4 pts:** Zero mypy errors in strict mode
- **2 pts:** Zero errors in standard mode (not strict)
- **0 pts:** Type errors present
- **Implementation Hint:** Run `mypy --strict` early and often during development — do not leave it for the end. Common strict-mode errors to pre-empt: (1) add return type annotations to every function including `-> None`, (2) annotate all `dict` and `list` usages with generics (e.g., `dict[str, str]` not `dict`), (3) replace `Any` with proper types or use `TypeVar`, (4) annotate `Optional` returns as `str | None`, (5) ensure all `async def` functions return typed coroutines. Add `mypy --strict secure_context_pipeline/` as a step in `eval_runner.sh` to catch regressions.

---

### 4.2 Architecture & Extensibility (5 pts)

#### EVAL-CODE-002: Strategy pattern implementation (3 pts)
```
Code review checks:
□ TokenizationStrategy and PseudonymizationStrategy both inherit from ObfuscationStrategy ABC
□ ObfuscationEngine accepts a strategy_map: dict[str, ObfuscationStrategy] at construction
□ Adding a new strategy class requires zero changes to ObfuscationEngine, vault, or pipeline
□ Verified by: implementing a mock RedactionStrategy and confirming it works without engine changes
```
- **3 pts:** All checks pass
- **1 pt:** Inheritance exists but engine has if/else on strategy type
- **Implementation Hint:** Define `class ObfuscationStrategy(ABC): @abstractmethod async def obfuscate(self, entity: DetectedEntity, vault: SessionVault) -> str: ...`. Then `class TokenizationStrategy(ObfuscationStrategy)` and `class PseudonymizationStrategy(ObfuscationStrategy)` implement only `obfuscate()`. `ObfuscationEngine.__init__` takes `strategy_map: dict[str, ObfuscationStrategy]` where keys are entity type strings (e.g., `"PII_NAME"`). In `process_entity()`, call `strategy = self.strategy_map.get(entity.type, self.default_strategy); return await strategy.obfuscate(entity, vault)`. Zero conditionals on strategy type inside the engine.

---

#### EVAL-CODE-003: Detector extensibility (2 pts)
```
Test: Add PASSPORT_NUMBER to Presidio recognizer config only
      Run detector on a text containing "Passport: AB1234567"
      Verify: entity detected with type PASSPORT_NUMBER
      Verify: no changes required in obfuscation engine, vault, or pipeline
```
- **2 pts:** Extension requires only config change
- **0 pts:** Extension requires code changes in obfuscation or pipeline
- **Implementation Hint:** Store recognizer definitions in `config/recognizers.yaml` in the format `[{name: "PassportRecognizer", entity_type: "PASSPORT_NUMBER", patterns: [{name: "passport", regex: "[A-Z]{2}[0-9]{7}", score: 0.85}], context: ["passport", "travel document"]}]`. At startup, `DetectorFactory.build()` reads this YAML and calls `engine.registry.add_recognizer(PatternRecognizer.from_dict(cfg))` for each entry. Adding a new entity type requires only a new YAML entry — the obfuscation engine, vault, and pipeline are unaffected because they operate on `DetectedEntity` objects generically.

---

### 4.3 Async Correctness (3 pts)

#### EVAL-CODE-004: No blocking I/O in async context
```
Static analysis + runtime check:
□ All database calls use async driver (aiosqlite / asyncpg) — not sqlite3 / psycopg2
□ All LLM calls use async HTTP client (httpx.AsyncClient / aiohttp) — not requests
□ No time.sleep() in async code — only asyncio.sleep()
□ Concurrent pipeline test: 5 sessions run concurrently; wall time < 2x single session time
```
- **3 pts:** All checks pass; concurrent test shows non-blocking behavior
- **2 pts:** Two of four checks pass
- **0 pts:** Blocking I/O in async context (defeats async requirement)
- **Implementation Hint:** Use `aiosqlite` for SQLite (`async with aiosqlite.connect(db_path) as db: await db.execute(...)`) and `httpx.AsyncClient` for LLM calls (`async with httpx.AsyncClient() as client: response = await client.post(...)`). Grep your own code with `grep -rn "import sqlite3\|import requests\|time\.sleep" secure_context_pipeline/` — any hit is a fail. For the concurrent test: `results = await asyncio.gather(*[run_pipeline(session_i) for i in range(5)])` and assert `wall_time < 2 * single_session_time` using `time.perf_counter()`.

---

### 4.4 Test Coverage (3 pts)

#### EVAL-CODE-005: Test completeness
```
Required test scenarios (each must have at least one test):
□ Happy path: full pipeline, all entity types detected and restored
□ Entity type not found: document with no PII; pipeline completes cleanly
□ Vault miss on de-obfuscation: token in response not in vault → [UNAVAILABLE]
□ Expired session: vault looked up after destroy_session() → error
□ Concurrent session isolation: sessions A and B run simultaneously; no data cross-contamination
□ Low-confidence entity: graceful redaction to [REDACTED]
□ Logging safety: no original values in log output
```
- **3 pts:** All 7 scenarios have passing tests
- **2 pts:** 5-6 scenarios covered
- **1 pt:** 3-4 scenarios covered
- **0 pts:** <3 scenarios covered
- **Implementation Hint:** Create one test file per scenario group: `test_happy_path.py`, `test_vault.py`, `test_deobfuscation_edge_cases.py`, `test_concurrency.py`, `test_audit_log_safety.py`. For the concurrent isolation test, use `asyncio.gather()` to run two sessions simultaneously and assert no data leaks by checking that each session's vault only contains its own entries after both complete. Mark all tests with appropriate pytest markers (`@pytest.mark.security`, `@pytest.mark.obfuscation`, etc.) for the grouped pytest commands in the Quick Eval Reference.

---

## Dimension 5: Critical Thinking (10 points)

### 5.1 README Threat Model (5 pts)

#### EVAL-THINK-001: Threat model depth
Reviewer assesses README section on threat model. Scoring rubric:

| Sub-criterion | Points |
|---|---|
| Identifies LLM provider as threat actor (inference from obfuscated payload) | 1 pt |
| Identifies vault as high-value target; describes vault-specific attacks (memory dump, DB breach) | 1 pt |
| Discusses re-identification risk for pseudonymization | 1 pt |
| Addresses prompt injection via document content | 1 pt |
| Notes audit log as attack surface (tampering or mining) | 1 pt |

---

### 5.2 Design Tradeoff Discussion (3 pts)

#### EVAL-THINK-002: Tokenization vs. pseudonymization comparison
README must compare the two strategies for at least two entity types:

| Sub-criterion | Points |
|---|---|
| Comparison for NAME entity with concrete pros/cons of each approach | 1 pt |
| Comparison for DIAGNOSIS / MEDICATION with reasoning about semantic fidelity vs. safety | 1 pt |
| Conclusion on which strategy to use by default and why | 1 pt |

---

### 5.3 Live Review Q&A Readiness (2 pts)

#### EVAL-THINK-003: Demonstrable understanding of key questions
The following questions from the challenge brief are used in the 45-minute live review. Pre-assessed based on README + code:

| Question | What Earns the Point |
|---|---|
| Q4 (Vault as single point of failure) | README or code shows awareness of KMS key wrapping, WORM audit log, key rotation |
| Q6 (Non-determinism across sessions as security requirement) | README or code comment explains: deterministic global tokens enable linkage attacks across sessions — an adversary who sees two sessions' obfuscated documents can correlate entities |

- **2 pts:** Both questions addressed in README or code comments
- **1 pt:** One addressed
- **0 pts:** Neither addressed

---

## Automated Eval Runner

The following shell script runs all automated eval checks. It is designed to be run from the repo root:

```bash
#!/bin/bash
# eval_runner.sh — Automated evaluation for Secure Context Pipeline

set -e
echo "=== Running Automated Evals ==="

# --- SECURITY EVALS ---
echo "[SEC] Running mypy type check..."
mypy --strict secure_context_pipeline/ || { echo "FAIL: mypy strict mode"; exit 1; }

echo "[SEC] Scanning for hardcoded secrets..."
grep -rn "sk-\|OPENAI_API_KEY\s*=\|anthropic_api_key\s*=" \
  secure_context_pipeline/ --include="*.py" | grep -v ".env" && \
  { echo "FAIL: hardcoded secrets found"; exit 1; } || echo "PASS: no hardcoded secrets"

echo "[SEC] Scanning git history for secrets..."
git log --all -p | grep -i "api_key\s*=\|secret\s*=\|password\s*=" | \
  grep -v ".env.example" | grep -v "os.environ" && \
  { echo "FAIL: secrets in git history"; } || echo "PASS: git history clean"

# --- OBFUSCATION EVALS ---
echo "[OBF] Running PII detection coverage test..."
python -m pytest tests/test_detection.py::test_all_entity_types_detected -v

echo "[OBF] Running tokenization determinism test..."
python -m pytest tests/test_obfuscation.py::test_within_session_determinism -v

echo "[OBF] Running cross-session non-determinism test..."
python -m pytest tests/test_obfuscation.py::test_cross_session_nondeterminism -v

# --- DE-OBFUSCATION EVALS ---
echo "[DEOB] Running round-trip fidelity test..."
python -m pytest tests/test_deobfuscation.py::test_round_trip_all_entities -v

echo "[DEOB] Running inflected token test..."
python -m pytest tests/test_deobfuscation.py::test_inflected_token_handling -v

# --- CODE QUALITY ---
echo "[CODE] Running full test suite..."
python -m pytest tests/ -v --tb=short

echo "[CODE] Running concurrent session isolation test..."
python -m pytest tests/test_concurrency.py -v

# --- PERFORMANCE BENCHMARKS ---
echo "[PERF] Running pipeline benchmarks..."
python -m pytest tests/test_performance.py -v --benchmark-only

# --- PII LEAKAGE SCAN (100 runs) ---
echo "[SECURITY] Running 100-run PII leakage verification..."
python scripts/pii_leakage_scan.py --runs=100 --fixture=tests/fixtures/golden_medical.txt

echo ""
echo "=== Eval Runner Complete ==="
```

---

## Scoring Summary Table

| Eval ID | Dimension | Points | Automated | Description |
|---|---|---|---|---|
| EVAL-SEC-001 | Security | 3 | ✓ | Per-session key uniqueness |
| EVAL-SEC-002 | Security | 3 | ✓ | Cross-session vault isolation |
| EVAL-SEC-003 | Security | 3 | ✓ | Vault at-rest encryption correctness |
| EVAL-SEC-004 | Security | 3 | ✓ | Session key lifecycle + destruction |
| EVAL-SEC-005 | Security | 4 | ✓ | LLM payload PII leak check |
| EVAL-SEC-006 | Security | 3 | ✓ | Pre-call leak gate enforcement |
| EVAL-SEC-007 | Security | 3 | ✓ | Audit log PII scan |
| EVAL-SEC-008 | Security | 4 | Partial | AES-256-GCM correctness |
| EVAL-SEC-009 | Security | 4 | ✓ | No secrets in code/git |
| EVAL-OBF-001 | Obfuscation | 3 | ✓ | Within-session token determinism |
| EVAL-OBF-002 | Obfuscation | 4 | ✓ | Cross-session non-determinism |
| EVAL-OBF-003 | Obfuscation | 3 | ✓ | Token format compliance |
| EVAL-OBF-004 | Obfuscation | 4 | Partial | Pseudonym semantic type preservation |
| EVAL-OBF-005 | Obfuscation | 4 | ✓ | Pseudonym consistency within session |
| EVAL-OBF-006 | Obfuscation | 4 | ✓ | Entity type coverage (all 14 types) |
| EVAL-OBF-007 | Obfuscation | 3 | ✓ | Graceful degradation (low confidence) |
| EVAL-DEOB-001 | De-obfuscation | 4 | ✓ | Complete token restoration |
| EVAL-DEOB-002 | De-obfuscation | 4 | ✓ | Inflected token handling |
| EVAL-DEOB-003 | De-obfuscation | 2 | ✓ | Vault miss handling |
| EVAL-DEOB-004 | De-obfuscation | 4 | ✓ | Non-PII text preservation |
| EVAL-DEOB-005 | De-obfuscation | 3 | ✓ | Pseudonym reverse lookup |
| EVAL-DEOB-006 | De-obfuscation | 3 | ✓ | End-to-end round-trip fidelity |
| EVAL-CODE-001 | Code Quality | 4 | ✓ | mypy strict compliance |
| EVAL-CODE-002 | Code Quality | 3 | Partial | Strategy pattern implementation |
| EVAL-CODE-003 | Code Quality | 2 | ✓ | Detector extensibility |
| EVAL-CODE-004 | Code Quality | 3 | ✓ | Async correctness |
| EVAL-CODE-005 | Code Quality | 3 | ✓ | Test completeness |
| EVAL-THINK-001 | Critical Thinking | 5 | Manual | Threat model depth |
| EVAL-THINK-002 | Critical Thinking | 3 | Manual | Tokenization vs pseudonymization |
| EVAL-THINK-003 | Critical Thinking | 2 | Manual | Live review Q&A readiness |
| **TOTAL** | | **100** | | |

---

## Hard Fails (Any one = Immediate Disqualification)

Regardless of score in other dimensions, the following are automatic failures:

| HF-001 | Any original PII/PHI value found in outbound LLM API payload |
|---|---|
| HF-002 | Any original PII/PHI value found in any audit log entry |
| HF-003 | Any hardcoded API key or secret in code or git history |
| HF-004 | Cross-session vault lookup succeeds (returns another session's data) |
| HF-005 | Low-confidence entity passed through unmasked to LLM |

---

## Live Review Q&A — Model Answers

The following are model answers for the six live review questions (Q1–Q6) listed in the challenge brief. These demonstrate senior-level understanding and are the standard against which verbal responses will be assessed.

### Q1: Why use AES-256-GCM rather than AES-256-CBC for vault storage?

GCM (Galois/Counter Mode) provides authenticated encryption, meaning it produces an authentication tag alongside the ciphertext that detects any tampering with the stored bytes. CBC provides only confidentiality — a malicious insider who can write to the vault database could flip ciphertext bits and cause predictable plaintext changes without detection. For a vault storing sensitive mappings, an attacker who can corrupt ciphertext without triggering an error could cause de-obfuscation to produce wrong — but not obviously wrong — output, which is arguably more dangerous than a visible failure. GCM's built-in integrity check ensures that any tampered ciphertext raises `InvalidTag` on decryption, making corruption immediately visible. Additionally, GCM is parallelizable, which provides better throughput for high-volume vault operations compared to the sequential nature of CBC.

### Q2: Why must the token suffix be generated with `os.urandom` rather than a hash of the original value?

If the token suffix were derived deterministically from the original value (e.g., `sha256(original)[:4]`), tokens would be consistent across sessions — an adversary who observes obfuscated documents from two different sessions could correlate entities by matching token suffixes, even without breaking the encryption. This enables a linkage attack: `[PII_NAME_3f2a]` in session A and `[PII_NAME_3f2a]` in session B would both correspond to the same person, leaking identity information without requiring vault access. Using `os.urandom` ensures tokens are random and session-scoped, so cross-session correlation is cryptographically infeasible. This property is fundamental to the threat model where the LLM provider is considered a potential adversary who could accumulate and correlate obfuscated payloads over time.

### Q3: What is the risk of pseudonymization compared to tokenization for PHI entities like diagnosis codes?

Pseudonymization preserves semantic plausibility — a real medication name in place of the original — which is what enables the LLM to reason meaningfully about clinical context. However, this plausibility is also a re-identification risk: if the pseudonym pool is small (e.g., a list of 50 rare medications), an adversary with domain knowledge can narrow the candidate original values significantly. Tokenization (`[PHI_MEDICATION_3f2a]`) is safer because it carries zero semantic information, but it limits the LLM's ability to reason about drug interactions, dosing, or contraindications. The recommended default for PHI_DIAGNOSIS and PHI_MEDICATION is tokenization when clinical reasoning is not required, and pseudonymization only when the downstream LLM task specifically requires semantic understanding of the clinical entity. This decision should be documented in the threat model and configurable per entity type via the strategy map.

### Q4: The vault is a single point of failure — how would you harden it in production?

Three complementary controls address this. First, wrap the per-session AES key with a KMS-managed master key (AWS KMS, Google Cloud KMS, or Azure Key Vault) — the vault stores only the encrypted session key, so a database breach yields no usable keys without KMS access. Second, implement key rotation: after a configurable number of re-encryptions (e.g., 1,000 vault operations), generate a new session key, re-encrypt all vault entries under the new key, and retire the old one — this limits the blast radius of a compromised key. Third, make the audit log append-only using a WORM (Write Once Read Many) storage backend or a cryptographically chained log (each entry contains the hash of the previous entry), so tampering with audit evidence is detectable. In a high-availability deployment, the vault DB should be replicated with synchronous replication to prevent data loss on node failure.

### Q5: How does the pre-call leak gate interact with partial obfuscation failures?

The leak gate acts as a defense-in-depth layer for scenarios where the obfuscation engine processes entities partially — for example, if a custom Presidio recognizer fails to detect a low-overlap entity type, or if an upstream text-splitting step introduces a new entity span that was not in the originally detected list. The gate calls `verify_no_pii_leak(payload, detected_entities)` immediately before the LLM API call, scanning the fully assembled payload against all known original values. If any original value is found — even one — it raises `PIILeakError` and aborts the call. The key design decision is that the gate checks the assembled payload string directly rather than trusting the obfuscation engine's self-reported results, making it independently verifiable. The logged error includes only the token ID (not the leaked value) so the audit trail is safe even when recording a leak event.

### Q6: Why is cross-session non-determinism a security requirement rather than merely a design preference?

If tokens were globally deterministic (same original value always produces the same token across all sessions and users), an attacker who compromises one user's session vault could use recovered original-to-token mappings to de-obfuscate other sessions' documents — a cross-session oracle attack. Even without vault access, an adversary who controls the LLM endpoint and observes multiple sessions' obfuscated payloads could correlate entities across users by matching token strings, enabling large-scale re-identification. Non-determinism — achieved by scoping the token map to a session with a session-unique key and random token suffix — ensures that `[PII_NAME_a3f2]` in session A and `[PII_NAME_b91f]` in session B are cryptographically unlinkable even if both refer to the same person. This property is what elevates the system from "logically isolated" to "cryptographically isolated," which is the standard required for multi-tenant PHI handling under HIPAA's technical safeguard requirements.

---

## Pre-Submission Checklist

Verify every item below before submitting. No partial credit is given for hard fails, and reviewers will run `eval_runner.sh` in a clean environment.

### Security

- [ ] `pytest tests/ -v -m security` passes with zero failures
- [ ] `mypy --strict secure_context_pipeline/` exits with code 0 and zero errors
- [ ] `grep -rn "sk-\|OPENAI_API_KEY\s*=\|anthropic_api_key\s*=" secure_context_pipeline/ --include="*.py"` returns no matches
- [ ] `git log --all -p | grep -i "api_key\|secret\|password"` returns no matches (or only matches in `.env.example` and `os.environ` references)
- [ ] `.env` is listed in `.gitignore` and is NOT tracked by git (`git ls-files .env` returns empty)
- [ ] `SessionVault.__init__` uses `os.urandom(32)` for key generation — no timestamp, user_id, or other deterministic input
- [ ] `destroy_session()` zeroes the in-memory key bytes and executes `DELETE FROM vault WHERE session_id = ?`
- [ ] All vault encryption uses `AESGCM` from the `cryptography` library with a fresh `os.urandom(12)` nonce per call
- [ ] The pre-call leak gate raises `PIILeakError` before the LLM call when a leak is detected — confirmed by `mock_llm.call_count == 0` in tests
- [ ] No original PII values appear in any audit log field — confirmed by `test_audit_log_pii_scan`

### Obfuscation

- [ ] `pytest tests/ -v -m obfuscation` passes with zero failures
- [ ] All 14 required entity types are detected with confidence >= 0.60 on the golden dataset fixture
- [ ] Within-session token determinism: the same original value in the same session always produces the same token
- [ ] Cross-session non-determinism: the same original value in different sessions produces different tokens
- [ ] All tokens match the regex `\[[A-Z]+_[A-Z]+_[0-9a-f]{8}\]`
- [ ] Low-confidence entities (confidence < 0.60) are replaced with `[REDACTED]` — never passed through unmasked
- [ ] Pseudonyms are semantically plausible for their entity type (real names, real addresses, plausible dates)
- [ ] Pseudonym consistency: the same original value maps to the same pseudonym within a session

### De-obfuscation

- [ ] `pytest tests/ -v -m deobfuscation` passes with zero failures
- [ ] 100% of tokens in the golden dataset mock LLM response are correctly restored
- [ ] Inflected token forms (`[TOKEN]'s`, `[TOKEN]s`) are handled correctly without breaking surrounding text
- [ ] Vault miss tokens are replaced with `[UNAVAILABLE]` — not passed through as raw token strings
- [ ] Non-PII text is bit-for-bit identical after de-obfuscation — confirmed by the text preservation test
- [ ] Pseudonym reverse lookup restores pseudonyms to original values in LLM responses
- [ ] Full round-trip test (`detect → obfuscate → mock LLM echo → deobfuscate`) achieves 100% fidelity

### Code Quality

- [ ] `pytest tests/ -v -m quality` passes with zero failures
- [ ] All 7 required test scenarios have at least one passing test (see EVAL-CODE-005)
- [ ] `ObfuscationEngine` uses the strategy pattern: no `if/else` on strategy type inside the engine
- [ ] Adding a new entity type requires only a YAML config change — no engine or pipeline code changes
- [ ] All database calls use `aiosqlite` or `asyncpg` — `import sqlite3` does not appear in production code
- [ ] All LLM HTTP calls use `httpx.AsyncClient` or `aiohttp` — `import requests` does not appear in production code
- [ ] `time.sleep()` does not appear in async contexts — only `asyncio.sleep()`
- [ ] Concurrent 5-session test completes in under 2x the single-session wall time

### Critical Thinking (README)

- [ ] README contains a Threat Model section that addresses all five sub-criteria (EVAL-THINK-001)
- [ ] README contains a Design Tradeoffs section comparing tokenization vs. pseudonymization for NAME and DIAGNOSIS/MEDICATION entity types with a reasoned conclusion
- [ ] README (or code comments) addresses Q4 (vault hardening: KMS, rotation, WORM audit log)
- [ ] README (or code comments) addresses Q6 (non-determinism as a security requirement, not merely a preference)

### Final Gates (Hard Fails — must all be clean)

- [ ] HF-001: No original PII/PHI value appears in any outbound LLM API payload
- [ ] HF-002: No original PII/PHI value appears in any audit log entry
- [ ] HF-003: No hardcoded API key or secret in code or git history
- [ ] HF-004: Cross-session vault lookup fails — Session B cannot access Session A's data
- [ ] HF-005: No low-confidence entity is passed through unmasked to the LLM

### Run Everything Command (final pre-submission gate)

```bash
pytest tests/ -v --cov=secure_context_pipeline --cov-report=term-missing
```

All tests must pass. Coverage for `secure_context_pipeline/vault.py`, `secure_context_pipeline/obfuscation.py`, and `secure_context_pipeline/deobfuscation.py` must be >= 85%.

---

*YourAI Confidential — Evaluation Framework v2.0*
