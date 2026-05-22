# Product Requirements Document
## Secure Context Pipeline — PII/PHI Obfuscation for External LLM Providers
**Version:** 2.0  
**Status:** Implementation Reference  
**Author:** Senior Engineer Candidate  
**Date:** 2026-05-21  
**Classification:** Confidential — Internal Use Only

---

## Quick Reference for Claude

> **Read this section first.** It contains everything needed to start building without reading the full document.

### What to Build

A Python 3.11+ async pipeline that sits between a document store and an external LLM API. It detects PII/PHI/privileged entities in user documents, replaces them with opaque tokens or plausible pseudonyms before sending to the LLM, stores the mapping in an encrypted per-session vault, and restores original values in the LLM response before returning it to the user. The vault is destroyed on session end — mappings are irrecoverable after that.

### Project Directory Structure

```
secure-context-pipeline/
├── secure_context_pipeline/
│   ├── __init__.py
│   ├── store/
│   │   ├── __init__.py
│   │   └── store.py              # SecureDocumentStore
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── detector.py           # PIIDetector (Presidio + spaCy)
│   │   └── recognizers/          # Custom Presidio recognizers (MRN, legal, etc.)
│   │       ├── __init__.py
│   │       ├── mrn_recognizer.py
│   │       ├── insurance_recognizer.py
│   │       └── legal_recognizer.py
│   ├── obfuscation/
│   │   ├── __init__.py
│   │   ├── strategies/
│   │   │   ├── __init__.py
│   │   │   ├── base.py           # ObfuscationStrategy ABC
│   │   │   ├── tokenization.py   # TokenizationStrategy
│   │   │   └── pseudonymization.py  # PseudonymizationStrategy
│   │   └── engine.py             # ObfuscationEngine (orchestrates)
│   ├── vault/
│   │   ├── __init__.py
│   │   └── vault.py              # SessionVault (AES-256-GCM, per-session key)
│   ├── pipeline/
│   │   ├── __init__.py
│   │   ├── pipeline.py           # SecureContextPipeline (top-level entry point)
│   │   ├── injector.py           # LLMContextInjector
│   │   └── exceptions.py         # PIILeakError, VaultMissError, etc.
│   ├── deobfuscation/
│   │   ├── __init__.py
│   │   └── engine.py             # DeobfuscationEngine
│   ├── audit/
│   │   ├── __init__.py
│   │   └── audit_log.py          # AuditLog
│   └── config.py                 # Pydantic Settings (loads from .env)
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   │   └── golden/               # F-001 through F-009 fixture files + JSON annotations
│   ├── test_detection.py
│   ├── test_obfuscation.py
│   ├── test_vault.py
│   ├── test_deobfuscation.py
│   ├── test_pipeline.py
│   ├── test_performance.py
│   ├── test_golden_dataset.py
│   └── test_edge_cases.py
├── scripts/
│   └── pii_leakage_scan.py       # 100-run PII leakage verification script
├── demo.py                        # End-to-end demo on bundled test document
├── docker-compose.yml
├── Dockerfile
├── pytest.ini
├── .env.example
├── pyproject.toml
└── README.md
```

### All 15 Entity Types

```python
ENTITY_TYPES = {
    # PII — GDPR, CCPA, COPPA
    "PII_NAME":        "NER (spaCy PERSON label)",
    "PII_SSN":         r"Regex: \b\d{3}-\d{2}-\d{4}\b",
    "PII_DOB":         "NER DATE + date-parsing heuristic",
    "PII_ADDRESS":     "NER GPE/LOC + street-pattern regex",
    "PII_EMAIL":       r"Regex: RFC-5322 subset",
    "PII_PHONE":       "Regex: E.164 + US local formats",
    # PHI — HIPAA 45 CFR §§164.308-164.312
    "PHI_MRN":         r"Regex: MRN-\d+ | PT-\d+",
    "PHI_DIAGNOSIS":   "medical NER (scispaCy en_ner_bc5cdr_md)",
    "PHI_MEDICATION":  "medical NER + RxNorm drug lexicon",
    "PHI_INSURANCE_ID":"Regex: carrier prefix patterns",
    "PHI_LAB_RESULT":  "NER + lab-value pattern (value + unit)",
    # Financial PII — GLBA, SOX, PCI-DSS
    "FIN_ACCOUNT":     "Regex + Luhn algorithm check",
    "FIN_TAX_ID":      r"Regex: \b\d{2}-\d{7}\b (EIN)",
    # Legal Privilege — Attorney-Client, Work Product Doctrine
    "LEGAL_CLIENT":    "NER + legal-entity classifier",
    "LEGAL_STRATEGY":  "privilege classifier (settlement/strategy signals)",
}
```

### Token Format

```python
import re
TOKEN_PATTERN = re.compile(r'\[([A-Z]+_[A-Z]+_[0-9a-f]{8})\]')
# Examples:
#   [PII_NAME_a3f2c1d4]
#   [PHI_DIAGNOSIS_2c8a4d7b]
#   [FIN_ACCOUNT_4d7c9a1e]
#   [LEGAL_STRATEGY_9b1e3f7c]
```

### Performance SLAs

- Full pipeline (detect → obfuscate → LLM call → restore) for a 2,000-word doc: **< 15 seconds**
- Obfuscation engine alone (excluding LLM call) for a 2,000-word doc: **< 2 seconds**
- Vault lookup per token (p99): **< 5 ms**
- De-obfuscation of a 500-token LLM response: **< 500 ms**
- Zero PII leakage: **0 leaks across 100 automated test runs**

### 5 Hard Fail Conditions (Automatic Disqualification)

| # | Condition |
|---|---|
| HF-001 | Any original PII/PHI value found in the outbound LLM API payload |
| HF-002 | Any original PII/PHI value found in any audit log entry |
| HF-003 | Any hardcoded API key or secret in source code or git history |
| HF-004 | Cross-session vault lookup succeeds (returns another session's plaintext) |
| HF-005 | Low-confidence entity (< 0.60) passed through unmasked to LLM |

### Required `.env` Variables

```bash
# .env.example — copy to .env and fill in values

# LLM Provider (use one)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
LLM_PROVIDER=anthropic          # "anthropic" | "openai"
LLM_MODEL=claude-3-5-sonnet-20241022

# Storage
VAULT_DB_PATH=./data/vault.db           # SQLite path (dev)
STORE_DB_PATH=./data/documents.db       # Encrypted doc store
STORE_ENCRYPTION_KEY_PATH=./data/master.key  # AES-256 master key file

# Session
SESSION_TIMEOUT_MINUTES=30
CONFIDENCE_THRESHOLD=0.60        # Below this → [REDACTED], not token
OBFUSCATION_STRATEGY=tokenization # "tokenization" | "pseudonymization"

# Logging
LOG_LEVEL=INFO
AUDIT_LOG_PATH=./data/audit.jsonl

# Optional: KMS for production key wrapping
# AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:...
# GCP_KMS_KEY_PATH=projects/.../cryptoKeyVersions/...
```

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Business Context & Problem Statement](#2-business-context--problem-statement)
3. [Users & Personas](#3-users--personas)
4. [Regulatory & Compliance Landscape](#4-regulatory--compliance-landscape)
5. [System Architecture](#5-system-architecture)
6. [Component Specifications](#6-component-specifications)
7. [Data Models & API Contracts](#7-data-models--api-contracts)
8. [Security Threat Model](#8-security-threat-model)
9. [Non-Functional Requirements](#9-non-functional-requirements)
10. [Performance Benchmarks](#10-performance-benchmarks)
11. [Technology Stack & Justifications](#11-technology-stack--justifications)
12. [Implementation Phases](#12-implementation-phases)
13. [Acceptance Criteria](#13-acceptance-criteria)
14. [Known Gaps & Future Work](#14-known-gaps--future-work)
15. [Open Questions](#15-open-questions)

---

## 1. Executive Summary

YourAI is building an AI productivity platform for regulated professionals — physicians, attorneys, financial advisors, and compliance officers. These users work with some of the most sensitive data that exists: medical records, legal case files, and financial disclosures. They require AI assistance, but cannot expose raw PII, PHI, or privileged content to third-party LLM providers.

The **Secure Context Pipeline** is the technical control that enforces this guarantee. It is a system layer that sits between YourAI's document store and any external LLM API. It performs a full round-trip:

```
detect → obfuscate → call LLM → de-obfuscate → restore
```

The pipeline ensures that what leaves YourAI's infrastructure is semantically meaningful but contains zero recoverable PII. What the user sees is fully restored to original values. The vault that holds the mapping is session-scoped, encrypted, and destroyed on logout — making the obfuscation cryptographically irreversible across sessions.

---

## 2. Business Context & Problem Statement

### 2.1 Why Contractual Guarantees Are Insufficient

YourAI uses OpenAI, Anthropic, and other providers as inference backends under zero-data-retention contracts. However:

- **Contractual guarantees are not technical controls.** A contract cannot prevent a misconfigured logging pipeline, a provider-side security incident, or a legal subpoena.
- **Re-identification risk is real.** Even if a provider stores nothing, the data transits their network and model infrastructure in plaintext.
- **Regulatory liability.** Under HIPAA, GLBA, and attorney-client privilege doctrine, unauthorized disclosure — even inadvertent — can constitute a violation regardless of intent.

### 2.2 Core Tension to Resolve

The pipeline must satisfy two opposing requirements simultaneously:

| Requirement | Direction |
|---|---|
| Zero PII/PHI must leave YourAI infrastructure in readable form | Maximally strip semantic content |
| The LLM must reason correctly and return a useful, contextually-grounded response | Preserve enough semantic structure |

The resolution: obfuscate identity while preserving role and context. A name becomes a typed token (`[PII_NAME_a3f2]`) or a demographically-neutral pseudonym (`Michael Torres`). The LLM can still reason about "the patient" without knowing who the patient is.

### 2.3 What This System Is Not

- Not a general-purpose data anonymization service
- Not a cryptographic key management system (though it depends on one)
- Not a replacement for contractual data agreements with LLM providers
- Not a content moderation or access control system

---

## 3. Users & Personas

### 3.1 Primary End Users

| Persona | Domain | Sensitivity | Key Concern |
|---|---|---|---|
| Dr. Sarah Chen, Hospitalist | Healthcare | PHI (diagnoses, meds, MRN) | HIPAA §164.312 — technical safeguards |
| Marcus Webb, M&A Attorney | Legal | Attorney-client privilege, work product | ABA Rule 1.6 — duty of confidentiality |
| Priya Okonkwo, Financial Advisor | Finance | Account numbers, tax IDs, transaction history | GLBA, SEC Rule 17a-4 |
| Raj Patel, Compliance Officer | Cross-domain | All PII types | SOX, CCPA, audit readiness |

### 3.2 Internal Platform Users

- **Platform Engineers:** Deploy and operate the pipeline; require observability without access to PII.
- **Security/Compliance Team:** Audit log consumers; require event records without original values.
- **LLM Integration Team:** Call the pipeline API from product features; must not need to understand obfuscation internals.

---

## 4. Regulatory & Compliance Landscape

### 4.1 Entity Type → Regulatory Mapping

| Entity Type | Examples | Primary Regulations | Key Obligations |
|---|---|---|---|
| PII | Name, SSN, DOB, address, email, phone | GDPR Art. 9, CCPA §1798.100, COPPA | Purpose limitation, deletion rights, breach notification |
| PHI | Diagnoses, medications, MRN, insurance IDs, lab results | HIPAA 45 CFR §§164.308–164.312 | Minimum necessary standard, audit controls, encryption in transit |
| Legal Privilege | Case strategy, client identity, settlement terms, privileged memos | Attorney-Client Privilege, Work Product Doctrine (FRCP 26(b)(3)) | Non-waiver; any disclosure may constitute waiver |
| Financial PII | Account numbers, tax IDs, transaction history | GLBA 15 U.S.C. §6801, SOX, PCI-DSS v4.0 | Safeguards Rule, data minimization, audit trails |

### 4.2 Compliance-Critical Design Constraints

1. **Audit logs must never contain original PII values** — HIPAA §164.312(b) requires audit controls but not the data itself.
2. **Minimum necessary standard (HIPAA)** — Only information required for the AI task should be included; the rest must be redacted.
3. **Vault-as-PHI** — The session vault, because it contains the mapping from token to original PHI, is itself a PHI store and must be protected accordingly.
4. **Breach notification threshold** — A vault compromise that exposes token↔original mappings constitutes a PHI breach under HIPAA §164.400.

---

## 5. System Architecture

### 5.1 High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        YOURAI INFRASTRUCTURE                            │
│                                                                         │
│  ┌─────────────┐     ┌──────────────────┐     ┌───────────────────┐    │
│  │ User Upload │────▶│ Secure Document  │────▶│  PII/PHI Detector │    │
│  │ (PDF/DOCX/  │     │ Store            │     │  (NER + Rules)    │    │
│  │  TXT)       │     │ AES-256-GCM      │     │                   │    │
│  └─────────────┘     │ Per-user vault   │     └────────┬──────────┘    │
│                      └──────────────────┘              │               │
│                                                        ▼               │
│                      ┌──────────────────┐     ┌───────────────────┐    │
│                      │  Session Vault   │◀────│ Obfuscation Engine│    │
│                      │  AES-256-GCM     │     │ Tokenization /    │    │
│                      │  Scoped per      │     │ Pseudonymization  │    │
│                      │  session         │     └────────┬──────────┘    │
│                      └──────────────────┘              │               │
│                                                        ▼               │
│                                               ┌───────────────────┐    │
│                                               │  LLM Context      │    │
│                                               │  Injector         │    │
│                                               └────────┬──────────┘    │
│                                                        │               │
└────────────────────────────────────────────────────────│───────────────┘
                              TRUST BOUNDARY             │
                                                         ▼
                                            ┌────────────────────────┐
                                            │   External LLM API     │
                                            │ (OpenAI / Anthropic)   │
                                            │  Zero raw PII in input │
                                            └────────────┬───────────┘
                              TRUST BOUNDARY             │
┌────────────────────────────────────────────────────────│───────────────┐
│                        YOURAI INFRASTRUCTURE            │               │
│                                                        ▼               │
│                                               ┌───────────────────┐    │
│                                               │ De-obfuscation    │    │
│                      ┌──────────────────┐     │ Engine            │    │
│                      │  Session Vault   │────▶│ Token detection + │    │
│                      │  (same session)  │     │ replacement       │    │
│                      └──────────────────┘     └────────┬──────────┘    │
│                                                        │               │
│                                               ┌────────▼──────────┐    │
│                                               │  Restored Response│    │
│                                               │  (original values)│    │
│                                               └───────────────────┘    │
│                                                                         │
│                      ┌──────────────────────────────────────────────┐  │
│                      │            Audit Log                          │  │
│                      │  (token IDs only — never original values)    │  │
│                      └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Trust Boundary Definition

The trust boundary is the network egress point from YourAI infrastructure. Anything crossing this boundary in either direction is subject to the following invariants:

- **Outbound (to LLM):** No string in the payload matches any entity from the original document. Verification is automated.
- **Inbound (from LLM):** The response may contain token references. It must never be returned to the user without de-obfuscation.

### 5.3 Session Lifecycle

```
Session Created
      │
      ├── Vault initialized (new AES-256-GCM key derived per session)
      │
      ├── [Multiple pipeline runs possible within session]
      │       ├── Detect → Obfuscate → vault.store(token, encrypted(original))
      │       ├── Call LLM (obfuscated payload)
      │       └── De-obfuscate → vault.lookup(token) → restore
      │
Session Destroyed (logout / expiry)
      │
      └── Vault key zeroed from memory + encrypted vault store deleted
              (token ↔ original mapping is permanently inaccessible)
```

---

## 6. Component Specifications

### 6.1 Component 1: Secure Document Store

**Purpose:** Accept user document uploads, encrypt at rest, and retrieve securely.

**Requirements:**
- Accept PDF, DOCX, and TXT file formats
- Encrypt each document with AES-256-GCM before persistence
- Use a per-user encryption key derived from a master key via HKDF (HMAC-based Key Derivation Function)
- Store encrypted blobs only; keys are never persisted alongside data
- Support async read/write operations
- Return a `DocumentID` (UUID) on successful upload
- Reject files exceeding a configurable maximum size (default: 50MB)
- Validate file MIME type; reject mismatches

**Non-requirements:** Full document management (versioning, sharing) — this is a pipeline component, not a DMS.

**Interface:**
```python
class SecureDocumentStore:
    async def upload(self, user_id: str, content: bytes, mime_type: str) -> DocumentID
    async def retrieve(self, user_id: str, doc_id: DocumentID) -> bytes
    async def delete(self, user_id: str, doc_id: DocumentID) -> None
    async def extract_text(self, user_id: str, doc_id: DocumentID) -> str
```

**Implementation Skeleton (`store/store.py`):**
```python
import os, uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import aiosqlite

ALLOWED_MIME_TYPES = {"text/plain", "application/pdf",
                      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB

class SecureDocumentStore:
    def __init__(self, db_path: str, master_key: bytes):
        self._db_path = db_path
        # Derive per-user key via HKDF in real impl; use master_key directly for dev
        self._master_key = master_key  # 32 bytes, AES-256

    def _user_key(self, user_id: str) -> bytes:
        """Derive a stable per-user encryption key from master key + user_id."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=user_id.encode())
        return hkdf.derive(self._master_key)

    async def upload(self, user_id: str, content: bytes, mime_type: str) -> str:
        if mime_type not in ALLOWED_MIME_TYPES:
            raise UnsupportedFileTypeError(mime_type)
        if len(content) > MAX_FILE_BYTES:
            raise FileTooLargeError(len(content))
        key = self._user_key(user_id)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, content, None)
        doc_id = str(uuid.uuid4())
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT INTO documents (doc_id, user_id, encrypted_blob, mime_type) VALUES (?,?,?,?)",
                (doc_id, user_id, nonce + ciphertext, mime_type)
            )
            await db.commit()
        return doc_id

    async def retrieve(self, user_id: str, doc_id: str) -> bytes:
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT encrypted_blob FROM documents WHERE doc_id=? AND user_id=?",
                (doc_id, user_id)
            ) as cursor:
                row = await cursor.fetchone()
        if row is None:
            raise DocumentNotFoundError(doc_id)
        blob = row[0]
        nonce, ciphertext = blob[:12], blob[12:]
        return AESGCM(self._user_key(user_id)).decrypt(nonce, ciphertext, None)

    async def extract_text(self, user_id: str, doc_id: str) -> str:
        content = await self.retrieve(user_id, doc_id)
        # Dispatch on mime_type stored in DB
        # PDF: use pypdf or pdfminer; DOCX: use python-docx; TXT: decode utf-8
        raise NotImplementedError
```

**Common Pitfalls:**
- Never store the user key in the database row alongside the encrypted data — that nullifies encryption.
- Always use a **fresh** `os.urandom(12)` nonce per `encrypt()` call — reusing a nonce with the same key is catastrophic for AES-GCM.
- For PDF extraction, `pypdf` is fastest; for DOCX, use `python-docx`. Both must be async-wrapped via `asyncio.to_thread()`.

**Storage Backend Options (in order of preference):**
1. PostgreSQL with `pgcrypto` + application-layer AES-256-GCM (recommended for production)
2. SQLite + SQLCipher (acceptable for development/local)
3. Encrypted filesystem (S3 + client-side encryption for cloud deployment)

---

### 6.2 Component 2: PII/PHI Detector

**Purpose:** Identify and classify sensitive entities in plaintext before any LLM call.

**Entity Types (Minimum Required):**

| Entity Type | Token Prefix | Examples | Detection Method |
|---|---|---|---|
| `NAME` | `PII_NAME` | "John Smith", "Dr. Sarah Chen" | NER (spaCy/Presidio) |
| `SSN` | `PII_SSN` | "123-45-6789", "123456789" | Regex + checksum |
| `DOB` | `PII_DOB` | "01/15/1985", "January 15, 1985" | Regex + date parsing |
| `ADDRESS` | `PII_ADDRESS` | "123 Main St, Boston, MA 02101" | NER + regex |
| `EMAIL` | `PII_EMAIL` | "john.smith@example.com" | Regex (RFC 5322) |
| `PHONE` | `PII_PHONE` | "(617) 555-1234", "+1-617-555-1234" | Regex + libphonenumber |
| `MRN` | `PHI_MRN` | "MRN-2847651", "PT-001234" | Regex (facility patterns) |
| `DIAGNOSIS` | `PHI_DIAGNOSIS` | "Type 2 Diabetes Mellitus", "Major Depressive Disorder" | NER + medical ontology |
| `MEDICATION` | `PHI_MEDICATION` | "Metformin 500mg", "Lisinopril" | NER + RxNorm lookup |
| `INSURANCE_ID` | `PHI_INSURANCE_ID` | "BCBS-1234567890" | Regex |
| `LAB_RESULT` | `PHI_LAB_RESULT` | "HbA1c: 8.2%", "Creatinine: 1.4 mg/dL" | NER + unit pattern |
| `ACCOUNT_NUMBER` | `FIN_ACCOUNT` | "Acct: 4532-1234-5678-9012" | Regex + Luhn algorithm |
| `TAX_ID` | `FIN_TAX_ID` | "EIN: 12-3456789", "SSN used as TIN" | Regex |
| `CLIENT_IDENTITY` | `LEGAL_CLIENT` | Client names in legal context | NER + legal entity classifier |
| `CASE_STRATEGY` | `LEGAL_STRATEGY` | "Our position is...", "We recommend settling at $X" | Privilege classifier |

**Detection Architecture:**

```
Input Text
    │
    ├──▶ [Rule-Based Recognizers] ─── Regex patterns for SSN, DOB, email, phone, account numbers
    │                                  High precision, low recall — runs first
    │
    ├──▶ [NER Model (spaCy + Presidio)] ─── Named Entity Recognition for PERSON, ORG, GPE, DATE
    │                                        Medium precision, medium recall
    │
    ├──▶ [Medical NER (scispaCy / custom)] ─── Diagnoses, medications, lab values
    │                                           Domain-specialized
    │
    └──▶ [Context Classifier] ─── Legal privilege signals, financial context
                                   Low recall but high precision for edge cases

All detectors → [Ensemble + Deduplication] → [Confidence Scoring]
                                                      │
                              ┌───────────────────────┼──────────────────────────┐
                              ▼                       ▼                          ▼
                    confidence ≥ 0.85        0.60 ≤ confidence < 0.85   confidence < 0.60
                    → Obfuscate              → Obfuscate (safer choice)  → Redact entirely
```

**Technology Choice Justification — Microsoft Presidio:**

Presidio is selected as the primary detection engine over alternatives for the following reasons:

- **spaCy alone** provides NER but lacks domain-specific recognizers for SSN, MRN, account numbers, and medical codes.
- **AWS Comprehend Medical** is excellent for PHI but has latency overhead (network call), cost at scale, and creates a new data-in-transit risk.
- **Presidio** is open-source, runs locally (no data egress), ships with 40+ built-in recognizers covering PII/PHI/financial entities, and supports custom recognizer plugins via a clean interface.
- **Hybrid approach**: Presidio's `AnalyzerEngine` combines NER (spaCy) with regex-based recognizers, allowing the detector config to be extended for new entity types with zero changes to the obfuscation logic — satisfying the extensibility NFR directly.

**Interface:**
```python
@dataclass
class DetectedEntity:
    entity_type: str          # e.g., "PHI_DIAGNOSIS"
    original_value: str       # e.g., "Type 2 Diabetes"
    start: int                # character offset in source text
    end: int                  # character offset in source text
    confidence: float         # 0.0 – 1.0
    detection_method: str     # "regex" | "ner" | "classifier"

class PIIDetector:
    async def detect(self, text: str, context_hint: str | None = None) -> list[DetectedEntity]
    async def detect_with_spans(self, text: str) -> AnnotatedDocument
```

**Implementation Skeleton (`detection/detector.py`):**
```python
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
import asyncio

PRESIDIO_TO_ENTITY_TYPE: dict[str, str] = {
    "PERSON":           "PII_NAME",
    "US_SSN":           "PII_SSN",
    "DATE_TIME":        "PII_DOB",        # use context filter for DOB specifically
    "LOCATION":         "PII_ADDRESS",
    "EMAIL_ADDRESS":    "PII_EMAIL",
    "PHONE_NUMBER":     "PII_PHONE",
    "US_BANK_NUMBER":   "FIN_ACCOUNT",
    "US_ITIN":          "FIN_TAX_ID",
    # Custom recognizers — registered in RecognizerRegistry:
    "MRN":              "PHI_MRN",
    "INSURANCE_ID":     "PHI_INSURANCE_ID",
    "DIAGNOSIS":        "PHI_DIAGNOSIS",
    "MEDICATION":       "PHI_MEDICATION",
    "LAB_RESULT":       "PHI_LAB_RESULT",
    "LEGAL_CLIENT":     "LEGAL_CLIENT",
    "LEGAL_STRATEGY":   "LEGAL_STRATEGY",
}
CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.60"))

class PIIDetector:
    def __init__(self) -> None:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
        })
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()
        # TODO: register custom recognizers here
        # registry.add_recognizer(MRNRecognizer())
        self._engine = AnalyzerEngine(
            nlp_engine=provider.create_engine(), registry=registry
        )

    async def detect(self, text: str, context_hint: str | None = None) -> list[DetectedEntity]:
        # CPU-bound — always offload to thread pool to keep event loop unblocked
        results = await asyncio.to_thread(self._engine.analyze, text=text, language="en")
        entities = []
        for r in results:
            entity_type = PRESIDIO_TO_ENTITY_TYPE.get(r.entity_type)
            if entity_type is None:
                continue
            entities.append(DetectedEntity(
                entity_type=entity_type,
                original_value=text[r.start:r.end],
                start=r.start, end=r.end,
                confidence=r.score,
                detection_method="presidio",
            ))
        return entities
```

**Common Pitfalls:**
- `AnalyzerEngine.analyze()` is **synchronous and CPU-intensive** — always wrap in `asyncio.to_thread()`, never call directly from an async function.
- Presidio's built-in `DATE_TIME` fires on all dates. Add a context-window check (nearby words: "born", "DOB", "date of birth", "birthday") before mapping to `PII_DOB`.
- Install: `pip install presidio-analyzer presidio-anonymizer && python -m spacy download en_core_web_lg`

**Graceful Degradation:** If `confidence < 0.60`, the entity is replaced with `[REDACTED]` rather than passed through unmasked. This is a hard rule with no override.

---

### 6.3 Component 3: Obfuscation Engine

**Purpose:** Replace detected entities with either typed tokens or demographically-neutral pseudonyms, and coordinate with the Session Vault.

**Strategy A: Tokenization**

Replace each entity with a typed, random token that is meaningless outside the vault context.

Token format: `[{ENTITY_TYPE}_{random_hex_8}]`

Examples:
- `"John Smith"` → `[PII_NAME_a3f2c1d4]`
- `"123-45-6789"` → `[PII_SSN_7b3e9f1a]`
- `"Type 2 Diabetes"` → `[PHI_DIAGNOSIS_2c8a4d7b]`

Properties:
- **Deterministic within a session:** The same original value always maps to the same token within a session (idempotent obfuscation prevents token explosion).
- **Non-deterministic across sessions:** A new session generates a new random hex suffix, so the same SSN produces a different token in Session B than Session A.
- **Type-preserving:** Token prefix encodes entity type, allowing the LLM to reason about the entity category without knowing the value.
- **Opaque:** The random suffix has no relationship to the original value. Given only the token, the original is irrecoverable.

**Strategy B: Pseudonymization**

Replace each entity with a plausible but fictional value of the same type.

Examples:
- `"John Smith"` → `"Michael Torres"` (same linguistic role; different identity)
- `"123 Main St, Boston, MA"` → `"456 Oak Ave, Portland, OR"` (same structural role; different location)
- `"Metformin 500mg"` → `"Lisinopril 10mg"` (same semantic role: medication; different drug)

Properties:
- **Richer semantic context:** The LLM receives a value it can reason about naturally, without needing to understand token syntax.
- **Higher LLM output quality** for tasks that require reasoning about specific values (e.g., "Is this dosage appropriate?").
- **Harder to de-obfuscate without vault:** A pseudonym looks like a real value, providing cover.
- **Risk:** A sufficiently sophisticated adversary who can see both the obfuscated document and the LLM response may be able to infer the real entity if the pseudonym is contextually implausible.

**Strategy Selection by Entity Type:**

| Entity Type | Recommended Strategy | Rationale |
|---|---|---|
| NAME | Pseudonymization | LLM reasons better about people than opaque tokens |
| SSN, MRN, Account Number | Tokenization | No semantic value to preserve; tokens are safer |
| DOB | Pseudonymization (shift ±3–7 years) | Age range matters for medical reasoning |
| DIAGNOSIS, MEDICATION | Tokenization | Substituting wrong drug/diagnosis corrupts reasoning |
| ADDRESS | Pseudonymization (same city/state) | Location context sometimes needed |
| EMAIL, PHONE | Tokenization | No semantic value to preserve |
| CASE_STRATEGY | Tokenization | Do not risk substituting real legal concepts |

**Idempotency Guarantee:**
```
If vault.lookup_by_original(entity_type, original_value) exists:
    → Return existing token (same value maps to same token within session)
Else:
    → Generate new token, store in vault, return new token
```

**Interface:**
```python
class ObfuscationStrategy(ABC):
    @abstractmethod
    async def obfuscate(
        self,
        entity: DetectedEntity,
        vault: SessionVault,
        session_id: str
    ) -> str  # returns the replacement string

class TokenizationStrategy(ObfuscationStrategy): ...
class PseudonymizationStrategy(ObfuscationStrategy): ...

class ObfuscationEngine:
    def __init__(self, strategy_map: dict[str, ObfuscationStrategy]): ...
    async def obfuscate_document(
        self,
        text: str,
        entities: list[DetectedEntity],
        vault: SessionVault,
        session_id: str
    ) -> ObfuscatedDocument
```

**Implementation Skeleton (`obfuscation/engine.py`):**
```python
import re
from .strategies.base import ObfuscationStrategy

CONFIDENCE_THRESHOLD = 0.60

class ObfuscationEngine:
    def __init__(self, strategy_map: dict[str, ObfuscationStrategy]) -> None:
        # Maps entity_type → strategy; e.g. {"PII_NAME": PseudonymizationStrategy()}
        self._strategy_map = strategy_map

    async def obfuscate_document(
        self, text: str, entities: list[DetectedEntity],
        vault: SessionVault, session_id: str
    ) -> ObfuscatedDocument:
        # Sort by start offset descending so replacements don't shift later offsets
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        result = text
        token_manifest: list[str] = []

        for entity in sorted_entities:
            if entity.confidence < CONFIDENCE_THRESHOLD:
                # Graceful degradation — redact entirely, never pass through
                result = result[:entity.start] + "[REDACTED]" + result[entity.end:]
                continue

            # Idempotency: reuse existing token/pseudonym if already stored
            existing = await vault.lookup_by_original(session_id, entity.entity_type, entity.original_value)
            if existing:
                replacement = existing
            else:
                strategy = self._strategy_map.get(entity.entity_type)
                if strategy is None:
                    # Unknown entity type — safe fallback is redaction
                    replacement = "[REDACTED]"
                else:
                    replacement = await strategy.obfuscate(entity, vault, session_id)
            result = result[:entity.start] + replacement + result[entity.end:]
            if replacement != "[REDACTED]":
                token_manifest.append(replacement)

        return ObfuscatedDocument(
            obfuscated_text=result,
            entity_count=len(entities),
            token_manifest=token_manifest,
            session_id=session_id,
        )
```

**Implementation Skeleton (`obfuscation/strategies/tokenization.py`):**
```python
import os, uuid
from .base import ObfuscationStrategy

class TokenizationStrategy(ObfuscationStrategy):
    async def obfuscate(self, entity: DetectedEntity, vault: SessionVault, session_id: str) -> str:
        suffix = os.urandom(4).hex()  # 8 hex chars, non-deterministic across sessions
        token = f"[{entity.entity_type}_{suffix}]"
        await vault.store(session_id, token, entity.original_value, entity.entity_type)
        return token
```

**Implementation Skeleton (`obfuscation/strategies/pseudonymization.py`):**
```python
from faker import Faker
from .base import ObfuscationStrategy

# Seed Faker per session for consistency within session; reseed per new session
_session_fakers: dict[str, Faker] = {}

def _get_faker(session_id: str) -> Faker:
    if session_id not in _session_fakers:
        import random
        seed = random.SystemRandom().randint(0, 2**32)
        _session_fakers[session_id] = Faker(seed=seed)
    return _session_fakers[session_id]

PSEUDONYM_GENERATORS = {
    "PII_NAME":    lambda f: f.name(),
    "PII_ADDRESS": lambda f: f.address().replace("\n", ", "),
    "PII_DOB":     lambda f: f.date_of_birth(minimum_age=18, maximum_age=85).strftime("%B %d, %Y"),
    "PII_EMAIL":   lambda f: f.email(),
    "PII_PHONE":   lambda f: f.phone_number(),
}

class PseudonymizationStrategy(ObfuscationStrategy):
    async def obfuscate(self, entity: DetectedEntity, vault: SessionVault, session_id: str) -> str:
        faker = _get_faker(session_id)
        gen = PSEUDONYM_GENERATORS.get(entity.entity_type)
        if gen is None:
            # Fall back to tokenization for types without a pseudonym generator
            from .tokenization import TokenizationStrategy
            return await TokenizationStrategy().obfuscate(entity, vault, session_id)
        pseudonym = gen(faker)
        # Store pseudonym as the "token" — reverse lookup works the same way
        await vault.store(session_id, pseudonym, entity.original_value, entity.entity_type)
        return pseudonym
```

**Common Pitfalls:**
- Sort entities by `start` descending before replacement — otherwise replacing an earlier span shifts all subsequent character offsets.
- `lookup_by_original` must be called before generating a new token to enforce idempotency.
- `DIAGNOSIS` and `MEDICATION` should default to tokenization (not pseudonymization) — substituting a wrong drug or wrong diagnosis corrupts LLM reasoning.

---

### 6.4 Component 4: Session Vault

**Purpose:** Store the bidirectional token ↔ original mapping, scoped to a user session. Vault entries are encrypted. The vault is the cryptographic heart of the pipeline.

**Security Properties:**
1. **Per-session key derivation:** Each session generates a new AES-256-GCM key using `os.urandom(32)`. The key is held in memory only during the session.
2. **At-rest encryption:** Vault entries are stored encrypted with the session key. The key itself is either (a) held in memory or (b) wrapped by a user-specific master key stored in a KMS.
3. **Session isolation:** Session A's key cannot decrypt Session B's vault. Even for the same user.
4. **Destruction guarantee:** On session end, the in-memory key is zeroed (`ctypes.memset`) and the vault store entry is deleted.
5. **Reverse lookup support:** The vault supports lookup by token (for de-obfuscation) and optionally by original value (for idempotent obfuscation).

**Data Model:**
```python
@dataclass
class VaultEntry:
    token: str              # e.g., "[PII_NAME_a3f2c1d4]"
    entity_type: str        # e.g., "PII_NAME"
    encrypted_original: bytes   # AES-256-GCM encrypted original value
    created_at: datetime
    session_id: str
    # original_value is NEVER stored in plaintext

class SessionVault:
    async def store(self, session_id: str, token: str, original: str, entity_type: str) -> None
    async def lookup_by_token(self, session_id: str, token: str) -> str  # decrypts + returns original
    async def lookup_by_original(self, session_id: str, entity_type: str, original: str) -> str | None
    async def destroy(self, session_id: str) -> None
    async def list_tokens(self, session_id: str) -> list[str]  # for audit; no originals
```

**Implementation Skeleton (`vault/vault.py`):**
```python
import os, ctypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import aiosqlite

class VaultMissError(Exception): ...

class SessionVault:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        # {session_id: bytearray(32)} — bytearray so we can zero it on destroy
        self._keys: dict[str, bytearray] = {}

    async def create_session(self, session_id: str) -> None:
        """Generate a fresh AES-256 key for this session. Store in memory only."""
        self._keys[session_id] = bytearray(os.urandom(32))
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "CREATE TABLE IF NOT EXISTS vault "
                "(session_id TEXT, token TEXT PRIMARY KEY, entity_type TEXT, "
                " encrypted_original BLOB, created_at TEXT)"
            )
            await db.commit()

    def _aesgcm(self, session_id: str) -> AESGCM:
        key = self._keys.get(session_id)
        if key is None:
            raise VaultMissError(f"No key for session {session_id} — destroyed or never created")
        return AESGCM(bytes(key))

    async def store(self, session_id: str, token: str, original: str, entity_type: str) -> None:
        nonce = os.urandom(12)
        blob = nonce + self._aesgcm(session_id).encrypt(nonce, original.encode(), None)
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT OR IGNORE INTO vault VALUES (?,?,?,?,datetime('now'))",
                (session_id, token, entity_type, blob)
            )
            await db.commit()

    async def lookup_by_token(self, session_id: str, token: str) -> str:
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT encrypted_original FROM vault WHERE session_id=? AND token=?",
                (session_id, token)
            ) as cur:
                row = await cur.fetchone()
        if row is None:
            raise VaultMissError(token)
        blob: bytes = row[0]
        return self._aesgcm(session_id).decrypt(blob[:12], blob[12:], None).decode()

    async def lookup_by_original(self, session_id: str, entity_type: str, original: str) -> str | None:
        """Return existing token if this (entity_type, original) was already stored."""
        tokens = await self.list_tokens(session_id)
        for token in tokens:
            try:
                value = await self.lookup_by_token(session_id, token)
                if value == original:
                    return token
            except VaultMissError:
                continue
        return None

    async def destroy(self, session_id: str) -> None:
        """Zero the in-memory key and delete all DB rows for this session."""
        key = self._keys.pop(session_id, None)
        if key is not None:
            # Overwrite memory — prevents key recovery from heap snapshots
            ctypes.memset((ctypes.c_char * len(key)).from_buffer(key), 0, len(key))
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("DELETE FROM vault WHERE session_id=?", (session_id,))
            await db.commit()

    async def list_tokens(self, session_id: str) -> list[str]:
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT token FROM vault WHERE session_id=?", (session_id,)
            ) as cur:
                rows = await cur.fetchall()
        return [r[0] for r in rows]
```

**Common Pitfalls:**
- `lookup_by_original` is O(n) in the number of vault entries. For production, add a `hashed_original` column (HMAC-SHA256 of original with session key) for O(1) reverse lookup without storing plaintext.
- `ctypes.memset` on a `bytearray` is the reliable way to zero memory in CPython. Do not rely on `del key` — Python GC doesn't guarantee immediate memory wipe.
- `INSERT OR IGNORE` ensures idempotency: the same token is never duplicated for the same original value within a session.

**Storage Backend:** SQLite + aiosqlite (dev) / asyncpg + PostgreSQL (production). Vault table contains only: `session_id`, `token`, `entity_type`, `encrypted_original`, `created_at`. No plaintext column ever.

**Key Wrapping Architecture (Production):**
```
Session Key (AES-256) ──▶ Encrypt with User Master Key ──▶ Store wrapped key in KMS
                                                            (AWS KMS / GCP KMS)
```
For local/dev: session key held in memory, never persisted.

---

### 6.5 Component 5: LLM Context Injector

**Purpose:** Assemble the obfuscated document into a context payload and call the external LLM API. The raw document content must never appear in this call.

**Invariants:**
- The outbound payload must contain zero instances of original PII/PHI values.
- This invariant is verified programmatically before each LLM call using a `PIILeakChecker` that scans the payload against the list of original values from the current session vault.
- If a leak is detected, the call is aborted and an error is raised. The original values are never logged.

**Context Assembly:**
```python
@dataclass
class LLMContextPayload:
    system_prompt: str       # Static system prompt (no user data)
    obfuscated_context: str  # Document with all PII replaced by tokens/pseudonyms
    user_query: str          # User's question (also checked for PII)
    session_id: str          # For vault correlation

class LLMContextInjector:
    async def build_payload(
        self,
        obfuscated_doc: ObfuscatedDocument,
        user_query: str,
        session_id: str
    ) -> LLMContextPayload
    
    async def call_llm(
        self,
        payload: LLMContextPayload,
        provider: str  # "openai" | "anthropic"
    ) -> LLMResponse
    
    async def verify_no_pii_leak(
        self,
        payload: LLMContextPayload,
        vault: SessionVault,
        session_id: str
    ) -> None  # raises PIILeakError if any original value detected
```

**System Prompt Strategy:** The LLM is instructed to preserve token references exactly as-is:
```
System: You are a helpful AI assistant. The document you are given has been 
processed for privacy. Some values have been replaced with tokens like [PII_NAME_xxxx] 
or pseudonyms. When referring to these entities in your response, use the exact token 
or pseudonym as given. Do not attempt to guess or reconstruct original values.
```

---

### 6.6 Component 6: De-obfuscation Engine

**Purpose:** Parse the LLM response, detect all token references, look them up in the session vault, and restore original values before the user sees the output.

**Token Detection:**

The engine uses a regex pattern anchored to the token format:
```python
TOKEN_PATTERN = re.compile(r'\[([A-Z]+_[A-Z]+_[0-9a-f]{8})\]')
```

For pseudonymized entities, the engine also maintains a reverse lookup table (pseudonym → token → original) within the vault, allowing it to catch cases where the LLM echoes the pseudonym back.

**Handling Grammatical Inflection:**

The LLM may modify token references in grammatically natural ways:
- `[PII_NAME_a3f2]'s` → possessive
- `[PHI_DIAGNOSIS_x7a]es` → plural

The engine normalizes these before lookup:
```python
def normalize_token(text: str) -> str:
    # Strip possessive 's, plural s, etc.
    return re.sub(r"'s$|s$", "", text.strip("[]")).strip()
```

**Co-reference Handling (Partial):**

If the LLM produces a phrase like "the patient's condition" without using the token, this is a **co-reference** — an indirect reference to an obfuscated entity. Full co-reference resolution is out of scope for v1 but is flagged as a known gap (see Section 14). The de-obfuscation engine logs these cases when detectable.

**Fault Behavior:**

If a token appears in the LLM response but is not found in the vault (e.g., the session expired mid-call):
- **Default:** Replace the token with `[UNAVAILABLE]` — never pass unresolved tokens to the user.
- **Log:** Record the vault miss as an audit event with the token ID only.
- **Do not:** Raise an exception that halts the entire response.

**Interface:**
```python
@dataclass
class DeobfuscatedResponse:
    restored_text: str
    tokens_restored: int
    tokens_missed: int          # vault misses
    unresolved_tokens: list[str]  # tokens not found (IDs only)

class DeobfuscationEngine:
    async def deobfuscate(
        self,
        llm_response: str,
        vault: SessionVault,
        session_id: str
    ) -> DeobfuscatedResponse
```

---

### 6.7 Component 7: Audit Log

**Purpose:** Provide a tamper-evident record of every obfuscation and de-obfuscation event for compliance and forensic purposes.

**Hard Requirements:**
- **Never log original values.** Only token IDs, entity types, session IDs, and timestamps.
- Log every obfuscation event (entity detected and replaced).
- Log every de-obfuscation event (token looked up and restored).
- Log vault destruction events (session end).
- Log PII leak detection events (aborted LLM calls).
- Log vault miss events (token not found during de-obfuscation).

**Log Entry Schema:**
```python
@dataclass
class AuditEvent:
    event_id: str           # UUID
    timestamp: datetime     # UTC
    session_id: str
    user_id: str
    event_type: AuditEventType  # OBFUSCATE | DEOBFUSCATE | VAULT_DESTROYED | PII_LEAK_DETECTED | VAULT_MISS
    entity_type: str | None     # e.g., "PHI_DIAGNOSIS" — never the value
    token_id: str | None        # e.g., "[PHI_DIAGNOSIS_x7a]" — never the original
    document_id: str | None
    strategy_used: str | None   # "tokenization" | "pseudonymization"
    confidence_score: float | None
    metadata: dict[str, str]    # Additional context (no PII)
```

**Audit Log Backend:** Append-only database table or structured log file. Consider write-once storage (WORM) for HIPAA compliance.

**HIPAA Audit Requirements Mapping:**

| HIPAA Requirement | Audit Log Coverage |
|---|---|
| §164.312(b) — Audit controls | ✓ All access and modification events logged |
| §164.308(a)(1)(ii)(D) — Information system activity review | ✓ Session-level activity with timestamps |
| §164.312(c)(1) — Integrity | ✓ Token IDs enable integrity verification without re-exposing data |
| §164.312(e)(1) — Transmission security | ✓ PII_LEAK_DETECTED events confirm enforcement |

---

## 7. Data Models & API Contracts

### 7.1 Core Data Types

```python
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid

class EntityType(str, Enum):
    # PII
    PII_NAME = "PII_NAME"
    PII_SSN = "PII_SSN"
    PII_DOB = "PII_DOB"
    PII_ADDRESS = "PII_ADDRESS"
    PII_EMAIL = "PII_EMAIL"
    PII_PHONE = "PII_PHONE"
    # PHI
    PHI_MRN = "PHI_MRN"
    PHI_DIAGNOSIS = "PHI_DIAGNOSIS"
    PHI_MEDICATION = "PHI_MEDICATION"
    PHI_INSURANCE_ID = "PHI_INSURANCE_ID"
    PHI_LAB_RESULT = "PHI_LAB_RESULT"
    # Financial PII
    FIN_ACCOUNT = "FIN_ACCOUNT"
    FIN_TAX_ID = "FIN_TAX_ID"
    # Legal Privilege
    LEGAL_CLIENT = "LEGAL_CLIENT"
    LEGAL_STRATEGY = "LEGAL_STRATEGY"

class ObfuscationStrategyType(str, Enum):
    TOKENIZATION = "tokenization"
    PSEUDONYMIZATION = "pseudonymization"
    REDACTION = "redaction"  # fallback for low-confidence entities

@dataclass
class DetectedEntity:
    entity_type: EntityType
    original_value: str
    start: int
    end: int
    confidence: float
    detection_method: str

@dataclass
class ObfuscatedDocument:
    original_doc_id: str
    session_id: str
    obfuscated_text: str
    entity_count: int
    strategy_used: ObfuscationStrategyType
    token_manifest: list[str]  # list of tokens (no originals)

@dataclass
class LLMResponse:
    raw_response: str
    provider: str
    model: str
    usage: dict[str, int]
    session_id: str

@dataclass
class PipelineResult:
    session_id: str
    document_id: str
    user_query: str
    restored_response: str
    entities_detected: int
    entities_obfuscated: int
    tokens_restored: int
    pipeline_duration_ms: float
    audit_event_ids: list[str]
```

### 7.2 Pipeline API

```python
class SecureContextPipeline:
    """
    The top-level orchestrator. This is the only entry point that
    product code should call. All other components are internal.
    """
    
    async def run(
        self,
        user_id: str,
        session_id: str,
        document_id: str,
        user_query: str,
        strategy: ObfuscationStrategyType = ObfuscationStrategyType.TOKENIZATION,
        provider: str = "anthropic"
    ) -> PipelineResult
    
    async def create_session(self, user_id: str) -> str  # returns session_id
    
    async def destroy_session(self, session_id: str) -> None  # vault destroyed
    
    async def upload_document(
        self,
        user_id: str,
        content: bytes,
        mime_type: str
    ) -> str  # returns document_id
```

---

## 8. Security Threat Model

### 8.1 Assets Under Protection

| Asset | Value | Location |
|---|---|---|
| Original PII/PHI values | Highest — direct regulatory liability | Document store, session vault |
| Session Vault | High — contains token↔original mappings (PHI store) | In-memory during session + encrypted at rest |
| Session Keys | High — decrypts vault | Memory only (never persisted in plaintext) |
| Audit Log | Medium — compliance record | Append-only store |
| Obfuscated Documents | Low — meaningless without vault | Sent to LLM provider |

### 8.2 Threat Actors & Attack Vectors

**T1: LLM Provider as Adversary**
- Attack: Provider logs or retains outbound payloads; attempts to extract PII.
- Mitigation: Tokens and pseudonyms contain zero recoverable PII. Token format provides no entropy for brute force.
- Residual risk: Co-reference leakage (see Known Gaps).

**T2: Network Intermediary**
- Attack: Man-in-the-middle intercepts API traffic.
- Mitigation: TLS 1.3 for all outbound calls. Certificate pinning in production.
- Residual risk: TLS termination at provider edge.

**T3: Compromised Session Vault**
- Attack: Attacker gains read access to vault store (database breach, backup theft).
- Mitigation: Vault entries are AES-256-GCM encrypted with in-memory session key. Ciphertext without key is useless.
- Residual risk: If attacker also captures the in-memory key (e.g., memory dump during session), the vault is decryptable. Key should be stored in HSM or KMS in production.

**T4: Cross-Session Vault Access**
- Attack: User A attempts to use Session B's tokens to re-identify Session B's data.
- Mitigation: Each session has an independent key. Vault entries are keyed by session_id. Cross-session lookup returns a cryptographic error, not data.

**T5: Inference Attack via LLM Output**
- Attack: Adversary has obfuscated document + LLM response. Uses the LLM's reasoning to infer the original entity.
- Example: LLM says "The dosage of [PHI_MEDICATION_x7a] may be too high for a patient with [PHI_DIAGNOSIS_b3c]" — adversary knows these two conditions co-occur, narrowing the identity.
- Mitigation: Tokenization removes direct identification. Pseudonymization with plausible-but-incorrect values adds noise.
- Residual risk: Cannot fully prevent inference attacks against de-anonymized data at the population level (the "re-identification" problem). This is a known limitation.

**T6: Prompt Injection via Document Content**
- Attack: A maliciously crafted document instructs the LLM to reveal tokens or ignore system prompt constraints.
- Mitigation: System prompt is separate from document content. Content is sandwiched between clear delimiters. Future: LLM output monitoring for injection indicators.

**T7: Audit Log Tampering**
- Attack: Insider threat attempts to delete audit records covering a data exposure event.
- Mitigation: Write-once (WORM) audit storage. Signed log entries in production.
- Residual risk: WORM enforcement depends on storage backend.

**T8: Logging of Original Values**
- Attack: Misconfigured logger emits original PII values to a log aggregation system.
- Mitigation: Hard rule — all logging paths receive only token IDs. Enforced by code review + automated test (grep-based scan of log output for known fixture PII values).

---

## 9. Non-Functional Requirements

| NFR | Requirement | Verification Method |
|---|---|---|
| Extensibility | Adding a new entity type requires only a new recognizer config entry — zero changes to obfuscation, vault, or pipeline logic | Code review: add `PASSPORT_NUMBER` in config only; all tests pass |
| Strategy swappability | Switching between tokenization and pseudonymization requires only a config change, not code changes | Integration test: run same document with both strategies via config flag |
| Zero PII in transit | Network traffic inspection of outbound LLM API call shows no recognizable PII/PHI | Automated scan of API payload against entity ground truth |
| Vault isolation | Session A vault cryptographically inaccessible to Session B | Test: attempt cross-session vault lookup; verify failure |
| Graceful degradation | Sub-threshold confidence entities are redacted, not passed through | Test: inject low-confidence entity; verify `[REDACTED]` in output |
| Async pipeline | All I/O operations are non-blocking (asyncio) | Profiling: no blocking calls; concurrent pipeline runs scale linearly |
| Secrets hygiene | No keys or secrets in code, git history, or logs | Static analysis + git pre-commit hook |
| Logging safety | Logs never contain original PII values | Automated log scan test after every pipeline run |

---

## 10. Performance Benchmarks

| Benchmark | Target | Measurement Method |
|---|---|---|
| Full pipeline (2,000-word doc) | < 15 seconds end-to-end | `pytest-benchmark`, includes LLM call latency |
| Obfuscation engine alone (2,000-word doc) | < 2 seconds | `pytest-benchmark`, LLM call excluded |
| Vault lookup per token | < 5ms | Isolated vault benchmark, p99 |
| De-obfuscation of 500-token LLM response | < 500ms | `pytest-benchmark` |
| Zero PII leakage | 0 leaks across 100 automated test runs | Automated fixture scan |
| Concurrent sessions | 10 concurrent sessions without degradation | `asyncio` concurrency test |

---

## 11. Technology Stack & Justifications

| Component | Technology | Justification |
|---|---|---|
| Language | Python 3.11+ | Required; asyncio native since 3.10; 3.11 faster |
| PII Detection | Microsoft Presidio + scispaCy | Local execution, 40+ built-in recognizers, extensible via config, medical NER support |
| NER Model | en_core_web_lg (spaCy) | Best balance of accuracy vs. speed for general NER |
| Medical NER | en_ner_bc5cdr_md (scispaCy) | Trained on biomedical corpus; diagnoses + medications |
| Encryption | Python `cryptography` library (AES-256-GCM) | Industry standard; no homebrew crypto; authenticated encryption prevents tampering |
| Session Vault Store | SQLite + aiosqlite (dev) / asyncpg + PostgreSQL (prod) | SQLite for reproducible local setup; PostgreSQL for production scale |
| LLM Provider | Anthropic Claude API (primary) / OpenAI (secondary) | Provider-agnostic adapter pattern; key via env var |
| Pseudonym Generation | Faker library (seeded per session, reset per entity type) | Deterministic within session, type-aware, locale-appropriate |
| Testing | pytest + pytest-asyncio + pytest-benchmark | Required; benchmark plugin for perf tests |
| Containerization | Docker + docker-compose | Reproducible setup; required by spec |
| Configuration | python-dotenv + Pydantic settings | Type-safe config; env var isolation |

---

## 12. Implementation Phases

### Phase 0: Skeleton & Interfaces (Hour 1)
- Define all dataclasses and abstract base classes
- Set up project structure per spec
- Docker compose with SQLite service
- `.env.example` with all required vars

### Phase 1: Secure Store + Detector (Hours 2-3)
- Implement `SecureDocumentStore` with AES-256-GCM
- Implement `PIIDetector` with Presidio + custom recognizers
- Unit tests for both components
- Golden dataset validation (see golden dataset doc)

### Phase 2: Obfuscation Engine + Session Vault (Hours 3-5)
- Implement `SessionVault` with per-session key isolation
- Implement `TokenizationStrategy` and `PseudonymizationStrategy`
- Implement `ObfuscationEngine` orchestrator
- Idempotency tests; cross-session isolation tests

### Phase 3: LLM Integration + De-obfuscation (Hours 5-7)
- Implement `LLMContextInjector` with pre-call PII leak check
- Implement `DeobfuscationEngine` with token normalization
- Integration test: full round-trip with mocked LLM
- Performance benchmarks

### Phase 4: Audit Log + Pipeline Orchestration (Hours 7-8)
- Implement `AuditLog` with schema above
- Implement `SecureContextPipeline` top-level orchestrator
- Demo script end-to-end
- README with threat model and tradeoffs

### Phase 5: Polish & Documentation (Hours 8-10)
- Docker compose polish
- Full test suite run + benchmark results in README
- Edge case coverage: expired session, vault miss, concurrent sessions
- README threat model discussion with live review Q&A prep

---

## 13. Acceptance Criteria

### 13.1 Functional Must-Haves (All must be ✓)

| # | Criterion | Verification |
|---|---|---|
| F1 | Document containing PII/PHI uploaded, stored encrypted, retrievable only with correct user key | Test: attempt retrieve with wrong key → failure |
| F2 | All specified entity types detected with labeled spans before any LLM call | Test: fixture doc → entity list matches ground truth |
| F3 | Outbound LLM API payload contains zero instances of original PII/PHI — verifiable by inspection | Test: scan payload against entity list → zero matches |
| F4 | LLM response tokens fully restored to original values in user-visible output | Test: mock LLM echoes all tokens → restored output equals original values |
| F5 | Session vault destroyed on logout; subsequent sessions cannot access prior vault mappings | Test: destroy session → new session lookup of old token → VaultMissError |
| F6 | Audit log captures all obfuscation events with no original values present | Test: scan audit log for any fixture PII values → zero matches |
| F7 | End-to-end pipeline runs successfully on provided test fixture document | Demo script runs clean |

### 13.2 Code Quality Checks

| # | Check | Automated? |
|---|---|---|
| C1 | All public interfaces fully type-annotated | mypy --strict |
| C2 | Obfuscation strategies implement shared base class | isinstance check in harness |
| C3 | All secrets via environment variables | grep for hardcoded keys |
| C4 | Tests cover: happy path, entity not found, vault miss, expired session, concurrent isolation | pytest coverage |
| C5 | Async I/O for all LLM calls, vault reads/writes, document store | asyncio lint |
| C6 | Logging never emits original values | Log scan test |

---

## 14. Known Gaps & Future Work

### Current Gaps (v1)

1. **Co-reference resolution:** The LLM may refer to obfuscated entities without using the token (e.g., "the patient's condition" when the diagnosis was tokenized). The de-obfuscation engine cannot restore these indirect references. This requires a co-reference resolution model (e.g., neuralcoref or spaCy's experimental coref pipeline) — planned for v2.

2. **Inference attack resistance:** Pseudonymization strategy does not prevent a sophisticated adversary from using context clues to narrow down the identity. Full resistance requires differential privacy techniques — out of scope for v1.

3. **Multi-page document chunking:** Documents exceeding the LLM context window must be chunked. The current spec handles single-chunk documents. Chunking with cross-chunk token consistency requires vault-aware chunking logic — planned for v1.1.

4. **Real-time streaming:** The pipeline is currently batch (full document). Streaming de-obfuscation (token-by-token as LLM outputs) requires a different architecture.

5. **Passport, Driver's License, NPI numbers:** The spec calls these out as extension targets. The detector config supports them, but ground-truth datasets and accuracy benchmarks are not included in v1.

6. **Vault as a single point of failure:** If the in-memory session key is lost (e.g., process crash mid-session), all vault entries for that session become permanently inaccessible. Production mitigation: KMS-wrapped keys stored alongside vault entries.

### What Would Be Built with an Additional Day

1. **Production vault key management:** Integrate AWS KMS or GCP KMS for key wrapping. Session keys wrapped with user master keys. Keys are only decrypted into memory when needed for vault operations.
2. **Streaming pipeline:** Async generator-based de-obfuscation that streams the restored response to the user as the LLM generates it.
3. **Co-reference resolution pass:** Run a coref resolution model over the obfuscated document before sending to LLM, annotate pronouns and indirect references, and include those annotations in the de-obfuscation step.
4. **HIPAA audit reporting:** Build a compliance report generator that reads the audit log and produces a 30-day PHI transmission summary (token IDs + counts, zero originals).
5. **Red team test suite:** Automated adversarial test suite that attempts to extract PII via prompt injection, response analysis, and cross-session token guessing.

---

## 15. Open Questions

| # | Question | Stakeholder | Priority |
|---|---|---|---|
| OQ1 | What is the expected maximum document size? 50MB is assumed. | Product | High |
| OQ2 | Should pseudonymization be demographically consistent (e.g., same gender, age range)? | Legal/Compliance | High |
| OQ3 | What is the session timeout policy? (Assumed: 30 minutes of inactivity) | Security | High |
| OQ4 | Is the vault persistence required across application restarts within a session? | Engineering | Medium |
| OQ5 | Are there entity types specific to client verticals (e.g., NPI numbers for healthcare, ISIN codes for finance)? | Product | Medium |
| OQ6 | What is the required audit log retention period? (HIPAA requires 6 years) | Compliance | High |
| OQ7 | Does the system need to support multi-language documents? | Product | Low |

---

---

## 16. CLAUDE.md — Development Checklist

> Use this checklist when building the project with Claude. Complete steps in order — later components depend on earlier ones.

### Phase 0: Project Skeleton (Hour 1)
- [ ] Create directory structure exactly as shown in Quick Reference Section above
- [ ] Write `pyproject.toml` with all dependencies: `presidio-analyzer`, `presidio-anonymizer`, `spacy`, `scispacy`, `cryptography`, `aiosqlite`, `httpx`, `faker`, `python-dotenv`, `pydantic-settings`, `pytest`, `pytest-asyncio`, `pytest-benchmark`, `mypy`
- [ ] Write `pytest.ini` with `asyncio_mode = auto` and markers: `security`, `obfuscation`, `deobfuscation`, `quality`, `performance`, `integration`, `unit`
- [ ] Write `.env.example` with all variables from Quick Reference
- [ ] Write `docker-compose.yml` with a single `app` service mounting the local directory
- [ ] Write `config.py` using `pydantic_settings.BaseSettings` to load all env vars with type annotations
- [ ] Define all dataclasses in a shared `models.py`: `DetectedEntity`, `ObfuscatedDocument`, `LLMResponse`, `PipelineResult`, `VaultEntry`, `AuditEvent`
- [ ] Define `ObfuscationStrategy` ABC in `obfuscation/strategies/base.py`
- [ ] Define all custom exceptions in `pipeline/exceptions.py`: `PIILeakError`, `VaultMissError`, `DocumentNotFoundError`, `UnsupportedFileTypeError`, `FileTooLargeError`

### Phase 1: Secure Document Store (Hours 1–2)
- [ ] Implement `SecureDocumentStore` using AES-256-GCM (skeleton in Section 6.1 above)
- [ ] Wire up PDF text extraction with `pypdf` (wrap in `asyncio.to_thread`)
- [ ] Wire up DOCX text extraction with `python-docx` (wrap in `asyncio.to_thread`)
- [ ] Write `tests/test_document_store.py`: upload, retrieve, wrong-user failure, MIME rejection, size limit
- [ ] Verify: raw SQLite file contains no plaintext of the uploaded document

### Phase 2: PII/PHI Detector (Hours 2–3)
- [ ] Implement `PIIDetector` with Presidio + `en_core_web_lg` (skeleton in Section 6.2 above)
- [ ] Write custom `MRNRecognizer` (Presidio `PatternRecognizer` subclass) for `PHI_MRN`
- [ ] Write custom `InsuranceIDRecognizer` for `PHI_INSURANCE_ID`
- [ ] Wire medical NER via `scispacy` model for `PHI_DIAGNOSIS` and `PHI_MEDICATION`
- [ ] Write `tests/test_detection.py`: all 15 entity types, span accuracy, no-PII document, low-confidence degradation
- [ ] Run against F-001 golden fixture — verify all 14 entity types detected

### Phase 3: Obfuscation Engine + Session Vault (Hours 3–5)
- [ ] Implement `SessionVault` with per-session AES-256-GCM key (skeleton in Section 6.4 above)
- [ ] Implement `TokenizationStrategy` (skeleton in Section 6.3 above)
- [ ] Implement `PseudonymizationStrategy` with Faker (skeleton in Section 6.3 above)
- [ ] Implement `ObfuscationEngine` with descending-sort replacement loop (skeleton in Section 6.3 above)
- [ ] Write `tests/test_vault.py`: store/lookup, cross-session isolation, destruction irreversibility, at-rest encryption check
- [ ] Write `tests/test_obfuscation.py`: within-session determinism, cross-session non-determinism, token format, pseudonym consistency, graceful degradation
- [ ] Run F-003 golden fixture — verify idempotency for repeated account number
- [ ] Run F-005 golden fixture — verify 7× repetition maps to 1 token

### Phase 4: LLM Integration + De-obfuscation (Hours 5–7)
- [ ] Implement `LLMContextInjector` with pre-call `verify_no_pii_leak()` gate
- [ ] Implement `DeobfuscationEngine` with token regex, possessive normalization, pseudonym reverse lookup
- [ ] Write `tests/test_deobfuscation.py`: complete restoration, inflected forms, vault miss → `[UNAVAILABLE]`, non-PII text preservation, pseudonym reverse lookup
- [ ] Run all F-007 de-obfuscation test cases (TC-001 through TC-007)
- [ ] Write integration test: mock LLM echoes all tokens → all restored in output
- [ ] Verify: LLM payload captured by mock contains zero original PII values

### Phase 5: Audit Log + Pipeline Orchestration (Hours 7–8)
- [ ] Implement `AuditLog` with append-only JSONL backend
- [ ] Verify: grep entire audit.jsonl for all 15 fixture PII values → zero matches
- [ ] Implement `SecureContextPipeline` top-level orchestrator
- [ ] Write `demo.py` that runs the full pipeline on a bundled test document and prints restored response
- [ ] Verify `docker-compose up` starts clean and `python demo.py` runs successfully

### Phase 6: Polish + README (Hours 8–10)
- [ ] Run `mypy --strict secure_context_pipeline/` → exit code 0
- [ ] Run `pytest tests/ -v --cov=secure_context_pipeline --cov-report=term-missing` → all pass
- [ ] Run `python scripts/pii_leakage_scan.py --runs=100` → 0 leaks
- [ ] Run all golden dataset integration tests → all pass
- [ ] Write `README.md` with: setup guide, architecture diagram, threat model, tokenization vs pseudonymization comparison, known gaps, what-would-I-build-next
- [ ] Verify README threat model addresses all 6 live review questions (Q1–Q6)

### Pre-Submission Final Checks
- [ ] `grep -r "sk-\|api_key\s*=" secure_context_pipeline/ --include="*.py"` → zero results
- [ ] `git log --all -p | grep -i "api_key\|secret"` → zero results  
- [ ] `.env` is in `.gitignore` and not committed
- [ ] `docker-compose up` + `python demo.py` runs cleanly on a fresh checkout
- [ ] All 5 Hard Fail conditions verified as non-triggered (see Quick Reference above)

---

*Document version 2.0 — Implementation Reference*  
*YourAI Confidential — For Internal Engineering Use Only*
