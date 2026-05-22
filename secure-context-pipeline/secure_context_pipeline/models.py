"""Shared data models for the Secure Context Pipeline.

These dataclasses define the contracts that flow between components. They are
deliberately framework-free (plain stdlib dataclasses + enums) so every component
can import them without creating dependency cycles.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class EntityType(str, Enum):
    """The 15 sensitive entity types the pipeline recognizes.

    Subclassing ``str`` means the members compare equal to their string value, so
    detectors and tests may use either ``EntityType.PII_NAME`` or the bare string
    ``"PII_NAME"`` interchangeably.
    """

    # PII — GDPR, CCPA, COPPA
    PII_NAME = "PII_NAME"
    PII_SSN = "PII_SSN"
    PII_DOB = "PII_DOB"
    PII_ADDRESS = "PII_ADDRESS"
    PII_EMAIL = "PII_EMAIL"
    PII_PHONE = "PII_PHONE"
    # PHI — HIPAA 45 CFR §§164.308-164.312
    PHI_MRN = "PHI_MRN"
    PHI_DIAGNOSIS = "PHI_DIAGNOSIS"
    PHI_MEDICATION = "PHI_MEDICATION"
    PHI_INSURANCE_ID = "PHI_INSURANCE_ID"
    PHI_LAB_RESULT = "PHI_LAB_RESULT"
    # Financial PII — GLBA, SOX, PCI-DSS
    FIN_ACCOUNT = "FIN_ACCOUNT"
    FIN_TAX_ID = "FIN_TAX_ID"
    # Legal privilege — attorney-client, work-product doctrine
    LEGAL_CLIENT = "LEGAL_CLIENT"
    LEGAL_STRATEGY = "LEGAL_STRATEGY"


# Canonical ordered list of every required entity type. Mirrors the test harness.
REQUIRED_ENTITY_TYPES: list[str] = [e.value for e in EntityType]


class ObfuscationStrategyType(str, Enum):
    TOKENIZATION = "tokenization"
    PSEUDONYMIZATION = "pseudonymization"
    REDACTION = "redaction"  # fallback for low-confidence entities


@dataclass
class DetectedEntity:
    """A single sensitive entity located in source text."""

    entity_type: str
    original_value: str
    start: int
    end: int
    confidence: float
    detection_method: str = "unknown"


@dataclass
class ObfuscatedDocument:
    """The result of replacing every detected entity in a document."""

    obfuscated_text: str
    entity_count: int
    token_manifest: list[str]
    session_id: str
    strategy_used: str = ObfuscationStrategyType.TOKENIZATION.value
    original_doc_id: str | None = None


@dataclass
class LLMResponse:
    raw_response: str
    provider: str
    model: str
    usage: dict[str, int] = field(default_factory=dict)
    session_id: str = ""


@dataclass
class DeobfuscatedResponse:
    """The result of restoring tokens in an LLM response."""

    restored_text: str
    tokens_restored: int
    tokens_missed: int
    unresolved_tokens: list[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    """The user-facing result of a full pipeline run."""

    session_id: str
    user_query: str
    restored_response: str
    entities_detected: int
    entities_obfuscated: int
    tokens_restored: int
    pipeline_duration_ms: float
    document_id: str | None = None
    audit_event_ids: list[str] = field(default_factory=list)


@dataclass
class VaultEntry:
    """A single token<->original mapping. ``original_value`` is never persisted in
    plaintext — only the AES-256-GCM ciphertext is stored."""

    token: str
    entity_type: str
    encrypted_original: bytes
    created_at: datetime
    session_id: str


class AuditEventType(str, Enum):
    OBFUSCATE = "OBFUSCATION"
    DEOBFUSCATE = "DEOBFUSCATION"
    VAULT_DESTROYED = "VAULT_DESTROYED"
    PII_LEAK_DETECTED = "PII_LEAK_DETECTED"
    VAULT_MISS = "VAULT_MISS"


@dataclass
class AuditEvent:
    """A single compliance audit record. Never contains original PII values."""

    event_type: str
    session_id: str
    user_id: str
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    entity_type: str | None = None
    token_id: str | None = None
    document_id: str | None = None
    strategy_used: str | None = None
    confidence_score: float | None = None
    stage: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
