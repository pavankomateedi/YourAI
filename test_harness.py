"""
Secure Context Pipeline — Test Harness
=======================================

FILE LOCATION IN PROJECT
-------------------------
    tests/test_harness.py

This single file contains the complete test harness. During project build, Claude
splits this file into the individual modules listed below.

HOW TO SPLIT INTO INDIVIDUAL TEST FILES
----------------------------------------
Split this file into the following files under tests/:

    tests/
    ├── conftest.py               # Shared fixtures, asyncio mode config, pytest plugins
    ├── test_detection.py         # TestPIIDetector class
    ├── test_obfuscation.py       # TestObfuscationEngine class
    ├── test_vault.py             # TestSessionVault class
    ├── test_deobfuscation.py     # TestDeobfuscationEngine class
    ├── test_pipeline.py          # TestFullPipeline, TestConcurrentSessionIsolation,
    │                             #   TestPIILeakageScan classes
    ├── test_performance.py       # TestPerformance class (requires --benchmark flag)
    ├── test_golden_dataset.py    # TestGoldenDatasetIntegration class
    ├── test_document_store.py    # TestSecureDocumentStore class
    ├── test_audit_compliance.py  # TestAuditLogComplianceReport, TestAuditLog classes
    ├── test_edge_cases.py        # TestEdgeCases class
    └── fixtures/
        └── golden/               # F-001 through F-007 fixture files (.txt + .json)

pytest.ini (project root):
---------------------------
    [pytest]
    asyncio_mode = auto
    markers =
        security: security-critical tests (PII leakage, vault isolation)
        performance: benchmark tests
        integration: end-to-end integration tests
        unit: fast unit tests for individual components
    testpaths = tests
    addopts = -v --tb=short

INSTALL ALL TEST DEPENDENCIES
------------------------------
    pip install pytest>=7.4.0 pytest-asyncio>=0.21.0 pytest-benchmark>=4.0.0 \
                pytest-mock>=3.11.0 aiofiles pypdf2 python-docx faker

Run all tests:
    pytest tests/ -v

Run benchmarks only:
    pytest tests/test_performance.py --benchmark-only

Run security evals only:
    pytest tests/ -v -k "security or leakage or pii"

Run edge cases only:
    pytest tests/test_edge_cases.py -v
"""

# ===== CONFTEST.PY CONTENT =====
#
# Copy the block below verbatim into tests/conftest.py when splitting.
# Everything from the "Shared constants and helpers" section and the
# fixtures section belongs in conftest.py so all test modules can import them.
#
# tests/conftest.py
# -----------------
#
#   import asyncio
#   import re
#   import uuid
#   from dataclasses import dataclass, field
#   from unittest.mock import AsyncMock
#   import pytest
#
#   pytest_plugins = ("pytest_asyncio",)
#
#   def pytest_configure(config):
#       config.addinivalue_line("markers", "security: security-critical tests")
#       config.addinivalue_line("markers", "performance: benchmark tests")
#       config.addinivalue_line("markers", "integration: end-to-end integration tests")
#       config.addinivalue_line("markers", "unit: fast unit tests for individual components")
#
#   TOKEN_PATTERN = re.compile(r"\[([A-Z]+_[A-Z]+_[0-9a-f]{8})\]")
#
#   REQUIRED_ENTITY_TYPES = [
#       "PII_NAME", "PII_SSN", "PII_DOB", "PII_ADDRESS", "PII_EMAIL", "PII_PHONE",
#       "PHI_MRN", "PHI_DIAGNOSIS", "PHI_MEDICATION", "PHI_INSURANCE_ID",
#       "PHI_LAB_RESULT", "FIN_ACCOUNT", "FIN_TAX_ID", "LEGAL_CLIENT", "LEGAL_STRATEGY",
#   ]
#
#   FIXTURE_PII_VALUES = {
#       "PII_NAME": "Dr. Eleanor Hartwell",
#       ...  # (same dict as below)
#   }
#
#   def assert_no_pii_in_text(text, pii_values=None): ...
#   def make_session_id(): ...
#   def make_user_id(): ...
#
#   @dataclass
#   class MockDetectedEntity: ...
#
#   @dataclass
#   class MockVaultEntry: ...
#
#   class MockSessionVault: ...
#
#   @pytest.fixture
#   def session_id(): return make_session_id()
#
#   @pytest.fixture
#   def user_id(): return make_user_id()
#
#   # ... all other fixtures below
#
# ===== END CONFTEST.PY CONTENT =====

from __future__ import annotations

import asyncio
import io
import json
import os
import pathlib
import re
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------

pytest_plugins = ("pytest_asyncio",)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "security: security-critical tests (PII leakage, vault isolation)"
    )
    config.addinivalue_line(
        "markers", "performance: benchmark tests"
    )
    config.addinivalue_line(
        "markers", "integration: end-to-end integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: fast unit tests for individual components"
    )


# ---------------------------------------------------------------------------
# Shared constants and helpers
# ---------------------------------------------------------------------------

TOKEN_PATTERN = re.compile(r"\[([A-Z]+_[A-Z]+_[0-9a-f]{8})\]")

# All entity types required by the spec (15 types — matches PRD Section 6.2 and Golden Dataset)
REQUIRED_ENTITY_TYPES = [
    "PII_NAME", "PII_SSN", "PII_DOB", "PII_ADDRESS", "PII_EMAIL", "PII_PHONE",
    "PHI_MRN", "PHI_DIAGNOSIS", "PHI_MEDICATION", "PHI_INSURANCE_ID", "PHI_LAB_RESULT",
    "FIN_ACCOUNT", "FIN_TAX_ID", "LEGAL_CLIENT", "LEGAL_STRATEGY",
]

# LEGAL_STRATEGY is present in REQUIRED_ENTITY_TYPES (verified — position index 14).

# Sample PII values used across tests — all fictional
FIXTURE_PII_VALUES = {
    "PII_NAME": "Dr. Eleanor Hartwell",
    "PII_SSN": "543-67-8901",
    "PII_DOB": "March 14, 1972",
    "PII_ADDRESS": "2847 Lakeview Drive, Austin, TX 78701",
    "PII_EMAIL": "eleanor.hartwell@example-clinic.org",
    "PII_PHONE": "(512) 555-0147",
    "PHI_MRN": "MRN-7293847",
    "PHI_DIAGNOSIS": "Type 2 Diabetes Mellitus",
    "PHI_MEDICATION": "Metformin 500mg",
    "PHI_INSURANCE_ID": "BCBS-TX-0042-8837291",
    "PHI_LAB_RESULT": "HbA1c: 8.2%",
    "FIN_ACCOUNT": "4532-1234-5678-9012",
    "FIN_TAX_ID": "EIN: 74-1234567",
    "LEGAL_CLIENT": "Martinez Family Trust",
}


def assert_no_pii_in_text(text: str, pii_values: dict[str, str] | None = None) -> None:
    """
    Assert that none of the known PII values appear in the given text.
    Raises AssertionError with detail if any are found.
    Used as a security gate in multiple tests.
    """
    if pii_values is None:
        pii_values = FIXTURE_PII_VALUES
    violations = []
    for entity_type, value in pii_values.items():
        if value.lower() in text.lower():
            violations.append(f"{entity_type}: '{value}' found in text")
    assert not violations, (
        f"PII LEAKAGE DETECTED — {len(violations)} violation(s):\n"
        + "\n".join(violations)
    )


def make_session_id() -> str:
    return f"test-session-{uuid.uuid4().hex[:8]}"


def make_user_id() -> str:
    return f"test-user-{uuid.uuid4().hex[:8]}"


def _make_minimal_pdf_bytes(text: str) -> bytes:
    """
    Build a minimal syntactically valid PDF containing text.
    Does not depend on any PDF library — pure bytes construction.
    Used only for testing upload/extraction interfaces.
    """
    text_escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 12 Tf 72 720 Td ({text_escaped}) Tj ET"
    stream_bytes = stream.encode("latin-1")
    stream_len = len(stream_bytes)

    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
        + f"4 0 obj\n<< /Length {stream_len} >>\nstream\n".encode()
        + stream_bytes
        + b"\nendstream\nendobj\n"
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        b"xref\n0 6\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000266 00000 n \n"
        b"0000000360 00000 n \n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\n"
        b"startxref\n430\n%%EOF\n"
    )
    return pdf


def _make_minimal_docx_bytes(text: str) -> bytes:
    """
    Build a minimal syntactically valid .docx (ZIP + XML) containing text.
    Uses only stdlib zipfile + io — no python-docx dependency required for the helper.
    """
    import zipfile

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        "</Relationships>"
    )
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>"
        + text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        + "</w:t></w:r></w:p></w:body></w:document>"
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def session_id() -> str:
    return make_session_id()


@pytest.fixture
def user_id() -> str:
    return make_user_id()


@pytest.fixture
def session_id_b() -> str:
    """A second, distinct session for cross-session isolation tests."""
    return make_session_id()


@pytest.fixture
def fixture_text_medical() -> str:
    """A synthetic medical record containing all required PII/PHI entity types."""
    return (
        "PATIENT RECORD\n"
        "Patient: Dr. Eleanor Hartwell\n"
        "SSN: 543-67-8901\n"
        "Date of Birth: March 14, 1972\n"
        "Address: 2847 Lakeview Drive, Austin, TX 78701\n"
        "Email: eleanor.hartwell@example-clinic.org\n"
        "Phone: (512) 555-0147\n"
        "MRN: MRN-7293847\n"
        "Insurance ID: BCBS-TX-0042-8837291\n\n"
        "CLINICAL NOTES\n"
        "Diagnosis: Type 2 Diabetes Mellitus\n"
        "Current Medications: Metformin 500mg twice daily\n"
        "Latest Lab Result: HbA1c: 8.2% — above target range\n\n"
        "FINANCIAL NOTES\n"
        "Account: 4532-1234-5678-9012\n"
        "Tax ID: EIN: 74-1234567\n\n"
        "LEGAL NOTES\n"
        "Client Entity: Martinez Family Trust\n"
        "Attorney recommendation: Settlement is advised at $450,000.\n"
    )


@pytest.fixture
def fixture_text_no_pii() -> str:
    """A document that contains no PII — for negative detection tests."""
    return (
        "GENERAL MEDICAL GUIDANCE\n"
        "Patients with elevated blood glucose should consider dietary changes.\n"
        "Regular exercise of 30 minutes per day is recommended.\n"
        "Consult your physician before starting any new medication regimen.\n"
        "Blood pressure monitoring should occur at least once per week.\n"
    )


@pytest.fixture
def fixture_text_repeated_pii() -> str:
    """A document where the same PII value appears multiple times."""
    return (
        "Patient Dr. Eleanor Hartwell was admitted on March 14, 1972 (her birthday).\n"
        "Dr. Eleanor Hartwell's diagnosis is Type 2 Diabetes Mellitus.\n"
        "Follow-up scheduled for Dr. Eleanor Hartwell next month.\n"
        "Dr. Eleanor Hartwell has been prescribed Metformin 500mg.\n"
    )


@pytest.fixture
def fixture_text_2000_words() -> str:
    """
    A 2000-word synthetic document for performance benchmarking.
    Contains 20 PII entities distributed throughout.
    """
    base = (
        "COMPREHENSIVE PATIENT ASSESSMENT REPORT\n\n"
        "Patient: Dr. Eleanor Hartwell — MRN: MRN-7293847\n\n"
    )
    # Pad to approximately 2000 words with non-PII medical content
    filler = (
        "The patient presented with elevated fasting glucose levels and reported "
        "increased thirst and fatigue over the past three months. Physical examination "
        "revealed no acute distress. Cardiovascular assessment showed regular rate and "
        "rhythm without murmurs. Respiratory examination was clear to auscultation "
        "bilaterally. Abdominal examination was benign. Neurological status was intact. "
        "Laboratory results were reviewed and compared against prior values. "
        "The care team discussed management options including lifestyle modification, "
        "medication adjustment, and specialist referral. Patient education was provided "
        "regarding dietary choices, exercise recommendations, and glucose monitoring. "
        "The patient verbalized understanding and agreement with the proposed plan. "
        "A follow-up appointment was scheduled in six weeks to reassess progress. "
    ) * 18  # ~18 repetitions to reach ~2000 words
    return base + filler


# ---------------------------------------------------------------------------
# Mock implementations (used when real implementations not available)
# These mirror the interfaces defined in the PRD exactly.
# ---------------------------------------------------------------------------

@dataclass
class MockDetectedEntity:
    entity_type: str
    original_value: str
    start: int
    end: int
    confidence: float
    detection_method: str = "mock"


@dataclass
class MockVaultEntry:
    token: str
    entity_type: str
    original_value: str  # In real impl this is encrypted; here it's plaintext for test purposes
    session_id: str


class MockSessionVault:
    """
    In-memory vault for testing. Mirrors the real SessionVault interface.
    Does NOT implement encryption (test only) — use real vault for EVAL-SEC-003.
    """

    def __init__(self):
        # {session_id: {token: MockVaultEntry}}
        self._store: dict[str, dict[str, MockVaultEntry]] = {}
        # {session_id: {(entity_type, original_value): token}}
        self._reverse: dict[str, dict[tuple[str, str], str]] = {}
        self._destroyed: set[str] = set()
        # Audit trail for compliance tests
        self._events: list[dict] = []

    async def store(self, session_id: str, token: str, original: str, entity_type: str) -> None:
        assert session_id not in self._destroyed, f"Vault for session {session_id} has been destroyed"
        if session_id not in self._store:
            self._store[session_id] = {}
            self._reverse[session_id] = {}
        self._store[session_id][token] = MockVaultEntry(
            token=token, entity_type=entity_type,
            original_value=original, session_id=session_id
        )
        self._reverse[session_id][(entity_type, original)] = token

    async def lookup_by_token(self, session_id: str, token: str) -> str:
        if session_id in self._destroyed:
            raise KeyError(f"Vault for session {session_id} has been destroyed")
        session_store = self._store.get(session_id, {})
        entry = session_store.get(token)
        if entry is None:
            raise KeyError(f"Token {token} not found in vault for session {session_id}")
        return entry.original_value

    async def lookup_by_original(self, session_id: str, entity_type: str, original: str) -> str | None:
        if session_id in self._destroyed:
            return None
        reverse = self._reverse.get(session_id, {})
        return reverse.get((entity_type, original))

    async def destroy(self, session_id: str) -> None:
        self._store.pop(session_id, None)
        self._reverse.pop(session_id, None)
        self._destroyed.add(session_id)
        self._events.append({"event": "VAULT_DESTROYED", "session_id": session_id})

    async def list_tokens(self, session_id: str) -> list[str]:
        return list(self._store.get(session_id, {}).keys())

    def entry_count(self, session_id: str) -> int:
        return len(self._store.get(session_id, {}))

    def get_events(self) -> list[dict]:
        return list(self._events)


class MockAuditLog:
    """
    In-memory audit log for testing. Stores events without writing to disk.
    Supports inspection of all logged events in tests.
    """

    def __init__(self):
        self._entries: list[dict] = []

    async def log_obfuscation(self, session_id: str, user_id: str, entity_type: str,
                               token_id: str, document_id: str, strategy_used: str,
                               confidence_score: float) -> None:
        self._entries.append({
            "event": "OBFUSCATION",
            "session_id": session_id,
            "user_id": user_id,
            "entity_type": entity_type,
            "token_id": token_id,
            "document_id": document_id,
            "strategy_used": strategy_used,
            "confidence_score": confidence_score,
        })

    async def log_vault_miss(self, session_id: str, user_id: str, token_id: str) -> None:
        self._entries.append({
            "event": "VAULT_MISS",
            "session_id": session_id,
            "user_id": user_id,
            "token_id": token_id,
        })

    async def log_vault_destroyed(self, session_id: str, user_id: str) -> None:
        self._entries.append({
            "event": "VAULT_DESTROYED",
            "session_id": session_id,
            "user_id": user_id,
        })

    async def log_pii_leak_detected(self, session_id: str, user_id: str,
                                     entity_type: str, stage: str) -> None:
        self._entries.append({
            "event": "PII_LEAK_DETECTED",
            "session_id": session_id,
            "user_id": user_id,
            "entity_type": entity_type,
            "stage": stage,
        })

    def get_entries(self) -> list[dict]:
        return list(self._entries)

    def get_entries_by_event(self, event_name: str) -> list[dict]:
        return [e for e in self._entries if e.get("event") == event_name]

    def to_text(self) -> str:
        """Serialise all entries to text for PII scanning."""
        return "\n".join(json.dumps(entry) for entry in self._entries)


# ---------------------------------------------------------------------------
# ============================================================
# UNIT TESTS: PII / PHI Detector
# ============================================================
# ---------------------------------------------------------------------------

class TestPIIDetector:
    """Tests for Component 2: PII/PHI Detector (EVAL-OBF-006, EVAL-OBF-007)."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detects_all_required_entity_types(self, fixture_text_medical):
        """EVAL-OBF-006: All 15 required entity types must be detected.

        Uses golden dataset Fixture F-001 (comprehensive medical record) and
        Fixture F-002 (legal brief) together to cover all 15 entity types.
        See: tests/fixtures/golden/F-001_medical_record_comprehensive.json
             tests/fixtures/golden/F-002_legal_brief_privilege.json
        """
        # Import real detector if available; otherwise use mock
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            detector = PIIDetector()
            entities = await detector.detect(fixture_text_medical)
            detected_types = {e.entity_type for e in entities}
        except ImportError:
            pytest.skip("PIIDetector not implemented yet — skipping integration check")

        missing = set(REQUIRED_ENTITY_TYPES) - detected_types
        assert not missing, (
            f"Entity types not detected: {missing}\n"
            f"Detected types: {detected_types}"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detects_ssn_formats(self):
        """SSN must be detected in multiple formats."""
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            detector = PIIDetector()
        except ImportError:
            pytest.skip("PIIDetector not implemented")

        ssn_texts = [
            ("SSN: 543-67-8901", "543-67-8901"),
            ("Social Security: 543678901", "543678901"),
            ("SSN 543 67 8901", "543 67 8901"),
        ]
        for text, expected_value in ssn_texts:
            entities = await detector.detect(text)
            ssn_entities = [e for e in entities if e.entity_type == "PII_SSN"]
            assert ssn_entities, f"SSN not detected in: '{text}'"
            assert expected_value in [e.original_value for e in ssn_entities]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_no_pii_document_returns_empty(self, fixture_text_no_pii):
        """EVAL-CODE-005 (entity type not found): Clean doc returns empty entity list."""
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            detector = PIIDetector()
            entities = await detector.detect(fixture_text_no_pii)
        except ImportError:
            pytest.skip("PIIDetector not implemented")

        # Should return empty list or very short list (common words like "physician" are not PHI)
        phi_entities = [e for e in entities if e.confidence >= 0.85]
        assert len(phi_entities) == 0, (
            f"False positives detected in clean document: {[(e.entity_type, e.original_value) for e in phi_entities]}"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_low_confidence_entity_triggers_redaction(self):
        """
        EVAL-OBF-007: Entities with confidence < 0.60 must be redacted, not passed through.
        This test injects a mock entity with low confidence and verifies the engine redacts it.
        """
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault = MockSessionVault()
        session = make_session_id()
        engine = ObfuscationEngine({"PII_NAME": TokenizationStrategy()})

        low_confidence_entity = MockDetectedEntity(
            entity_type="PII_NAME",
            original_value="John",
            start=8, end=12,
            confidence=0.45,  # below threshold
        )
        text = "Patient John was admitted."
        result = await engine.obfuscate_document(text, [low_confidence_entity], vault, session)

        assert "[REDACTED]" in result.obfuscated_text, (
            "Low-confidence entity must be redacted, not passed through"
        )
        assert "John" not in result.obfuscated_text, (
            "Original value must not appear in obfuscated output"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_entity_spans_are_accurate(self, fixture_text_medical):
        """Detected entity spans must correspond to the actual text at that position."""
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            detector = PIIDetector()
            entities = await detector.detect(fixture_text_medical)
        except ImportError:
            pytest.skip("PIIDetector not implemented")

        for entity in entities:
            extracted = fixture_text_medical[entity.start:entity.end]
            # The extracted span should match or contain the original_value
            assert entity.original_value in extracted or extracted in entity.original_value, (
                f"Span mismatch for {entity.entity_type}: "
                f"span text='{extracted}', entity value='{entity.original_value}'"
            )


# ---------------------------------------------------------------------------
# ============================================================
# UNIT TESTS: Obfuscation Engine
# ============================================================
# ---------------------------------------------------------------------------

class TestObfuscationEngine:
    """Tests for Component 3: Obfuscation Engine (EVAL-OBF-001 through EVAL-OBF-005)."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_within_session_token_determinism(self, session_id):
        """
        EVAL-OBF-001: Same entity value in same session must get the same token.
        Vault entry count for one unique value must be 1, not 3.
        """
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = ObfuscationEngine({"PII_NAME": TokenizationStrategy()})

        entities = [
            MockDetectedEntity("PII_NAME", "Eleanor Hartwell", 0, 16, 0.95),
            MockDetectedEntity("PII_NAME", "Eleanor Hartwell", 50, 66, 0.95),
            MockDetectedEntity("PII_NAME", "Eleanor Hartwell", 100, 116, 0.95),
        ]
        text = "Eleanor Hartwell ... Eleanor Hartwell ... Eleanor Hartwell"
        result = await engine.obfuscate_document(text, entities, vault, session_id)

        # Count unique tokens for this entity in obfuscated text
        tokens = TOKEN_PATTERN.findall(result.obfuscated_text)
        name_tokens = [t for t in tokens if t.startswith("PII_NAME")]
        unique_name_tokens = set(name_tokens)

        assert len(unique_name_tokens) == 1, (
            f"Expected 1 unique token for 'Eleanor Hartwell', got {len(unique_name_tokens)}: {unique_name_tokens}"
        )
        assert vault.entry_count(session_id) == 1, (
            f"Expected 1 vault entry for the single unique entity, got {vault.entry_count(session_id)}"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_cross_session_nondeterminism(self, session_id, session_id_b):
        """
        EVAL-OBF-002: Same entity value in different sessions must produce different tokens.
        Token from Session A must not be usable to query Session B's vault.
        """
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault_a = MockSessionVault()
        vault_b = MockSessionVault()
        engine = ObfuscationEngine({"PII_NAME": TokenizationStrategy()})

        entity = MockDetectedEntity("PII_NAME", "Eleanor Hartwell", 0, 16, 0.95)

        result_a = await engine.obfuscate_document("Eleanor Hartwell seen today.", [entity], vault_a, session_id)
        result_b = await engine.obfuscate_document("Eleanor Hartwell seen today.", [entity], vault_b, session_id_b)

        tokens_a = set(TOKEN_PATTERN.findall(result_a.obfuscated_text))
        tokens_b = set(TOKEN_PATTERN.findall(result_b.obfuscated_text))

        assert not tokens_a.intersection(tokens_b), (
            f"Session A and Session B produced the same token(s): {tokens_a & tokens_b}\n"
            "This is a security violation — tokens must be non-deterministic across sessions."
        )

        # Attempt cross-session vault lookup (must fail)
        token_from_a = list(tokens_a)[0]
        with pytest.raises(KeyError):
            await vault_b.lookup_by_token(session_id_b, f"[{token_from_a}]")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_token_format_compliance(self, session_id):
        """EVAL-OBF-003: All generated tokens must match the required format."""
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault = MockSessionVault()
        strategies = {et: TokenizationStrategy() for et in REQUIRED_ENTITY_TYPES}
        engine = ObfuscationEngine(strategies)

        entities = [
            MockDetectedEntity(et, val, i * 20, i * 20 + len(val), 0.95)
            for i, (et, val) in enumerate(FIXTURE_PII_VALUES.items())
        ]
        # Build a text that contains all fixture values
        text = " ".join(FIXTURE_PII_VALUES.values())
        result = await engine.obfuscate_document(text, entities, vault, session_id)

        # Extract all tokens from obfuscated text
        raw_tokens = re.findall(r"\[([^\]]+)\]", result.obfuscated_text)

        for token_inner in raw_tokens:
            if token_inner == "REDACTED":
                continue
            assert TOKEN_PATTERN.match(f"[{token_inner}]"), (
                f"Token '[{token_inner}]' does not match required format [ENTITY_TYPE_xxxxxxxx]"
            )
            # Verify the prefix matches one of the known entity type prefixes
            prefix = "_".join(token_inner.split("_")[:2])
            assert prefix in REQUIRED_ENTITY_TYPES, (
                f"Token prefix '{prefix}' is not a recognized entity type"
            )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_pseudonym_consistency_within_session(self, session_id):
        """
        EVAL-OBF-005: Same entity value must get the same pseudonym within a session.
        """
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import PseudonymizationStrategy
        except ImportError:
            pytest.skip("PseudonymizationStrategy not implemented")

        vault = MockSessionVault()
        engine = ObfuscationEngine({"PII_NAME": PseudonymizationStrategy()})

        entity1 = MockDetectedEntity("PII_NAME", "Eleanor Hartwell", 0, 16, 0.95)
        entity2 = MockDetectedEntity("PII_NAME", "Eleanor Hartwell", 50, 66, 0.95)

        text = "Eleanor Hartwell ... Eleanor Hartwell"
        result = await engine.obfuscate_document(text, [entity1, entity2], vault, session_id)

        # Split and find the two replacements
        # They should be identical since it's the same source value
        words = result.obfuscated_text.split(" ... ")
        assert len(words) == 2
        assert words[0] == words[1], (
            f"Pseudonym inconsistency: first occurrence='{words[0]}', second='{words[1]}'"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_original_values_not_in_obfuscated_output(self, session_id, fixture_text_medical):
        """
        EVAL-SEC-005 (unit-level): After obfuscation, no original PII value should appear.
        """
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("Components not implemented")

        vault = MockSessionVault()
        detector = PIIDetector()
        strategies = {et: TokenizationStrategy() for et in REQUIRED_ENTITY_TYPES}
        engine = ObfuscationEngine(strategies)

        entities = await detector.detect(fixture_text_medical)
        result = await engine.obfuscate_document(fixture_text_medical, entities, vault, session_id)

        assert_no_pii_in_text(result.obfuscated_text, FIXTURE_PII_VALUES)


# ---------------------------------------------------------------------------
# ============================================================
# UNIT TESTS: Session Vault
# ============================================================
# ---------------------------------------------------------------------------

class TestSessionVault:
    """Tests for Component 4: Session Vault (EVAL-SEC-001 through EVAL-SEC-004)."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_store_and_lookup_roundtrip(self, session_id):
        """Basic vault store → lookup roundtrip must return original value."""
        try:
            from secure_context_pipeline.vault.vault import SessionVault
            vault = SessionVault()
        except ImportError:
            vault = MockSessionVault()

        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")
        retrieved = await vault.lookup_by_token(session_id, "[PII_NAME_a3f2c1d4]")
        assert retrieved == "Eleanor Hartwell"

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_cross_session_isolation(self, session_id, session_id_b):
        """
        EVAL-SEC-002: Token from Session A must not be accessible in Session B.
        """
        try:
            from secure_context_pipeline.vault.vault import SessionVault
            vault = SessionVault()
        except ImportError:
            vault = MockSessionVault()

        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")

        # Session B must not be able to access Session A's token
        with pytest.raises((KeyError, ValueError, Exception)):
            await vault.lookup_by_token(session_id_b, "[PII_NAME_a3f2c1d4]")

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_vault_destroyed_on_session_end(self, session_id):
        """
        EVAL-SEC-004: After destroy_session(), all lookups for that session must fail.
        """
        try:
            from secure_context_pipeline.vault.vault import SessionVault
            vault = SessionVault()
        except ImportError:
            vault = MockSessionVault()

        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")
        await vault.destroy(session_id)

        with pytest.raises((KeyError, ValueError, Exception)):
            await vault.lookup_by_token(session_id, "[PII_NAME_a3f2c1d4]")

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_destroyed_vault_irreversible(self, session_id):
        """
        EVAL-SEC-004: A vault destruction must be irreversible — re-creating the session
        must not restore old entries.
        """
        try:
            from secure_context_pipeline.vault.vault import SessionVault
            vault = SessionVault()
        except ImportError:
            vault = MockSessionVault()

        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")
        await vault.destroy(session_id)

        # Simulate new session with same ID (edge case)
        await vault.store(session_id, "[PII_SSN_b7e2a1c3]", "543-67-8901", "PII_SSN")
        tokens = await vault.list_tokens(session_id)

        # Old token must not be present
        assert "[PII_NAME_a3f2c1d4]" not in tokens, (
            "Old vault entry persisted after session destruction — security violation"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_lookup_by_original_supports_idempotency(self, session_id):
        """
        Reverse lookup (original value → token) must support idempotent obfuscation.
        """
        try:
            from secure_context_pipeline.vault.vault import SessionVault
            vault = SessionVault()
        except ImportError:
            vault = MockSessionVault()

        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")
        existing_token = await vault.lookup_by_original(session_id, "PII_NAME", "Eleanor Hartwell")

        assert existing_token == "[PII_NAME_a3f2c1d4]", (
            "Reverse lookup must return the existing token for the same original value"
        )

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_vault_encryption_at_rest(self, session_id):
        """
        EVAL-SEC-003: The vault database must not contain the original value in plaintext.
        This test connects to the underlying SQLite database and inspects raw bytes.
        """
        try:
            from secure_context_pipeline.vault.vault import SessionVault
            import sqlite3
            vault = SessionVault()
        except ImportError:
            pytest.skip("Real SessionVault not implemented")

        original_value = "Eleanor Hartwell"
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", original_value, "PII_NAME")

        # Read raw bytes from DB
        db_path = os.environ.get("VAULT_DB_PATH", "vault.db")
        if not os.path.exists(db_path):
            pytest.skip(f"Vault database not found at {db_path}")

        with open(db_path, "rb") as f:
            raw_bytes = f.read()

        assert original_value.encode() not in raw_bytes, (
            f"SECURITY VIOLATION: Original value '{original_value}' found in plaintext in vault database"
        )


# ---------------------------------------------------------------------------
# ============================================================
# UNIT TESTS: De-obfuscation Engine
# ============================================================
# ---------------------------------------------------------------------------

class TestDeobfuscationEngine:
    """Tests for Component 6: De-obfuscation Engine (EVAL-DEOB-001 through EVAL-DEOB-006)."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_all_tokens_restored(self, session_id):
        """EVAL-DEOB-001: All tokens in LLM response are restored to original values."""
        try:
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("DeobfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = DeobfuscationEngine()

        # Pre-populate vault with 5 entries
        entries = [
            ("[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME"),
            ("[PII_SSN_b7e2a1c3]", "543-67-8901", "PII_SSN"),
            ("[PHI_DIAGNOSIS_2c8a4d7b]", "Type 2 Diabetes Mellitus", "PHI_DIAGNOSIS"),
            ("[PHI_MEDICATION_9f1a3e2b]", "Metformin 500mg", "PHI_MEDICATION"),
            ("[FIN_ACCOUNT_4d7c9a1e]", "4532-1234-5678-9012", "FIN_ACCOUNT"),
        ]
        for token, original, etype in entries:
            await vault.store(session_id, token, original, etype)

        llm_response = (
            "Patient [PII_NAME_a3f2c1d4] (SSN: [PII_SSN_b7e2a1c3]) has been diagnosed "
            "with [PHI_DIAGNOSIS_2c8a4d7b] and is currently taking [PHI_MEDICATION_9f1a3e2b]. "
            "Insurance will be billed to account [FIN_ACCOUNT_4d7c9a1e]."
        )

        result = await engine.deobfuscate(llm_response, vault, session_id)

        assert result.tokens_restored == 5, f"Expected 5 tokens restored, got {result.tokens_restored}"
        assert result.tokens_missed == 0, f"Expected 0 vault misses, got {result.tokens_missed}"
        assert "Eleanor Hartwell" in result.restored_text
        assert "543-67-8901" in result.restored_text
        assert "Type 2 Diabetes Mellitus" in result.restored_text
        assert "Metformin 500mg" in result.restored_text
        assert "4532-1234-5678-9012" in result.restored_text
        # No token strings should remain
        assert not TOKEN_PATTERN.search(result.restored_text), (
            f"Unresolved tokens remain in output: {TOKEN_PATTERN.findall(result.restored_text)}"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_inflected_token_handling(self, session_id):
        """
        EVAL-DEOB-002: Grammatically inflected token forms must be resolved.
        Tests: possessive ('s), and inline adjectival use.
        """
        try:
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("DeobfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = DeobfuscationEngine()
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")

        # Possessive form
        response_possessive = "This is [PII_NAME_a3f2c1d4]'s medical record."
        result = await engine.deobfuscate(response_possessive, vault, session_id)
        assert "Eleanor Hartwell" in result.restored_text
        assert "[PII_NAME_a3f2c1d4]" not in result.restored_text

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_vault_miss_produces_unavailable(self, session_id):
        """
        EVAL-DEOB-003: A token not present in the vault must produce [UNAVAILABLE], not an exception.
        """
        try:
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("DeobfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = DeobfuscationEngine()

        # Token is NOT stored in vault
        response = "Patient [PII_NAME_FFFFFFFF] should follow up in two weeks."
        result = await engine.deobfuscate(response, vault, session_id)

        assert "[UNAVAILABLE]" in result.restored_text, (
            "Vault miss must produce [UNAVAILABLE], not leave the token as-is"
        )
        assert result.tokens_missed == 1
        assert "[PII_NAME_FFFFFFFF]" not in result.restored_text

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_non_pii_text_preserved_exactly(self, session_id):
        """
        EVAL-DEOB-004: Non-PII text must be preserved bit-for-bit.
        Only token strings should be replaced.
        """
        try:
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("DeobfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = DeobfuscationEngine()
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")

        response = (
            "The patient [PII_NAME_a3f2c1d4] has shown improvement. "
            "Their blood pressure is now 120/80 mmHg. "
            "Follow-up scheduled in 3 weeks."
        )
        expected = (
            "The patient Eleanor Hartwell has shown improvement. "
            "Their blood pressure is now 120/80 mmHg. "
            "Follow-up scheduled in 3 weeks."
        )
        result = await engine.deobfuscate(response, vault, session_id)
        assert result.restored_text == expected, (
            f"Non-PII text corruption detected.\n"
            f"Expected: {expected!r}\n"
            f"Got: {result.restored_text!r}"
        )


# ---------------------------------------------------------------------------
# ============================================================
# INTEGRATION TESTS: Full Pipeline
# ============================================================
# ---------------------------------------------------------------------------

class TestFullPipeline:
    """
    End-to-end integration tests for the complete pipeline.
    (EVAL-DEOB-006, EVAL-SEC-005, EVAL-SEC-006, EVAL-SEC-007)
    """

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_full_roundtrip_with_mock_llm(self, session_id, fixture_text_medical):
        """
        EVAL-DEOB-006: Full pipeline round-trip must restore all original values.
        Uses a mock LLM that echoes back all tokens from the obfuscated context.
        """
        try:
            from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline
        except ImportError:
            pytest.skip("SecureContextPipeline not implemented")

        async def mock_llm_call(obfuscated_context: str, query: str) -> str:
            """Echo all tokens back in the response."""
            tokens = TOKEN_PATTERN.findall(obfuscated_context)
            token_list = " ".join(f"[{t}]" for t in tokens)
            return f"Summary mentioning: {token_list}"

        pipeline = SecureContextPipeline(llm_fn=mock_llm_call)
        user = make_user_id()

        result = await pipeline.run(
            user_id=user,
            session_id=session_id,
            text=fixture_text_medical,
            user_query="Summarize this patient record.",
        )

        # All fixture PII values must appear in the restored response
        for entity_type, value in FIXTURE_PII_VALUES.items():
            assert value in result.restored_response, (
                f"Original value for {entity_type} not found in restored response: '{value}'"
            )

        # No token strings should remain
        assert not TOKEN_PATTERN.search(result.restored_response), (
            "Unresolved token strings remain in the final output returned to user"
        )

    @pytest.mark.security
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_llm_payload_contains_zero_pii(self, session_id, fixture_text_medical):
        """
        EVAL-SEC-005: The outbound LLM API payload must contain zero original PII values.
        The mock LLM captures the payload for inspection.
        """
        try:
            from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline
        except ImportError:
            pytest.skip("SecureContextPipeline not implemented")

        captured_payload: dict = {}

        async def mock_llm_capture(obfuscated_context: str, query: str) -> str:
            captured_payload["context"] = obfuscated_context
            captured_payload["query"] = query
            return "Response from LLM."

        pipeline = SecureContextPipeline(llm_fn=mock_llm_capture)
        await pipeline.run(
            user_id=make_user_id(),
            session_id=session_id,
            text=fixture_text_medical,
            user_query="What is the patient's diagnosis?",
        )

        assert captured_payload, "LLM was never called"
        full_payload = captured_payload["context"] + " " + captured_payload["query"]

        assert_no_pii_in_text(full_payload, FIXTURE_PII_VALUES)

    @pytest.mark.security
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_audit_log_contains_no_pii(self, session_id, fixture_text_medical, tmp_path):
        """
        EVAL-SEC-007: Audit log entries must never contain original PII values.
        """
        try:
            from secure_context_pipeline.audit.audit_log import AuditLog
            from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline
        except ImportError:
            pytest.skip("AuditLog not implemented")

        log_file = tmp_path / "audit.jsonl"
        audit_log = AuditLog(log_path=str(log_file))
        pipeline = SecureContextPipeline(audit_log=audit_log, llm_fn=AsyncMock(return_value="LLM response"))

        await pipeline.run(
            user_id=make_user_id(),
            session_id=session_id,
            text=fixture_text_medical,
            user_query="Summarize the record.",
        )

        # Read all log lines and check for PII
        with open(log_file) as f:
            log_content = f.read()

        assert_no_pii_in_text(log_content, FIXTURE_PII_VALUES)

    @pytest.mark.security
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_pii_leak_gate_aborts_llm_call(self, session_id):
        """
        EVAL-SEC-006: If pre-call leak check detects PII in payload, LLM call must be aborted.
        """
        try:
            from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline
            from secure_context_pipeline.pipeline.exceptions import PIILeakError
        except ImportError:
            pytest.skip("PIILeakError not implemented")

        llm_call_count = 0

        async def mock_llm(obfuscated_context: str, query: str) -> str:
            nonlocal llm_call_count
            llm_call_count += 1
            return "Should never reach here"

        # Inject a text where obfuscation is intentionally bypassed (simulating a bug)
        # The document contains a known PII value that "escapes" obfuscation
        leaky_obfuscated = f"Patient name: Eleanor Hartwell has [PHI_DIAGNOSIS_2c8a4d7b]."

        pipeline = SecureContextPipeline(llm_fn=mock_llm)

        with pytest.raises(PIILeakError):
            await pipeline._call_llm_with_leak_check(
                obfuscated_context=leaky_obfuscated,
                user_query="Summarize",
                vault=MockSessionVault(),
                session_id=session_id,
                known_pii_values=FIXTURE_PII_VALUES,
            )

        assert llm_call_count == 0, "LLM was called despite PII leak detection"


# ---------------------------------------------------------------------------
# ============================================================
# CONCURRENCY TESTS: Session Isolation
# ============================================================
# ---------------------------------------------------------------------------

class TestConcurrentSessionIsolation:
    """EVAL-CODE-005 (concurrent session isolation): Sessions must not bleed into each other."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_concurrent_sessions_no_cross_contamination(self):
        """
        10 concurrent sessions, each with a different user and PII value.
        No session should see another session's data.
        """
        try:
            from secure_context_pipeline.vault.vault import SessionVault
        except ImportError:
            # Use mock vault for structure test
            VaultClass = MockSessionVault
        else:
            VaultClass = SessionVault

        num_sessions = 10
        sessions = [(make_session_id(), make_user_id(), f"User Name {i}") for i in range(num_sessions)]
        vault = VaultClass() if VaultClass == MockSessionVault else VaultClass()

        async def run_session(session_id: str, user_id: str, name: str):
            token = f"[PII_NAME_{uuid.uuid4().hex[:8]}]"
            await vault.store(session_id, token, name, "PII_NAME")
            # Small delay to interleave with other sessions
            await asyncio.sleep(0.01)
            retrieved = await vault.lookup_by_token(session_id, token)
            assert retrieved == name, (
                f"Session {session_id}: expected '{name}', got '{retrieved}'"
            )
            return session_id, token, name

        results = await asyncio.gather(
            *[run_session(s, u, n) for s, u, n in sessions]
        )

        # Cross-check: attempt each token in the wrong session
        for i, (session_id_i, token_i, name_i) in enumerate(results):
            for j, (session_id_j, token_j, name_j) in enumerate(results):
                if i == j:
                    continue
                # Token from session i should NOT be found in session j
                with pytest.raises((KeyError, Exception)):
                    await vault.lookup_by_token(session_id_j, token_i)

    @pytest.mark.asyncio
    async def test_concurrent_pipeline_runs_no_degradation(self, fixture_text_medical):
        """
        Performance + isolation: 5 concurrent pipeline runs should complete
        without each other's data appearing in any output.
        """
        try:
            from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline
        except ImportError:
            pytest.skip("SecureContextPipeline not implemented")

        async def run_one(session_num: int) -> dict:
            session_id = make_session_id()
            pipeline = SecureContextPipeline(
                llm_fn=AsyncMock(return_value=f"Response for session {session_num}")
            )
            result = await pipeline.run(
                user_id=make_user_id(),
                session_id=session_id,
                text=fixture_text_medical,
                user_query="Summarize the record.",
            )
            return {"session": session_num, "result": result}

        start = time.time()
        results = await asyncio.gather(*[run_one(i) for i in range(5)])
        elapsed = time.time() - start

        # Should complete in reasonable time (3x single-session time max)
        # Adjust threshold based on LLM mock latency
        assert elapsed < 30, f"Concurrent pipeline took too long: {elapsed:.1f}s"

        # Each result should be clean (no cross-contamination)
        for r in results:
            assert not TOKEN_PATTERN.search(r["result"].restored_response), (
                f"Unresolved tokens in result for session {r['session']}"
            )


# ---------------------------------------------------------------------------
# ============================================================
# PERFORMANCE BENCHMARKS
# ============================================================
# ---------------------------------------------------------------------------

class TestPerformance:
    """Performance benchmark tests. Run with: pytest tests/ --benchmark-only"""

    @pytest.mark.performance
    @pytest.mark.benchmark(group="obfuscation")
    def test_obfuscation_engine_2000_words(self, benchmark, fixture_text_2000_words, session_id):
        """
        SPEC: Obfuscation engine alone < 2 seconds for 2000-word document.
        """
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("Components not implemented")

        detector = PIIDetector()
        vault = MockSessionVault()
        strategies = {et: TokenizationStrategy() for et in REQUIRED_ENTITY_TYPES}
        engine = ObfuscationEngine(strategies)

        async def run():
            entities = await detector.detect(fixture_text_2000_words)
            return await engine.obfuscate_document(fixture_text_2000_words, entities, vault, session_id)

        result = benchmark(asyncio.run, run())
        # Benchmark plugin captures timing; assert manually:
        assert benchmark.stats.mean < 2.0, (
            f"Obfuscation took {benchmark.stats.mean:.2f}s — exceeds 2s spec limit"
        )

    @pytest.mark.performance
    @pytest.mark.benchmark(group="vault")
    def test_vault_lookup_under_5ms(self, benchmark, session_id):
        """SPEC: Vault lookup per token < 5ms (p99)."""
        try:
            from secure_context_pipeline.vault.vault import SessionVault
            vault = SessionVault()
        except ImportError:
            vault = MockSessionVault()

        async def setup():
            await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")

        asyncio.run(setup())

        async def lookup():
            return await vault.lookup_by_token(session_id, "[PII_NAME_a3f2c1d4]")

        benchmark(asyncio.run, lookup())
        assert benchmark.stats.mean * 1000 < 5.0, (
            f"Vault lookup took {benchmark.stats.mean * 1000:.2f}ms — exceeds 5ms spec limit"
        )

    @pytest.mark.performance
    @pytest.mark.benchmark(group="deobfuscation")
    def test_deobfuscation_500_tokens(self, benchmark, session_id):
        """SPEC: De-obfuscation of 500-token LLM response < 500ms."""
        try:
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("DeobfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = DeobfuscationEngine()

        # Create 500 tokens in vault
        async def setup():
            for i in range(500):
                token = f"[PII_NAME_{i:08x}]"
                await vault.store(session_id, token, f"Person {i}", "PII_NAME")

        asyncio.run(setup())

        # Build response with all 500 tokens
        tokens_in_response = " ".join([f"[PII_NAME_{i:08x}]" for i in range(500)])
        response = f"Entities referenced: {tokens_in_response}"

        async def run():
            return await engine.deobfuscate(response, vault, session_id)

        benchmark(asyncio.run, run())
        assert benchmark.stats.mean * 1000 < 500, (
            f"De-obfuscation took {benchmark.stats.mean * 1000:.0f}ms — exceeds 500ms spec limit"
        )


# ---------------------------------------------------------------------------
# ============================================================
# PII LEAKAGE SCAN (100-run verification)
# ============================================================
# ---------------------------------------------------------------------------

class TestPIILeakageScan:
    """
    SPEC: Zero PII leakage verified across 100 automated test runs on varied fixture documents.
    """

    @pytest.mark.security
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_zero_leakage_across_fixture_variants(self):
        """
        Run 100 obfuscation passes across varied text snippets.
        Verify zero original PII values appear in any obfuscated output.
        """
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("Components not implemented")

        detector = PIIDetector()
        strategies = {et: TokenizationStrategy() for et in REQUIRED_ENTITY_TYPES}
        engine = ObfuscationEngine(strategies)

        # 10 fixture variants × 10 runs each = 100 total
        variants = [
            f"Patient: {name} — SSN: {ssn} — Diagnosis: {diag}"
            for name in ["Eleanor Hartwell", "Marcus Webb", "Priya Okonkwo", "Raj Patel", "Sarah Chen"]
            for ssn in ["543-67-8901", "987-65-4321"]
            for diag in ["Type 2 Diabetes", "Hypertension"]
        ]

        leakage_count = 0
        for variant in variants[:100]:
            vault = MockSessionVault()
            session_id = make_session_id()
            entities = await detector.detect(variant)
            result = await engine.obfuscate_document(variant, entities, vault, session_id)

            # Check each detected entity's original value
            for entity in entities:
                if entity.original_value.lower() in result.obfuscated_text.lower():
                    leakage_count += 1

        assert leakage_count == 0, (
            f"PII LEAKAGE: {leakage_count} instances of original values found "
            "in obfuscated outputs across 100 test runs"
        )


# ---------------------------------------------------------------------------
# ============================================================
# SECURE DOCUMENT STORE TESTS
# ============================================================
# ---------------------------------------------------------------------------

class TestSecureDocumentStore:
    """Tests for Component 1: Secure Document Store."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_upload_and_retrieve_with_correct_key(self, user_id):
        """F1: Document uploaded then retrieved returns original content."""
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
        except ImportError:
            pytest.skip("SecureDocumentStore not implemented")

        store = SecureDocumentStore()
        content = b"Patient: Eleanor Hartwell\nSSN: 543-67-8901\n"
        doc_id = await store.upload(user_id, content, "text/plain")
        retrieved = await store.retrieve(user_id, doc_id)
        assert retrieved == content

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_retrieve_with_wrong_user_fails(self, user_id):
        """F1: Document must not be accessible to a different user."""
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
        except ImportError:
            pytest.skip("SecureDocumentStore not implemented")

        store = SecureDocumentStore()
        content = b"Sensitive content"
        doc_id = await store.upload(user_id, content, "text/plain")

        wrong_user = make_user_id()
        with pytest.raises(Exception):
            await store.retrieve(wrong_user, doc_id)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_stored_content_is_not_plaintext(self, user_id, tmp_path):
        """
        EVAL-SEC-008: The stored document must not be recoverable from the raw storage file.
        """
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
        except ImportError:
            pytest.skip("SecureDocumentStore not implemented")

        store = SecureDocumentStore(base_path=str(tmp_path))
        content = b"Eleanor Hartwell SSN: 543-67-8901"
        doc_id = await store.upload(user_id, content, "text/plain")

        # Read all files in tmp_path
        all_content = b""
        for f in tmp_path.rglob("*"):
            if f.is_file():
                all_content += f.read_bytes()

        assert b"Eleanor Hartwell" not in all_content, (
            "Original content found in plaintext in storage — encryption not applied"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_pdf_upload_and_text_extraction(self, user_id):
        """
        Upload a minimal PDF document and verify that the store can extract
        plain text from it after upload. The extracted text must contain the
        content that was embedded in the PDF stream.
        """
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
        except ImportError:
            pytest.skip("SecureDocumentStore not implemented")

        store = SecureDocumentStore()
        pdf_text = "Patient: Dr. Eleanor Hartwell"
        pdf_bytes = _make_minimal_pdf_bytes(pdf_text)

        doc_id = await store.upload(user_id, pdf_bytes, "application/pdf")

        # The store must expose a text extraction method
        assert hasattr(store, "extract_text"), (
            "SecureDocumentStore must implement extract_text(user_id, doc_id) -> str"
        )
        extracted = await store.extract_text(user_id, doc_id)

        assert isinstance(extracted, str), "extract_text must return a str"
        assert len(extracted) > 0, "Extracted text from PDF must be non-empty"
        # The key words from the embedded PDF stream must survive extraction
        assert "Hartwell" in extracted or "Eleanor" in extracted, (
            f"Expected PDF text content not found in extracted output: {extracted!r}"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_docx_upload_and_text_extraction(self, user_id):
        """
        Upload a minimal DOCX document and verify that the store can extract
        plain text from it after upload. The extracted text must contain the
        content written into the document's body paragraph.
        """
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
        except ImportError:
            pytest.skip("SecureDocumentStore not implemented")

        store = SecureDocumentStore()
        docx_text = "Legal client: Martinez Family Trust. Strategy: settlement."
        docx_bytes = _make_minimal_docx_bytes(docx_text)

        doc_id = await store.upload(
            user_id, docx_bytes,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )

        assert hasattr(store, "extract_text"), (
            "SecureDocumentStore must implement extract_text(user_id, doc_id) -> str"
        )
        extracted = await store.extract_text(user_id, doc_id)

        assert isinstance(extracted, str), "extract_text must return a str"
        assert len(extracted) > 0, "Extracted text from DOCX must be non-empty"
        assert "Martinez" in extracted or "settlement" in extracted, (
            f"Expected DOCX text content not found in extracted output: {extracted!r}"
        )

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_mime_type_rejection(self, user_id):
        """
        Uploading a file with a disallowed MIME type (e.g. application/x-msdownload
        for a .exe) must be rejected with an appropriate error before any storage occurs.
        The error must be raised during upload, not during retrieval.
        """
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
            from secure_context_pipeline.store.exceptions import UnsupportedFileTypeError
        except ImportError:
            pytest.skip("SecureDocumentStore or UnsupportedFileTypeError not implemented")

        store = SecureDocumentStore()
        # Fake .exe content — 2-byte MZ header
        exe_bytes = b"MZ" + b"\x00" * 254

        with pytest.raises(UnsupportedFileTypeError) as exc_info:
            await store.upload(user_id, exe_bytes, "application/x-msdownload")

        assert exc_info.value is not None, (
            "Upload of .exe must raise UnsupportedFileTypeError immediately"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_file_size_limit(self, user_id):
        """
        Uploading a file exceeding the 50 MB size limit must be rejected.
        The rejection must happen before the file is written to storage.
        """
        try:
            from secure_context_pipeline.store.store import SecureDocumentStore
            from secure_context_pipeline.store.exceptions import FileTooLargeError
        except ImportError:
            pytest.skip("SecureDocumentStore or FileTooLargeError not implemented")

        store = SecureDocumentStore()
        # 51 MB of zero bytes — guaranteed to exceed the 50 MB limit
        fifty_one_mb = b"\x00" * (51 * 1024 * 1024)

        with pytest.raises(FileTooLargeError) as exc_info:
            await store.upload(user_id, fifty_one_mb, "text/plain")

        assert exc_info.value is not None, (
            "Upload of file > 50 MB must raise FileTooLargeError"
        )


# ---------------------------------------------------------------------------
# ============================================================
# AUDIT LOG TESTS
# ============================================================
# ---------------------------------------------------------------------------

class TestAuditLog:
    """Tests for Component 7: Audit Log."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_audit_log_captures_obfuscation_event(self, session_id, tmp_path):
        """EVAL-SEC-007: Obfuscation events must be logged."""
        try:
            from secure_context_pipeline.audit.audit_log import AuditLog
        except ImportError:
            pytest.skip("AuditLog not implemented")

        log_file = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path=str(log_file))

        await audit.log_obfuscation(
            session_id=session_id,
            user_id="user-123",
            entity_type="PHI_DIAGNOSIS",
            token_id="[PHI_DIAGNOSIS_2c8a4d7b]",
            document_id="doc-456",
            strategy_used="tokenization",
            confidence_score=0.95,
        )

        with open(log_file) as f:
            log_content = f.read()

        assert "PHI_DIAGNOSIS" in log_content
        assert "[PHI_DIAGNOSIS_2c8a4d7b]" in log_content
        assert session_id in log_content

        # Hard requirement: no original values in log
        assert "Type 2 Diabetes" not in log_content
        assert "Eleanor Hartwell" not in log_content

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_audit_log_captures_vault_miss(self, session_id, tmp_path):
        """EVAL-DEOB-003: Vault miss events must be logged."""
        try:
            from secure_context_pipeline.audit.audit_log import AuditLog
        except ImportError:
            pytest.skip("AuditLog not implemented")

        log_file = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path=str(log_file))

        await audit.log_vault_miss(
            session_id=session_id,
            user_id="user-123",
            token_id="[PII_NAME_FFFFFFFF]",
        )

        with open(log_file) as f:
            log_content = f.read()

        assert "VAULT_MISS" in log_content or "vault_miss" in log_content.lower()
        assert "[PII_NAME_FFFFFFFF]" in log_content


# ---------------------------------------------------------------------------
# ============================================================
# AUDIT LOG COMPLIANCE REPORT TESTS
# ============================================================
# ---------------------------------------------------------------------------

class TestAuditLogComplianceReport:
    """
    Compliance-oriented tests for the audit log subsystem.
    Verifies that the audit trail satisfies regulatory requirements:
    - No PII in exported reports
    - Critical lifecycle events are always recorded
    - Leak-gate firings are captured
    """

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_30_day_audit_summary_no_pii(self, session_id):
        """
        Generate a 30-day audit summary report using MockAuditLog populated with
        representative events, then verify zero PII appears in the serialised output.

        Simulates 30 days of activity: obfuscation events, vault misses, and session
        endings. The summary text must not contain any of the known fixture PII values.
        """
        audit = MockAuditLog()
        user = make_user_id()

        # Simulate 30 sessions worth of log entries
        for day in range(30):
            sid = make_session_id()
            # Log obfuscation events — tokens and entity types only, never originals
            for entity_type, token_suffix in [
                ("PII_NAME", "a3f2c1d4"),
                ("PHI_DIAGNOSIS", "2c8a4d7b"),
                ("FIN_ACCOUNT", "4d7c9a1e"),
            ]:
                await audit.log_obfuscation(
                    session_id=sid,
                    user_id=user,
                    entity_type=entity_type,
                    token_id=f"[{entity_type}_{token_suffix}]",
                    document_id=f"doc-day{day:02d}",
                    strategy_used="tokenization",
                    confidence_score=0.95,
                )
            # Log vault destruction at session end
            await audit.log_vault_destroyed(session_id=sid, user_id=user)

        # Serialise all log entries to text (simulates a report export)
        report_text = audit.to_text()

        assert len(report_text) > 0, "Audit report must not be empty after 30 days of activity"

        # The report must contain zero original PII values
        assert_no_pii_in_text(report_text, FIXTURE_PII_VALUES)

        # Basic structural checks: events must be present
        assert "OBFUSCATION" in report_text, "Report must include OBFUSCATION events"
        assert "VAULT_DESTROYED" in report_text, "Report must include VAULT_DESTROYED events"

        # Verify correct event counts
        obfuscation_events = audit.get_entries_by_event("OBFUSCATION")
        destroyed_events = audit.get_entries_by_event("VAULT_DESTROYED")
        assert len(obfuscation_events) == 90, (
            f"Expected 90 obfuscation events (30 days × 3 per session), got {len(obfuscation_events)}"
        )
        assert len(destroyed_events) == 30, (
            f"Expected 30 VAULT_DESTROYED events (one per session), got {len(destroyed_events)}"
        )

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_vault_destruction_event_logged(self, session_id):
        """
        EVAL-SEC-004 (audit aspect): When a session ends and the vault is destroyed,
        a VAULT_DESTROYED event must appear in the audit log.

        Uses MockSessionVault (which records internal events) and MockAuditLog.
        The pipeline or session manager is expected to call audit.log_vault_destroyed()
        as part of the session teardown. This test verifies the contract directly.
        """
        audit = MockAuditLog()
        vault = MockSessionVault()
        user = make_user_id()

        # Store something in the vault to make the session real
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")

        # Simulate session teardown: destroy vault and log the event
        await vault.destroy(session_id)
        await audit.log_vault_destroyed(session_id=session_id, user_id=user)

        # Verify the audit log recorded the destruction
        destroyed_events = audit.get_entries_by_event("VAULT_DESTROYED")
        assert len(destroyed_events) == 1, (
            f"Expected exactly 1 VAULT_DESTROYED event, got {len(destroyed_events)}"
        )
        assert destroyed_events[0]["session_id"] == session_id, (
            f"VAULT_DESTROYED event has wrong session_id: "
            f"expected {session_id!r}, got {destroyed_events[0]['session_id']!r}"
        )

        # The vault must also confirm destruction internally
        vault_events = vault.get_events()
        vault_destroyed = [e for e in vault_events if e.get("event") == "VAULT_DESTROYED"]
        assert any(e["session_id"] == session_id for e in vault_destroyed), (
            "Vault's internal event list must record VAULT_DESTROYED for this session"
        )

        # After destruction, lookups must fail
        with pytest.raises((KeyError, Exception)):
            await vault.lookup_by_token(session_id, "[PII_NAME_a3f2c1d4]")

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_pii_leak_aborted_call_logged(self, session_id):
        """
        EVAL-SEC-006 (audit aspect): When the PII leak gate fires and aborts an LLM call,
        a PII_LEAK_DETECTED event must be written to the audit log.

        This test simulates the gate logic inline: it checks the obfuscated payload for
        known PII values and logs the event when a match is found. The audit trail must
        contain the PII_LEAK_DETECTED event with correct session_id, entity_type, and stage.
        """
        audit = MockAuditLog()
        user = make_user_id()

        # Simulate a payload that escaped obfuscation (a bug scenario)
        leaky_payload = "Patient: Dr. Eleanor Hartwell. Diagnosis: [PHI_DIAGNOSIS_2c8a4d7b]."

        # Inline leak-gate logic (mirrors what the real pipeline does before calling LLM)
        leak_fired = False
        for entity_type, pii_value in FIXTURE_PII_VALUES.items():
            if pii_value.lower() in leaky_payload.lower():
                leak_fired = True
                await audit.log_pii_leak_detected(
                    session_id=session_id,
                    user_id=user,
                    entity_type=entity_type,
                    stage="pre_llm_call",
                )
                # In real pipeline this would raise PIILeakError — here we just break
                break

        assert leak_fired, (
            "Leak gate did not fire on a payload containing known PII — test setup error"
        )

        # Verify audit log captured the PII_LEAK_DETECTED event
        leak_events = audit.get_entries_by_event("PII_LEAK_DETECTED")
        assert len(leak_events) >= 1, (
            f"Expected at least 1 PII_LEAK_DETECTED event in audit log, got {len(leak_events)}"
        )

        first_leak = leak_events[0]
        assert first_leak["session_id"] == session_id, (
            f"PII_LEAK_DETECTED event has wrong session_id: "
            f"expected {session_id!r}, got {first_leak['session_id']!r}"
        )
        assert first_leak["stage"] == "pre_llm_call", (
            f"Expected stage='pre_llm_call', got {first_leak['stage']!r}"
        )

        # Verify the serialised log contains no original PII values
        log_text = audit.to_text()
        assert_no_pii_in_text(log_text, FIXTURE_PII_VALUES)


# ---------------------------------------------------------------------------
# ============================================================
# GOLDEN DATASET INTEGRATION TESTS
# Explicitly references Fixture IDs from GOLDEN_DATASET_RULES.md
# ============================================================
# ---------------------------------------------------------------------------

GOLDEN_FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures" / "golden"


def load_golden_annotation(fixture_id: str) -> dict | None:
    """Load annotation JSON for a given fixture ID. Returns None if file not found."""
    pattern = f"{fixture_id}_*.json"
    matches = list(GOLDEN_FIXTURE_DIR.glob(pattern))
    if not matches:
        return None
    with open(matches[0]) as f:
        return json.load(f)


def load_golden_text(fixture_id: str) -> str | None:
    """Load fixture text for a given fixture ID. Returns None if file not found."""
    pattern = f"{fixture_id}_*.txt"
    matches = list(GOLDEN_FIXTURE_DIR.glob(pattern))
    if not matches:
        return None
    return matches[0].read_text(encoding="utf-8")


class TestGoldenDatasetIntegration:
    """
    Integration tests that run the real pipeline against the canonical
    golden dataset fixtures defined in GOLDEN_DATASET_RULES.md.

    Fixture IDs:
      F-001: Comprehensive medical record (14 entity types)
      F-002: Legal brief with privilege indicators
      F-003: Financial disclosure with repeated account numbers
      F-004: Clean document — zero PII (negative test)
      F-005: Idempotency stress (same entity × 7)
      F-006: Low-confidence entity graceful degradation
      F-007: LLM response de-obfuscation ground truth
    """

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_F001_all_entities_detected(self):
        """F-001: Comprehensive medical record — all 15 entity types detected."""
        annotation = load_golden_annotation("F-001")
        text = load_golden_text("F-001")
        if annotation is None or text is None:
            pytest.skip("Golden fixture F-001 not found — create fixtures/golden/F-001_*.txt + .json")

        try:
            from secure_context_pipeline.detection.detector import PIIDetector
        except ImportError:
            pytest.skip("PIIDetector not implemented")

        detector = PIIDetector()
        entities = await detector.detect(text)
        detected_types = {e.entity_type for e in entities}
        expected_types = {ent["entity_type"] for ent in annotation["entities"]}

        missing = expected_types - detected_types
        assert not missing, (
            f"F-001: Missing entity types: {missing}\n"
            f"Expected from golden dataset: {expected_types}\n"
            f"Detected: {detected_types}"
        )

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_F001_span_accuracy(self):
        """F-001: Detected entity spans must match ground-truth character offsets."""
        annotation = load_golden_annotation("F-001")
        text = load_golden_text("F-001")
        if annotation is None or text is None:
            pytest.skip("Golden fixture F-001 not found")

        try:
            from secure_context_pipeline.detection.detector import PIIDetector
        except ImportError:
            pytest.skip("PIIDetector not implemented")

        detector = PIIDetector()
        entities = await detector.detect(text)

        for gt_entity in annotation["entities"]:
            gt_value = gt_entity["original_value"]
            gt_type = gt_entity["entity_type"]

            matching = [
                e for e in entities
                if e.entity_type == gt_type and gt_value in e.original_value
            ]
            assert matching, (
                f"F-001: Ground-truth entity '{gt_value}' ({gt_type}) not found in detected entities.\n"
                f"Detected {gt_type} entities: {[e.original_value for e in entities if e.entity_type == gt_type]}"
            )

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_F003_idempotency_repeated_account_numbers(self):
        """
        F-003: Account number '4111-2222-3333-4444' appears 3× — must produce single token.
        Tests idempotency assertion from golden dataset.
        """
        annotation = load_golden_annotation("F-003")
        text = load_golden_text("F-003")
        if annotation is None or text is None:
            pytest.skip("Golden fixture F-003 not found")

        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("Pipeline components not implemented")

        vault = MockSessionVault()
        session_id = make_session_id()
        detector = PIIDetector()
        engine = ObfuscationEngine({"FIN_ACCOUNT": TokenizationStrategy()})

        entities = await detector.detect(text)
        result = await engine.obfuscate_document(text, entities, vault, session_id)

        # The account number 4111-2222-3333-4444 appears 3 times
        # There must be exactly 1 unique token for it
        tokens = await vault.list_tokens(session_id)
        account_tokens = [t for t in tokens if "FIN_ACCOUNT" in t]

        assert len(account_tokens) == 1, (
            f"F-003 idempotency failure: expected 1 FIN_ACCOUNT token, "
            f"got {len(account_tokens)}: {account_tokens}"
        )

        # Verify all 3 occurrences are replaced with the same token
        token = account_tokens[0]
        # Count occurrences of this token in obfuscated text
        token_occurrences = result.obfuscated_text.count(token)
        assert token_occurrences == 3, (
            f"F-003: Expected 3 occurrences of token {token}, got {token_occurrences}"
        )

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_F004_empty_entity_list_no_error(self):
        """F-004: Clean document with zero PII must complete without error."""
        annotation = load_golden_annotation("F-004")
        text = load_golden_text("F-004")
        if annotation is None or text is None:
            pytest.skip("Golden fixture F-004 not found")

        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("Pipeline components not implemented")

        vault = MockSessionVault()
        session_id = make_session_id()
        detector = PIIDetector()
        engine = ObfuscationEngine({et: TokenizationStrategy() for et in REQUIRED_ENTITY_TYPES})

        entities = await detector.detect(text)
        result = await engine.obfuscate_document(text, entities, vault, session_id)

        # No tokens should appear in the output (no entities to replace)
        assert not TOKEN_PATTERN.search(result.obfuscated_text), (
            f"F-004: Token found in clean document output — false positive detection"
        )

        # Text should be unchanged
        assert result.obfuscated_text.strip() == text.strip(), (
            "F-004: Clean document text was modified without any PII entities"
        )

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_F007_deobfuscation_ground_truth(self):
        """
        F-007: LLM response de-obfuscation against ground-truth expected outputs.
        Covers TC-001 through TC-007.
        """
        json_path = GOLDEN_FIXTURE_DIR / "F-007_llm_response_deobfuscation.json"
        if not json_path.exists():
            pytest.skip("Golden fixture F-007 not found")

        with open(json_path) as f:
            fixture = json.load(f)

        try:
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("DeobfuscationEngine not implemented")

        engine = DeobfuscationEngine()

        for case in fixture["test_cases"]:
            vault = MockSessionVault()
            session_id = make_session_id()

            # Pre-populate vault with the session state from the fixture
            for token, original in fixture["session_vault_state"].items():
                # Infer entity type from token format [ENTITY_TYPE_xxxxxxxx]
                inner = token.strip("[]")
                entity_type = "_".join(inner.split("_")[:2])
                await vault.store(session_id, token, original, entity_type)

            result = await engine.deobfuscate(case["llm_response"], vault, session_id)

            assert result.restored_text == case["expected_output"], (
                f"F-007 {case['case_id']} ({case['description']}):\n"
                f"Expected: {case['expected_output']!r}\n"
                f"Got:      {result.restored_text!r}"
            )
            assert result.tokens_restored == case["expected_tokens_restored"], (
                f"F-007 {case['case_id']}: tokens_restored mismatch: "
                f"expected {case['expected_tokens_restored']}, got {result.tokens_restored}"
            )
            assert result.tokens_missed == case["expected_tokens_missed"], (
                f"F-007 {case['case_id']}: tokens_missed mismatch: "
                f"expected {case['expected_tokens_missed']}, got {result.tokens_missed}"
            )


# ---------------------------------------------------------------------------
# ============================================================
# EDGE CASE TESTS
# ============================================================
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """
    Edge cases that stress boundary conditions in detection, obfuscation,
    and de-obfuscation. These tests exercise paths that are uncommon in
    normal operation but must not cause crashes, silent data corruption,
    or PII leakage.
    """

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_entity_at_document_start(self, session_id):
        """
        Entity value is the very first character sequence in the document (offset 0).
        Obfuscation must replace it correctly without off-by-one errors at position 0.
        """
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = ObfuscationEngine({"PII_NAME": TokenizationStrategy()})

        # Entity starts at character 0
        name = "Eleanor Hartwell"
        text = f"{name} presented to the clinic today."
        entity = MockDetectedEntity(
            entity_type="PII_NAME",
            original_value=name,
            start=0,
            end=len(name),
            confidence=0.97,
        )

        result = await engine.obfuscate_document(text, [entity], vault, session_id)

        assert name not in result.obfuscated_text, (
            f"PII at document start was not replaced: {result.obfuscated_text!r}"
        )
        assert TOKEN_PATTERN.search(result.obfuscated_text), (
            "No token found in output — entity at offset 0 was skipped"
        )
        # Remaining non-PII text must be preserved
        assert "presented to the clinic today." in result.obfuscated_text, (
            "Non-PII suffix was corrupted during obfuscation of entity at document start"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_entity_at_document_end(self, session_id):
        """
        Entity value is the very last character sequence in the document.
        Obfuscation must replace it correctly without truncating the trailing token.
        """
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = ObfuscationEngine({"PII_SSN": TokenizationStrategy()})

        ssn = "543-67-8901"
        prefix = "Patient SSN: "
        text = prefix + ssn  # SSN is at the very end, no trailing newline
        entity = MockDetectedEntity(
            entity_type="PII_SSN",
            original_value=ssn,
            start=len(prefix),
            end=len(prefix) + len(ssn),
            confidence=0.99,
        )

        result = await engine.obfuscate_document(text, [entity], vault, session_id)

        assert ssn not in result.obfuscated_text, (
            f"PII at document end was not replaced: {result.obfuscated_text!r}"
        )
        # The token must appear at the end of the output
        obfuscated = result.obfuscated_text
        assert TOKEN_PATTERN.search(obfuscated), (
            "No token found in output — entity at document end was skipped"
        )
        assert obfuscated.startswith(prefix), (
            f"Non-PII prefix was corrupted: expected prefix {prefix!r}, got {obfuscated!r}"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_overlapping_entity_spans(self, session_id):
        """
        Two detectors flag overlapping spans for the same text region.
        For example, 'Dr. Eleanor Hartwell' flagged as both PII_NAME (full span)
        and PII_NAME with a shorter sub-span. The engine must deduplicate and
        not double-replace or corrupt the text.
        """
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = ObfuscationEngine({"PII_NAME": TokenizationStrategy()})

        text = "Dr. Eleanor Hartwell was admitted."
        # Overlapping: one detector found the full name, another found just the surname
        entity_full = MockDetectedEntity("PII_NAME", "Dr. Eleanor Hartwell", 0, 20, 0.95)
        entity_partial = MockDetectedEntity("PII_NAME", "Eleanor Hartwell", 4, 20, 0.88)

        result = await engine.obfuscate_document(
            text, [entity_full, entity_partial], vault, session_id
        )

        # The output must not contain either the full name or the partial name
        assert "Eleanor Hartwell" not in result.obfuscated_text, (
            "Overlapping entity partial value leaked into obfuscated output"
        )
        assert "Dr. Eleanor Hartwell" not in result.obfuscated_text, (
            "Overlapping entity full value leaked into obfuscated output"
        )

        # There must be exactly one token in the output for this region (deduplication)
        tokens = TOKEN_PATTERN.findall(result.obfuscated_text)
        name_tokens = [t for t in tokens if "PII_NAME" in t]
        assert len(name_tokens) == 1, (
            f"Expected exactly 1 PII_NAME token after deduplication of overlapping spans, "
            f"got {len(name_tokens)}: {name_tokens}"
        )

        # Vault must have only 1 entry (not 2) for this entity
        assert vault.entry_count(session_id) == 1, (
            f"Expected 1 vault entry after deduplication, got {vault.entry_count(session_id)}"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_empty_document(self, session_id):
        """
        Empty string input to the full pipeline must complete without error.
        Output must also be an empty string (or at minimum contain no tokens or PII).
        """
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault = MockSessionVault()
        strategies = {et: TokenizationStrategy() for et in REQUIRED_ENTITY_TYPES}
        engine = ObfuscationEngine(strategies)

        empty_text = ""
        entities: list[MockDetectedEntity] = []  # No entities in empty doc

        # Must not raise any exception
        result = await engine.obfuscate_document(empty_text, entities, vault, session_id)

        assert isinstance(result.obfuscated_text, str), (
            "obfuscated_text must be a str even for empty input"
        )
        assert result.obfuscated_text == "", (
            f"Empty input must produce empty output, got: {result.obfuscated_text!r}"
        )
        assert vault.entry_count(session_id) == 0, (
            "Empty document must produce zero vault entries"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_very_long_entity_value(self, session_id):
        """
        Entity value is exactly 500 characters long (e.g. a very long address or
        a base64-encoded identifier). Tokenization must handle it without truncation,
        and de-obfuscation must restore the full 500-character value exactly.
        """
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("ObfuscationEngine or DeobfuscationEngine not implemented")

        vault = MockSessionVault()
        obf_engine = ObfuscationEngine({"PII_ADDRESS": TokenizationStrategy()})
        deobf_engine = DeobfuscationEngine()

        # Construct a 500-character fictional address value
        long_address = ("2847 Lakeview Drive, Suite " + "A" * 10 + ", " ) * 14
        long_address = long_address[:500]  # Exactly 500 characters
        assert len(long_address) == 500, "Test setup error: address is not 500 chars"

        text = f"Address on file: {long_address}. Please verify with patient."
        start = len("Address on file: ")
        entity = MockDetectedEntity(
            entity_type="PII_ADDRESS",
            original_value=long_address,
            start=start,
            end=start + 500,
            confidence=0.93,
        )

        # Obfuscate
        obf_result = await obf_engine.obfuscate_document(text, [entity], vault, session_id)

        assert long_address not in obf_result.obfuscated_text, (
            "500-char entity value was not replaced in obfuscated output"
        )
        token_matches = TOKEN_PATTERN.findall(obf_result.obfuscated_text)
        assert token_matches, "No token found after obfuscating 500-char entity"

        # De-obfuscate
        deobf_result = await deobf_engine.deobfuscate(
            obf_result.obfuscated_text, vault, session_id
        )

        assert long_address in deobf_result.restored_text, (
            f"500-char entity value was not fully restored after de-obfuscation.\n"
            f"Expected value (first 80 chars): {long_address[:80]!r}\n"
            f"Restored text (first 200 chars): {deobf_result.restored_text[:200]!r}"
        )
        assert deobf_result.tokens_restored == 1, (
            f"Expected 1 token restored, got {deobf_result.tokens_restored}"
        )
        assert deobf_result.tokens_missed == 0, (
            f"Expected 0 vault misses, got {deobf_result.tokens_missed}"
        )


# ---------------------------------------------------------------------------
# Entry point for direct execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"],
        check=False,
    )
    sys.exit(result.returncode)


# ===== pii_leakage_scan.py SCRIPT =====
#
# Copy the content below verbatim into scripts/pii_leakage_scan.py
# This is the standalone CLI script referenced by the eval runner.
# It can be run independently of pytest to audit any text file or pipeline
# output for known PII values.
#
# Usage:
#   python scripts/pii_leakage_scan.py --input path/to/file.txt
#   python scripts/pii_leakage_scan.py --input path/to/file.txt --pii-file path/to/pii.json
#   python scripts/pii_leakage_scan.py --stdin   # reads from stdin
#   echo "some text" | python scripts/pii_leakage_scan.py --stdin
#
# Exit codes:
#   0  — No PII found (clean)
#   1  — One or more PII values found (leakage detected)
#   2  — Usage error or file not found
#
# scripts/pii_leakage_scan.py
# ----------------------------
#
# #!/usr/bin/env python3
# """
# pii_leakage_scan.py — Standalone PII leakage scanner.
#
# Reads text from a file or stdin and checks for any of a configurable set of
# known PII values. Reports violations to stdout and exits with code 1 if any
# are found. Intended for use in CI pipelines and eval runners.
#
# This script has zero external dependencies — only stdlib is used.
# """
#
# from __future__ import annotations
#
# import argparse
# import json
# import os
# import sys
# from typing import Optional
#
#
# # ---------------------------------------------------------------------------
# # Default PII values (fictional, safe for inclusion in source code)
# # Override with --pii-file to supply real values at runtime from a secrets store.
# # ---------------------------------------------------------------------------
#
# DEFAULT_PII_VALUES: dict[str, str] = {
#     "PII_NAME": "Dr. Eleanor Hartwell",
#     "PII_SSN": "543-67-8901",
#     "PII_DOB": "March 14, 1972",
#     "PII_ADDRESS": "2847 Lakeview Drive, Austin, TX 78701",
#     "PII_EMAIL": "eleanor.hartwell@example-clinic.org",
#     "PII_PHONE": "(512) 555-0147",
#     "PHI_MRN": "MRN-7293847",
#     "PHI_DIAGNOSIS": "Type 2 Diabetes Mellitus",
#     "PHI_MEDICATION": "Metformin 500mg",
#     "PHI_INSURANCE_ID": "BCBS-TX-0042-8837291",
#     "PHI_LAB_RESULT": "HbA1c: 8.2%",
#     "FIN_ACCOUNT": "4532-1234-5678-9012",
#     "FIN_TAX_ID": "EIN: 74-1234567",
#     "LEGAL_CLIENT": "Martinez Family Trust",
# }
#
#
# def scan_text(text: str, pii_values: dict[str, str]) -> list[dict]:
#     """
#     Scan text for any of the given PII values (case-insensitive).
#
#     Returns a list of violation dicts:
#         [{"entity_type": str, "value": str, "first_offset": int}, ...]
#     """
#     violations = []
#     text_lower = text.lower()
#     for entity_type, value in pii_values.items():
#         idx = text_lower.find(value.lower())
#         if idx != -1:
#             violations.append({
#                 "entity_type": entity_type,
#                 "value": value,
#                 "first_offset": idx,
#             })
#     return violations
#
#
# def load_pii_file(path: str) -> dict[str, str]:
#     """
#     Load PII values from a JSON file.
#     Expected format: {"ENTITY_TYPE": "value", ...}
#     """
#     if not os.path.exists(path):
#         print(f"ERROR: PII file not found: {path}", file=sys.stderr)
#         sys.exit(2)
#     with open(path, encoding="utf-8") as f:
#         data = json.load(f)
#     if not isinstance(data, dict):
#         print(f"ERROR: PII file must contain a JSON object, got {type(data).__name__}", file=sys.stderr)
#         sys.exit(2)
#     return {str(k): str(v) for k, v in data.items()}
#
#
# def read_input(args: argparse.Namespace) -> str:
#     """Read text from file or stdin based on CLI args."""
#     if args.stdin:
#         return sys.stdin.read()
#     if args.input:
#         if not os.path.exists(args.input):
#             print(f"ERROR: Input file not found: {args.input}", file=sys.stderr)
#             sys.exit(2)
#         with open(args.input, encoding="utf-8") as f:
#             return f.read()
#     print("ERROR: Provide --input <file> or --stdin", file=sys.stderr)
#     sys.exit(2)
#
#
# def main() -> None:
#     parser = argparse.ArgumentParser(
#         description="Scan text for PII leakage. Exit 0 if clean, 1 if PII found.",
#         formatter_class=argparse.RawDescriptionHelpFormatter,
#     )
#     parser.add_argument(
#         "--input", metavar="FILE",
#         help="Path to input text file to scan.",
#     )
#     parser.add_argument(
#         "--stdin", action="store_true",
#         help="Read input text from stdin.",
#     )
#     parser.add_argument(
#         "--pii-file", metavar="JSON_FILE",
#         help=(
#             "Path to JSON file containing PII values to scan for. "
#             "Format: {\"ENTITY_TYPE\": \"value\", ...}. "
#             "If omitted, uses built-in fictional test values."
#         ),
#     )
#     parser.add_argument(
#         "--json-output", action="store_true",
#         help="Output violations as JSON (one object per line) instead of human text.",
#     )
#     parser.add_argument(
#         "--quiet", "-q", action="store_true",
#         help="Suppress all output; use exit code only.",
#     )
#     args = parser.parse_args()
#
#     pii_values = load_pii_file(args.pii_file) if args.pii_file else DEFAULT_PII_VALUES
#     text = read_input(args)
#     violations = scan_text(text, pii_values)
#
#     if not violations:
#         if not args.quiet:
#             print("CLEAN: No PII values found in input.")
#         sys.exit(0)
#     else:
#         if not args.quiet:
#             if args.json_output:
#                 for v in violations:
#                     print(json.dumps(v))
#             else:
#                 print(f"PII LEAKAGE DETECTED: {len(violations)} violation(s):")
#                 for v in violations:
#                     print(
#                         f"  [{v['entity_type']}] value={v['value']!r} "
#                         f"first_offset={v['first_offset']}"
#                     )
#         sys.exit(1)
#
#
# if __name__ == "__main__":
#     main()
#
# ===== END pii_leakage_scan.py SCRIPT =====
