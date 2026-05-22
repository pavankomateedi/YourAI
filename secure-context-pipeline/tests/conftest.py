"""Shared fixtures, helpers, and mock implementations for the test suite.

This is the conftest block described in the test harness header: every test module
imports the constants, helpers, and mock classes from here, and pytest injects the
fixtures by name. The mocks mirror the real component interfaces exactly.
"""

from __future__ import annotations

import io
import json
import re
import uuid
from dataclasses import dataclass

import pytest

pytest_plugins = ("pytest_asyncio",)


def pytest_configure(config):
    config.addinivalue_line("markers", "security: security-critical tests (PII leakage, vault isolation)")
    config.addinivalue_line("markers", "performance: benchmark tests")
    config.addinivalue_line("markers", "integration: end-to-end integration tests")
    config.addinivalue_line("markers", "unit: fast unit tests for individual components")
    config.addinivalue_line("markers", "obfuscation: obfuscation-engine tests")
    config.addinivalue_line("markers", "deobfuscation: de-obfuscation tests")
    config.addinivalue_line("markers", "quality: code-quality checks")


# --------------------------------------------------------------------------
# Shared constants and helpers
# --------------------------------------------------------------------------

TOKEN_PATTERN = re.compile(r"\[([A-Z]+_[A-Z]+_[0-9a-f]{8})\]")

REQUIRED_ENTITY_TYPES = [
    "PII_NAME", "PII_SSN", "PII_DOB", "PII_ADDRESS", "PII_EMAIL", "PII_PHONE",
    "PHI_MRN", "PHI_DIAGNOSIS", "PHI_MEDICATION", "PHI_INSURANCE_ID", "PHI_LAB_RESULT",
    "FIN_ACCOUNT", "FIN_TAX_ID", "LEGAL_CLIENT", "LEGAL_STRATEGY",
]

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


def assert_no_pii_in_text(text: str, pii_values: dict | None = None) -> None:
    if pii_values is None:
        pii_values = FIXTURE_PII_VALUES
    violations = []
    for entity_type, value in pii_values.items():
        if value.lower() in text.lower():
            violations.append(f"{entity_type}: '{value}' found in text")
    assert not violations, (
        f"PII LEAKAGE DETECTED — {len(violations)} violation(s):\n" + "\n".join(violations)
    )


def make_session_id() -> str:
    return f"test-session-{uuid.uuid4().hex[:8]}"


def make_user_id() -> str:
    return f"test-user-{uuid.uuid4().hex[:8]}"


def _make_minimal_pdf_bytes(text: str) -> bytes:
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
        b"0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n"
        b"0000000115 00000 n \n0000000266 00000 n \n0000000360 00000 n \n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n430\n%%EOF\n"
    )
    return pdf


def _make_minimal_docx_bytes(text: str) -> bytes:
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


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def session_id() -> str:
    return make_session_id()


@pytest.fixture
def user_id() -> str:
    return make_user_id()


@pytest.fixture
def session_id_b() -> str:
    return make_session_id()


@pytest.fixture
def fixture_text_medical() -> str:
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
    return (
        "GENERAL MEDICAL GUIDANCE\n"
        "Patients with elevated blood glucose should consider dietary changes.\n"
        "Regular exercise of 30 minutes per day is recommended.\n"
        "Consult your physician before starting any new medication regimen.\n"
        "Blood pressure monitoring should occur at least once per week.\n"
    )


@pytest.fixture
def fixture_text_repeated_pii() -> str:
    return (
        "Patient Dr. Eleanor Hartwell was admitted on March 14, 1972 (her birthday).\n"
        "Dr. Eleanor Hartwell's diagnosis is Type 2 Diabetes Mellitus.\n"
        "Follow-up scheduled for Dr. Eleanor Hartwell next month.\n"
        "Dr. Eleanor Hartwell has been prescribed Metformin 500mg.\n"
    )


@pytest.fixture
def fixture_text_2000_words() -> str:
    base = (
        "COMPREHENSIVE PATIENT ASSESSMENT REPORT\n\n"
        "Patient: Dr. Eleanor Hartwell — MRN: MRN-7293847\n\n"
    )
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
    ) * 18
    return base + filler


# --------------------------------------------------------------------------
# Mock implementations (mirror the real interfaces)
# --------------------------------------------------------------------------

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
    original_value: str
    session_id: str


class MockSessionVault:
    """In-memory vault for testing (no encryption — use the real vault for SEC-003)."""

    def __init__(self):
        self._store: dict = {}
        self._reverse: dict = {}
        self._destroyed: set = set()
        self._events: list = []

    async def store(self, session_id, token, original, entity_type):
        assert session_id not in self._destroyed, f"Vault for session {session_id} has been destroyed"
        self._store.setdefault(session_id, {})
        self._reverse.setdefault(session_id, {})
        self._store[session_id][token] = MockVaultEntry(token, entity_type, original, session_id)
        self._reverse[session_id][(entity_type, original)] = token

    async def lookup_by_token(self, session_id, token):
        if session_id in self._destroyed:
            raise KeyError(f"Vault for session {session_id} has been destroyed")
        entry = self._store.get(session_id, {}).get(token)
        if entry is None:
            raise KeyError(f"Token {token} not found in vault for session {session_id}")
        return entry.original_value

    async def lookup_by_original(self, session_id, entity_type, original):
        if session_id in self._destroyed:
            return None
        return self._reverse.get(session_id, {}).get((entity_type, original))

    async def destroy(self, session_id):
        self._store.pop(session_id, None)
        self._reverse.pop(session_id, None)
        self._destroyed.add(session_id)
        self._events.append({"event": "VAULT_DESTROYED", "session_id": session_id})

    async def list_tokens(self, session_id):
        return list(self._store.get(session_id, {}).keys())

    def entry_count(self, session_id):
        return len(self._store.get(session_id, {}))

    def get_events(self):
        return list(self._events)


class MockAuditLog:
    def __init__(self):
        self._entries: list = []

    async def log_obfuscation(self, session_id, user_id, entity_type, token_id,
                              document_id, strategy_used, confidence_score):
        self._entries.append({
            "event": "OBFUSCATION", "session_id": session_id, "user_id": user_id,
            "entity_type": entity_type, "token_id": token_id, "document_id": document_id,
            "strategy_used": strategy_used, "confidence_score": confidence_score,
        })

    async def log_vault_miss(self, session_id, user_id, token_id):
        self._entries.append({
            "event": "VAULT_MISS", "session_id": session_id, "user_id": user_id, "token_id": token_id,
        })

    async def log_vault_destroyed(self, session_id, user_id):
        self._entries.append({"event": "VAULT_DESTROYED", "session_id": session_id, "user_id": user_id})

    async def log_pii_leak_detected(self, session_id, user_id, entity_type, stage):
        self._entries.append({
            "event": "PII_LEAK_DETECTED", "session_id": session_id, "user_id": user_id,
            "entity_type": entity_type, "stage": stage,
        })

    def get_entries(self):
        return list(self._entries)

    def get_entries_by_event(self, event_name):
        return [e for e in self._entries if e.get("event") == event_name]

    def to_text(self):
        return "\n".join(json.dumps(entry) for entry in self._entries)
