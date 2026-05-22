"""Residual-PII scanner — defense-in-depth for the outbound leak gate.

The primary leak gate scans the payload against values the detector *found* (the
session vault). That cannot catch an identifier the detector *missed*, since a
missed value never enters the vault. This scanner is independent of detection: it
re-applies the high-precision structured-identifier patterns directly to the
outbound payload (after removing legitimate tokens) and flags anything that still
looks like raw PII.

Only high-precision identifier patterns are used (SSN, email, phone, account, tax
id, MRN, insurance id). Softer signals (names, diagnoses) are deliberately excluded
to avoid blocking legitimate context — those remain the responsibility of the
detector + the vault-based gate.
"""

from __future__ import annotations

import re

from ..detection.patterns import PATTERNS

# Identifier types worth a hard block if they appear un-obfuscated on the wire.
RESIDUAL_TYPES = (
    "PII_SSN",
    "PII_EMAIL",
    "PII_PHONE",
    "FIN_ACCOUNT",
    "FIN_TAX_ID",
    "PHI_MRN",
    "PHI_INSURANCE_ID",
)

# Strip legitimate tokens first so token hex (e.g. an 8-digit suffix) can never be
# mistaken for residual PII.
_TOKEN_RE = re.compile(r"\[[A-Z][A-Z0-9_]*_[0-9a-fA-F]{8}\]")


def find_residual_pii(text: str) -> str | None:
    """Return the entity type of the first un-obfuscated identifier found, else None."""
    stripped = _TOKEN_RE.sub(" ", text)
    for entity_type in RESIDUAL_TYPES:
        for pattern in PATTERNS.get(entity_type, []):
            if pattern.search(stripped):
                return entity_type
    return None
