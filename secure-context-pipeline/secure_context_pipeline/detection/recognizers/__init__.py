"""Custom Presidio recognizers for entity types not covered by Presidio defaults.

These are used when the full Presidio + spaCy stack is installed. They wrap the
same regexes defined in :mod:`..patterns`, so the rule-based path and the Presidio
path share one source of truth. Importing this module never fails if Presidio is
absent — :func:`build_custom_recognizers` simply returns an empty list.
"""

from __future__ import annotations


def build_custom_recognizers() -> list:
    """Return Presidio ``PatternRecognizer`` instances, or [] if Presidio is absent."""
    try:
        from .insurance_recognizer import InsuranceIDRecognizer
        from .legal_recognizer import LegalClientRecognizer, LegalStrategyRecognizer
        from .mrn_recognizer import MRNRecognizer
    except Exception:
        return []
    return [
        MRNRecognizer(),
        InsuranceIDRecognizer(),
        LegalClientRecognizer(),
        LegalStrategyRecognizer(),
    ]


__all__ = ["build_custom_recognizers"]
