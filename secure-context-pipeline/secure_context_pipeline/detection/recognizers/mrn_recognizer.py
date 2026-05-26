"""Presidio recognizer for Medical Record Numbers (PHI_MRN)."""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class MRNRecognizer(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity="PHI_MRN",
            patterns=[
                Pattern(name="mrn_hyphen", regex=r"\b(?:MRN|PT)-\d+\b", score=0.85),
                # Space/colon/hash separated form (``MRN 884211``, ``MRN: 884211``).
                Pattern(name="mrn_sep", regex=r"\bMRN[\s:#-]*\d{3,}\b", score=0.8),
            ],
            context=["mrn", "medical record", "patient"],
        )
