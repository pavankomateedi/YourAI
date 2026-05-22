"""Presidio recognizer for Medical Record Numbers (PHI_MRN)."""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class MRNRecognizer(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity="PHI_MRN",
            patterns=[Pattern(name="mrn", regex=r"\b(?:MRN|PT)-\d+\b", score=0.85)],
            context=["mrn", "medical record", "patient"],
        )
