"""Presidio recognizer for health-insurance member IDs (PHI_INSURANCE_ID)."""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

from ..patterns import INSURANCE_CARRIERS


class InsuranceIDRecognizer(PatternRecognizer):
    def __init__(self) -> None:
        regex = rf"\b(?:{'|'.join(INSURANCE_CARRIERS)})-[A-Z0-9\-]+\b"
        super().__init__(
            supported_entity="PHI_INSURANCE_ID",
            patterns=[Pattern(name="insurance_id", regex=regex, score=0.85)],
            context=["insurance", "member", "policy", "carrier"],
        )
