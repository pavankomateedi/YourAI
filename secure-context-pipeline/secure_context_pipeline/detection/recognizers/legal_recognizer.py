"""Presidio recognizers for legal-privilege entities (LEGAL_CLIENT, LEGAL_STRATEGY)."""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class LegalClientRecognizer(PatternRecognizer):
    def __init__(self) -> None:
        regex = (
            r"\b[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+"
            r"(?:Trust|LLC|Inc\.?|Corp\.?|Foundation|Estate|Partners|Group|Holdings)\b"
        )
        super().__init__(
            supported_entity="LEGAL_CLIENT",
            patterns=[Pattern(name="legal_client", regex=regex, score=0.80)],
            context=["client", "trustee", "represented", "matter"],
        )


class LegalStrategyRecognizer(PatternRecognizer):
    def __init__(self) -> None:
        regex = (
            r"(?i)\b(?:settlement\s+is\s+advised[^\n]*"
            r"|settle\s+at\s+no\s+less\s+than[^\n]*"
            r"|our\s+position\s+is[^\n]*"
            r"|we\s+recommend\s+(?:settling|initiating)[^\n]*)"
        )
        super().__init__(
            supported_entity="LEGAL_STRATEGY",
            patterns=[Pattern(name="legal_strategy", regex=regex, score=0.75)],
            context=["strategy", "settle", "privileged", "position"],
        )
