"""Unit tests: PII/PHI Detector (EVAL-OBF-006, EVAL-OBF-007)."""

import pytest

from conftest import REQUIRED_ENTITY_TYPES, MockDetectedEntity, MockSessionVault, make_session_id


class TestPIIDetector:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detects_all_required_entity_types(self, fixture_text_medical):
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            detector = PIIDetector()
            entities = await detector.detect(fixture_text_medical)
            detected_types = {e.entity_type for e in entities}
        except ImportError:
            pytest.skip("PIIDetector not implemented yet — skipping integration check")

        missing = set(REQUIRED_ENTITY_TYPES) - detected_types
        assert not missing, f"Entity types not detected: {missing}\nDetected types: {detected_types}"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detects_ssn_formats(self):
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
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            detector = PIIDetector()
            entities = await detector.detect(fixture_text_no_pii)
        except ImportError:
            pytest.skip("PIIDetector not implemented")

        phi_entities = [e for e in entities if e.confidence >= 0.85]
        assert len(phi_entities) == 0, (
            f"False positives detected in clean document: "
            f"{[(e.entity_type, e.original_value) for e in phi_entities]}"
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_low_confidence_entity_triggers_redaction(self):
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault = MockSessionVault()
        session = make_session_id()
        engine = ObfuscationEngine({"PII_NAME": TokenizationStrategy()})

        low_confidence_entity = MockDetectedEntity(
            entity_type="PII_NAME", original_value="John", start=8, end=12, confidence=0.45,
        )
        text = "Patient John was admitted."
        result = await engine.obfuscate_document(text, [low_confidence_entity], vault, session)

        assert "[REDACTED]" in result.obfuscated_text
        assert "John" not in result.obfuscated_text

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_entity_spans_are_accurate(self, fixture_text_medical):
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            detector = PIIDetector()
            entities = await detector.detect(fixture_text_medical)
        except ImportError:
            pytest.skip("PIIDetector not implemented")

        for entity in entities:
            extracted = fixture_text_medical[entity.start:entity.end]
            assert entity.original_value in extracted or extracted in entity.original_value, (
                f"Span mismatch for {entity.entity_type}: "
                f"span text='{extracted}', entity value='{entity.original_value}'"
            )
