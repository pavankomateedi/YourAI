"""Unit tests: Obfuscation Engine (EVAL-OBF-001 through EVAL-OBF-005)."""

import re

import pytest

from conftest import (
    FIXTURE_PII_VALUES,
    REQUIRED_ENTITY_TYPES,
    TOKEN_PATTERN,
    MockDetectedEntity,
    MockSessionVault,
    assert_no_pii_in_text,
)


class TestObfuscationEngine:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_within_session_token_determinism(self, session_id):
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

        tokens = TOKEN_PATTERN.findall(result.obfuscated_text)
        name_tokens = [t for t in tokens if t.startswith("PII_NAME")]
        assert len(set(name_tokens)) == 1, f"Expected 1 unique token, got {set(name_tokens)}"
        assert vault.entry_count(session_id) == 1

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_cross_session_nondeterminism(self, session_id, session_id_b):
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
        assert not tokens_a.intersection(tokens_b)

        token_from_a = list(tokens_a)[0]
        with pytest.raises(KeyError):
            await vault_b.lookup_by_token(session_id_b, f"[{token_from_a}]")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_token_format_compliance(self, session_id):
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
        text = " ".join(FIXTURE_PII_VALUES.values())
        result = await engine.obfuscate_document(text, entities, vault, session_id)

        raw_tokens = re.findall(r"\[([^\]]+)\]", result.obfuscated_text)
        for token_inner in raw_tokens:
            if token_inner == "REDACTED":
                continue
            assert TOKEN_PATTERN.match(f"[{token_inner}]"), (
                f"Token '[{token_inner}]' does not match required format"
            )
            prefix = "_".join(token_inner.split("_")[:2])
            assert prefix in REQUIRED_ENTITY_TYPES, f"Token prefix '{prefix}' not recognized"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_pseudonym_consistency_within_session(self, session_id):
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

        words = result.obfuscated_text.split(" ... ")
        assert len(words) == 2
        assert words[0] == words[1], f"Pseudonym inconsistency: {words[0]!r} vs {words[1]!r}"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_original_values_not_in_obfuscated_output(self, session_id, fixture_text_medical):
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
