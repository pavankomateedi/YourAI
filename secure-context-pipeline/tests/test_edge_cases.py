"""Edge cases: boundary conditions in obfuscation and de-obfuscation."""

import pytest

from conftest import REQUIRED_ENTITY_TYPES, TOKEN_PATTERN, MockDetectedEntity, MockSessionVault


class TestEdgeCases:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_entity_at_document_start(self, session_id):
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = ObfuscationEngine({"PII_NAME": TokenizationStrategy()})
        name = "Eleanor Hartwell"
        text = f"{name} presented to the clinic today."
        entity = MockDetectedEntity("PII_NAME", name, 0, len(name), 0.97)
        result = await engine.obfuscate_document(text, [entity], vault, session_id)

        assert name not in result.obfuscated_text
        assert TOKEN_PATTERN.search(result.obfuscated_text)
        assert "presented to the clinic today." in result.obfuscated_text

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_entity_at_document_end(self, session_id):
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = ObfuscationEngine({"PII_SSN": TokenizationStrategy()})
        ssn = "543-67-8901"
        prefix = "Patient SSN: "
        text = prefix + ssn
        entity = MockDetectedEntity("PII_SSN", ssn, len(prefix), len(prefix) + len(ssn), 0.99)
        result = await engine.obfuscate_document(text, [entity], vault, session_id)

        assert ssn not in result.obfuscated_text
        assert TOKEN_PATTERN.search(result.obfuscated_text)
        assert result.obfuscated_text.startswith(prefix)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_overlapping_entity_spans(self, session_id):
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = ObfuscationEngine({"PII_NAME": TokenizationStrategy()})
        text = "Dr. Eleanor Hartwell was admitted."
        entity_full = MockDetectedEntity("PII_NAME", "Dr. Eleanor Hartwell", 0, 20, 0.95)
        entity_partial = MockDetectedEntity("PII_NAME", "Eleanor Hartwell", 4, 20, 0.88)
        result = await engine.obfuscate_document(text, [entity_full, entity_partial], vault, session_id)

        assert "Eleanor Hartwell" not in result.obfuscated_text
        assert "Dr. Eleanor Hartwell" not in result.obfuscated_text
        name_tokens = [t for t in TOKEN_PATTERN.findall(result.obfuscated_text) if "PII_NAME" in t]
        assert len(name_tokens) == 1
        assert vault.entry_count(session_id) == 1

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_empty_document(self, session_id):
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("ObfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = ObfuscationEngine({et: TokenizationStrategy() for et in REQUIRED_ENTITY_TYPES})
        result = await engine.obfuscate_document("", [], vault, session_id)

        assert isinstance(result.obfuscated_text, str)
        assert result.obfuscated_text == ""
        assert vault.entry_count(session_id) == 0

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_very_long_entity_value(self, session_id):
        try:
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("Engines not implemented")

        vault = MockSessionVault()
        obf_engine = ObfuscationEngine({"PII_ADDRESS": TokenizationStrategy()})
        deobf_engine = DeobfuscationEngine()

        long_address = ("2847 Lakeview Drive, Suite " + "A" * 10 + ", ") * 14
        long_address = long_address[:500]
        assert len(long_address) == 500

        text = f"Address on file: {long_address}. Please verify with patient."
        start = len("Address on file: ")
        entity = MockDetectedEntity("PII_ADDRESS", long_address, start, start + 500, 0.93)

        obf_result = await obf_engine.obfuscate_document(text, [entity], vault, session_id)
        assert long_address not in obf_result.obfuscated_text
        assert TOKEN_PATTERN.findall(obf_result.obfuscated_text)

        deobf_result = await deobf_engine.deobfuscate(obf_result.obfuscated_text, vault, session_id)
        assert long_address in deobf_result.restored_text
        assert deobf_result.tokens_restored == 1
        assert deobf_result.tokens_missed == 0
