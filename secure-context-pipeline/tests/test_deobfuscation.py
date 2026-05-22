"""Unit tests: De-obfuscation Engine (EVAL-DEOB-001 through EVAL-DEOB-006)."""

import pytest

from conftest import TOKEN_PATTERN, MockSessionVault


class TestDeobfuscationEngine:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_all_tokens_restored(self, session_id):
        try:
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("DeobfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = DeobfuscationEngine()
        entries = [
            ("[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME"),
            ("[PII_SSN_b7e2a1c3]", "543-67-8901", "PII_SSN"),
            ("[PHI_DIAGNOSIS_2c8a4d7b]", "Type 2 Diabetes Mellitus", "PHI_DIAGNOSIS"),
            ("[PHI_MEDICATION_9f1a3e2b]", "Metformin 500mg", "PHI_MEDICATION"),
            ("[FIN_ACCOUNT_4d7c9a1e]", "4532-1234-5678-9012", "FIN_ACCOUNT"),
        ]
        for token, original, etype in entries:
            await vault.store(session_id, token, original, etype)

        llm_response = (
            "Patient [PII_NAME_a3f2c1d4] (SSN: [PII_SSN_b7e2a1c3]) has been diagnosed "
            "with [PHI_DIAGNOSIS_2c8a4d7b] and is currently taking [PHI_MEDICATION_9f1a3e2b]. "
            "Insurance will be billed to account [FIN_ACCOUNT_4d7c9a1e]."
        )
        result = await engine.deobfuscate(llm_response, vault, session_id)

        assert result.tokens_restored == 5
        assert result.tokens_missed == 0
        for value in ["Eleanor Hartwell", "543-67-8901", "Type 2 Diabetes Mellitus",
                      "Metformin 500mg", "4532-1234-5678-9012"]:
            assert value in result.restored_text
        assert not TOKEN_PATTERN.search(result.restored_text)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_inflected_token_handling(self, session_id):
        try:
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("DeobfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = DeobfuscationEngine()
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")

        response = "This is [PII_NAME_a3f2c1d4]'s medical record."
        result = await engine.deobfuscate(response, vault, session_id)
        assert "Eleanor Hartwell" in result.restored_text
        assert "[PII_NAME_a3f2c1d4]" not in result.restored_text

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_vault_miss_produces_unavailable(self, session_id):
        try:
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("DeobfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = DeobfuscationEngine()
        response = "Patient [PII_NAME_FFFFFFFF] should follow up in two weeks."
        result = await engine.deobfuscate(response, vault, session_id)

        assert "[UNAVAILABLE]" in result.restored_text
        assert result.tokens_missed == 1
        assert "[PII_NAME_FFFFFFFF]" not in result.restored_text

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_non_pii_text_preserved_exactly(self, session_id):
        try:
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("DeobfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = DeobfuscationEngine()
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")

        response = (
            "The patient [PII_NAME_a3f2c1d4] has shown improvement. "
            "Their blood pressure is now 120/80 mmHg. Follow-up scheduled in 3 weeks."
        )
        expected = (
            "The patient Eleanor Hartwell has shown improvement. "
            "Their blood pressure is now 120/80 mmHg. Follow-up scheduled in 3 weeks."
        )
        result = await engine.deobfuscate(response, vault, session_id)
        assert result.restored_text == expected
