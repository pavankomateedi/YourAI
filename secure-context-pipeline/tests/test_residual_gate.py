"""Defense-in-depth leak gate: raw structured PII in the outbound payload is
blocked even when the detector missed it (so it was never vaulted)."""

import pytest

from conftest import MockSessionVault, make_session_id


class TestResidualLeakGate:
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_unvaulted_raw_ssn_is_blocked(self):
        """An SSN that bypassed detection (empty vault, no known values) must still
        abort the LLM call via the residual scan."""
        from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline
        from secure_context_pipeline.pipeline.exceptions import PIILeakError

        called = False

        async def llm(ctx, query):
            nonlocal called
            called = True
            return "should not run"

        pipeline = SecureContextPipeline(llm_fn=llm)
        with pytest.raises(PIILeakError):
            await pipeline._call_llm_with_leak_check(
                obfuscated_context="Account holder SSN is 543-67-8901 on file.",
                user_query="summarize",
                vault=MockSessionVault(),
                session_id=make_session_id(),
                known_pii_values=None,
            )
        assert called is False

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_clean_tokenized_payload_passes(self):
        """A fully tokenized payload (token hex is not raw PII) must NOT be blocked."""
        from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline

        async def llm(ctx, query):
            return "ok"

        pipeline = SecureContextPipeline(llm_fn=llm)
        result = await pipeline._call_llm_with_leak_check(
            obfuscated_context="Patient [PII_NAME_a3f2c1d4] SSN [PII_SSN_b7e2a1c3] verified.",
            user_query="summarize",
            vault=MockSessionVault(),
            session_id=make_session_id(),
            known_pii_values=None,
        )
        assert result == "ok"

    @pytest.mark.security
    def test_residual_scanner_unit(self):
        from secure_context_pipeline.pipeline.residual_scan import find_residual_pii

        assert find_residual_pii("call (512) 555-0147 now") == "PII_PHONE"
        assert find_residual_pii("email a@b.com please") == "PII_EMAIL"
        assert find_residual_pii("card 4532-1234-5678-9012") == "FIN_ACCOUNT"
        # Tokens (and their hex) must not trip the scanner.
        assert find_residual_pii("Patient [PII_PHONE_12345678] seen [PHI_MRN_abcd1234].") is None
        assert find_residual_pii("No identifiers here at all.") is None
