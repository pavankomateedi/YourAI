"""Multi-chunk obfuscation consistency + streaming de-obfuscation."""

import pytest

from conftest import TOKEN_PATTERN, MockSessionVault, make_session_id


class TestChunking:
    def test_chunk_text_roundtrips(self):
        from secure_context_pipeline.obfuscation.chunking import chunk_text

        text = "line one\n" * 500
        chunks = chunk_text(text, max_chars=200)
        assert len(chunks) > 1
        assert "".join(chunks) == text  # byte-identical reconstruction

    def test_chunk_text_no_split_when_small(self):
        from secure_context_pipeline.obfuscation.chunking import chunk_text

        assert chunk_text("short", max_chars=12000) == ["short"]

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_cross_chunk_token_consistency(self):
        """The same value in two different chunks must map to one token (shared vault)."""
        from secure_context_pipeline.detection.detector import PIIDetector
        from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
        from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy

        detector = PIIDetector()
        engine = ObfuscationEngine({"PII_SSN": TokenizationStrategy()})
        vault = MockSessionVault()
        sid = make_session_id()

        chunk_a = "Account on file lists SSN 543-67-8901 for the holder.\n"
        chunk_b = "Verification confirmed SSN 543-67-8901 again later.\n"
        od_a = await engine.obfuscate_document(chunk_a, await detector.detect(chunk_a), vault, sid)
        od_b = await engine.obfuscate_document(chunk_b, await detector.detect(chunk_b), vault, sid)

        tok_a = [t for t in TOKEN_PATTERN.findall(od_a.obfuscated_text) if "PII_SSN" in t]
        tok_b = [t for t in TOKEN_PATTERN.findall(od_b.obfuscated_text) if "PII_SSN" in t]
        assert tok_a and tok_b and tok_a[0] == tok_b[0], "token must be consistent across chunks"
        assert vault.entry_count(sid) == 1, "repeated value across chunks must be one vault entry"


class TestStreamingDeobfuscation:
    @pytest.mark.asyncio
    async def test_stream_restores_token_split_across_chunks(self):
        from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine

        vault = MockSessionVault()
        sid = make_session_id()
        await vault.store(sid, "[PII_NAME_a3f2c1d4]", "Dr. Eleanor Hartwell", "PII_NAME")
        engine = DeobfuscationEngine()

        full = "Summary for [PII_NAME_a3f2c1d4] is ready. Follow up soon."

        async def char_stream():
            # Emit 3 chars at a time, deliberately splitting the token.
            for i in range(0, len(full), 3):
                yield full[i : i + 3]

        collected = ""
        async for piece in engine.deobfuscate_stream(char_stream(), vault, sid):
            collected += piece

        assert collected == "Summary for Dr. Eleanor Hartwell is ready. Follow up soon."
        assert "[PII_NAME_a3f2c1d4]" not in collected

    @pytest.mark.asyncio
    async def test_stream_vault_miss_unavailable(self):
        from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine

        vault = MockSessionVault()
        sid = make_session_id()
        engine = DeobfuscationEngine()

        async def stream():
            yield "Patient [PII_NAME_FFFFFFFF] "
            yield "needs review."

        collected = ""
        async for piece in engine.deobfuscate_stream(stream(), vault, sid):
            collected += piece
        assert collected == "Patient [UNAVAILABLE] needs review."
