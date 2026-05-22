"""Integration tests: full pipeline, concurrency, and PII-leakage scan."""

import asyncio
import time
import uuid
from unittest.mock import AsyncMock

import pytest

from conftest import (
    FIXTURE_PII_VALUES,
    REQUIRED_ENTITY_TYPES,
    TOKEN_PATTERN,
    MockSessionVault,
    assert_no_pii_in_text,
    make_session_id,
    make_user_id,
)


class TestFullPipeline:
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_full_roundtrip_with_mock_llm(self, session_id, fixture_text_medical):
        try:
            from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline
        except ImportError:
            pytest.skip("SecureContextPipeline not implemented")

        async def mock_llm_call(obfuscated_context: str, query: str) -> str:
            tokens = TOKEN_PATTERN.findall(obfuscated_context)
            token_list = " ".join(f"[{t}]" for t in tokens)
            return f"Summary mentioning: {token_list}"

        pipeline = SecureContextPipeline(llm_fn=mock_llm_call)
        result = await pipeline.run(
            user_id=make_user_id(),
            session_id=session_id,
            text=fixture_text_medical,
            user_query="Summarize this patient record.",
        )

        for entity_type, value in FIXTURE_PII_VALUES.items():
            assert value in result.restored_response, f"Missing {entity_type}: '{value}'"
        assert not TOKEN_PATTERN.search(result.restored_response)

    @pytest.mark.security
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_llm_payload_contains_zero_pii(self, session_id, fixture_text_medical):
        try:
            from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline
        except ImportError:
            pytest.skip("SecureContextPipeline not implemented")

        captured_payload: dict = {}

        async def mock_llm_capture(obfuscated_context: str, query: str) -> str:
            captured_payload["context"] = obfuscated_context
            captured_payload["query"] = query
            return "Response from LLM."

        pipeline = SecureContextPipeline(llm_fn=mock_llm_capture)
        await pipeline.run(
            user_id=make_user_id(), session_id=session_id,
            text=fixture_text_medical, user_query="What is the patient's diagnosis?",
        )
        assert captured_payload, "LLM was never called"
        full_payload = captured_payload["context"] + " " + captured_payload["query"]
        assert_no_pii_in_text(full_payload, FIXTURE_PII_VALUES)

    @pytest.mark.security
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_audit_log_contains_no_pii(self, session_id, fixture_text_medical, tmp_path):
        try:
            from secure_context_pipeline.audit.audit_log import AuditLog
            from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline
        except ImportError:
            pytest.skip("AuditLog not implemented")

        log_file = tmp_path / "audit.jsonl"
        audit_log = AuditLog(log_path=str(log_file))
        pipeline = SecureContextPipeline(audit_log=audit_log, llm_fn=AsyncMock(return_value="LLM response"))
        await pipeline.run(
            user_id=make_user_id(), session_id=session_id,
            text=fixture_text_medical, user_query="Summarize the record.",
        )
        with open(log_file) as f:
            log_content = f.read()
        assert_no_pii_in_text(log_content, FIXTURE_PII_VALUES)

    @pytest.mark.security
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_pii_leak_gate_aborts_llm_call(self, session_id):
        try:
            from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline
            from secure_context_pipeline.pipeline.exceptions import PIILeakError
        except ImportError:
            pytest.skip("PIILeakError not implemented")

        llm_call_count = 0

        async def mock_llm(obfuscated_context: str, query: str) -> str:
            nonlocal llm_call_count
            llm_call_count += 1
            return "Should never reach here"

        leaky_obfuscated = "Patient name: Eleanor Hartwell has [PHI_DIAGNOSIS_2c8a4d7b]."
        pipeline = SecureContextPipeline(llm_fn=mock_llm)

        with pytest.raises(PIILeakError):
            await pipeline._call_llm_with_leak_check(
                obfuscated_context=leaky_obfuscated, user_query="Summarize",
                vault=MockSessionVault(), session_id=session_id,
                known_pii_values=FIXTURE_PII_VALUES,
            )
        assert llm_call_count == 0


class TestConcurrentSessionIsolation:
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_concurrent_sessions_no_cross_contamination(self):
        try:
            from secure_context_pipeline.vault.vault import SessionVault
            VaultClass = SessionVault
        except ImportError:
            VaultClass = MockSessionVault

        num_sessions = 10
        sessions = [(make_session_id(), make_user_id(), f"User Name {i}") for i in range(num_sessions)]
        vault = VaultClass()

        async def run_session(session_id, user_id, name):
            token = f"[PII_NAME_{uuid.uuid4().hex[:8]}]"
            await vault.store(session_id, token, name, "PII_NAME")
            await asyncio.sleep(0.01)
            retrieved = await vault.lookup_by_token(session_id, token)
            assert retrieved == name
            return session_id, token, name

        results = await asyncio.gather(*[run_session(s, u, n) for s, u, n in sessions])

        for i, (sid_i, token_i, _) in enumerate(results):
            for j, (sid_j, _, _) in enumerate(results):
                if i == j:
                    continue
                with pytest.raises((KeyError, Exception)):
                    await vault.lookup_by_token(sid_j, token_i)

    @pytest.mark.asyncio
    async def test_concurrent_pipeline_runs_no_degradation(self, fixture_text_medical):
        try:
            from secure_context_pipeline.pipeline.pipeline import SecureContextPipeline
        except ImportError:
            pytest.skip("SecureContextPipeline not implemented")

        async def run_one(session_num: int) -> dict:
            session_id = make_session_id()
            pipeline = SecureContextPipeline(llm_fn=AsyncMock(return_value=f"Response for session {session_num}"))
            result = await pipeline.run(
                user_id=make_user_id(), session_id=session_id,
                text=fixture_text_medical, user_query="Summarize the record.",
            )
            return {"session": session_num, "result": result}

        start = time.time()
        results = await asyncio.gather(*[run_one(i) for i in range(5)])
        elapsed = time.time() - start
        assert elapsed < 30, f"Concurrent pipeline took too long: {elapsed:.1f}s"
        for r in results:
            assert not TOKEN_PATTERN.search(r["result"].restored_response)


class TestPIILeakageScan:
    @pytest.mark.security
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_zero_leakage_across_fixture_variants(self):
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("Components not implemented")

        detector = PIIDetector()
        strategies = {et: TokenizationStrategy() for et in REQUIRED_ENTITY_TYPES}
        engine = ObfuscationEngine(strategies)

        variants = [
            f"Patient: {name} — SSN: {ssn} — Diagnosis: {diag}"
            for name in ["Eleanor Hartwell", "Marcus Webb", "Priya Okonkwo", "Raj Patel", "Sarah Chen"]
            for ssn in ["543-67-8901", "987-65-4321"]
            for diag in ["Type 2 Diabetes", "Hypertension"]
        ]

        leakage_count = 0
        for variant in variants[:100]:
            vault = MockSessionVault()
            session_id = make_session_id()
            entities = await detector.detect(variant)
            result = await engine.obfuscate_document(variant, entities, vault, session_id)
            for entity in entities:
                if entity.original_value.lower() in result.obfuscated_text.lower():
                    leakage_count += 1

        assert leakage_count == 0, f"PII LEAKAGE: {leakage_count} instances found across runs"
