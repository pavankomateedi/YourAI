"""Performance benchmarks (SLA assertions).

Uses pytest-benchmark for reporting but asserts against an independent manual
timing so the pass/fail does not depend on the benchmark stats API version.
Run with: pytest tests/test_performance.py --benchmark-only
"""

import asyncio
import time

import pytest

from conftest import REQUIRED_ENTITY_TYPES, MockSessionVault


def _mean_seconds(fn, iterations: int = 5) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    return (time.perf_counter() - start) / iterations


class TestPerformance:
    @pytest.mark.performance
    @pytest.mark.benchmark(group="obfuscation")
    def test_obfuscation_engine_2000_words(self, benchmark, fixture_text_2000_words, session_id):
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("Components not implemented")

        detector = PIIDetector()
        vault = MockSessionVault()
        engine = ObfuscationEngine({et: TokenizationStrategy() for et in REQUIRED_ENTITY_TYPES})

        async def run():
            entities = await detector.detect(fixture_text_2000_words)
            return await engine.obfuscate_document(fixture_text_2000_words, entities, vault, session_id)

        call = lambda: asyncio.run(run())
        benchmark(call)
        assert _mean_seconds(call) < 2.0, "Obfuscation exceeds the 2s SLA for a 2000-word doc"

    @pytest.mark.performance
    @pytest.mark.benchmark(group="vault")
    def test_vault_lookup_under_5ms(self, benchmark, session_id):
        try:
            from secure_context_pipeline.vault.vault import SessionVault
            vault = SessionVault()
        except ImportError:
            vault = MockSessionVault()

        asyncio.run(vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME"))
        call = lambda: asyncio.run(vault.lookup_by_token(session_id, "[PII_NAME_a3f2c1d4]"))
        benchmark(call)
        assert _mean_seconds(call, 20) * 1000 < 5.0, "Vault lookup exceeds the 5ms SLA"

    @pytest.mark.performance
    @pytest.mark.benchmark(group="deobfuscation")
    def test_deobfuscation_500_tokens(self, benchmark, session_id):
        try:
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("DeobfuscationEngine not implemented")

        vault = MockSessionVault()
        engine = DeobfuscationEngine()

        async def setup():
            for i in range(500):
                await vault.store(session_id, f"[PII_NAME_{i:08x}]", f"Person {i}", "PII_NAME")

        asyncio.run(setup())
        tokens_in_response = " ".join([f"[PII_NAME_{i:08x}]" for i in range(500)])
        response = f"Entities referenced: {tokens_in_response}"
        call = lambda: asyncio.run(engine.deobfuscate(response, vault, session_id))
        benchmark(call)
        assert _mean_seconds(call) * 1000 < 500, "De-obfuscation exceeds the 500ms SLA for 500 tokens"
