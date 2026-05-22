"""Integration tests against the canonical golden dataset (F-001 .. F-007)."""

import json
import pathlib

import pytest

from conftest import TOKEN_PATTERN, MockSessionVault, make_session_id

GOLDEN_FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures" / "golden"


def load_golden_annotation(fixture_id: str):
    matches = list(GOLDEN_FIXTURE_DIR.glob(f"{fixture_id}_*.json"))
    if not matches:
        return None
    with open(matches[0]) as f:
        return json.load(f)


def load_golden_text(fixture_id: str):
    matches = list(GOLDEN_FIXTURE_DIR.glob(f"{fixture_id}_*.txt"))
    if not matches:
        return None
    return matches[0].read_text(encoding="utf-8")


class TestGoldenDatasetIntegration:
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_F001_all_entities_detected(self):
        annotation = load_golden_annotation("F-001")
        text = load_golden_text("F-001")
        if annotation is None or text is None:
            pytest.skip("Golden fixture F-001 not found")
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
        except ImportError:
            pytest.skip("PIIDetector not implemented")

        detector = PIIDetector()
        entities = await detector.detect(text)
        detected_types = {e.entity_type for e in entities}
        expected_types = {ent["entity_type"] for ent in annotation["entities"]}
        missing = expected_types - detected_types
        assert not missing, f"F-001 missing types: {missing}\nDetected: {detected_types}"

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_F001_span_accuracy(self):
        annotation = load_golden_annotation("F-001")
        text = load_golden_text("F-001")
        if annotation is None or text is None:
            pytest.skip("Golden fixture F-001 not found")
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
        except ImportError:
            pytest.skip("PIIDetector not implemented")

        detector = PIIDetector()
        entities = await detector.detect(text)
        for gt in annotation["entities"]:
            matching = [
                e for e in entities
                if e.entity_type == gt["entity_type"] and gt["original_value"] in e.original_value
            ]
            assert matching, (
                f"F-001: ground-truth '{gt['original_value']}' ({gt['entity_type']}) not found.\n"
                f"Detected {gt['entity_type']}: "
                f"{[e.original_value for e in entities if e.entity_type == gt['entity_type']]}"
            )

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_F003_idempotency_repeated_account_numbers(self):
        annotation = load_golden_annotation("F-003")
        text = load_golden_text("F-003")
        if annotation is None or text is None:
            pytest.skip("Golden fixture F-003 not found")
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("Pipeline components not implemented")

        vault = MockSessionVault()
        session_id = make_session_id()
        detector = PIIDetector()
        engine = ObfuscationEngine({"FIN_ACCOUNT": TokenizationStrategy()})

        entities = await detector.detect(text)
        result = await engine.obfuscate_document(text, entities, vault, session_id)

        tokens = await vault.list_tokens(session_id)
        account_tokens = [t for t in tokens if "FIN_ACCOUNT" in t]
        assert len(account_tokens) == 1, f"Expected 1 FIN_ACCOUNT token, got {account_tokens}"

        token = account_tokens[0]
        assert result.obfuscated_text.count(token) == 3, (
            f"Expected 3 occurrences of {token}, got {result.obfuscated_text.count(token)}"
        )

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_F004_empty_entity_list_no_error(self):
        annotation = load_golden_annotation("F-004")
        text = load_golden_text("F-004")
        if annotation is None or text is None:
            pytest.skip("Golden fixture F-004 not found")
        try:
            from secure_context_pipeline.detection.detector import PIIDetector
            from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
            from secure_context_pipeline.obfuscation.strategies import TokenizationStrategy
        except ImportError:
            pytest.skip("Pipeline components not implemented")

        vault = MockSessionVault()
        session_id = make_session_id()
        detector = PIIDetector()
        from conftest import REQUIRED_ENTITY_TYPES
        engine = ObfuscationEngine({et: TokenizationStrategy() for et in REQUIRED_ENTITY_TYPES})

        entities = await detector.detect(text)
        result = await engine.obfuscate_document(text, entities, vault, session_id)

        assert not TOKEN_PATTERN.search(result.obfuscated_text), "F-004: token in clean document"
        assert result.obfuscated_text.strip() == text.strip(), "F-004: clean text was modified"

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_F007_deobfuscation_ground_truth(self):
        json_path = GOLDEN_FIXTURE_DIR / "F-007_llm_response_deobfuscation.json"
        if not json_path.exists():
            pytest.skip("Golden fixture F-007 not found")
        with open(json_path) as f:
            fixture = json.load(f)
        try:
            from secure_context_pipeline.deobfuscation.engine import DeobfuscationEngine
        except ImportError:
            pytest.skip("DeobfuscationEngine not implemented")

        engine = DeobfuscationEngine()
        for case in fixture["test_cases"]:
            vault = MockSessionVault()
            session_id = make_session_id()
            for token, original in fixture["session_vault_state"].items():
                inner = token.strip("[]")
                entity_type = "_".join(inner.split("_")[:2])
                await vault.store(session_id, token, original, entity_type)

            result = await engine.deobfuscate(case["llm_response"], vault, session_id)
            assert result.restored_text == case["expected_output"], (
                f"F-007 {case['case_id']}: expected {case['expected_output']!r}, "
                f"got {result.restored_text!r}"
            )
            assert result.tokens_restored == case["expected_tokens_restored"]
            assert result.tokens_missed == case["expected_tokens_missed"]
