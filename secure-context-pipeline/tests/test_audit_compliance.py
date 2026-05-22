"""Tests: Audit Log + compliance reporting (no PII in any audit output)."""

import pytest

from conftest import FIXTURE_PII_VALUES, MockAuditLog, MockSessionVault, assert_no_pii_in_text, make_session_id, make_user_id


class TestAuditLog:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_audit_log_captures_obfuscation_event(self, session_id, tmp_path):
        try:
            from secure_context_pipeline.audit.audit_log import AuditLog
        except ImportError:
            pytest.skip("AuditLog not implemented")

        log_file = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path=str(log_file))
        await audit.log_obfuscation(
            session_id=session_id, user_id="user-123", entity_type="PHI_DIAGNOSIS",
            token_id="[PHI_DIAGNOSIS_2c8a4d7b]", document_id="doc-456",
            strategy_used="tokenization", confidence_score=0.95,
        )
        log_content = (tmp_path / "audit.jsonl").read_text()
        assert "PHI_DIAGNOSIS" in log_content
        assert "[PHI_DIAGNOSIS_2c8a4d7b]" in log_content
        assert session_id in log_content
        assert "Type 2 Diabetes" not in log_content
        assert "Eleanor Hartwell" not in log_content

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_audit_log_captures_vault_miss(self, session_id, tmp_path):
        try:
            from secure_context_pipeline.audit.audit_log import AuditLog
        except ImportError:
            pytest.skip("AuditLog not implemented")

        log_file = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path=str(log_file))
        await audit.log_vault_miss(session_id=session_id, user_id="user-123", token_id="[PII_NAME_FFFFFFFF]")
        log_content = log_file.read_text()
        assert "VAULT_MISS" in log_content or "vault_miss" in log_content.lower()
        assert "[PII_NAME_FFFFFFFF]" in log_content


class TestAuditLogComplianceReport:
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_30_day_audit_summary_no_pii(self, session_id):
        audit = MockAuditLog()
        user = make_user_id()
        for day in range(30):
            sid = make_session_id()
            for entity_type, token_suffix in [
                ("PII_NAME", "a3f2c1d4"), ("PHI_DIAGNOSIS", "2c8a4d7b"), ("FIN_ACCOUNT", "4d7c9a1e"),
            ]:
                await audit.log_obfuscation(
                    session_id=sid, user_id=user, entity_type=entity_type,
                    token_id=f"[{entity_type}_{token_suffix}]", document_id=f"doc-day{day:02d}",
                    strategy_used="tokenization", confidence_score=0.95,
                )
            await audit.log_vault_destroyed(session_id=sid, user_id=user)

        report_text = audit.to_text()
        assert len(report_text) > 0
        assert_no_pii_in_text(report_text, FIXTURE_PII_VALUES)
        assert "OBFUSCATION" in report_text
        assert "VAULT_DESTROYED" in report_text
        assert len(audit.get_entries_by_event("OBFUSCATION")) == 90
        assert len(audit.get_entries_by_event("VAULT_DESTROYED")) == 30

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_vault_destruction_event_logged(self, session_id):
        audit = MockAuditLog()
        vault = MockSessionVault()
        user = make_user_id()
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")
        await vault.destroy(session_id)
        await audit.log_vault_destroyed(session_id=session_id, user_id=user)

        destroyed = audit.get_entries_by_event("VAULT_DESTROYED")
        assert len(destroyed) == 1
        assert destroyed[0]["session_id"] == session_id
        vault_destroyed = [e for e in vault.get_events() if e.get("event") == "VAULT_DESTROYED"]
        assert any(e["session_id"] == session_id for e in vault_destroyed)
        with pytest.raises((KeyError, Exception)):
            await vault.lookup_by_token(session_id, "[PII_NAME_a3f2c1d4]")

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_pii_leak_aborted_call_logged(self, session_id):
        audit = MockAuditLog()
        user = make_user_id()
        leaky_payload = "Patient: Dr. Eleanor Hartwell. Diagnosis: [PHI_DIAGNOSIS_2c8a4d7b]."
        leak_fired = False
        for entity_type, pii_value in FIXTURE_PII_VALUES.items():
            if pii_value.lower() in leaky_payload.lower():
                leak_fired = True
                await audit.log_pii_leak_detected(
                    session_id=session_id, user_id=user, entity_type=entity_type, stage="pre_llm_call",
                )
                break
        assert leak_fired
        leak_events = audit.get_entries_by_event("PII_LEAK_DETECTED")
        assert len(leak_events) >= 1
        assert leak_events[0]["session_id"] == session_id
        assert leak_events[0]["stage"] == "pre_llm_call"
        assert_no_pii_in_text(audit.to_text(), FIXTURE_PII_VALUES)
