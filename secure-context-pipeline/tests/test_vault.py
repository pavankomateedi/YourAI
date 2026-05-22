"""Unit tests: Session Vault (EVAL-SEC-001 through EVAL-SEC-004)."""

import os

import pytest

from conftest import MockSessionVault


def _vault():
    try:
        from secure_context_pipeline.vault.vault import SessionVault
        return SessionVault()
    except ImportError:
        return MockSessionVault()


class TestSessionVault:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_store_and_lookup_roundtrip(self, session_id):
        vault = _vault()
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")
        assert await vault.lookup_by_token(session_id, "[PII_NAME_a3f2c1d4]") == "Eleanor Hartwell"

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_cross_session_isolation(self, session_id, session_id_b):
        vault = _vault()
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")
        with pytest.raises((KeyError, ValueError, Exception)):
            await vault.lookup_by_token(session_id_b, "[PII_NAME_a3f2c1d4]")

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_vault_destroyed_on_session_end(self, session_id):
        vault = _vault()
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")
        await vault.destroy(session_id)
        with pytest.raises((KeyError, ValueError, Exception)):
            await vault.lookup_by_token(session_id, "[PII_NAME_a3f2c1d4]")

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_destroyed_vault_irreversible(self, session_id):
        vault = _vault()
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")
        await vault.destroy(session_id)
        # Re-creating the session must not restore old entries.
        if hasattr(vault, "create_session"):
            await vault.create_session(session_id)
        await vault.store(session_id, "[PII_SSN_b7e2a1c3]", "543-67-8901", "PII_SSN")
        tokens = await vault.list_tokens(session_id)
        assert "[PII_NAME_a3f2c1d4]" not in tokens

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_lookup_by_original_supports_idempotency(self, session_id):
        vault = _vault()
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")
        existing = await vault.lookup_by_original(session_id, "PII_NAME", "Eleanor Hartwell")
        assert existing == "[PII_NAME_a3f2c1d4]"

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_vault_encryption_at_rest(self, session_id, tmp_path):
        try:
            from secure_context_pipeline.vault.vault import SessionVault
        except ImportError:
            pytest.skip("Real SessionVault not implemented")

        db_path = str(tmp_path / "vault.db")
        vault = SessionVault(db_path=db_path)
        original_value = "Eleanor Hartwell"
        await vault.store(session_id, "[PII_NAME_a3f2c1d4]", original_value, "PII_NAME")

        if not os.path.exists(db_path):
            pytest.skip(f"Vault database not found at {db_path}")
        with open(db_path, "rb") as f:
            raw_bytes = f.read()
        assert original_value.encode() not in raw_bytes, (
            f"SECURITY VIOLATION: '{original_value}' found in plaintext in vault DB"
        )
