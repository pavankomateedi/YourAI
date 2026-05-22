"""Postgres vault backend tests.

Live DB tests run only when SCP_TEST_PG_DSN is set (e.g. in CI with a postgres
service). The import/construction guard test always runs.
"""

import os

import pytest

PG_DSN = os.environ.get("SCP_TEST_PG_DSN")


class TestPostgresVaultGuards:
    def test_requires_dsn(self, monkeypatch):
        from secure_context_pipeline.vault.postgres_vault import PostgresSessionVault

        monkeypatch.delenv("DATABASE_URL", raising=False)
        with pytest.raises(ValueError):
            PostgresSessionVault()

    def test_build_vault_defaults_to_sqlite(self, monkeypatch):
        monkeypatch.delenv("VAULT_BACKEND", raising=False)
        from secure_context_pipeline.vault.postgres_vault import build_vault
        from secure_context_pipeline.vault.vault import SessionVault

        assert isinstance(build_vault(), SessionVault)


@pytest.mark.skipif(not PG_DSN, reason="Set SCP_TEST_PG_DSN to run live Postgres vault tests")
class TestPostgresVaultLive:
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_roundtrip_isolation_and_destroy(self):
        from secure_context_pipeline.vault.postgres_vault import PostgresSessionVault

        vault = PostgresSessionVault(dsn=PG_DSN)
        try:
            sid_a, sid_b = "pg-a", "pg-b"
            await vault.store(sid_a, "[PII_NAME_a3f2c1d4]", "Eleanor Hartwell", "PII_NAME")
            assert await vault.lookup_by_token(sid_a, "[PII_NAME_a3f2c1d4]") == "Eleanor Hartwell"
            # Cross-session isolation
            with pytest.raises(Exception):
                await vault.lookup_by_token(sid_b, "[PII_NAME_a3f2c1d4]")
            # Destroy is irreversible
            await vault.destroy(sid_a)
            with pytest.raises(Exception):
                await vault.lookup_by_token(sid_a, "[PII_NAME_a3f2c1d4]")
        finally:
            await vault.close()
