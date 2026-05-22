"""PostgreSQL-backed Session Vault (production scale/HA).

Drop-in replacement for :class:`SessionVault` with the same public interface and
the same security model: per-session AES-256-GCM keys held only in memory, rows
persisted as ``nonce || ciphertext`` (no plaintext column), keys zeroed and rows
deleted on destroy. Uses an asyncpg connection pool.

Select it via ``VAULT_BACKEND=postgres`` + ``DATABASE_URL`` (see ``build_vault``).
asyncpg is an optional dependency; importing this module without it raises only
when the class is actually instantiated.
"""

from __future__ import annotations

import ctypes
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..pipeline.exceptions import VaultMissError

_NONCE_BYTES = 12
_KEY_BYTES = 32

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS vault (
    session_id TEXT NOT NULL,
    token TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    encrypted_original BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, token)
)
"""


class PostgresSessionVault:
    def __init__(self, dsn: str | None = None) -> None:
        self._dsn = dsn or os.environ.get("DATABASE_URL")
        if not self._dsn:
            raise ValueError("PostgresSessionVault requires a DSN (DATABASE_URL)")
        self._pool = None
        self._keys: dict[str, bytearray] = {}
        self._cache: dict[str, dict[str, tuple[str, bytes]]] = {}
        self._destroyed: set[str] = set()

    async def _ensure_pool(self):
        if self._pool is None:
            import asyncpg

            self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=10)
            async with self._pool.acquire() as conn:
                await conn.execute(_CREATE_TABLE)
        return self._pool

    def _key(self, session_id: str) -> bytearray:
        key = self._keys.get(session_id)
        if key is None:
            key = bytearray(os.urandom(_KEY_BYTES))
            self._keys[session_id] = key
            self._cache.setdefault(session_id, {})
        return key

    def _aesgcm(self, session_id: str) -> AESGCM:
        return AESGCM(bytes(self._key(session_id)))

    async def create_session(self, session_id: str) -> None:
        self._destroyed.discard(session_id)
        await self._ensure_pool()
        self._key(session_id)

    async def store(self, session_id: str, token: str, original: str, entity_type: str) -> None:
        self._destroyed.discard(session_id)
        pool = await self._ensure_pool()
        nonce = os.urandom(_NONCE_BYTES)
        blob = nonce + self._aesgcm(session_id).encrypt(nonce, original.encode(), None)
        self._cache.setdefault(session_id, {})[token] = (entity_type, blob)
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO vault (session_id, token, entity_type, encrypted_original) "
                "VALUES ($1,$2,$3,$4) ON CONFLICT (session_id, token) DO NOTHING",
                session_id, token, entity_type, blob,
            )

    async def lookup_by_token(self, session_id: str, token: str) -> str:
        if session_id in self._destroyed:
            raise VaultMissError(f"Vault for session {session_id} has been destroyed")
        entry = self._cache.get(session_id, {}).get(token)
        if entry is None:
            pool = await self._ensure_pool()
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT entity_type, encrypted_original FROM vault "
                    "WHERE session_id=$1 AND token=$2",
                    session_id, token,
                )
            if row is None:
                raise VaultMissError(f"Token {token} not found for session {session_id}")
            entry = (row["entity_type"], bytes(row["encrypted_original"]))
            self._cache.setdefault(session_id, {})[token] = entry
        _etype, blob = entry
        return self._aesgcm(session_id).decrypt(blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], None).decode()

    async def lookup_by_original(self, session_id: str, entity_type: str, original: str) -> str | None:
        if session_id in self._destroyed:
            return None
        for token, (etype, blob) in self._cache.get(session_id, {}).items():
            if etype != entity_type:
                continue
            try:
                value = self._aesgcm(session_id).decrypt(
                    blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], None
                ).decode()
            except Exception:
                continue
            if value == original:
                return token
        return None

    async def destroy(self, session_id: str) -> None:
        key = self._keys.pop(session_id, None)
        if key is not None:
            ctypes.memset((ctypes.c_char * len(key)).from_buffer(key), 0, len(key))
        self._cache.pop(session_id, None)
        self._destroyed.add(session_id)
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM vault WHERE session_id=$1", session_id)

    async def list_tokens(self, session_id: str) -> list[str]:
        return list(self._cache.get(session_id, {}).keys())

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()


def build_vault():
    """Construct the configured vault backend (``VAULT_BACKEND`` = sqlite|postgres)."""
    backend = os.environ.get("VAULT_BACKEND", "sqlite").lower()
    if backend == "postgres":
        return PostgresSessionVault()
    from .vault import SessionVault

    return SessionVault()
