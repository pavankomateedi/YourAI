"""Session Vault — encrypted, per-session token<->original mapping.

Security properties
-------------------
* **Per-session key:** each session gets a fresh ``os.urandom(32)`` AES-256-GCM
  key held in memory only. Session A's key cannot decrypt Session B's entries.
* **At-rest encryption:** entries are persisted to SQLite as ``nonce || ciphertext``
  only — no plaintext column ever exists (EVAL-SEC-003).
* **Destruction:** on ``destroy`` the in-memory key is zeroed with ``ctypes.memset``
  and the session's rows are deleted, making the mapping permanently irrecoverable.
* **Fast reads:** decryption uses an in-memory ciphertext cache so per-token lookup
  stays well under the 5 ms p99 budget; SQLite is the durable at-rest copy.

The constructor takes no required arguments so callers can simply do
``SessionVault()``; ``store`` lazily provisions a session key on first use.
"""

from __future__ import annotations

import ctypes
import os
import sqlite3
import asyncio
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..pipeline.exceptions import VaultMissError

_NONCE_BYTES = 12
_KEY_BYTES = 32  # AES-256


class SessionVault:
    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or os.environ.get("VAULT_DB_PATH", "vault.db")
        # In-memory per-session AES-256 keys (bytearray so they can be zeroed).
        self._keys: dict[str, bytearray] = {}
        # Decryption cache: {session_id: {token: (entity_type, nonce+ciphertext)}}.
        self._cache: dict[str, dict[str, tuple[str, bytes]]] = {}
        self._destroyed: set[str] = set()
        self._init_db()

    # ------------------------------------------------------------------ db
    def _init_db(self) -> None:
        parent = os.path.dirname(os.path.abspath(self._db_path))
        os.makedirs(parent, exist_ok=True)
        with sqlite3.connect(self._db_path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS vault ("
                "session_id TEXT, token TEXT, entity_type TEXT, "
                "encrypted_original BLOB, created_at TEXT, "
                "PRIMARY KEY (session_id, token))"
            )
            db.commit()

    def _persist(self, session_id: str, token: str, entity_type: str, blob: bytes) -> None:
        with sqlite3.connect(self._db_path) as db:
            db.execute(
                "INSERT OR IGNORE INTO vault VALUES (?,?,?,?,?)",
                (session_id, token, entity_type, blob, datetime.now(timezone.utc).isoformat()),
            )
            db.commit()

    def _delete_rows(self, session_id: str) -> None:
        with sqlite3.connect(self._db_path) as db:
            db.execute("DELETE FROM vault WHERE session_id=?", (session_id,))
            db.commit()

    # --------------------------------------------------------------- crypto
    def _key(self, session_id: str) -> bytearray:
        key = self._keys.get(session_id)
        if key is None:
            if session_id in self._destroyed:
                raise VaultMissError(f"Vault for session {session_id} has been destroyed")
            # Lazily provision a fresh key on first use of a new session.
            key = bytearray(os.urandom(_KEY_BYTES))
            self._keys[session_id] = key
            self._cache.setdefault(session_id, {})
        return key

    def _aesgcm(self, session_id: str) -> AESGCM:
        return AESGCM(bytes(self._key(session_id)))

    # ----------------------------------------------------------- public API
    async def create_session(self, session_id: str) -> None:
        """Explicitly provision a fresh key for a session (optional; ``store`` is lazy)."""
        self._destroyed.discard(session_id)
        self._key(session_id)

    async def store(self, session_id: str, token: str, original: str, entity_type: str) -> None:
        # Storing into a previously destroyed session id re-provisions it as a
        # brand-new session: a fresh key and empty state. The old mappings stay
        # gone (rows deleted, key zeroed on destroy) — destruction is irreversible.
        self._destroyed.discard(session_id)
        aes = self._aesgcm(session_id)
        nonce = os.urandom(_NONCE_BYTES)
        blob = nonce + aes.encrypt(nonce, original.encode(), None)
        self._cache.setdefault(session_id, {})[token] = (entity_type, blob)
        await asyncio.to_thread(self._persist, session_id, token, entity_type, blob)

    async def lookup_by_token(self, session_id: str, token: str) -> str:
        if session_id in self._destroyed:
            raise VaultMissError(f"Vault for session {session_id} has been destroyed")
        entry = self._cache.get(session_id, {}).get(token)
        if entry is None:
            raise VaultMissError(f"Token {token} not found for session {session_id}")
        _entity_type, blob = entry
        plaintext = self._aesgcm(session_id).decrypt(blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], None)
        return plaintext.decode()

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
            except Exception:  # pragma: no cover - defensive
                continue
            if value == original:
                return token
        return None

    async def destroy(self, session_id: str) -> None:
        """Zero the in-memory key and delete all persisted rows for this session."""
        key = self._keys.pop(session_id, None)
        if key is not None:
            # Overwrite the key bytes in place so they cannot be recovered from a
            # heap snapshot; Python's GC gives no such guarantee on its own.
            ctypes.memset((ctypes.c_char * len(key)).from_buffer(key), 0, len(key))
        self._cache.pop(session_id, None)
        self._destroyed.add(session_id)
        await asyncio.to_thread(self._delete_rows, session_id)

    async def list_tokens(self, session_id: str) -> list[str]:
        return list(self._cache.get(session_id, {}).keys())
