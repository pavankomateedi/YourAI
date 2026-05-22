"""Audit Log — append-only, PII-free compliance trail (HIPAA §164.312(b)).

Every event records token ids, entity types, session/user ids, and timestamps —
never an original value. Events are written as JSON Lines so the log is both
human-greppable and machine-parseable, and appends are atomic per line.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone


class AuditLog:
    def __init__(self, log_path: str | None = None) -> None:
        self._log_path = log_path or os.environ.get("AUDIT_LOG_PATH", "./data/audit.jsonl")
        parent = os.path.dirname(os.path.abspath(self._log_path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    def _write(self, event: dict) -> None:
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        with open(self._log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")

    async def _log(self, event: dict) -> None:
        await asyncio.to_thread(self._write, event)

    async def log_obfuscation(
        self,
        session_id: str,
        user_id: str,
        entity_type: str,
        token_id: str,
        document_id: str | None = None,
        strategy_used: str | None = None,
        confidence_score: float | None = None,
    ) -> None:
        await self._log({
            "event": "OBFUSCATION",
            "session_id": session_id,
            "user_id": user_id,
            "entity_type": entity_type,
            "token_id": token_id,
            "document_id": document_id,
            "strategy_used": strategy_used,
            "confidence_score": confidence_score,
        })

    async def log_deobfuscation(
        self, session_id: str, user_id: str, token_id: str
    ) -> None:
        await self._log({
            "event": "DEOBFUSCATION",
            "session_id": session_id,
            "user_id": user_id,
            "token_id": token_id,
        })

    async def log_vault_miss(self, session_id: str, user_id: str, token_id: str) -> None:
        await self._log({
            "event": "VAULT_MISS",
            "session_id": session_id,
            "user_id": user_id,
            "token_id": token_id,
        })

    async def log_vault_destroyed(self, session_id: str, user_id: str) -> None:
        await self._log({
            "event": "VAULT_DESTROYED",
            "session_id": session_id,
            "user_id": user_id,
        })

    async def log_pii_leak_detected(
        self, session_id: str, user_id: str, entity_type: str | None, stage: str
    ) -> None:
        await self._log({
            "event": "PII_LEAK_DETECTED",
            "session_id": session_id,
            "user_id": user_id,
            "entity_type": entity_type,
            "stage": stage,
        })
