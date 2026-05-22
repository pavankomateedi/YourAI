"""De-obfuscation Engine — restore original values in an LLM response.

Finds every token reference, looks each up in the session vault, and substitutes
the original value. Non-token text is preserved byte-for-byte. A token that is not
in the vault (e.g. the session expired) becomes ``[UNAVAILABLE]`` rather than
raising — a single missing entity must not break the whole response.

The token regex accepts multi-segment entity prefixes and upper- or lower-case hex
so inflected and edge-case tokens (``[PII_NAME_FFFFFFFF]``) still resolve. Inflected
forms like ``[PII_NAME_xxxx]'s`` work for free: only the bracketed token is matched,
so a trailing ``'s`` is left untouched on the restored value.
"""

from __future__ import annotations

import re
from typing import AsyncIterator

from ..models import DeobfuscatedResponse

# Broader than the spec's narrow pattern: multi-segment types + case-insensitive hex.
TOKEN_PATTERN = re.compile(r"\[([A-Z][A-Z0-9_]*_[0-9a-fA-F]{8})\]")


class DeobfuscationEngine:
    async def deobfuscate(
        self,
        llm_response: str,
        vault,
        session_id: str,
        user_id: str | None = None,
        audit_log=None,
    ) -> DeobfuscatedResponse:
        restored = 0
        missed = 0
        unresolved: list[str] = []
        miss_events: list[str] = []

        async def resolve(token: str) -> str:
            nonlocal restored, missed
            try:
                value = await vault.lookup_by_token(session_id, token)
            except Exception:
                missed += 1
                unresolved.append(token)
                miss_events.append(token)
                return "[UNAVAILABLE]"
            restored += 1
            return value

        # Resolve tokens left-to-right, rebuilding the string so untouched text is
        # preserved exactly. (re.sub can't await, so we iterate matches manually.)
        out: list[str] = []
        pos = 0
        for m in TOKEN_PATTERN.finditer(llm_response):
            out.append(llm_response[pos : m.start()])
            out.append(await resolve(m.group(0)))
            pos = m.end()
        out.append(llm_response[pos:])
        text = "".join(out)

        # Optional second pass: restore pseudonyms (non-bracket vault keys) that the
        # LLM echoed back. No-op when only tokenization was used.
        text = await self._restore_pseudonyms(text, vault, session_id)

        if audit_log is not None and miss_events:
            for token in miss_events:
                await audit_log.log_vault_miss(
                    session_id=session_id, user_id=user_id or "unknown", token_id=token
                )

        return DeobfuscatedResponse(
            restored_text=text,
            tokens_restored=restored,
            tokens_missed=missed,
            unresolved_tokens=unresolved,
        )

    async def deobfuscate_stream(
        self,
        chunks: AsyncIterator[str],
        vault,
        session_id: str,
    ) -> AsyncIterator[str]:
        """Restore tokens incrementally as the LLM streams output.

        A token may be split across stream chunks (``[PII_NA`` ... ``ME_xxxx]``), so
        text is emitted only up to the last point that cannot begin an unterminated
        token; the trailing partial is buffered until the next chunk completes it.
        Token-only restoration (no pseudonym reverse pass) in streaming mode.
        """
        buffer = ""
        async for piece in chunks:
            buffer += piece
            safe, buffer = self._split_safe(buffer)
            if safe:
                yield await self._restore_tokens(safe, vault, session_id)
        if buffer:
            yield await self._restore_tokens(buffer, vault, session_id)

    @staticmethod
    def _split_safe(buffer: str) -> tuple[str, str]:
        """Split into (emittable_prefix, buffered_remainder).

        The remainder begins at the last ``[`` that has no closing ``]`` yet — a
        possibly-incomplete token. Everything before it is safe to emit.
        """
        idx = buffer.rfind("[")
        if idx == -1 or "]" in buffer[idx:]:
            return buffer, ""
        return buffer[:idx], buffer[idx:]

    async def _restore_tokens(self, text: str, vault, session_id: str) -> str:
        out: list[str] = []
        pos = 0
        for m in TOKEN_PATTERN.finditer(text):
            out.append(text[pos : m.start()])
            try:
                out.append(await vault.lookup_by_token(session_id, m.group(0)))
            except Exception:
                out.append("[UNAVAILABLE]")
            pos = m.end()
        out.append(text[pos:])
        return "".join(out)

    async def _restore_pseudonyms(self, text: str, vault, session_id: str) -> str:
        try:
            keys = await vault.list_tokens(session_id)
        except Exception:
            return text
        # Only consider non-token (pseudonym) keys; restore longest first to avoid
        # partial overlaps.
        pseudonyms = [k for k in keys if not TOKEN_PATTERN.fullmatch(k)]
        for key in sorted(pseudonyms, key=len, reverse=True):
            if key and key in text:
                try:
                    original = await vault.lookup_by_token(session_id, key)
                except Exception:
                    continue
                text = text.replace(key, original)
        return text
