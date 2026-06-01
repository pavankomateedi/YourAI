"""SecureContextPipeline — the single public entry point for product code.

Round trip::

    detect -> obfuscate -> [leak gate] -> call LLM -> de-obfuscate -> restore

The vault is created at the start of a session and destroyed on
:meth:`destroy_session`, after which its token<->original mappings are
irrecoverable. A pre-call leak gate scans the outbound payload against the
session's known original values and aborts (raising :class:`PIILeakError`) before
any data crosses the trust boundary if a value escaped obfuscation.
"""

from __future__ import annotations

import inspect
import re
import time
import uuid

from ..audit.audit_log import AuditLog
from ..config import CONFIDENCE_THRESHOLD, get_settings
from ..deobfuscation.engine import DeobfuscationEngine
from ..detection.detector import PIIDetector
from ..models import PipelineResult, REQUIRED_ENTITY_TYPES, ObfuscationStrategyType
from ..obfuscation.chunking import chunk_text
from ..obfuscation.engine import ObfuscationEngine
from ..obfuscation.strategies import (
    ObfuscationStrategy,
    PseudonymizationStrategy,
    TokenizationStrategy,
)
from ..vault.vault import SessionVault
from .events import EventBus
from .exceptions import PIILeakError
from .injector import LLMContextInjector
from .residual_scan import find_residual_pii

_TITLE_RE = re.compile(r"^(?:Dr|Mr|Mrs|Ms|Prof)\.?\s+", re.IGNORECASE)
_TOKEN_INNER_RE = re.compile(r"\[([A-Z][A-Z0-9_]*_[0-9a-fA-F]{8})\]")


def _default_vault():
    """Build the configured vault backend (sqlite default, postgres via env)."""
    from ..vault.postgres_vault import build_vault

    return build_vault()


def _build_strategy_map(strategy: str):
    """Map every entity type to a strategy instance for the chosen mode."""
    shared: ObfuscationStrategy
    if strategy == ObfuscationStrategyType.PSEUDONYMIZATION.value:
        shared = PseudonymizationStrategy()
    else:
        shared = TokenizationStrategy()
    return {etype: shared for etype in REQUIRED_ENTITY_TYPES}


class SecureContextPipeline:
    def __init__(
        self,
        llm_fn=None,
        audit_log: AuditLog | None = None,
        detector: PIIDetector | None = None,
        vault: SessionVault | None = None,
        store=None,
        provider: str | None = None,
        strategy: str = ObfuscationStrategyType.TOKENIZATION.value,
        max_chunk_chars: int = 12000,
        event_bus: EventBus | None = None,
    ) -> None:
        self._llm_fn = llm_fn
        self._audit = audit_log
        self._detector = detector or PIIDetector()
        self._vault = vault or _default_vault()
        self._store = store
        self._strategy = strategy
        # Documents longer than this are obfuscated chunk-by-chunk against the same
        # vault (cross-chunk token consistency). 0 disables chunking.
        self._max_chunk_chars = max_chunk_chars
        self._obf_engine = ObfuscationEngine(_build_strategy_map(strategy))
        self._deobf_engine = DeobfuscationEngine()
        self._provider = provider or get_settings().llm_provider
        self._injector = LLMContextInjector(provider=self._provider)
        self._events = event_bus

    def _emit(self, session_id: str, event_type: str, **data) -> None:
        """Fire-and-forget event for the UI timeline; no-op if no bus attached."""
        if self._events is not None:
            self._events.publish(session_id, event_type, data)

    # ------------------------------------------------------------- session
    async def create_session(self, user_id: str | None = None) -> str:
        session_id = f"session-{uuid.uuid4().hex}"
        await self._vault.create_session(session_id)
        return session_id

    async def destroy_session(self, session_id: str, user_id: str = "unknown") -> None:
        await self._vault.destroy(session_id)
        if self._audit is not None:
            await self._audit.log_vault_destroyed(session_id=session_id, user_id=user_id)

    async def upload_document(self, user_id: str, content: bytes, mime_type: str) -> str:
        if self._store is None:
            raise RuntimeError("No document store configured for this pipeline")
        return await self._store.upload(user_id, content, mime_type)

    # ---------------------------------------------------------------- run
    async def run(
        self,
        user_id: str,
        session_id: str,
        text: str | None = None,
        user_query: str = "",
        document_id: str | None = None,
        strategy: str | None = None,
        provider: str | None = None,
    ) -> PipelineResult:
        start = time.perf_counter()
        self._emit(session_id, "pipeline.started",
                   document_id=document_id, has_inline_text=text is not None,
                   chars=(len(text) if text else 0))
        try:
            await self._vault.create_session(session_id)

            if text is None:
                if document_id is None or self._store is None:
                    raise ValueError("Provide either `text` or a `document_id` with a store")
                text = await self._store.extract_text(user_id, document_id)
            text = text or ""

            engine = self._obf_engine
            if strategy and strategy != self._strategy:
                engine = ObfuscationEngine(_build_strategy_map(strategy))
            strat_name = strategy or self._strategy

            # detect -> obfuscate. For large documents, process chunk-by-chunk against
            # the shared vault so a value repeated across chunks maps to one token.
            chunks = chunk_text(text, self._max_chunk_chars)
            self._emit(session_id, "pipeline.detecting", chunks=len(chunks), chars=len(text))
            entities = []
            obf_parts: list[str] = []
            token_manifest: list[str] = []
            for chunk in chunks:
                chunk_entities = await self._detector.detect(chunk)
                entities.extend(chunk_entities)
                part = await engine.obfuscate_document(
                    chunk, chunk_entities, self._vault, session_id, strat_name
                )
                obf_parts.append(part.obfuscated_text)
                token_manifest.extend(part.token_manifest)
            obfuscated_text = "".join(obf_parts)
            by_type: dict[str, int] = {}
            for e in entities:
                by_type[e.entity_type] = by_type.get(e.entity_type, 0) + 1
            self._emit(session_id, "pipeline.detected",
                       entities_count=len(entities), by_type=by_type)
            self._emit(session_id, "pipeline.obfuscated",
                       tokens_count=len(token_manifest), strategy=strat_name)

            # audit each obfuscated (non-redacted) entity — token id + type only, no value
            obfuscated_count = 0
            if self._audit is not None:
                for e in entities:
                    if e.confidence < CONFIDENCE_THRESHOLD:
                        continue
                    token = await self._vault.lookup_by_original(session_id, e.entity_type, e.original_value)
                    if token:
                        obfuscated_count += 1
                        await self._audit.log_obfuscation(
                            session_id=session_id, user_id=user_id, entity_type=e.entity_type,
                            token_id=token, document_id=document_id,
                            strategy_used=strat_name, confidence_score=e.confidence,
                        )
            else:
                obfuscated_count = len(token_manifest)

            # leak gate + LLM call (emits gate.checking/passed and llm.calling/responded inside)
            raw_response = await self._call_llm_with_leak_check(
                obfuscated_context=obfuscated_text,
                user_query=user_query,
                vault=self._vault,
                session_id=session_id,
                known_pii_values=None,
                user_id=user_id,
                provider=provider,
            )

            # de-obfuscate
            self._emit(session_id, "pipeline.restoring")
            deob = await self._deobf_engine.deobfuscate(
                raw_response, self._vault, session_id, user_id=user_id, audit_log=self._audit
            )
            self._emit(session_id, "pipeline.restored", tokens_restored=deob.tokens_restored)

            duration_ms = (time.perf_counter() - start) * 1000
            self._emit(session_id, "pipeline.completed",
                       entities_detected=len(entities),
                       entities_obfuscated=obfuscated_count,
                       tokens_restored=deob.tokens_restored,
                       duration_ms=duration_ms)
            return PipelineResult(
                session_id=session_id,
                user_query=user_query,
                restored_response=deob.restored_text,
                entities_detected=len(entities),
                entities_obfuscated=obfuscated_count,
                tokens_restored=deob.tokens_restored,
                pipeline_duration_ms=duration_ms,
                document_id=document_id,
                obfuscated_preview=obfuscated_text,
                llm_raw_response=raw_response,
            )
        except PIILeakError as e:
            # gate_aborted already emitted inside _call_llm_with_leak_check; re-raise.
            raise
        except Exception as e:
            self._emit(session_id, "pipeline.failed",
                       error=type(e).__name__, message=str(e))
            raise

    # ----------------------------------------------------------- leak gate
    async def _call_llm_with_leak_check(
        self,
        obfuscated_context: str,
        user_query: str,
        vault,
        session_id: str,
        known_pii_values: dict | None = None,
        user_id: str = "unknown",
        provider: str | None = None,
    ) -> str:
        payload_text = f"{obfuscated_context} {user_query}"
        self._emit(session_id, "pipeline.gate_checking", payload_chars=len(payload_text))
        # Gate 1: scan against values the detector found (the session vault).
        leaked_type = await self._scan_for_leak(payload_text, vault, session_id, known_pii_values)
        # Gate 2 (defense in depth): scan the payload itself for raw structured
        # identifiers — catches anything detection missed and never vaulted.
        if leaked_type is None:
            leaked_type = find_residual_pii(payload_text)
        if leaked_type is not None:
            self._emit(session_id, "pipeline.gate_aborted",
                       entity_type=leaked_type, stage="pre_llm_call")
            if self._audit is not None:
                await self._audit.log_pii_leak_detected(
                    session_id=session_id, user_id=user_id,
                    entity_type=leaked_type, stage="pre_llm_call",
                )
            raise PIILeakError(entity_type=leaked_type, stage="pre_llm_call")
        self._emit(session_id, "pipeline.gate_passed")

        llm_start = time.perf_counter()
        self._emit(session_id, "pipeline.llm_calling",
                   provider=(provider or self._provider))
        if self._llm_fn is not None:
            result = self._llm_fn(obfuscated_context, user_query)
            if inspect.isawaitable(result):
                result = await result
            self._emit(session_id, "pipeline.llm_responded",
                       duration_ms=(time.perf_counter() - llm_start) * 1000,
                       chars=len(result or ""))
            return result

        # No injected llm_fn: assemble a payload and call the real provider
        # (Anthropic by default, with an offline echo fallback inside the injector).
        built = await self._injector.build_payload(obfuscated_context, user_query, session_id)
        response = await self._injector.call_llm(built, provider=provider)
        self._emit(session_id, "pipeline.llm_responded",
                   duration_ms=(time.perf_counter() - llm_start) * 1000,
                   chars=len(response.raw_response or ""))
        return response.raw_response

    async def _scan_for_leak(
        self, payload_text: str, vault, session_id: str, known_pii_values: dict | None
    ) -> str | None:
        """Return the entity type of the first leaked original value, else None."""
        low = payload_text.lower()
        items: list[tuple[str | None, str]] = []
        if known_pii_values:
            items = [(etype, value) for etype, value in known_pii_values.items()]
        else:
            try:
                tokens = await vault.list_tokens(session_id)
            except Exception:
                tokens = []
            for token in tokens:
                try:
                    original = await vault.lookup_by_token(session_id, token)
                except Exception:
                    continue
                m = _TOKEN_INNER_RE.match(token)
                etype = m.group(1).rsplit("_", 1)[0] if m else None
                items.append((etype, original))

        for etype, value in items:
            for candidate in self._leak_candidates(value):
                if len(candidate) >= 4 and candidate.lower() in low:
                    return etype
        return None

    @staticmethod
    def _leak_candidates(value: str) -> list[str]:
        """Forms of an original value to scan for, including an honorific-stripped name."""
        candidates = [value]
        stripped = _TITLE_RE.sub("", value).strip()
        if stripped and stripped != value:
            candidates.append(stripped)
        return candidates
