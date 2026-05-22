"""Obfuscation Engine — orchestrates entity replacement and vault coordination.

Replacement is performed at each entity's reported character offset, processed in
descending order so replacing one span never shifts the offsets of spans not yet
processed. Idempotency (the same original value maps to one token within a session)
is enforced here via ``vault.lookup_by_original`` before any new token is minted.

Offset robustness
-----------------
Detector output always reports offsets that match the source text, so the common
path is a simple validated slice replacement. For resilience against stale offsets
(e.g. an entity carried over from a pre-edit version of the text) the engine:

* replaces at the offset when ``text[start:end]`` matches the entity's value;
* falls back to value-based replacement when the offset is out of range; and
* skips an in-range span whose content does not match (a stale offset pointing at
  unrelated text), so unrelated content is never corrupted.

Overlapping spans (two detectors flagging the same region) are de-duplicated,
keeping the longest span, so a region is replaced exactly once.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..config import CONFIDENCE_THRESHOLD
from ..models import ObfuscatedDocument, ObfuscationStrategyType
from .strategies.base import ObfuscationStrategy

if TYPE_CHECKING:  # pragma: no cover
    from ..models import DetectedEntity

REDACTED = "[REDACTED]"


class ObfuscationEngine:
    def __init__(self, strategy_map: dict[str, ObfuscationStrategy]) -> None:
        # Maps entity_type -> strategy, e.g. {"PII_NAME": PseudonymizationStrategy()}.
        self._strategy_map = strategy_map

    async def obfuscate_document(
        self,
        text: str,
        entities: "list[DetectedEntity]",
        vault,
        session_id: str,
        strategy_used: str | None = None,
    ) -> ObfuscatedDocument:
        n = len(text)

        # Partition entities by how their offset relates to the current text.
        valid: list = []  # offset matches the value exactly
        out_of_range: list = []  # start beyond text -> value-based fallback
        for e in entities:
            s, end = e.start, e.end
            if 0 <= s < end <= n and text[s:end] == e.original_value:
                valid.append(e)
            elif s >= n:
                out_of_range.append(e)
            # else: in-range but content mismatch -> stale offset, skip silently.

        valid = self._dedupe_overlaps(valid)

        token_manifest: list[str] = []
        result = text

        # Offset-based replacement, descending so earlier offsets stay valid.
        for e in sorted(valid, key=lambda x: x.start, reverse=True):
            replacement = await self._replacement_for(e, vault, session_id)
            result = result[: e.start] + replacement + result[e.end :]
            if replacement != REDACTED:
                token_manifest.append(replacement)

        # Value-based fallback for out-of-range spans (idempotent via the vault).
        for e in out_of_range:
            if not e.original_value or e.original_value not in result:
                continue
            replacement = await self._replacement_for(e, vault, session_id)
            result = result.replace(e.original_value, replacement)
            if replacement != REDACTED:
                token_manifest.append(replacement)

        if strategy_used is None:
            strategy_used = ObfuscationStrategyType.TOKENIZATION.value

        return ObfuscatedDocument(
            obfuscated_text=result,
            entity_count=len(entities),
            token_manifest=token_manifest,
            session_id=session_id,
            strategy_used=strategy_used,
        )

    async def _replacement_for(self, entity, vault, session_id: str) -> str:
        """Resolve the replacement string for one entity, enforcing idempotency."""
        if entity.confidence < CONFIDENCE_THRESHOLD:
            # Hard rule: sub-threshold entities are redacted, never passed through.
            return REDACTED

        existing = await vault.lookup_by_original(
            session_id, entity.entity_type, entity.original_value
        )
        if existing:
            return existing

        strategy = self._strategy_map.get(entity.entity_type)
        if strategy is None:
            # No strategy registered for this type — redaction is the safe fallback.
            return REDACTED
        return await strategy.obfuscate(entity, vault, session_id)

    @staticmethod
    def _dedupe_overlaps(entities: list) -> list:
        """Drop overlapping spans, keeping the longest at each region.

        Adjacent (non-overlapping) spans are both kept. Used so two detectors
        flagging the same text (e.g. a full name and just the surname) collapse to
        a single replacement.
        """
        if not entities:
            return entities
        ordered = sorted(entities, key=lambda e: (e.start, -(e.end - e.start)))
        kept: list = []
        last_end = -1
        for e in ordered:
            if e.start >= last_end:  # no overlap with the last kept span
                kept.append(e)
                last_end = e.end
            # else: overlaps a longer/earlier span already kept -> drop.
        return kept
