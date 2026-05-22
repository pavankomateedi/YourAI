"""Tokenization strategy: replace an entity with an opaque typed token.

A token has the form ``[{PREFIX}_{8-hex}]`` (e.g. ``[PII_NAME_a3f2c1d4]``). The
random 8-hex suffix carries no information about the original value and is
generated fresh per session, so the same value yields a different token in a
different session (cross-session non-determinism).

The prefix is the entity type rendered as exactly two upper-case segments: a
three-part type such as ``PHI_INSURANCE_ID`` becomes ``PHI_INSURANCEID``. This
keeps every token within the canonical ``[A-Z]+_[A-Z]+_[0-9a-f]{8}`` token grammar
regardless of how many words the entity-type name has, so any consumer scanning
for tokens (the LLM, the de-obfuscator) reliably finds them.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from .base import ObfuscationStrategy, _VaultLike

if TYPE_CHECKING:  # pragma: no cover
    from ...models import DetectedEntity


def token_prefix(entity_type: str) -> str:
    """Render an entity type as a two-segment ``CATEGORY_TYPE`` token prefix."""
    parts = entity_type.split("_")
    if len(parts) <= 2:
        return entity_type
    return f"{parts[0]}_{''.join(parts[1:])}"


class TokenizationStrategy(ObfuscationStrategy):
    strategy_name = "tokenization"

    async def obfuscate(
        self,
        entity: "DetectedEntity",
        vault: _VaultLike,
        session_id: str,
    ) -> str:
        suffix = os.urandom(4).hex()  # 8 lowercase hex chars, cryptographically random
        token = f"[{token_prefix(entity.entity_type)}_{suffix}]"
        await vault.store(session_id, token, entity.original_value, entity.entity_type)
        return token
