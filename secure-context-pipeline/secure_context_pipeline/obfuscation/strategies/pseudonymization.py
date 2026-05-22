"""Pseudonymization strategy: replace an entity with a plausible fake value.

The LLM can reason naturally about a realistic value (e.g. a name or address)
without learning the real one. Within a session the same original always maps to
the same pseudonym — consistency is guaranteed by the engine, which reuses the
stored mapping via ``vault.lookup_by_original`` before ever calling a strategy.

Entity types with no semantic value worth preserving (SSN, account numbers,
diagnoses, medications, legal strategy) fall back to tokenization, because
substituting a *wrong* drug or diagnosis would corrupt the LLM's reasoning.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Callable

from .base import ObfuscationStrategy, _VaultLike
from .tokenization import TokenizationStrategy

if TYPE_CHECKING:  # pragma: no cover
    from ...models import DetectedEntity

# One Faker per session so pseudonyms are stable within a session and differ
# across sessions. Seeded from a system-random value per new session.
_session_fakers: dict[str, object] = {}


def _get_faker(session_id: str):
    """Return (and lazily create) a per-session Faker, or None if unavailable."""
    if session_id in _session_fakers:
        return _session_fakers[session_id]
    try:
        from faker import Faker
    except Exception:  # pragma: no cover - faker optional
        _session_fakers[session_id] = None
        return None
    faker = Faker()
    faker.seed_instance(random.SystemRandom().randint(0, 2**32))
    _session_fakers[session_id] = faker
    return faker


# Maps entity type -> generator. Types absent here are tokenized instead.
def _generators() -> dict[str, Callable[[object], str]]:
    return {
        "PII_NAME": lambda f: f.name(),
        "PII_ADDRESS": lambda f: f.address().replace("\n", ", "),
        "PII_DOB": lambda f: f.date_of_birth(minimum_age=18, maximum_age=85).strftime("%B %d, %Y"),
        "PII_EMAIL": lambda f: f.email(),
        "PII_PHONE": lambda f: f.phone_number(),
        "LEGAL_CLIENT": lambda f: f.company(),
    }


class PseudonymizationStrategy(ObfuscationStrategy):
    strategy_name = "pseudonymization"

    def __init__(self) -> None:
        self._fallback = TokenizationStrategy()

    async def obfuscate(
        self,
        entity: "DetectedEntity",
        vault: _VaultLike,
        session_id: str,
    ) -> str:
        faker = _get_faker(session_id)
        gen = _generators().get(entity.entity_type)
        if faker is None or gen is None:
            # No realistic substitute for this type (or Faker unavailable) — tokenize.
            return await self._fallback.obfuscate(entity, vault, session_id)
        pseudonym = gen(faker)
        # Store the pseudonym as the lookup key; reverse lookup restores the original.
        await vault.store(session_id, pseudonym, entity.original_value, entity.entity_type)
        return pseudonym
