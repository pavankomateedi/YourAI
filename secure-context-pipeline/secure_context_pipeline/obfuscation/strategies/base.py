"""Abstract base class for obfuscation strategies.

A strategy turns a single detected entity into its replacement string and records
the mapping in the session vault. Concrete strategies (tokenization,
pseudonymization) are interchangeable — the engine selects one per entity type, so
switching the global strategy is a config change, not a code change (NFR:
strategy swappability).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...models import DetectedEntity


class _VaultLike(Protocol):
    """The subset of the vault interface a strategy depends on."""

    async def store(self, session_id: str, token: str, original: str, entity_type: str) -> None: ...
    async def lookup_by_original(self, session_id: str, entity_type: str, original: str) -> str | None: ...


class ObfuscationStrategy(ABC):
    """Replace an entity with an opaque or pseudonymous stand-in."""

    #: Human-readable strategy name, surfaced in audit logs.
    strategy_name: str = "base"

    @abstractmethod
    async def obfuscate(
        self,
        entity: "DetectedEntity",
        vault: _VaultLike,
        session_id: str,
    ) -> str:
        """Return the replacement string for ``entity`` and persist the mapping."""
        raise NotImplementedError
