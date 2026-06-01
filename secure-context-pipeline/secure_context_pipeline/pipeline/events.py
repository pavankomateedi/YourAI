"""In-memory pub/sub for live pipeline activity events.

Used by the demo UI's activity timeline. The events carry **no recoverable PII**
— only counts, token ids, durations, types, and structured error info — so they
are safe to emit over an SSE stream. This is a presentation/observability layer,
not a substitute for the append-only ``AuditLog`` which remains the persisted
compliance record.

Two pieces:

* ``EventBus.publish(session_id, event_type, data)`` — fire-and-forget; also
  stores into a small ring buffer per session so the UI can fetch history on
  reload (``GET /events/history``) before re-subscribing to the live stream.
* ``EventBus.subscribe(session_id)`` — async generator that yields every event
  emitted for that session for the lifetime of the subscription.

Designed to scale to ~tens of concurrent demo sessions — a single-process
broker is plenty for that. A larger fan-out would swap this for Redis pub/sub
without changing call sites.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import deque
from typing import AsyncIterator, Deque, Dict, List


HISTORY_PER_SESSION = 256


class EventBus:
    def __init__(self, history_per_session: int = HISTORY_PER_SESSION) -> None:
        self._history: Dict[str, Deque[dict]] = {}
        self._subs: Dict[str, List[asyncio.Queue]] = {}
        self._history_size = history_per_session

    def publish(self, session_id: str, event_type: str, data: dict | None = None) -> dict:
        """Record + fan out an event. Returns the stored envelope."""
        env = {
            "id": uuid.uuid4().hex[:12],
            "session_id": session_id,
            "type": event_type,
            "ts": time.time(),
            "data": data or {},
        }
        # ring buffer for replay
        buf = self._history.setdefault(session_id, deque(maxlen=self._history_size))
        buf.append(env)
        # live fan-out
        for q in list(self._subs.get(session_id, ())):
            try:
                q.put_nowait(env)
            except asyncio.QueueFull:  # pragma: no cover — bounded queues only
                pass
        return env

    def history(self, session_id: str) -> list[dict]:
        return list(self._history.get(session_id, ()))

    async def subscribe(
        self, session_id: str, idle_keepalive_seconds: float | None = None
    ) -> AsyncIterator[dict | None]:
        """Yield events for a session until the consumer stops iterating.

        When ``idle_keepalive_seconds`` is set, ``None`` is yielded after that
        many seconds of inactivity so the caller can emit a heartbeat — needed
        to keep SSE connections alive through AWS ALB's 60-second idle timeout.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=1024)
        self._subs.setdefault(session_id, []).append(q)
        try:
            while True:
                if idle_keepalive_seconds is None:
                    yield await q.get()
                else:
                    try:
                        yield await asyncio.wait_for(q.get(), timeout=idle_keepalive_seconds)
                    except asyncio.TimeoutError:
                        yield None
        finally:
            try:
                self._subs.get(session_id, []).remove(q)
            except ValueError:  # pragma: no cover
                pass

    def forget(self, session_id: str) -> None:
        """Drop history + subscribers after a session is destroyed."""
        self._history.pop(session_id, None)
        self._subs.pop(session_id, None)


# Module-level singleton — the API and pipeline share one bus.
default_bus = EventBus()
