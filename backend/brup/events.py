"""Fan-out of live proxy events to connected UI WebSockets."""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any

log = logging.getLogger("brup.events")
QUEUE_SIZE = 2000


class EventHub:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def publish(self, event_type: str, payload: Any = None) -> None:
        """Non-blocking broadcast.

        A slow or stalled UI must never apply back-pressure to the proxy, so a
        full queue drops its oldest event rather than waiting.
        """
        message = json.dumps({"type": event_type, "data": payload})
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
                with contextlib.suppress(asyncio.QueueFull):
                    queue.put_nowait(message)
