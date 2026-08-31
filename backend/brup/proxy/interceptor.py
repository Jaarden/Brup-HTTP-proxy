"""Holds requests and responses until the operator decides what to do."""
from __future__ import annotations

import asyncio
import base64
import itertools
import time
from dataclasses import dataclass, field
from typing import Literal

from ..events import EventHub

Decision = Literal["forward", "drop"]


@dataclass
class PendingItem:
    id: str
    kind: Literal["request", "response"]
    project_id: str
    flow_id: int | None
    host: str
    port: int
    tls: bool
    url: str
    method: str
    raw: bytes
    future: asyncio.Future = field(repr=False)
    created: float = field(default_factory=time.time)
    status: int | None = None

    def summary(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "project_id": self.project_id,
            "flow_id": self.flow_id,
            "host": self.host,
            "port": self.port,
            "tls": self.tls,
            "url": self.url,
            "method": self.method,
            "status": self.status,
            "created": self.created,
            "raw_b64": base64.b64encode(self.raw).decode(),
            "length": len(self.raw),
        }


class Interceptor:
    """A FIFO of held messages, each awaiting a forward/drop decision."""

    def __init__(self, hub: EventHub):
        self.hub = hub
        self._pending: dict[str, PendingItem] = {}
        self._ids = itertools.count(1)

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def list_pending(self) -> list[dict]:
        return [item.summary() for item in self._pending.values()]

    def get(self, item_id: str) -> PendingItem | None:
        return self._pending.get(item_id)

    async def hold(
        self,
        *,
        kind: Literal["request", "response"],
        project_id: str,
        flow_id: int | None,
        host: str,
        port: int,
        tls: bool,
        url: str,
        method: str,
        raw: bytes,
        status: int | None = None,
    ) -> tuple[Decision, bytes]:
        """Park a message and await the operator's decision.

        Returns the decision plus the (possibly edited) raw bytes to use.
        """
        loop = asyncio.get_running_loop()
        item = PendingItem(
            id=f"i{next(self._ids)}",
            kind=kind,
            project_id=project_id,
            flow_id=flow_id,
            host=host,
            port=port,
            tls=tls,
            url=url,
            method=method,
            raw=raw,
            status=status,
            future=loop.create_future(),
        )
        self._pending[item.id] = item
        self.hub.publish(f"intercept_{kind}", item.summary())
        try:
            return await item.future
        finally:
            self._pending.pop(item.id, None)
            self.hub.publish("intercept_resolved", {"id": item.id})

    def _resolve(self, item: PendingItem, decision: Decision, raw: bytes | None) -> bool:
        if item.future.done():
            return False
        item.future.set_result((decision, raw if raw is not None else item.raw))
        return True

    def forward(self, item_id: str, raw: bytes | None = None) -> bool:
        item = self._pending.get(item_id)
        return bool(item) and self._resolve(item, "forward", raw)

    def drop(self, item_id: str) -> bool:
        item = self._pending.get(item_id)
        return bool(item) and self._resolve(item, "drop", None)

    def forward_all(self) -> int:
        return sum(self._resolve(i, "forward", None) for i in list(self._pending.values()))

    def drop_all(self) -> int:
        return sum(self._resolve(i, "drop", None) for i in list(self._pending.values()))
