"""Sending one HTTP/2 request to an origin server.

Uses the ``h2`` sans-IO state machine over asyncio streams. Reading runs as a
background task so that sending a body can wait on WINDOW_UPDATE frames while
the peer's frames keep being processed - a large upload deadlocks otherwise.

One request per connection, matching the HTTP/1.1 path. HTTP/2's multiplexing
is a client-side concern here; upstream, predictability is worth more than
shaving a handshake.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.settings

from .. import http_message as hm

log = logging.getLogger("brup.h2")

READ_CHUNK = 65536
MAX_BODY = 64 * 1024 * 1024


class H2ProtocolError(Exception):
    """The peer broke the protocol, or reset our stream."""


@dataclass
class H2Response:
    headers: hm.Headers = field(default_factory=list)
    body: bytes = b""
    trailers: hm.Headers = field(default_factory=list)


class H2Exchange:
    """One request/response over a fresh HTTP/2 connection."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(
                client_side=True,
                # Keep bytes: the rest of the codebase works in bytes, and
                # decoding would lose whatever a server actually sent.
                header_encoding=None,
            )
        )
        self.response = H2Response()
        self._stream_id: int | None = None
        self._window = asyncio.Event()
        self._finished = asyncio.Event()
        self._failure: str | None = None
        self._reader_task: asyncio.Task | None = None

    async def _flush(self) -> None:
        data = self.conn.data_to_send()
        if data:
            self.writer.write(data)
            await self.writer.drain()

    async def _pump(self) -> None:
        """Feed inbound bytes to the state machine until the stream ends."""
        try:
            while not self._finished.is_set():
                data = await self.reader.read(READ_CHUNK)
                if not data:
                    if not self._finished.is_set():
                        self._failure = "server closed the connection early"
                        self._finished.set()
                    return
                for event in self.conn.receive_data(data):
                    self._handle(event)
                await self._flush()
        except asyncio.CancelledError:
            raise
        except (h2.exceptions.ProtocolError, OSError, ConnectionError) as exc:
            self._failure = f"{type(exc).__name__}: {exc}"
            self._finished.set()

    def _handle(self, event) -> None:
        if isinstance(event, h2.events.ResponseReceived):
            self.response.headers = list(event.headers)
        elif isinstance(event, h2.events.DataReceived):
            if len(self.response.body) + len(event.data) > MAX_BODY:
                self._failure = "response body too large"
                self._finished.set()
                return
            self.response.body += event.data
            # Tell the peer we consumed it, or the window closes and it stalls.
            self.conn.acknowledge_received_data(
                event.flow_controlled_length, event.stream_id
            )
        elif isinstance(event, h2.events.TrailersReceived):
            self.response.trailers = list(event.headers)
        elif isinstance(event, h2.events.StreamEnded):
            self._finished.set()
        elif isinstance(event, h2.events.StreamReset):
            self._failure = (
                f"server reset the stream ({getattr(event, 'error_code', '?')})"
            )
            self._finished.set()
        elif isinstance(event, h2.events.ConnectionTerminated):
            code = getattr(event, "error_code", "?")
            extra = (event.additional_data or b"").decode("latin-1", "replace")
            self._failure = f"server closed the connection (GOAWAY {code}) {extra}".strip()
            self._finished.set()
        elif isinstance(event, h2.events.PushedStreamReceived):
            # Belt and braces: a server that pushed before seeing our SETTINGS
            # would otherwise leave the stream open at both ends.
            try:
                self.conn.reset_stream(
                    event.pushed_stream_id, error_code=h2.errors.ErrorCodes.REFUSED_STREAM
                )
            except (h2.exceptions.ProtocolError, h2.exceptions.StreamClosedError):
                pass
        elif isinstance(event, h2.events.WindowUpdated):
            self._window.set()

    async def _send_body(self, body: bytes) -> None:
        """Write the body, respecting the peer's flow-control window."""
        assert self._stream_id is not None
        offset = 0
        while offset < len(body):
            if self._finished.is_set():
                return
            window = self.conn.local_flow_control_window(self._stream_id)
            if window <= 0:
                self._window.clear()
                # The pump keeps running, so a WINDOW_UPDATE can arrive.
                waiter = asyncio.create_task(self._window.wait())
                done = asyncio.create_task(self._finished.wait())
                await asyncio.wait({waiter, done}, return_when=asyncio.FIRST_COMPLETED)
                for task in (waiter, done):
                    task.cancel()
                continue
            chunk = min(window, self.conn.max_outbound_frame_size, len(body) - offset)
            self.conn.send_data(self._stream_id, body[offset:offset + chunk])
            offset += chunk
            await self._flush()
        self.conn.end_stream(self._stream_id)
        await self._flush()

    async def perform(self, headers: hm.Headers, body: bytes, timeout: float) -> H2Response:
        self.conn.initiate_connection()
        # Refuse server push. This has to come *after* initiate_connection: it
        # queues a second SETTINGS frame, and anything emitted before the
        # connection preface is rejected outright. Assigning to
        # local_settings.enable_push instead looks right but is silently
        # ignored - the emitted SETTINGS still advertises push.
        self.conn.update_settings({h2.settings.SettingCodes.ENABLE_PUSH: 0})
        await self._flush()

        self._stream_id = self.conn.get_next_available_stream_id()
        try:
            self.conn.send_headers(self._stream_id, headers, end_stream=not body)
        except (h2.exceptions.ProtocolError, ValueError) as exc:
            raise H2ProtocolError(f"cannot send these headers: {exc}") from exc
        await self._flush()

        self._reader_task = asyncio.create_task(self._pump())
        try:
            if body:
                await self._send_body(body)
            async with asyncio.timeout(timeout):
                await self._finished.wait()
        finally:
            if self._reader_task is not None:
                self._reader_task.cancel()
                try:
                    await self._reader_task
                except (asyncio.CancelledError, Exception):
                    pass

        if self._failure and not self.response.headers:
            raise H2ProtocolError(self._failure)
        if not self.response.headers:
            raise H2ProtocolError("no response headers received")
        return self.response
