"""Serving HTTP/2 to a client whose TLS session negotiated h2.

Each request stream is handled in its own task, because interception can hold
one indefinitely and the others must keep flowing - that concurrency is the
whole point of HTTP/2 and a browser will open several streams at once.

All mutation of the connection state machine happens under a lock, since those
tasks finish in any order and ``h2`` is not safe to drive concurrently.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions

from .. import http_message as hm

log = logging.getLogger("brup.h2")

READ_CHUNK = 65536
MAX_BODY = 64 * 1024 * 1024
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


@dataclass
class H2Stream:
    stream_id: int
    headers: hm.Headers = field(default_factory=list)
    body: bytes = b""
    ended: bool = False


# Given a request, produce a response: (headers, body). Returning None drops
# the stream, which is how a dropped interception is expressed.
Handler = Callable[[H2Stream], Awaitable[tuple[hm.Headers, bytes] | None]]


class H2Server:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 handler: Handler):
        self.reader = reader
        self.writer = writer
        self.handler = handler
        self.conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(
                client_side=False, header_encoding=None,
            )
        )
        self._streams: dict[int, H2Stream] = {}
        self._tasks: set[asyncio.Task] = set()
        self._lock = asyncio.Lock()
        self._window = asyncio.Event()
        self._closed = False

    # ------------------------------------------------------------ plumbing
    async def _flush(self) -> None:
        data = self.conn.data_to_send()
        if data:
            self.writer.write(data)
            await self.writer.drain()

    async def serve(self, *, initial: bytes = b"") -> None:
        """Run the connection until the client goes away."""
        async with self._lock:
            self.conn.initiate_connection()
            await self._flush()

        buffer = initial
        try:
            while not self._closed:
                if buffer:
                    data, buffer = buffer, b""
                else:
                    data = await self.reader.read(READ_CHUNK)
                    if not data:
                        return
                async with self._lock:
                    try:
                        events = self.conn.receive_data(data)
                    except h2.exceptions.ProtocolError as exc:
                        log.info("client broke HTTP/2: %s", exc)
                        await self._flush()
                        return
                    await self._flush()
                for event in events:
                    await self._dispatch(event)
        except (ConnectionError, OSError):
            pass
        finally:
            self._closed = True
            for task in list(self._tasks):
                task.cancel()
            for task in list(self._tasks):
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

    async def _dispatch(self, event) -> None:
        if isinstance(event, h2.events.RequestReceived):
            self._streams[event.stream_id] = H2Stream(
                event.stream_id, list(event.headers)
            )
        elif isinstance(event, h2.events.DataReceived):
            stream = self._streams.get(event.stream_id)
            if stream is not None:
                if len(stream.body) + len(event.data) > MAX_BODY:
                    await self._reset(event.stream_id)
                    return
                stream.body += event.data
            async with self._lock:
                self.conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
                await self._flush()
        elif isinstance(event, h2.events.StreamEnded):
            stream = self._streams.pop(event.stream_id, None)
            if stream is not None:
                stream.ended = True
                task = asyncio.create_task(self._run_stream(stream))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
        elif isinstance(event, h2.events.StreamReset):
            self._streams.pop(event.stream_id, None)
        elif isinstance(event, h2.events.WindowUpdated):
            self._window.set()
        elif isinstance(event, h2.events.ConnectionTerminated):
            self._closed = True

    # -------------------------------------------------------------- streams
    async def _run_stream(self, stream: H2Stream) -> None:
        try:
            result = await self.handler(stream)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("HTTP/2 stream handler failed")
            await self._reset(stream.stream_id, h2.errors.ErrorCodes.INTERNAL_ERROR)
            return
        if result is None:
            # Dropped: cancel the stream rather than inventing a response.
            await self._reset(stream.stream_id)
            return
        headers, body = result
        await self._respond(stream.stream_id, headers, body)

    async def _reset(self, stream_id: int,
                     code: int = h2.errors.ErrorCodes.CANCEL) -> None:
        async with self._lock:
            try:
                self.conn.reset_stream(stream_id, error_code=code)
                await self._flush()
            except (h2.exceptions.ProtocolError, h2.exceptions.StreamClosedError,
                    ConnectionError, OSError):
                pass

    async def _respond(self, stream_id: int, headers: hm.Headers, body: bytes) -> None:
        try:
            async with self._lock:
                self.conn.send_headers(stream_id, headers, end_stream=not body)
                await self._flush()
            if body:
                await self._send_body(stream_id, body)
        except (h2.exceptions.ProtocolError, h2.exceptions.StreamClosedError) as exc:
            log.info("could not respond on stream %s: %s", stream_id, exc)
        except (ConnectionError, OSError):
            self._closed = True

    async def _send_body(self, stream_id: int, body: bytes) -> None:
        offset = 0
        while offset < len(body) and not self._closed:
            async with self._lock:
                window = self.conn.local_flow_control_window(stream_id)
                chunk = min(window, self.conn.max_outbound_frame_size,
                            len(body) - offset) if window > 0 else 0
                if chunk:
                    self.conn.send_data(stream_id, body[offset:offset + chunk])
                    await self._flush()
            if chunk:
                offset += chunk
                continue
            # Window is closed; wait for the peer to open it.
            self._window.clear()
            try:
                async with asyncio.timeout(30):
                    await self._window.wait()
            except asyncio.TimeoutError:
                log.info("stream %s stalled waiting for a window update", stream_id)
                await self._reset(stream_id)
                return
        async with self._lock:
            try:
                self.conn.end_stream(stream_id)
                await self._flush()
            except (h2.exceptions.ProtocolError, h2.exceptions.StreamClosedError):
                pass
