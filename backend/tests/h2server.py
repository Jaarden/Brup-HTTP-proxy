"""A minimal HTTP/2 origin server, for exercising BRUP's HTTP/2 paths.

Deliberately hand-rolled on the same `h2` state machine BRUP uses, so the tests
depend on nothing beyond it and the exchange is fully under their control.
"""
from __future__ import annotations

import asyncio

import h2.config
import h2.connection
import h2.events


class H2Target:
    """Echoes back what it was asked, and can be told to misbehave."""

    def __init__(self, *, reset_streams: bool = False, goaway: bool = False):
        self.received: list[tuple[list[tuple[bytes, bytes]], bytes]] = []
        self.reset_streams = reset_streams
        self.goaway = goaway
        self.server: asyncio.Server | None = None
        self.port = 0

    async def start(self, ssl_context):
        self.server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0, ssl=ssl_context
        )
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader, writer):
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding=None)
        )
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()

        bodies: dict[int, bytes] = {}
        headers: dict[int, list[tuple[bytes, bytes]]] = {}
        # Data still to send per stream, so a closed window pauses rather than
        # truncates - otherwise a large body test proves nothing.
        pending: dict[int, bytes] = {}
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    return
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        headers[event.stream_id] = list(event.headers)
                        bodies[event.stream_id] = b""
                    elif isinstance(event, h2.events.DataReceived):
                        bodies[event.stream_id] += event.data
                        conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, h2.events.StreamEnded):
                        sid = event.stream_id
                        self.received.append((headers.get(sid, []), bodies.get(sid, b"")))
                        if self.goaway:
                            conn.close_connection(error_code=1)
                        elif self.reset_streams:
                            conn.reset_stream(sid, error_code=2)
                        else:
                            pending[sid] = self._respond(
                                conn, sid, headers.get(sid, []), bodies.get(sid, b"")
                            )
                    elif isinstance(event, h2.events.WindowUpdated):
                        pass   # handled by the pump below
                self._pump(conn, pending)
                writer.write(conn.data_to_send())
                await writer.drain()
                if self.goaway:
                    return
        except (asyncio.CancelledError, ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except OSError:
                pass

    @staticmethod
    def _pump(conn, pending: dict[int, bytes]) -> None:
        """Send as much of each stream's remaining body as the window allows."""
        for stream_id in list(pending):
            data = pending[stream_id]
            while data:
                window = conn.local_flow_control_window(stream_id)
                if window <= 0:
                    break
                size = min(window, conn.max_outbound_frame_size, len(data))
                conn.send_data(stream_id, data[:size])
                data = data[size:]
            pending[stream_id] = data
            if not data:
                conn.end_stream(stream_id)
                del pending[stream_id]

    @staticmethod
    def _respond(conn, stream_id, request_headers, body) -> bytes:
        def field(name: bytes) -> bytes:
            for key, value in request_headers:
                if key == name:
                    return value
            return b""

        path = field(b":path")
        if path.startswith(b"/status/"):
            status = path.rsplit(b"/", 1)[1]
        else:
            status = b"200"

        payload = (b"h2-saw:" + path + b"|body:" + body
                   + b"|authority:" + field(b":authority"))
        if path == b"/big":
            payload = b"x" * 200000

        conn.send_headers(stream_id, [
            (b":status", status),
            (b"content-type", b"text/plain"),
            (b"content-length", str(len(payload)).encode()),
            (b"x-served-by", b"h2target"),
        ])
        return payload
