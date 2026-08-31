"""Shared low-level networking helpers."""
from __future__ import annotations

import asyncio
import gzip
import ssl
import zlib

try:  # optional, only needed for Brotli-encoded bodies
    import brotli
except ImportError:  # pragma: no cover
    brotli = None

STREAM_LIMIT = 4 * 1024 * 1024


async def upgrade_to_tls(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    context: ssl.SSLContext,
    *,
    server_side: bool,
    server_hostname: str | None = None,
    timeout: float = 15.0,
) -> None:
    """Wrap an existing stream pair in TLS, in place.

    ``loop.start_tls`` hands back a replacement transport but the StreamWriter
    keeps pointing at the old one, so we reassign it. The StreamReader keeps
    working because the same protocol object is reused across the upgrade.
    """
    loop = asyncio.get_running_loop()
    transport = writer.transport
    protocol = transport.get_protocol()
    async with asyncio.timeout(timeout):
        new_transport = await loop.start_tls(
            transport,
            protocol,
            context,
            server_side=server_side,
            server_hostname=None if server_side else server_hostname,
        )
    if new_transport is None:
        raise ssl.SSLError("TLS upgrade failed")
    writer._transport = new_transport  # noqa: SLF001 - no public API for this


async def close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    try:
        if not writer.is_closing():
            writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=5)
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ConnectionError):
        pass


async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    """Copy bytes one way until EOF; used for TLS pass-through tunnels."""
    try:
        while True:
            chunk = await src.read(65536)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
    except (OSError, ConnectionError, ssl.SSLError, asyncio.CancelledError):
        pass
    finally:
        try:
            if dst.can_write_eof():
                dst.write_eof()
        except (OSError, ConnectionError, ssl.SSLError):
            pass


async def tunnel(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    server_reader: asyncio.StreamReader,
    server_writer: asyncio.StreamWriter,
) -> None:
    await asyncio.gather(
        pipe(client_reader, server_writer),
        pipe(server_reader, client_writer),
        return_exceptions=True,
    )


def decode_content(encoding: bytes | str | None, body: bytes) -> tuple[bytes, str | None]:
    """Best-effort Content-Encoding decode for display purposes.

    Returns ``(body, error)`` - on failure the original bytes come back so the
    viewer can still show something.
    """
    if not encoding or not body:
        return body, None
    enc = (encoding.decode("latin-1") if isinstance(encoding, bytes) else encoding).lower()
    enc = enc.split(",")[0].strip()
    try:
        if enc in ("gzip", "x-gzip"):
            return gzip.decompress(body), None
        if enc == "deflate":
            try:
                return zlib.decompress(body), None
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS), None
        if enc == "br":
            if brotli is None:
                return body, "brotli support not installed"
            return brotli.decompress(body), None
        if enc == "zstd":
            try:
                import zstandard
            except ImportError:
                return body, "zstd support not installed"
            return zstandard.ZstdDecompressor().decompress(body), None
    except Exception as exc:  # noqa: BLE001 - display must not fail hard
        return body, f"{enc} decode failed: {exc}"
    return body, None
