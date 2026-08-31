"""Sending a raw request to an origin server and reading the raw response.

Used by the proxy path, Repeater and Intruder alike, so all three share exactly
the same wire behaviour.
"""
from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from .. import http_message as hm
from ..ca import client_context
from ..config import Settings
from ..netutil import STREAM_LIMIT, close_writer, upgrade_to_tls


@dataclass
class UpstreamResult:
    raw_response: bytes = b""
    response: hm.Response | None = None
    duration_ms: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.response is not None


def _prepare(raw_request: bytes, *, tls: bool, via_http_proxy: bool,
             host: str, port: int) -> tuple[hm.Request, bytes]:
    """Rewrite the request target for its destination and drop hop-by-hop cruft."""
    req = hm.parse_request(raw_request)
    hm.remove_header(req.headers, "proxy-connection")

    if via_http_proxy and not tls:
        # A forward proxy expects absolute-form.
        if not req.is_absolute_form:
            authority = (req.header("host") or f"{host}:{port}".encode())
            req.target = b"http://" + authority + req.origin_form_target()
    else:
        req.target = req.origin_form_target()
    return req, req.raw


async def _open_direct(host: str, port: int, tls: bool, settings: Settings):
    ctx = client_context(settings.upstream_verify_tls) if tls else None
    async with asyncio.timeout(settings.connect_timeout):
        return await asyncio.open_connection(
            host, port,
            ssl=ctx,
            server_hostname=host if tls else None,
            limit=STREAM_LIMIT,
        )


async def _open_via_proxy(host: str, port: int, tls: bool, settings: Settings):
    parsed = urlparse(settings.upstream_proxy)
    phost = parsed.hostname or ""
    pport = parsed.port or (443 if parsed.scheme == "https" else 8080)
    if not phost:
        raise OSError(f"invalid upstream proxy: {settings.upstream_proxy!r}")

    async with asyncio.timeout(settings.connect_timeout):
        reader, writer = await asyncio.open_connection(phost, pport, limit=STREAM_LIMIT)

    if not tls:
        return reader, writer

    # Establish a CONNECT tunnel, then start TLS inside it.
    authority = f"{host}:{port}"
    writer.write(
        f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n".encode()
    )
    await writer.drain()
    async with asyncio.timeout(settings.connect_timeout):
        head = await hm.read_head(reader)
    if head is None:
        raise OSError("upstream proxy closed the connection during CONNECT")
    status = hm.parse_response(head + b"\r\n\r\n").status
    if status != 200:
        raise OSError(f"upstream proxy refused CONNECT with status {status}")

    ctx = client_context(settings.upstream_verify_tls)
    await upgrade_to_tls(
        reader, writer, ctx,
        server_side=False,
        server_hostname=host,
        timeout=settings.connect_timeout,
    )
    return reader, writer


async def send_request(
    host: str,
    port: int,
    tls: bool,
    raw_request: bytes,
    settings: Settings,
) -> UpstreamResult:
    """Perform one request/response exchange on a fresh connection."""
    started = time.perf_counter()
    writer = None
    via_proxy = bool(settings.upstream_proxy.strip())
    try:
        req, wire = _prepare(
            raw_request, tls=tls, via_http_proxy=via_proxy, host=host, port=port
        )
    except hm.ParseError as exc:
        return UpstreamResult(error=f"could not parse request: {exc}")

    try:
        if via_proxy:
            reader, writer = await _open_via_proxy(host, port, tls, settings)
        else:
            reader, writer = await _open_direct(host, port, tls, settings)

        writer.write(wire)
        await writer.drain()

        async with asyncio.timeout(settings.read_timeout):
            head = await hm.read_head(reader)
            if head is None:
                raise OSError("server closed the connection without responding")
            resp = hm.parse_response(head + b"\r\n\r\n")
            body, was_chunked = await hm.read_body(
                reader, resp.headers,
                is_response=True,
                status=resp.status,
                request_method=req.method,
            )
        resp.body = body
        hm.normalise_framing(resp.headers, body, was_chunked)
        elapsed = (time.perf_counter() - started) * 1000
        return UpstreamResult(resp.raw, resp, elapsed)

    except asyncio.TimeoutError:
        return UpstreamResult(
            error=f"timed out after {settings.read_timeout:g}s",
            duration_ms=(time.perf_counter() - started) * 1000,
        )
    except (hm.ParseError, ssl.SSLError, OSError, ConnectionError, ValueError) as exc:
        return UpstreamResult(
            error=f"{type(exc).__name__}: {exc}",
            duration_ms=(time.perf_counter() - started) * 1000,
        )
    finally:
        await close_writer(writer)
