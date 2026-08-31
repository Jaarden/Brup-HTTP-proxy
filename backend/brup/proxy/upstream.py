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
from .. import http2
from ..ca import client_context
from ..config import Settings
from ..netutil import STREAM_LIMIT, close_writer, upgrade_to_tls
from .h2_client import H2Exchange, H2ProtocolError


@dataclass
class UpstreamResult:
    raw_response: bytes = b""
    response: hm.Response | None = None
    duration_ms: float = 0.0
    error: str | None = None
    # What was actually spoken to the origin: "http/1.1" or "h2".
    protocol: str = "http/1.1"
    # HTTP/2 responses are header fields, not a status line; kept so the caller
    # can render or forward them without re-parsing the text form.
    h2_headers: hm.Headers | None = None
    h2_body: bytes = b""

    @property
    def ok(self) -> bool:
        if self.protocol == "h2":
            return self.error is None and self.h2_headers is not None
        return self.error is None and self.response is not None

    @property
    def status(self) -> int | None:
        if self.protocol == "h2" and self.h2_headers is not None:
            raw = http2.get(self.h2_headers, b":status")
            if raw is not None:
                try:
                    return int(raw)
                except ValueError:
                    return None
            return None
        return self.response.status if self.response else None


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


async def _open_direct(host: str, port: int, tls: bool, settings: Settings,
                       *, http2_alpn: bool = False):
    ctx = (client_context(settings.upstream_verify_tls, http2=http2_alpn)
           if tls else None)
    async with asyncio.timeout(settings.connect_timeout):
        return await asyncio.open_connection(
            host, port,
            ssl=ctx,
            server_hostname=host if tls else None,
            limit=STREAM_LIMIT,
        )


async def _open_via_proxy(host: str, port: int, tls: bool, settings: Settings,
                          *, http2_alpn: bool = False):
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

    ctx = client_context(settings.upstream_verify_tls, http2=http2_alpn)
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


def negotiated_protocol(writer: asyncio.StreamWriter) -> str:
    """Which protocol ALPN settled on, defaulting to HTTP/1.1."""
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return "http/1.1"
    return ssl_object.selected_alpn_protocol() or "http/1.1"


async def send_h2_request(
    host: str,
    port: int,
    headers: hm.Headers,
    body: bytes,
    settings: Settings,
) -> UpstreamResult:
    """Send an HTTP/2 request, downgrading if the origin only speaks HTTP/1.1.

    Most servers still do, so the downgrade is not an edge case: the request is
    translated to HTTP/1.1, sent, and the reply translated back into HTTP/2
    header fields, so the client sees a coherent HTTP/2 response either way.
    """
    started = time.perf_counter()
    writer = None
    via_proxy = bool(settings.upstream_proxy.strip())
    offer_h2 = settings.upstream_http2
    # What we end up actually speaking. Tracked separately so a failure reports
    # the protocol that was really in use rather than the one we hoped for.
    spoken = "h2" if offer_h2 else "http/1.1"

    def elapsed() -> float:
        return (time.perf_counter() - started) * 1000

    try:
        opener = _open_via_proxy if via_proxy else _open_direct
        reader, writer = await opener(host, port, True, settings, http2_alpn=offer_h2)
        spoken = protocol = negotiated_protocol(writer)

        if protocol != "h2":
            # The origin did not take h2. Speak HTTP/1.1 to it and translate.
            wire = http2.to_h1_request(headers, body)
            request = hm.parse_request(wire)
            writer.write(wire)
            await writer.drain()
            async with asyncio.timeout(settings.read_timeout):
                head = await hm.read_head(reader)
                if head is None:
                    raise OSError("server closed the connection without responding")
                resp = hm.parse_response(head + b"\r\n\r\n")
                resp_body, was_chunked = await hm.read_body(
                    reader, resp.headers, is_response=True,
                    status=resp.status, request_method=request.method,
                )
            resp.body = resp_body
            hm.normalise_framing(resp.headers, resp_body, was_chunked)
            h2_headers, h2_body = http2.from_h1_response(resp)
            return UpstreamResult(
                raw_response=resp.raw, response=resp, duration_ms=elapsed(),
                protocol="http/1.1", h2_headers=h2_headers, h2_body=h2_body,
            )

        exchange = H2Exchange(reader, writer)
        response = await exchange.perform(
            http2.strip_for_h2(headers), body, settings.read_timeout
        )
        combined = list(response.headers)
        if response.trailers:
            combined += response.trailers
        return UpstreamResult(
            raw_response=http2.response_to_text(response.headers, response.body),
            duration_ms=elapsed(), protocol="h2",
            h2_headers=combined, h2_body=response.body,
        )

    except asyncio.TimeoutError:
        return UpstreamResult(
            error=f"timed out after {settings.read_timeout:g}s",
            duration_ms=elapsed(), protocol=spoken,
        )
    except (H2ProtocolError, hm.ParseError, http2.Http2Error) as exc:
        return UpstreamResult(error=str(exc), duration_ms=elapsed(), protocol=spoken)
    except (ssl.SSLError, OSError, ConnectionError, ValueError) as exc:
        return UpstreamResult(
            error=f"{type(exc).__name__}: {exc}", duration_ms=elapsed(),
            protocol=spoken,
        )
    finally:
        await close_writer(writer)
