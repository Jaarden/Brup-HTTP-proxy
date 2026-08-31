"""Talking HTTP/2 to an origin server, and downgrading when it cannot."""
from __future__ import annotations

import pytest

from brup import http2
from brup.ca import CertificateAuthority
from brup.config import Settings
from brup.proxy.upstream import send_h2_request
from tests.h2server import H2Target


@pytest.fixture
def ca(tmp_path):
    return CertificateAuthority(tmp_path / "ca")


def h2_request(port: int, path: bytes = b"/hello", body: bytes = b""):
    headers = [
        (b":method", b"POST" if body else b"GET"),
        (b":scheme", b"https"),
        (b":authority", f"localhost:{port}".encode()),
        (b":path", path),
        (b"accept", b"*/*"),
    ]
    if body:
        headers.append((b"content-length", str(len(body)).encode()))
    return headers, body


async def test_request_and_response_over_h2(ca):
    target = await H2Target().start(ca.context_for("localhost", http2=True))
    try:
        headers, body = h2_request(target.port)
        result = await send_h2_request("localhost", target.port, headers, body,
                                      Settings())
        assert result.ok, result.error
        assert result.protocol == "h2"
        assert result.status == 200
        assert http2.get(result.h2_headers, b"x-served-by") == b"h2target"
        assert b"h2-saw:/hello" in result.h2_body
        assert result.duration_ms > 0

        # The origin saw a genuine HTTP/2 request, pseudo-headers and all.
        seen, _ = target.received[0]
        assert (b":method", b"GET") in seen
        assert (b":path", b"/hello") in seen
        assert (b":authority", f"localhost:{target.port}".encode()) in seen
    finally:
        await target.stop()


async def test_request_body_is_delivered(ca):
    target = await H2Target().start(ca.context_for("localhost", http2=True))
    try:
        headers, body = h2_request(target.port, b"/echo", b'{"a":1}')
        result = await send_h2_request("localhost", target.port, headers, body,
                                      Settings())
        assert result.ok, result.error
        assert b'body:{"a":1}' in result.h2_body
        assert target.received[0][1] == b'{"a":1}'
    finally:
        await target.stop()


async def test_a_body_larger_than_the_flow_control_window(ca):
    """The initial window is 64 KiB, so this only works if WINDOW_UPDATE is honoured."""
    target = await H2Target().start(ca.context_for("localhost", http2=True))
    try:
        payload = b"A" * 300_000
        headers, body = h2_request(target.port, b"/upload", payload)
        result = await send_h2_request("localhost", target.port, headers, body,
                                      Settings(read_timeout=30))
        assert result.ok, result.error
        assert target.received[0][1] == payload, "the upload was truncated"
    finally:
        await target.stop()


async def test_a_response_larger_than_the_flow_control_window(ca):
    target = await H2Target().start(ca.context_for("localhost", http2=True))
    try:
        headers, body = h2_request(target.port, b"/big")
        result = await send_h2_request("localhost", target.port, headers, body,
                                      Settings(read_timeout=30))
        assert result.ok, result.error
        assert len(result.h2_body) == 200_000, len(result.h2_body)
    finally:
        await target.stop()


async def test_status_is_taken_from_the_status_pseudo_header(ca):
    target = await H2Target().start(ca.context_for("localhost", http2=True))
    try:
        for code in (204, 404, 503):
            headers, body = h2_request(target.port, f"/status/{code}".encode())
            result = await send_h2_request("localhost", target.port, headers, body,
                                          Settings())
            assert result.status == code, result.error
    finally:
        await target.stop()


async def test_a_reset_stream_becomes_a_clean_error(ca):
    target = await H2Target(reset_streams=True).start(
        ca.context_for("localhost", http2=True))
    try:
        headers, body = h2_request(target.port)
        result = await send_h2_request("localhost", target.port, headers, body,
                                       Settings(read_timeout=10))
        assert not result.ok
        assert "reset" in result.error.lower(), result.error
    finally:
        await target.stop()


async def test_a_goaway_becomes_a_clean_error(ca):
    target = await H2Target(goaway=True).start(
        ca.context_for("localhost", http2=True))
    try:
        headers, body = h2_request(target.port)
        result = await send_h2_request("localhost", target.port, headers, body,
                                       Settings(read_timeout=10))
        assert not result.ok
        assert "goaway" in result.error.lower() or "closed" in result.error.lower(), \
            result.error
    finally:
        await target.stop()


async def test_unreachable_origin_reports_cleanly(ca):
    headers, body = h2_request(1, b"/nope")
    result = await send_h2_request("127.0.0.1", 1, headers, body,
                                   Settings(connect_timeout=3))
    assert not result.ok and result.error


# ------------------------------------------------------- downgrade to HTTP/1.1

async def test_downgrades_when_the_origin_does_not_offer_h2(ca):
    """Most servers still do not, so this is the common path, not an edge case."""
    from tests.test_proxy import Target
    # An HTTP/1.1-only TLS server: its context offers no h2 in ALPN.
    target = await Target().start(ssl_context=ca.context_for("localhost"))
    try:
        headers, body = h2_request(target.port, b"/downgraded")
        result = await send_h2_request("localhost", target.port, headers, body,
                                       Settings())
        assert result.ok, result.error
        assert result.protocol == "http/1.1"
        assert result.status == 200
        # The client still gets a coherent HTTP/2 response.
        assert http2.get(result.h2_headers, b":status") == b"200"
        assert b"target-saw:/downgraded" in result.h2_body
        # And the origin saw a normal HTTP/1.1 request with a Host header.
        assert target.received[0].startswith(b"GET /downgraded HTTP/1.1")
        assert b"Host: localhost:" in target.received[0]
    finally:
        await target.stop()


async def test_a_body_survives_the_downgrade(ca):
    from tests.test_proxy import Target
    target = await Target().start(ssl_context=ca.context_for("localhost"))
    try:
        headers, body = h2_request(target.port, b"/post", b"payload=1")
        result = await send_h2_request("localhost", target.port, headers, body,
                                       Settings())
        assert result.ok, result.error
        assert b"body:payload=1" in result.h2_body
        # HTTP/1.1 field names are case-insensitive, and the downgrade keeps
        # the lowercase name HTTP/2 required.
        assert b"content-length: 9" in target.received[0].lower()
    finally:
        await target.stop()


async def test_h2_can_be_turned_off_to_force_http1(ca):
    """Useful for comparing how a target behaves on each protocol."""
    target = await H2Target().start(ca.context_for("localhost", http2=True))
    try:
        headers, body = h2_request(target.port)
        result = await send_h2_request("localhost", target.port, headers, body,
                                       Settings(upstream_http2=False))
        # The origin would have spoken h2, but we did not offer it, so the
        # exchange fell back to HTTP/1.1 - which this h2-only server cannot
        # answer, and that failure is reported rather than hidden.
        assert result.protocol == "http/1.1"
        assert not result.ok
    finally:
        await target.stop()


async def test_chunked_downgrade_response_is_dechunked_for_h2(ca):
    """HTTP/2 has no chunked encoding, so the field must not survive."""
    from tests.test_proxy import Target
    target = await Target().start(ssl_context=ca.context_for("localhost"))
    try:
        headers, body = h2_request(target.port, b"/chunked")
        result = await send_h2_request("localhost", target.port, headers, body,
                                       Settings())
        assert result.ok, result.error
        names = [n for n, _ in result.h2_headers]
        assert b"transfer-encoding" not in names
        assert result.h2_body == b"hello world"
    finally:
        await target.stop()
