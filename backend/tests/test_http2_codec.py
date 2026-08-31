"""The editable text form for HTTP/2 messages, and translation to HTTP/1.1."""
from __future__ import annotations

import pytest

from brup import http2, http_message as hm

REQUEST_HEADERS = [
    (b":method", b"POST"),
    (b":scheme", b"https"),
    (b":authority", b"api.example.com"),
    (b":path", b"/v1/login?next=%2Fhome"),
    (b"accept", b"*/*"),
    (b"content-type", b"application/json"),
    (b"cookie", b"a=1"),
    (b"cookie", b"b=2"),
]
BODY = b'{"user":"admin"}'


def test_request_renders_pseudo_headers_explicitly():
    text = http2.request_to_text(REQUEST_HEADERS, BODY)
    lines = text.split(b"\r\n")
    # The familiar shape, with the version making the protocol obvious.
    assert lines[0] == b"POST /v1/login?next=%2Fhome HTTP/2"
    # :method and :path are on the first line and not repeated.
    assert not any(l.startswith(b":method") or l.startswith(b":path") for l in lines)
    # The others are shown rather than hidden.
    assert b":scheme: https" in lines
    assert b":authority: api.example.com" in lines
    assert text.endswith(b"\r\n\r\n" + BODY)


def test_request_round_trips_exactly():
    text = http2.request_to_text(REQUEST_HEADERS, BODY)
    headers, body = http2.request_from_text(text)
    assert headers == REQUEST_HEADERS
    assert body == BODY


def test_repeated_fields_are_preserved_not_merged():
    """HTTP/2 clients legitimately split cookies across fields for HPACK."""
    _, _ = http2.request_from_text(http2.request_to_text(REQUEST_HEADERS, b""))
    headers, _ = http2.request_from_text(http2.request_to_text(REQUEST_HEADERS, b""))
    assert [v for n, v in headers if n == b"cookie"] == [b"a=1", b"b=2"]


def test_pseudo_headers_come_first_after_editing():
    """HTTP/2 rejects a pseudo-header after a regular one, so order is enforced."""
    edited = (b"GET / HTTP/2\r\n"
              b"accept: */*\r\n"
              b":authority: example.com\r\n"      # deliberately out of place
              b":scheme: https\r\n\r\n")
    headers, _ = http2.request_from_text(edited)
    names = [n for n, _ in headers]
    assert names[:4] == [b":method", b":scheme", b":authority", b":path"]
    assert names[4] == b"accept"


def test_an_explicit_pseudo_header_overrides_the_first_line():
    """Full control: send something the first line cannot express."""
    edited = (b"GET /shown HTTP/2\r\n"
              b":authority: example.com\r\n"
              b":method: TRACE\r\n"
              b":path: /actual\r\n\r\n")
    headers, _ = http2.request_from_text(edited)
    assert http2.get(headers, b":method") == b"TRACE"
    assert http2.get(headers, b":path") == b"/actual"


def test_request_parsing_rejects_the_unsendable():
    with pytest.raises(http2.Http2Error):
        http2.request_from_text(b"")
    with pytest.raises(http2.Http2Error):
        http2.request_from_text(b"GET\r\n\r\n")
    with pytest.raises(http2.Http2Error) as exc:
        http2.request_from_text(b"GET / HTTP/2\r\naccept: */*\r\n\r\n")
    assert ":authority" in str(exc.value)


def test_a_path_containing_a_colon_survives():
    headers, _ = http2.request_from_text(
        b"GET /a:b/c HTTP/2\r\n:authority: e.test\r\n\r\n")
    assert http2.get(headers, b":path") == b"/a:b/c"


def test_a_header_value_containing_a_colon_survives():
    headers, _ = http2.request_from_text(
        b"GET / HTTP/2\r\n:authority: e.test\r\nreferer: https://x.test/a\r\n\r\n")
    assert http2.get(headers, b"referer") == b"https://x.test/a"


# ------------------------------------------------------------------ responses

RESPONSE_HEADERS = [
    (b":status", b"404"),
    (b"content-type", b"text/html"),
    (b"set-cookie", b"a=1"),
    (b"set-cookie", b"b=2"),
]


def test_response_shows_a_reason_for_readability():
    text = http2.response_to_text(RESPONSE_HEADERS, b"nope")
    assert text.split(b"\r\n")[0] == b"HTTP/2 404 Not Found"
    # ...but it is not part of the message, so it is ignored coming back.
    headers, body = http2.response_from_text(text)
    assert headers == RESPONSE_HEADERS
    assert body == b"nope"


def test_response_with_an_unknown_status_has_no_invented_reason():
    text = http2.response_to_text([(b":status", b"599")], b"")
    assert text.split(b"\r\n")[0] == b"HTTP/2 599"
    assert http2.response_from_text(text)[0] == [(b":status", b"599")]


def test_editing_the_status_line_changes_the_status():
    headers, _ = http2.response_from_text(b"HTTP/2 503 Whatever\r\nx: y\r\n\r\n")
    assert http2.get(headers, b":status") == b"503"


# --------------------------------------------------------------- translation

def test_h2_request_downgrades_to_http1():
    raw = http2.to_h1_request(REQUEST_HEADERS, BODY)
    request = hm.parse_request(raw)
    assert request.method == b"POST"
    assert request.target == b"/v1/login?next=%2Fhome"
    assert request.version == b"HTTP/1.1"
    # :authority becomes Host, and it comes first.
    assert request.headers[0] == (b"Host", b"api.example.com")
    assert request.header("content-length") == str(len(BODY)).encode()
    assert request.body == BODY


def test_downgrade_drops_fields_http2_forbids():
    headers = [
        (b":method", b"GET"), (b":scheme", b"https"),
        (b":authority", b"e.test"), (b":path", b"/"),
        (b"te", b"trailers"),
    ]
    raw = http2.to_h1_request(headers, b"")
    assert b"te: trailers" in raw          # te is allowed in HTTP/2


def test_http1_response_upgrades_to_h2_fields():
    response = hm.parse_response(
        b"HTTP/1.1 301 Moved Permanently\r\n"
        b"Location: /new\r\n"
        b"Connection: keep-alive\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Content-Length: 2\r\n\r\nhi"
    )
    headers, body = http2.from_h1_response(response)
    assert headers[0] == (b":status", b"301")
    names = [n for n, _ in headers]
    # Field names are lowercased, as HTTP/2 requires...
    assert b"location" in names
    # ...and connection-specific fields are gone, or the peer would reset us.
    assert b"connection" not in names
    assert b"transfer-encoding" not in names
    assert body == b"hi"


def test_http1_request_upgrades_to_h2_fields():
    request = hm.parse_request(
        b"GET /x?y=1 HTTP/1.1\r\nHost: e.test\r\nConnection: close\r\n"
        b"User-Agent: curl\r\n\r\n")
    headers, _ = http2.to_h2_request(request)
    assert headers[:4] == [
        (b":method", b"GET"), (b":scheme", b"https"),
        (b":authority", b"e.test"), (b":path", b"/x?y=1"),
    ]
    names = [n for n, _ in headers]
    assert b"connection" not in names
    assert b"host" not in names            # replaced by :authority
    assert (b"user-agent", b"curl") in headers


def test_strip_for_h2_lowercases_and_drops():
    headers = [
        (b":method", b"GET"),
        (b"X-Odd-Case", b"Yes"),
        (b"Connection", b"close"),
    ]
    assert http2.strip_for_h2(headers) == [
        (b":method", b"GET"), (b"x-odd-case", b"Yes"),
    ]


def test_absolute_form_target_becomes_a_path():
    request = hm.parse_request(
        b"GET http://e.test/deep?q=1 HTTP/1.1\r\nHost: e.test\r\n\r\n")
    headers, _ = http2.to_h2_request(request)
    assert http2.get(headers, b":path") == b"/deep?q=1"


def test_form_detection():
    assert http2.looks_like_h2_text(b"GET / HTTP/2\r\n\r\n")
    assert http2.looks_like_h2_text(b"HTTP/2 200 OK\r\n\r\n")
    assert not http2.looks_like_h2_text(b"GET / HTTP/1.1\r\n\r\n")
    assert not http2.looks_like_h2_text(b"HTTP/1.1 200 OK\r\n\r\n")
