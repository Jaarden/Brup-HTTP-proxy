"""HTTP/2 message representation.

An HTTP/2 request is a set of header fields, not a request line, so there is no
single canonical text form. Operators still need to read and edit one, so
messages are rendered like this:

    GET /search?q=1 HTTP/2
    :authority: example.com
    :scheme: https
    accept: */*

The first line carries ``:method`` and ``:path`` in the familiar place; the
remaining pseudo-headers are shown explicitly so nothing is hidden, and regular
fields keep their wire order and (lowercase) names. Parsing reverses it exactly,
so an edited message goes back on the wire as the operator wrote it.
"""
from __future__ import annotations

from . import http_message as hm

# HTTP/2 requires pseudo-headers first, and this is the conventional order.
REQUEST_PSEUDO_ORDER = (b":method", b":scheme", b":authority", b":path")

# Hop-by-hop fields HTTP/2 forbids (RFC 9113 8.2.2). Carrying them over from an
# HTTP/1.1 message is a protocol error, so they are dropped in translation.
CONNECTION_SPECIFIC = frozenset({
    b"connection", b"keep-alive", b"proxy-connection",
    b"transfer-encoding", b"upgrade", b"proxy-authenticate",
})

REASONS = {
    200: b"OK", 201: b"Created", 202: b"Accepted", 204: b"No Content",
    301: b"Moved Permanently", 302: b"Found", 303: b"See Other",
    304: b"Not Modified", 307: b"Temporary Redirect", 308: b"Permanent Redirect",
    400: b"Bad Request", 401: b"Unauthorized", 403: b"Forbidden",
    404: b"Not Found", 405: b"Method Not Allowed", 408: b"Request Timeout",
    409: b"Conflict", 410: b"Gone", 413: b"Payload Too Large",
    418: b"I'm a teapot", 422: b"Unprocessable Entity", 429: b"Too Many Requests",
    500: b"Internal Server Error", 501: b"Not Implemented",
    502: b"Bad Gateway", 503: b"Service Unavailable", 504: b"Gateway Timeout",
}


class Http2Error(Exception):
    """A message that cannot be represented or parsed as HTTP/2."""


def get(headers: hm.Headers, name: bytes) -> bytes | None:
    for field, value in headers:
        if field == name:
            return value
    return None


def split_pseudo(headers: hm.Headers) -> tuple[hm.Headers, hm.Headers]:
    """Separate pseudo-headers from ordinary ones, keeping each group's order."""
    pseudo = [(n, v) for n, v in headers if n.startswith(b":")]
    regular = [(n, v) for n, v in headers if not n.startswith(b":")]
    return pseudo, regular


# --------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------

def request_to_text(headers: hm.Headers, body: bytes = b"") -> bytes:
    """Render an HTTP/2 request in the editable form described above."""
    pseudo, regular = split_pseudo(headers)
    method = get(pseudo, b":method") or b"GET"
    path = get(pseudo, b":path") or b"/"

    lines = [b" ".join([method, path, b"HTTP/2"])]
    # :method and :path are already on the first line; show the rest.
    for name, value in pseudo:
        if name not in (b":method", b":path"):
            lines.append(name + b": " + value)
    for name, value in regular:
        lines.append(name + b": " + value)
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def request_from_text(raw: bytes) -> tuple[hm.Headers, bytes]:
    """Parse the editable form back into HTTP/2 header fields and a body.

    An explicit ``:method`` or ``:path`` header line overrides the first line,
    so the operator can send something the first line cannot express.
    """
    head, body = _split(raw)
    lines = _head_lines(head)
    if not lines:
        raise Http2Error("empty request")

    bits = lines[0].split()
    if len(bits) < 2:
        raise Http2Error(f"malformed first line: {lines[0][:80]!r}")
    method, path = bits[0], bits[1]

    pseudo: dict[bytes, bytes] = {b":method": method, b":path": path}
    regular: hm.Headers = []
    for line in lines[1:]:
        name, value = _field(line)
        if name.startswith(b":"):
            pseudo[name] = value
        else:
            regular.append((name, value))

    headers: hm.Headers = [
        (name, pseudo[name]) for name in REQUEST_PSEUDO_ORDER if name in pseudo
    ]
    # Any pseudo-header we do not know about still goes before the regular ones.
    headers += [(n, v) for n, v in pseudo.items() if n not in REQUEST_PSEUDO_ORDER]
    headers += regular

    if get(headers, b":authority") is None and get(headers, b"host") is None:
        raise Http2Error("an HTTP/2 request needs :authority (or a Host header)")
    return headers, body


# --------------------------------------------------------------------------
# Responses
# --------------------------------------------------------------------------

def response_to_text(headers: hm.Headers, body: bytes = b"") -> bytes:
    pseudo, regular = split_pseudo(headers)
    status_raw = get(pseudo, b":status") or b"0"
    try:
        status = int(status_raw)
    except ValueError:
        status = 0
    # HTTP/2 has no reason phrase; one is shown for readability and ignored
    # when parsing back.
    reason = REASONS.get(status, b"")
    line = b"HTTP/2 " + status_raw + ((b" " + reason) if reason else b"")

    lines = [line]
    for name, value in pseudo:
        if name != b":status":
            lines.append(name + b": " + value)
    for name, value in regular:
        lines.append(name + b": " + value)
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def response_from_text(raw: bytes) -> tuple[hm.Headers, bytes]:
    head, body = _split(raw)
    lines = _head_lines(head)
    if not lines:
        raise Http2Error("empty response")

    bits = lines[0].split()
    if len(bits) < 2:
        raise Http2Error(f"malformed status line: {lines[0][:80]!r}")
    status = bits[1]

    headers: hm.Headers = [(b":status", status)]
    for line in lines[1:]:
        name, value = _field(line)
        if name == b":status":
            headers[0] = (b":status", value)
        elif name.startswith(b":"):
            headers.insert(1, (name, value))
        else:
            headers.append((name, value))
    return headers, body


# --------------------------------------------------------------------------
# Translation to and from HTTP/1.1, for origins that do not speak HTTP/2
# --------------------------------------------------------------------------

def to_h1_request(headers: hm.Headers, body: bytes) -> bytes:
    """Build an HTTP/1.1 request from HTTP/2 header fields."""
    pseudo, regular = split_pseudo(headers)
    method = get(pseudo, b":method") or b"GET"
    path = get(pseudo, b":path") or b"/"
    authority = get(pseudo, b":authority")

    out: hm.Headers = []
    if authority:
        out.append((b"Host", authority))
    seen_host = bool(authority)
    for name, value in regular:
        if name.lower() in CONNECTION_SPECIFIC:
            continue
        if name.lower() == b"host":
            if seen_host:
                continue
            seen_host = True
        out.append((name, value))

    request = hm.Request(method, path, b"HTTP/1.1", out, body)
    if body:
        hm.set_header(request.headers, "Content-Length", len(body))
    return request.raw


def from_h1_response(response: hm.Response) -> tuple[hm.Headers, bytes]:
    """Turn an HTTP/1.1 response into HTTP/2 header fields."""
    headers: hm.Headers = [(b":status", str(response.status).encode())]
    for name, value in response.headers:
        lower = name.lower()
        if lower in CONNECTION_SPECIFIC:
            continue
        # HTTP/2 field names must be lowercase.
        headers.append((lower, value))
    return headers, response.body


def to_h2_request(request: hm.Request, *, scheme: bytes = b"https") -> tuple[hm.Headers, bytes]:
    """Turn an HTTP/1.1 request into HTTP/2 header fields."""
    authority = request.header("host") or b""
    headers: hm.Headers = [
        (b":method", request.method),
        (b":scheme", scheme),
        (b":authority", authority),
        (b":path", request.origin_form_target()),
    ]
    for name, value in request.headers:
        lower = name.lower()
        if lower in CONNECTION_SPECIFIC or lower == b"host":
            continue
        headers.append((lower, value))
    return headers, request.body


def strip_for_h2(headers: hm.Headers) -> hm.Headers:
    """Drop fields HTTP/2 forbids and lowercase the names it requires lowercase."""
    out: hm.Headers = []
    for name, value in headers:
        if name.startswith(b":"):
            out.append((name, value))
            continue
        lower = name.lower()
        if lower in CONNECTION_SPECIFIC:
            continue
        out.append((lower, value))
    return out


# --------------------------------------------------------------------------
# Shared text helpers
# --------------------------------------------------------------------------

def _split(raw: bytes) -> tuple[bytes, bytes]:
    index = raw.find(b"\r\n\r\n")
    length = 4
    if index == -1:
        index = raw.find(b"\n\n")
        length = 2
    if index == -1:
        return raw, b""
    return raw[:index], raw[index + length:]


def _head_lines(head: bytes) -> list[bytes]:
    lines = [ln[:-1] if ln.endswith(b"\r") else ln for ln in head.split(b"\n")]
    return [ln for ln in lines if ln.strip()]


def _field(line: bytes) -> tuple[bytes, bytes]:
    index = line.find(b":", 1)   # from 1, so a leading ':' stays in the name
    if index == -1:
        raise Http2Error(f"malformed header line: {line[:80]!r}")
    return line[:index].strip(), line[index + 1:].strip()


def looks_like_h2_text(raw: bytes) -> bool:
    """Whether an editor buffer is in the HTTP/2 form rather than HTTP/1.x."""
    first = raw.split(b"\n", 1)[0]
    return b"HTTP/2" in first
