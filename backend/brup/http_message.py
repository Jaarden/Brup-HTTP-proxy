"""Raw, byte-level HTTP/1.x parsing and serialisation.

Deliberately permissive: this is a security tool, so we preserve header order,
header casing and odd whitespace wherever possible instead of normalising them.
The only normalisation applied is de-chunking of ``Transfer-Encoding: chunked``
bodies (converted to ``Content-Length``), which keeps Repeater/Intruder sane.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

CRLF = b"\r\n"
MAX_HEAD = 512 * 1024
MAX_BODY = 64 * 1024 * 1024


class ParseError(Exception):
    """Raised when a message cannot be parsed well enough to proxy it."""


Headers = list[tuple[bytes, bytes]]


def _split_head_lines(head: bytes) -> list[bytes]:
    # Tolerate bare LF line endings as well as CRLF.
    lines = head.split(b"\n")
    return [ln[:-1] if ln.endswith(b"\r") else ln for ln in lines]


def _parse_headers(lines: list[bytes]) -> Headers:
    headers: Headers = []
    for ln in lines:
        if not ln:
            continue
        if ln[:1] in (b" ", b"\t") and headers:
            # obs-fold continuation line: append to previous value.
            name, value = headers[-1]
            headers[-1] = (name, value + b" " + ln.strip())
            continue
        idx = ln.find(b":")
        if idx <= 0:
            raise ParseError(f"malformed header line: {ln[:80]!r}")
        headers.append((ln[:idx], ln[idx + 1:].strip()))
    return headers


def get_header(headers: Headers, name: str | bytes) -> bytes | None:
    key = (name if isinstance(name, bytes) else name.encode()).lower()
    for n, v in headers:
        if n.lower() == key:
            return v
    return None


def get_all_headers(headers: Headers, name: str | bytes) -> list[bytes]:
    key = (name if isinstance(name, bytes) else name.encode()).lower()
    return [v for n, v in headers if n.lower() == key]


def remove_header(headers: Headers, name: str | bytes) -> None:
    key = (name if isinstance(name, bytes) else name.encode()).lower()
    headers[:] = [(n, v) for n, v in headers if n.lower() != key]


def set_header(headers: Headers, name: str | bytes, value: str | bytes) -> None:
    """Replace the first occurrence in place, dropping any duplicates."""
    nb = name if isinstance(name, bytes) else name.encode()
    vb = value if isinstance(value, bytes) else str(value).encode()
    key = nb.lower()
    out: Headers = []
    done = False
    for n, v in headers:
        if n.lower() == key:
            if done:
                continue
            out.append((n, vb))
            done = True
        else:
            out.append((n, v))
    if not done:
        out.append((nb, vb))
    headers[:] = out


def _serialise(start_line: bytes, headers: Headers, body: bytes) -> bytes:
    parts = [start_line, CRLF]
    for name, value in headers:
        parts += [name, b": ", value, CRLF]
    parts += [CRLF, body]
    return b"".join(parts)


@dataclass
class Request:
    method: bytes
    target: bytes
    version: bytes
    headers: Headers = field(default_factory=list)
    body: bytes = b""

    @property
    def start_line(self) -> bytes:
        return b" ".join([self.method, self.target, self.version])

    @property
    def raw(self) -> bytes:
        return _serialise(self.start_line, self.headers, self.body)

    def header(self, name: str | bytes) -> bytes | None:
        return get_header(self.headers, name)

    @property
    def is_absolute_form(self) -> bool:
        low = self.target.lower()
        return low.startswith(b"http://") or low.startswith(b"https://")

    def authority(self) -> bytes | None:
        """Best-effort target authority, from the request target or Host header."""
        if self.is_absolute_form:
            rest = self.target.split(b"//", 1)[1]
            return rest.split(b"/", 1)[0]
        return self.header("host")

    def origin_form_target(self) -> bytes:
        """Strip scheme+authority so the target is suitable for an origin server."""
        if not self.is_absolute_form:
            return self.target
        rest = self.target.split(b"//", 1)[1]
        slash = rest.find(b"/")
        return rest[slash:] if slash != -1 else b"/"


@dataclass
class Response:
    version: bytes
    status: int
    reason: bytes
    headers: Headers = field(default_factory=list)
    body: bytes = b""

    @property
    def start_line(self) -> bytes:
        line = self.version + b" " + str(self.status).encode()
        return line + b" " + self.reason if self.reason else line

    @property
    def raw(self) -> bytes:
        return _serialise(self.start_line, self.headers, self.body)

    def header(self, name: str | bytes) -> bytes | None:
        return get_header(self.headers, name)


def parse_request(raw: bytes) -> Request:
    """Parse a complete raw request (head + body) as produced by an editor."""
    sep = raw.find(b"\r\n\r\n")
    seplen = 4
    if sep == -1:
        sep = raw.find(b"\n\n")
        seplen = 2
    if sep == -1:
        head, body = raw, b""
    else:
        head, body = raw[:sep], raw[sep + seplen:]
    lines = _split_head_lines(head)
    if not lines or not lines[0].strip():
        raise ParseError("empty request line")
    bits = lines[0].split()
    if len(bits) < 2:
        raise ParseError(f"malformed request line: {lines[0][:80]!r}")
    method, target = bits[0], bits[1]
    version = bits[2] if len(bits) > 2 else b"HTTP/1.1"
    return Request(method, target, version, _parse_headers(lines[1:]), body)


def parse_response(raw: bytes) -> Response:
    sep = raw.find(b"\r\n\r\n")
    seplen = 4
    if sep == -1:
        sep = raw.find(b"\n\n")
        seplen = 2
    if sep == -1:
        head, body = raw, b""
    else:
        head, body = raw[:sep], raw[sep + seplen:]
    lines = _split_head_lines(head)
    if not lines:
        raise ParseError("empty status line")
    bits = lines[0].split(None, 2)
    if len(bits) < 2:
        raise ParseError(f"malformed status line: {lines[0][:80]!r}")
    try:
        status = int(bits[1])
    except ValueError as exc:
        raise ParseError(f"bad status code: {bits[1]!r}") from exc
    reason = bits[2] if len(bits) > 2 else b""
    return Response(bits[0], status, reason, _parse_headers(lines[1:]), body)


# --------------------------------------------------------------------------
# Streaming readers
# --------------------------------------------------------------------------

async def read_head(reader: asyncio.StreamReader) -> bytes | None:
    """Read up to and including the blank line ending the head.

    Returns the head *without* its trailing blank line, or None on a clean EOF
    (which is how a keep-alive connection normally ends).
    """
    try:
        data = await reader.readuntil(b"\r\n\r\n")
        return data[:-4]
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return None
        # Some clients terminate the head with bare LFs.
        idx = exc.partial.find(b"\n\n")
        if idx != -1:
            return exc.partial[:idx]
        raise ParseError("connection closed mid-head")
    except asyncio.LimitOverrunError as exc:
        raise ParseError("head exceeds buffer limit") from exc


async def _read_chunked(reader: asyncio.StreamReader) -> bytes:
    out = bytearray()
    while True:
        line = await reader.readuntil(CRLF)
        token = line.strip().split(b";", 1)[0]
        try:
            size = int(token, 16)
        except ValueError as exc:
            raise ParseError(f"bad chunk size: {token[:40]!r}") from exc
        if size == 0:
            # Consume any trailers up to the terminating blank line.
            while True:
                trailer = await reader.readuntil(CRLF)
                if trailer == CRLF:
                    break
            return bytes(out)
        if len(out) + size > MAX_BODY:
            raise ParseError("chunked body too large")
        out += await reader.readexactly(size)
        await reader.readexactly(2)  # trailing CRLF


async def read_body(
    reader: asyncio.StreamReader,
    headers: Headers,
    *,
    is_response: bool,
    status: int | None = None,
    request_method: bytes | None = None,
) -> tuple[bytes, bool]:
    """Read a message body per RFC 9112 framing.

    Returns ``(body, was_chunked)``; the caller must fix up framing headers when
    ``was_chunked`` is true.
    """
    if is_response:
        # These responses never carry a body regardless of headers.
        if status is not None and (status // 100 == 1 or status in (204, 304)):
            return b"", False
        if request_method and request_method.upper() == b"HEAD":
            return b"", False

    te = get_header(headers, "transfer-encoding")
    if te and b"chunked" in te.lower():
        return await _read_chunked(reader), True

    cl = get_header(headers, "content-length")
    if cl is not None:
        try:
            length = int(cl.split(b",")[0].strip())
        except ValueError as exc:
            raise ParseError(f"bad Content-Length: {cl[:40]!r}") from exc
        if length < 0 or length > MAX_BODY:
            raise ParseError(f"unacceptable Content-Length: {length}")
        try:
            return await reader.readexactly(length), False
        except asyncio.IncompleteReadError as exc:
            return exc.partial, False

    if is_response:
        # No framing headers: the body runs to EOF.
        return await reader.read(-1), False
    return b"", False


def normalise_framing(headers: Headers, body: bytes, was_chunked: bool) -> None:
    """After de-chunking, replace chunked framing with an accurate length."""
    if was_chunked:
        remove_header(headers, "transfer-encoding")
        set_header(headers, "Content-Length", len(body))


def split_authority(authority: bytes | str, default_port: int) -> tuple[str, int]:
    """Split ``host:port`` (including bracketed IPv6) into its parts."""
    text = authority.decode("latin-1") if isinstance(authority, bytes) else authority
    text = text.strip()
    if text.startswith("["):
        end = text.find("]")
        host = text[1:end]
        rest = text[end + 1:]
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, default_port
    if ":" in text:
        host, _, port = text.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            return text, default_port
    return text, default_port


def build_url(tls: bool, host: str, port: int, target: bytes) -> str:
    scheme = "https" if tls else "http"
    path = target.decode("latin-1", "replace")
    if path.lower().startswith(("http://", "https://")):
        return path
    default = 443 if tls else 80
    hostpart = host if port == default else f"{host}:{port}"
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{hostpart}{path}"


def apply_header_rules(headers: Headers, rules, target: str) -> int:
    """Apply the project's header rules in order. Returns how many fired.

    Framing headers are refused at configuration time, so nothing here can
    desynchronise the message.
    """
    applied = 0
    for rule in rules:
        if not rule.enabled or rule.target != target:
            continue
        name = rule.name.strip()
        if not name:
            continue
        if rule.action == "remove":
            before = len(headers)
            remove_header(headers, name)
            if len(headers) != before:
                applied += 1
        elif rule.action == "add":
            # A second instance, for headers that legitimately repeat.
            headers.append((name.encode("latin-1", "replace"),
                            rule.value.encode("latin-1", "replace")))
            applied += 1
        else:  # set
            set_header(headers, name, rule.value.encode("latin-1", "replace"))
            applied += 1
    return applied
