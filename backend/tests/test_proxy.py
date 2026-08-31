"""End-to-end exercises for the proxy, interceptor and intruder engine."""
from __future__ import annotations

import asyncio
import base64
import ssl
import tempfile
from pathlib import Path

import pytest

from brup import http_message as hm
from brup.ca import CertificateAuthority
from brup.config import ScopeRule, Settings, SettingsStore, should_intercept
from brup.db import Database
from brup.events import EventHub
from brup.intruder import (
    AttackConfig, PayloadRule, PayloadSet, apply_rules, build_request,
    count_jobs, fix_content_length, generate_jobs, parse_positions,
)
from brup.projects import ProjectManager
from brup.proxy.interceptor import Interceptor
from brup.proxy.server import ProxyServer
from brup.proxy.upstream import send_request


# ---------------------------------------------------------------- fixtures

class Target:
    """A tiny origin server that reports back what it received."""

    def __init__(self):
        self.received: list[bytes] = []
        self.server = None
        self.port = 0

    async def start(self, ssl_context=None):
        self.server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0, ssl=ssl_context
        )
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            while True:
                head = await hm.read_head(reader)
                if head is None:
                    return
                req = hm.parse_request(head + b"\r\n\r\n")
                body, chunked = await hm.read_body(reader, req.headers, is_response=False)
                req.body = body
                self.received.append(req.raw)

                if req.target == b"/chunked":
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                        b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
                    )
                elif req.target.startswith(b"/status/"):
                    code = int(req.target.rsplit(b"/", 1)[1])
                    writer.write(
                        f"HTTP/1.1 {code} Custom\r\nContent-Length: 2\r\n\r\nok".encode()
                    )
                else:
                    payload = b"target-saw:" + req.target + b"|body:" + body
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                        b"Content-Length: " + str(len(payload)).encode()
                        + b"\r\n\r\n" + payload
                    )
                await writer.drain()
                if b"close" in (req.header("connection") or b"").lower():
                    return
        except (hm.ParseError, ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except OSError:
                pass


@pytest.fixture
async def tmpstate(tmp_path):
    store = SettingsStore(tmp_path / "settings.json")
    store.settings.proxy_host = "127.0.0.1"
    store.settings.proxy_port = 0  # ephemeral
    ca = CertificateAuthority(tmp_path / "ca")
    db = Database(tmp_path / "t.sqlite3")
    hub = EventHub()
    projects = ProjectManager(db, store, hub)
    await projects.load()
    interceptor = Interceptor(hub)
    proxy = ProxyServer(projects, ca, interceptor, hub, db)
    yield Ctx(store, ca, db, hub, interceptor, proxy, projects)
    db.close()


class Ctx:
    """Bundle of the pieces a proxy test needs, so tests read by name."""

    def __init__(self, store, ca, db, hub, interceptor, proxy, projects):
        self.store = store
        self.ca = ca
        self.db = db
        self.hub = hub
        self.interceptor = interceptor
        self.proxy = proxy
        self.projects = projects

    @property
    def pid(self):
        return self.projects.active_id

    async def flows(self, **kw):
        return await self.db.list_flows(self.pid, **kw)

    async def set(self, **overrides):
        """Change behaviour the way the API does: as project overrides."""
        await self.projects.set_overrides(self.pid, overrides)

    def __iter__(self):
        # Keeps the older tuple-unpacking call sites working.
        return iter((self.store, self.ca, self.db, self.hub,
                     self.interceptor, self.proxy))


async def _start(proxy):
    await proxy.start()
    return proxy._servers[0].sockets[0].getsockname()[1]


async def raw_exchange(port: int, payload: bytes, *, read_all=True) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    try:
        data = await asyncio.wait_for(reader.read(-1) if read_all else reader.read(65536), 10)
    finally:
        writer.close()
    return data


# ------------------------------------------------------------------- tests

async def test_parse_and_roundtrip_preserves_bytes():
    raw = (b"POST /a?b=1 HTTP/1.1\r\nHost: x.test\r\nX-Odd-Case: Yes\r\n"
           b"Content-Length: 4\r\n\r\nbody")
    req = hm.parse_request(raw)
    assert req.method == b"POST"
    assert req.header("x-odd-case") == b"Yes"
    assert req.body == b"body"
    assert req.raw == raw  # byte-for-byte, header casing intact


async def test_absolute_form_proxying(tmpstate):
    ctx = tmpstate
    store, db, proxy = ctx.store, ctx.db, ctx.proxy
    target = await Target().start()
    port = await _start(proxy)
    try:
        resp = await raw_exchange(port, (
            f"GET http://127.0.0.1:{target.port}/hello HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{target.port}\r\nConnection: close\r\n\r\n"
        ).encode())
        assert b"200 OK" in resp
        assert b"target-saw:/hello" in resp
        # The origin server must receive an origin-form target.
        assert target.received[0].startswith(b"GET /hello HTTP/1.1")

        flows = await ctx.flows(limit=10)
        assert flows["total"] == 1
        assert flows["items"][0]["status"] == 200
        assert flows["items"][0]["host"] == "127.0.0.1"
    finally:
        await proxy.stop()
        await target.stop()


async def test_invisible_proxy_origin_form(tmpstate):
    ctx = tmpstate
    store, proxy = ctx.store, ctx.proxy
    target = await Target().start()
    port = await _start(proxy)
    try:
        request = (f"GET /invisible HTTP/1.1\r\nHost: 127.0.0.1:{target.port}\r\n"
                   f"Connection: close\r\n\r\n").encode()

        # Off by default: BRUP cannot know where this is headed.
        await ctx.set(invisible_proxy=False)
        resp = await raw_exchange(port, request)
        assert b"400 Bad Request" in resp

        await ctx.set(invisible_proxy=True)
        resp = await raw_exchange(port, request)
        assert b"200 OK" in resp
        assert b"target-saw:/invisible" in resp
    finally:
        await proxy.stop()
        await target.stop()


async def test_intercept_forward_with_edit(tmpstate):
    ctx = tmpstate
    store, db, interceptor, proxy = ctx.store, ctx.db, ctx.interceptor, ctx.proxy
    target = await Target().start()
    port = await _start(proxy)
    await ctx.set(intercept_enabled=True, intercept_requests=True)
    try:
        task = asyncio.create_task(raw_exchange(port, (
            f"GET http://127.0.0.1:{target.port}/original HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{target.port}\r\nConnection: close\r\n\r\n"
        ).encode()))

        # Wait for the request to be held.
        for _ in range(100):
            if interceptor.pending_count:
                break
            await asyncio.sleep(0.02)
        assert interceptor.pending_count == 1

        item = interceptor.list_pending()[0]
        assert item["kind"] == "request"
        edited = base64.b64decode(item["raw_b64"]).replace(b"/original", b"/edited")
        assert interceptor.forward(item["id"], edited)

        resp = await task
        assert b"target-saw:/edited" in resp
        flows = await ctx.flows(limit=5)
        assert flows["items"][0]["was_edited"] == 1
    finally:
        await proxy.stop()
        await target.stop()


async def test_intercept_drop(tmpstate):
    ctx = tmpstate
    store, interceptor, proxy = ctx.store, ctx.interceptor, ctx.proxy
    target = await Target().start()
    port = await _start(proxy)
    await ctx.set(intercept_enabled=True)
    try:
        task = asyncio.create_task(raw_exchange(port, (
            f"GET http://127.0.0.1:{target.port}/nope HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{target.port}\r\n\r\n"
        ).encode()))
        for _ in range(100):
            if interceptor.pending_count:
                break
            await asyncio.sleep(0.02)
        assert interceptor.drop_all() == 1
        assert await task == b""          # connection closed, nothing forwarded
        assert target.received == []      # the origin never saw it
    finally:
        await proxy.stop()
        await target.stop()


async def test_https_connect_mitm(tmpstate):
    ctx = tmpstate
    store, ca, db, proxy = ctx.store, ctx.ca, ctx.db, ctx.proxy
    # Serve TLS using a cert minted by our own CA so the client can verify it.
    server_ctx = ca.context_for("localhost")
    target = await Target().start(ssl_context=server_ctx)
    port = await _start(proxy)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(f"CONNECT localhost:{target.port} HTTP/1.1\r\n"
                     f"Host: localhost:{target.port}\r\n\r\n".encode())
        await writer.drain()
        head = await asyncio.wait_for(hm.read_head(reader), 10)
        assert b"200" in head.split(b"\r\n")[0]

        # Trust BRUP's CA, exactly as a browser would after installing it.
        client_ctx = ssl.create_default_context()
        with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as fh:
            fh.write(ca.cert_pem())
            ca_file = fh.name
        client_ctx.load_verify_locations(ca_file)

        from brup.netutil import upgrade_to_tls
        await upgrade_to_tls(reader, writer, client_ctx,
                             server_side=False, server_hostname="localhost")

        writer.write(b"GET /secure HTTP/1.1\r\nHost: localhost\r\n"
                     b"Connection: close\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(-1), 10)
        assert b"target-saw:/secure" in data
        writer.close()

        flows = await ctx.flows(limit=5)
        assert flows["items"][0]["tls"] == 1
        assert flows["items"][0]["url"].startswith("https://localhost")
        Path(ca_file).unlink()
    finally:
        await proxy.stop()
        await target.stop()


async def test_chunked_response_is_dechunked(tmpstate):
    ctx = tmpstate
    store, proxy = ctx.store, ctx.proxy
    target = await Target().start()
    port = await _start(proxy)
    try:
        resp = await raw_exchange(port, (
            f"GET http://127.0.0.1:{target.port}/chunked HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{target.port}\r\nConnection: close\r\n\r\n"
        ).encode())
        assert b"hello world" in resp
        assert b"Content-Length: 11" in resp
        assert b"chunked" not in resp.lower()
    finally:
        await proxy.stop()
        await target.stop()


async def test_keep_alive_two_requests(tmpstate):
    ctx = tmpstate
    store, db, proxy = ctx.store, ctx.db, ctx.proxy
    target = await Target().start()
    port = await _start(proxy)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        for path in ("/one", "/two"):
            writer.write((
                f"GET http://127.0.0.1:{target.port}{path} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target.port}\r\n\r\n"
            ).encode())
            await writer.drain()
            head = await asyncio.wait_for(hm.read_head(reader), 10)
            resp = hm.parse_response(head + b"\r\n\r\n")
            body, _ = await hm.read_body(
                reader, resp.headers, is_response=True, status=resp.status,
                request_method=b"GET",
            )
            assert body == f"target-saw:{path}|body:".encode()
        writer.close()
        assert (await ctx.flows(limit=5))["total"] == 2
    finally:
        await proxy.stop()
        await target.stop()


async def test_upstream_error_becomes_502(tmpstate):
    ctx = tmpstate
    store, proxy = ctx.store, ctx.proxy
    await ctx.set(connect_timeout=2)
    port = await _start(proxy)
    try:
        resp = await raw_exchange(port, (
            b"GET http://127.0.0.1:1/dead HTTP/1.1\r\n"
            b"Host: 127.0.0.1:1\r\nConnection: close\r\n\r\n"
        ))
        assert b"502 Bad Gateway" in resp
    finally:
        await proxy.stop()


async def test_scope_and_intercept_filters():
    s = Settings(intercept_enabled=True)
    s.scope_include = [ScopeRule(pattern=r"^https?://target\.test")]
    assert should_intercept(s, "http://target.test/app")
    assert not should_intercept(s, "http://other.test/app")
    # Static assets are skipped by default even when in scope.
    assert not should_intercept(s, "http://target.test/main.css")
    assert should_intercept(s, "http://target.test/a.php")


# --------------------------------------------------------- intruder engine

def test_position_parsing_and_build():
    literals, bases = parse_positions(b"GET /u=\xa7admin\xa7&p=\xa7pw\xa7 HTTP/1.1")
    assert bases == [b"admin", b"pw"]
    assert build_request(literals, [b"root", b"toor"]) == b"GET /u=root&p=toor HTTP/1.1"

    with pytest.raises(Exception):
        parse_positions(b"a\xa7b")  # unbalanced


def test_attack_type_counts_and_shapes():
    bases = [b"A", b"B"]
    sets = [["1", "2", "3"], ["x", "y"]]

    def run(kind, limit=1000):
        return [
            (j.display, j.values)
            for j in generate_jobs(kind, bases, sets, url_encode=False, limit=limit)
        ]

    sniper = run("sniper")
    assert len(sniper) == 6 == count_jobs("sniper", 2, sets)
    # Position 0 varies while position 1 keeps its base value.
    assert sniper[0][1] == [b"1", b"B"]
    assert sniper[3][1] == [b"A", b"1"]

    ram = run("battering_ram")
    assert len(ram) == 3 == count_jobs("battering_ram", 2, sets)
    assert ram[0][1] == [b"1", b"1"]  # same payload in every position

    fork = run("pitchfork")
    assert len(fork) == 2 == count_jobs("pitchfork", 2, sets)
    assert fork[1][1] == [b"2", b"y"]

    bomb = run("cluster_bomb")
    assert len(bomb) == 6 == count_jobs("cluster_bomb", 2, sets)
    assert bomb[0][1] == [b"1", b"x"]
    assert bomb[5][1] == [b"3", b"y"]


def test_url_encoding_and_limit():
    jobs = list(generate_jobs(
        "battering_ram", [b"x"], [["a b&c=d"]], url_encode=True, limit=10
    ))
    assert jobs[0].values == [b"a%20b%26c%3Dd"]
    assert len(list(generate_jobs(
        "sniper", [b"x"], [[str(i) for i in range(100)]], url_encode=False, limit=7
    ))) == 7


def test_content_length_is_recalculated():
    raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nX: y\r\n\r\nlonger-body"
    fixed = fix_content_length(raw)
    assert b"Content-Length: 11" in fixed
    assert b"X: y" in fixed          # everything else untouched
    assert fixed.endswith(b"longer-body")


def test_payload_rules_and_sets():
    assert apply_rules("ab", [PayloadRule(kind="upper"), PayloadRule(kind="suffix", value="!")]) == "AB!"
    assert apply_rules("a b", [PayloadRule(kind="url_encode")]) == "a%20b"
    assert apply_rules("abc", [PayloadRule(kind="md5")]) == "900150983cd24fb0d6963f7d28e17f72"

    assert PayloadSet(kind="numbers", number_from=1, number_to=5, number_step=2).values() == ["1", "3", "5"]
    assert len(PayloadSet(kind="brute", charset="ab", min_length=1, max_length=2).values()) == 6
    assert PayloadSet(kind="list", payloads=["a", "", "b"]).values() == ["a", "b"]


async def test_intruder_end_to_end(tmpstate):
    ctx = tmpstate
    store, db, hub = ctx.store, ctx.db, ctx.hub
    from brup.intruder import AttackManager
    target = await Target().start()
    manager = AttackManager(ctx.projects, db, hub)

    template = (f"GET /status/\xa7200\xa7 HTTP/1.1\r\nHost: 127.0.0.1:{target.port}\r\n"
                "Connection: close\r\n\r\n").encode("latin-1")
    config = AttackConfig(
        host="127.0.0.1", port=target.port, tls=False,
        template_b64=base64.b64encode(template).decode(),
        attack_type="battering_ram",
        payload_sets=[PayloadSet(kind="list", payloads=["200", "404", "500"])],
        concurrency=3, grep_match=["Custom"],
    )
    try:
        preview = await manager.preview(config)
        assert preview["positions"] == 1 and preview["total"] == 3

        attack = await manager.start(config)
        for _ in range(200):
            if attack.status in ("finished", "error", "stopped"):
                break
            await asyncio.sleep(0.05)
        assert attack.status == "finished", attack.message
        assert attack.completed == 3

        rows = await db.list_results(attack.id)
        assert sorted(r["status"] for r in rows) == [200, 404, 500]
        assert all("Custom" in r["grep_hits"] for r in rows)
    finally:
        await target.stop()


async def test_repeater_style_send(tmpstate):
    ctx = tmpstate
    store = ctx.store
    target = await Target().start()
    try:
        raw = (f"GET /repeat HTTP/1.1\r\nHost: 127.0.0.1:{target.port}\r\n"
               "Connection: close\r\n\r\n").encode()
        result = await send_request("127.0.0.1", target.port, False, raw, store.settings)
        assert result.ok and result.response.status == 200
        assert b"target-saw:/repeat" in result.raw_response
        assert result.duration_ms > 0
    finally:
        await target.stop()


async def test_connect_target_wins_over_host_header(tmpstate):
    """A spoofed Host header must not redirect a CONNECT-tunnelled request."""
    ctx = tmpstate
    store, ca, db, proxy = ctx.store, ctx.ca, ctx.db, ctx.proxy
    real = await Target().start(ssl_context=ca.context_for("localhost"))
    port = await _start(proxy)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(f"CONNECT localhost:{real.port} HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        await asyncio.wait_for(hm.read_head(reader), 10)

        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE
        from brup.netutil import upgrade_to_tls
        await upgrade_to_tls(reader, writer, client_ctx,
                             server_side=False, server_hostname="localhost")

        # Claim a completely different destination in the Host header.
        writer.write(b"GET /probe HTTP/1.1\r\nHost: evil.example:9\r\n"
                     b"Connection: close\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(-1), 10)
        writer.close()

        assert b"target-saw:/probe" in data      # went to the CONNECT target
        flows = await ctx.flows(limit=5)
        assert flows["items"][0]["host"] == "localhost"
        assert "evil.example" not in (flows["items"][0]["url"] or "")
    finally:
        await proxy.stop()
        await real.stop()


async def test_edited_request_is_logged_with_its_new_url(tmpstate):
    ctx = tmpstate
    store, db, interceptor, proxy = ctx.store, ctx.db, ctx.interceptor, ctx.proxy
    target = await Target().start()
    port = await _start(proxy)
    await ctx.set(intercept_enabled=True)
    try:
        task = asyncio.create_task(raw_exchange(port, (
            f"GET http://127.0.0.1:{target.port}/before HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{target.port}\r\nConnection: close\r\n\r\n"
        ).encode()))
        for _ in range(100):
            if interceptor.pending_count:
                break
            await asyncio.sleep(0.02)
        item = interceptor.list_pending()[0]
        edited = base64.b64decode(item["raw_b64"]).replace(b"/before", b"/after")
        interceptor.forward(item["id"], edited)
        await task

        row = (await ctx.flows(limit=1))["items"][0]
        assert row["url"].endswith("/after"), row["url"]
        assert row["target"] == f"http://127.0.0.1:{target.port}/after"
    finally:
        await proxy.stop()
        await target.stop()
