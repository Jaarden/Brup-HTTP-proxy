"""HTTP/2 end to end: a real h2 client, through BRUP, to a real h2 origin."""
from __future__ import annotations

import asyncio
import base64
import ssl

import httpx
import pytest

from brup import http2
from brup.ca import CertificateAuthority
from brup.config import SettingsStore
from brup.db import Database
from brup.events import EventHub
from brup.projects import ProjectManager
from brup.proxy.interceptor import Interceptor
from brup.proxy.server import ProxyServer
from tests.h2server import H2Target


class Fixture:
    def __init__(self, projects, db, proxy, interceptor, ca, port, target):
        self.projects = projects
        self.db = db
        self.proxy = proxy
        self.interceptor = interceptor
        self.ca = ca
        self.port = port
        self.target = target

    async def set(self, **overrides):
        await self.projects.set_overrides(self.projects.active_id, overrides)

    async def flows(self, **kw):
        return await self.db.list_flows(self.projects.active_id, **kw)

    def client(self, *, http2_enabled=True):
        """An httpx client that proxies through BRUP and trusts its CA."""
        verify = ssl.create_default_context(cafile=self.ca_file)
        return httpx.AsyncClient(
            http2=http2_enabled,
            proxy=f"http://127.0.0.1:{self.port}",
            verify=verify,
            timeout=30,
        )


@pytest.fixture
async def fx(tmp_path):
    ca = CertificateAuthority(tmp_path / "ca")
    db = Database(tmp_path / "h2.sqlite3")
    store = SettingsStore(tmp_path / "s.json")
    store.settings.proxy_host = "127.0.0.1"
    store.settings.proxy_port = 0
    hub = EventHub()
    projects = ProjectManager(db, store, hub)
    await projects.load()
    interceptor = Interceptor(hub)
    proxy = ProxyServer(projects, ca, interceptor, hub, db)

    target = await H2Target().start(ca.context_for("localhost", http2=True))
    await proxy.start()
    port = proxy._servers[0].sockets[0].getsockname()[1]

    fixture = Fixture(projects, db, proxy, interceptor, ca, port, target)
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca.cert_pem())
    fixture.ca_file = str(ca_file)

    yield fixture
    await proxy.stop()
    await target.stop()
    db.close()


async def test_a_browser_speaking_h2_is_proxied_end_to_end(fx):
    async with fx.client() as client:
        response = await client.get(f"https://localhost:{fx.target.port}/hello")
    assert response.status_code == 200
    # The client really used HTTP/2, not a downgrade.
    assert response.http_version == "HTTP/2", response.http_version
    assert b"h2-saw:/hello" in response.content
    assert response.headers["x-served-by"] == "h2target"

    # And the origin saw HTTP/2 too, so it was h2 the whole way.
    seen, _ = fx.target.received[0]
    assert (b":method", b"GET") in seen
    assert (b":path", b"/hello") in seen


async def test_it_is_logged_as_h2(fx):
    async with fx.client() as client:
        await client.get(f"https://localhost:{fx.target.port}/logged")
    rows = (await fx.flows())["items"]
    assert len(rows) == 1
    assert rows[0]["protocol"] == "h2"
    assert rows[0]["status"] == 200
    assert rows[0]["url"].endswith("/logged")
    assert rows[0]["tls"] == 1

    detail = await fx.db.get_flow(fx.projects.active_id, rows[0]["id"])
    # History stores the editable HTTP/2 form, pseudo-headers included.
    assert detail["raw_request"].startswith(b"GET /logged HTTP/2")
    assert b":authority: localhost:" in detail["raw_request"]
    assert detail["raw_response"].startswith(b"HTTP/2 200 OK")


async def test_a_post_body_survives_both_directions(fx):
    payload = b'{"user":"admin","pass":"hunter2"}'
    async with fx.client() as client:
        response = await client.post(
            f"https://localhost:{fx.target.port}/login", content=payload,
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 200
    assert payload in response.content
    assert fx.target.received[0][1] == payload


async def test_concurrent_streams_are_multiplexed(fx):
    """Several requests on one connection, which is the point of HTTP/2."""
    async with fx.client() as client:
        responses = await asyncio.gather(*[
            client.get(f"https://localhost:{fx.target.port}/s{i}") for i in range(10)
        ])
    assert [r.status_code for r in responses] == [200] * 10
    assert all(r.http_version == "HTTP/2" for r in responses)
    paths = sorted(
        http2.get(headers, b":path") for headers, _ in fx.target.received
    )
    assert paths == sorted(f"/s{i}".encode() for i in range(10))
    assert (await fx.flows())["total"] == 10


async def test_a_large_response_crosses_the_flow_control_window(fx):
    async with fx.client() as client:
        response = await client.get(f"https://localhost:{fx.target.port}/big")
    assert response.status_code == 200
    assert len(response.content) == 200_000


async def test_header_rules_apply_to_h2(fx):
    await fx.set(header_rules=[
        {"enabled": True, "target": "request", "action": "set",
         "name": "x-forwarded-for", "value": "203.0.113.9"},
        {"enabled": True, "target": "response", "action": "remove",
         "name": "x-served-by", "value": ""},
    ])
    async with fx.client() as client:
        response = await client.get(f"https://localhost:{fx.target.port}/rules")

    seen, _ = fx.target.received[0]
    assert (b"x-forwarded-for", b"203.0.113.9") in seen
    assert "x-served-by" not in response.headers


async def test_interception_can_edit_an_h2_request(fx):
    await fx.set(intercept_enabled=True, intercept_requests=True)

    async with fx.client() as client:
        task = asyncio.create_task(
            client.get(f"https://localhost:{fx.target.port}/original"))
        for _ in range(200):
            if fx.interceptor.pending_count:
                break
            await asyncio.sleep(0.02)
        assert fx.interceptor.pending_count == 1

        item = fx.interceptor.list_pending()[0]
        held = base64.b64decode(item["raw_b64"])
        # The operator sees the HTTP/2 form.
        assert held.startswith(b"GET /original HTTP/2")
        assert b":authority: localhost:" in held

        edited = held.replace(b"/original", b"/edited")
        assert fx.interceptor.forward(item["id"], edited)
        response = await task

    assert b"h2-saw:/edited" in response.content
    assert http2.get(fx.target.received[0][0], b":path") == b"/edited"
    row = (await fx.flows())["items"][0]
    assert row["was_edited"] == 1
    assert row["url"].endswith("/edited")


async def test_dropping_an_h2_request_resets_the_stream(fx):
    await fx.set(intercept_enabled=True, intercept_requests=True)
    async with fx.client() as client:
        task = asyncio.create_task(
            client.get(f"https://localhost:{fx.target.port}/dropped"))
        for _ in range(200):
            if fx.interceptor.pending_count:
                break
            await asyncio.sleep(0.02)
        assert fx.interceptor.drop_all() == 1
        with pytest.raises(httpx.HTTPError):
            await task
    assert fx.target.received == [], "a dropped request reached the origin"


async def test_a_client_that_prefers_http1_still_works(fx):
    """ALPN offers both; nothing forces a browser onto HTTP/2."""
    from tests.test_proxy import Target
    h1_target = await Target().start(ssl_context=fx.ca.context_for("localhost"))
    try:
        async with fx.client(http2_enabled=False) as client:
            response = await client.get(f"https://localhost:{h1_target.port}/plain")
        assert response.status_code == 200
        assert response.http_version == "HTTP/1.1"
        assert b"target-saw:/plain" in response.content
        assert (await fx.flows())["items"][0]["protocol"] == "http/1.1"
    finally:
        await h1_target.stop()


async def test_h2_client_to_an_http1_origin_is_bridged(fx):
    """The common real case: browser speaks h2, the server does not."""
    from tests.test_proxy import Target
    h1_target = await Target().start(ssl_context=fx.ca.context_for("localhost"))
    try:
        async with fx.client() as client:
            response = await client.get(f"https://localhost:{h1_target.port}/bridged")
        assert response.http_version == "HTTP/2"      # to the client
        assert response.status_code == 200
        assert b"target-saw:/bridged" in response.content
        # The origin was spoken to in HTTP/1.1, and history records that.
        assert h1_target.received[0].startswith(b"GET /bridged HTTP/1.1")
        assert (await fx.flows())["items"][0]["protocol"] == "http/1.1"
    finally:
        await h1_target.stop()


async def test_listen_http2_off_keeps_clients_on_http1(fx):
    from tests.test_proxy import Target
    h1_target = await Target().start(ssl_context=fx.ca.context_for("localhost"))
    try:
        # A listener property, so it lives in the system tier.
        await fx.projects.update_system({"listen_http2": False})
        async with fx.client() as client:
            response = await client.get(f"https://localhost:{h1_target.port}/nope")
        assert response.http_version == "HTTP/1.1"
        assert response.status_code == 200
    finally:
        await h1_target.stop()


async def test_an_unreachable_origin_returns_an_h2_error_page(fx):
    async with fx.client() as client:
        response = await client.get("https://127.0.0.1:1/dead")
    assert response.status_code == 502
    assert response.http_version == "HTTP/2"
    assert b"BRUP could not reach" in response.content


async def test_the_vpn_killswitch_covers_h2(fx):
    from brup.vpn import VpnManager
    manager = VpnManager(fx.db, fx.projects.system, EventHub())
    fx.proxy.vpn = manager
    await fx.projects.update_system({"vpn_required": True})
    try:
        async with fx.client() as client:
            response = await client.get(f"https://localhost:{fx.target.port}/blocked")
        assert response.status_code == 502
        assert b"kill switch" in response.content
        assert fx.target.received == [], "HTTP/2 leaked past the kill switch"
    finally:
        await fx.projects.update_system({"vpn_required": False})


# ----------------------------------------------------------------- Repeater

@pytest.fixture
async def api_client(fx):
    """The HTTP API, temporarily pointed at this test's own instances.

    The app builds its singletons at import time and other test modules share
    them, so every attribute this swaps has to be put back - otherwise later
    tests find a database that has been closed underneath them.
    """
    import brup.main as main
    from httpx import ASGITransport

    swapped = {
        "db": fx.db,
        "projects": fx.projects,
        "ca": fx.ca,
        "proxy": fx.proxy,
        "interceptor": fx.interceptor,
    }
    original = {name: getattr(main.state, name) for name in swapped}
    for name, value in swapped.items():
        setattr(main.state, name, value)
    try:
        async with httpx.AsyncClient(
            transport=ASGITransport(app=main.app), base_url="http://t"
        ) as c:
            yield c
    finally:
        for name, value in original.items():
            setattr(main.state, name, value)


async def test_repeater_sends_http2(fx, api_client):
    raw = (f"GET /repeated HTTP/2\r\n"
           f":authority: localhost:{fx.target.port}\r\n"
           f":scheme: https\r\n"
           f"accept: */*\r\n\r\n").encode()
    response = await api_client.post("/api/repeater/send", json={
        "host": "localhost", "port": fx.target.port, "tls": True,
        "raw_b64": base64.b64encode(raw).decode(),
        "update_content_length": False, "log": True,
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True, body["error"]
    assert body["protocol"] == "h2"
    assert body["status"] == 200
    decoded = base64.b64decode(body["raw_response_b64"])
    assert decoded.startswith(b"HTTP/2 200 OK")
    assert b"h2-saw:/repeated" in decoded
    assert http2.get(fx.target.received[0][0], b":path") == b"/repeated"

    row = (await fx.flows(source="repeater"))["items"][0]
    assert row["protocol"] == "h2"


async def test_repeater_sends_an_http2_body(fx, api_client):
    raw = (f"POST /post HTTP/2\r\n"
           f":authority: localhost:{fx.target.port}\r\n"
           f":scheme: https\r\n"
           f"content-type: application/json\r\n\r\n"
           f'{{"a":1}}').encode()
    response = await api_client.post("/api/repeater/send", json={
        "host": "localhost", "port": fx.target.port, "tls": True,
        "raw_b64": base64.b64encode(raw).decode(),
        "update_content_length": False, "log": True,
    })
    body = response.json()
    assert body["ok"] is True, body["error"]
    assert fx.target.received[0][1] == b'{"a":1}'


async def test_repeater_refuses_http2_without_tls(fx, api_client):
    raw = b"GET / HTTP/2\r\n:authority: localhost\r\n\r\n"
    response = await api_client.post("/api/repeater/send", json={
        "host": "localhost", "port": 80, "tls": False,
        "raw_b64": base64.b64encode(raw).decode(),
        "update_content_length": False, "log": False,
    })
    assert response.status_code == 400
    assert "needs TLS" in response.json()["detail"]


async def test_repeater_reports_an_unusable_http2_request(fx, api_client):
    raw = b"GET / HTTP/2\r\naccept: */*\r\n\r\n"        # no :authority
    response = await api_client.post("/api/repeater/send", json={
        "host": "localhost", "port": fx.target.port, "tls": True,
        "raw_b64": base64.b64encode(raw).decode(),
        "update_content_length": False, "log": False,
    })
    assert response.status_code == 400
    assert ":authority" in response.json()["detail"]


async def test_repeater_still_sends_http1(fx, api_client):
    from tests.test_proxy import Target
    h1 = await Target().start()
    try:
        raw = (f"GET /plain HTTP/1.1\r\nHost: 127.0.0.1:{h1.port}\r\n"
               f"Connection: close\r\n\r\n").encode()
        response = await api_client.post("/api/repeater/send", json={
            "host": "127.0.0.1", "port": h1.port, "tls": False,
            "raw_b64": base64.b64encode(raw).decode(),
            "update_content_length": False, "log": True,
        })
        body = response.json()
        assert body["ok"] is True, body["error"]
        assert body["protocol"] == "http/1.1"
        assert b"target-saw:/plain" in base64.b64decode(body["raw_response_b64"])
    finally:
        await h1.stop()


# ----------------------------------------------------------------- Intruder

async def test_intruder_attacks_over_http2(fx):
    """A template written in the HTTP/2 form is sent as HTTP/2."""
    from brup.events import EventHub as Hub
    from brup.intruder import AttackConfig, AttackManager, PayloadSet

    manager = AttackManager(fx.projects, fx.db, Hub())
    template = (f"GET /§index§ HTTP/2\r\n"
                f":authority: localhost:{fx.target.port}\r\n"
                f":scheme: https\r\n\r\n").encode("latin-1")
    attack = await manager.start(AttackConfig(
        host="localhost", port=fx.target.port, tls=True,
        template_b64=base64.b64encode(template).decode(),
        attack_type="battering_ram",
        payload_sets=[PayloadSet(kind="list", payloads=["one", "two", "three"])],
        concurrency=2, grep_match=["h2-saw"], url_encode_payloads=False,
    ))
    for _ in range(300):
        if attack.status in ("finished", "error", "stopped"):
            break
        await asyncio.sleep(0.05)
    assert attack.status == "finished", attack.message
    assert attack.completed == 3
    assert attack.errors == 0

    rows = await fx.db.list_results(attack.id)
    assert sorted(r["status"] for r in rows) == [200, 200, 200]
    assert all("h2-saw" in (r["grep_hits"] or "") for r in rows)

    # The origin really saw three HTTP/2 requests with the substituted paths.
    paths = sorted(http2.get(h, b":path") for h, _ in fx.target.received)
    assert paths == [b"/one", b"/three", b"/two"]

    detail = await fx.db.get_result(attack.id, 0)
    assert detail["raw_request"].startswith(b"GET /one HTTP/2")
    assert detail["raw_response"].startswith(b"HTTP/2 200 OK")


async def test_intruder_still_attacks_over_http1(fx):
    from brup.events import EventHub as Hub
    from brup.intruder import AttackConfig, AttackManager, PayloadSet
    from tests.test_proxy import Target

    h1 = await Target().start()
    try:
        manager = AttackManager(fx.projects, fx.db, Hub())
        template = (f"GET /§x§ HTTP/1.1\r\nHost: 127.0.0.1:{h1.port}\r\n"
                    "Connection: close\r\n\r\n").encode("latin-1")
        attack = await manager.start(AttackConfig(
            host="127.0.0.1", port=h1.port, tls=False,
            template_b64=base64.b64encode(template).decode(),
            attack_type="battering_ram",
            payload_sets=[PayloadSet(kind="list", payloads=["a", "b"])],
            concurrency=1, url_encode_payloads=False,
        ))
        for _ in range(300):
            if attack.status in ("finished", "error", "stopped"):
                break
            await asyncio.sleep(0.05)
        assert attack.status == "finished", attack.message
        rows = await fx.db.list_results(attack.id)
        assert [r["status"] for r in rows] == [200, 200]
        assert (await fx.db.get_result(attack.id, 0))["raw_response"].startswith(
            b"HTTP/1.1 200 OK")
    finally:
        await h1.stop()


async def test_server_push_is_refused_on_the_wire(fx):
    """The SETTINGS we actually emit must advertise ENABLE_PUSH=0.

    Asserted against the emitted bytes rather than ``local_settings``: assigning
    to that attribute is silently ignored, so an attribute check would pass
    while the wire still advertised push.
    """
    import h2.settings
    from brup.proxy.h2_client import H2Exchange

    sent: list[bytes] = []

    class FakeWriter:
        def write(self, data):
            sent.append(data)

        async def drain(self):
            pass

    exchange = H2Exchange(None, FakeWriter())
    exchange.conn.initiate_connection()
    exchange.conn.update_settings(
        {h2.settings.SettingCodes.ENABLE_PUSH: 0})
    await exchange._flush()

    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    data = b"".join(sent)
    assert data.startswith(preface)

    # Walk the frames and collect every ENABLE_PUSH value advertised.
    values = []
    rest = data[len(preface):]
    while len(rest) >= 9:
        length = int.from_bytes(rest[0:3], "big")
        frame_type = rest[3]
        payload = rest[9:9 + length]
        if frame_type == 0x4:      # SETTINGS
            for i in range(0, len(payload), 6):
                ident = int.from_bytes(payload[i:i + 2], "big")
                value = int.from_bytes(payload[i + 2:i + 6], "big")
                if ident == h2.settings.SettingCodes.ENABLE_PUSH:
                    values.append(value)
        rest = rest[9 + length:]

    assert values, "no ENABLE_PUSH setting was advertised at all"
    assert values[-1] == 0, f"push not disabled; advertised {values}"
