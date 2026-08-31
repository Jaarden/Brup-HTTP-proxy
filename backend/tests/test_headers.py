"""Project header-rewriting rules."""
from __future__ import annotations

import os
import tempfile

import pytest

os.environ.setdefault("BRUP_DATA_DIR", tempfile.mkdtemp(prefix="brup-hdrtest-"))

import httpx  # noqa: E402
from httpx import ASGITransport  # noqa: E402

from brup import http_message as hm  # noqa: E402
from brup.ca import CertificateAuthority  # noqa: E402
from brup.config import (  # noqa: E402
    HeaderRule, SettingsStore, validate_header_rules,
)
from brup.db import Database  # noqa: E402
from brup.events import EventHub  # noqa: E402
from brup.projects import ProjectManager  # noqa: E402
from brup.proxy.interceptor import Interceptor  # noqa: E402
from brup.proxy.server import ProxyServer  # noqa: E402


def headers_of(raw: bytes) -> list[tuple[bytes, bytes]]:
    return hm.parse_request(raw).headers


# ------------------------------------------------------------ rule engine

def test_set_replaces_or_adds():
    headers = [(b"Host", b"a.test"), (b"User-Agent", b"curl")]
    hm.apply_header_rules(headers, [
        HeaderRule(name="X-Forwarded-For", value="127.0.0.1"),
        HeaderRule(name="User-Agent", value="BRUP"),
    ], "request")
    assert hm.get_header(headers, "x-forwarded-for") == b"127.0.0.1"
    assert hm.get_header(headers, "user-agent") == b"BRUP"
    # Replacing does not duplicate.
    assert len(hm.get_all_headers(headers, "user-agent")) == 1


def test_set_collapses_existing_duplicates():
    headers = [(b"X-Real-IP", b"1.1.1.1"), (b"X-Real-IP", b"2.2.2.2")]
    hm.apply_header_rules(headers, [HeaderRule(name="X-Real-IP", value="9.9.9.9")], "request")
    assert hm.get_all_headers(headers, "x-real-ip") == [b"9.9.9.9"]


def test_add_appends_another_instance():
    headers = [(b"Cookie", b"a=1")]
    hm.apply_header_rules(headers, [
        HeaderRule(action="add", name="Cookie", value="b=2"),
    ], "request")
    assert hm.get_all_headers(headers, "cookie") == [b"a=1", b"b=2"]


def test_remove_deletes_every_instance():
    headers = [(b"X-Debug", b"1"), (b"Host", b"a.test"), (b"X-Debug", b"2")]
    applied = hm.apply_header_rules(headers, [
        HeaderRule(action="remove", name="X-Debug"),
    ], "request")
    assert applied == 1
    assert hm.get_all_headers(headers, "x-debug") == []
    assert hm.get_header(headers, "host") == b"a.test"


def test_remove_of_an_absent_header_does_nothing():
    headers = [(b"Host", b"a.test")]
    assert hm.apply_header_rules(
        headers, [HeaderRule(action="remove", name="X-Nope")], "request"
    ) == 0
    assert headers == [(b"Host", b"a.test")]


def test_rules_are_applied_in_order():
    headers: list[tuple[bytes, bytes]] = []
    hm.apply_header_rules(headers, [
        HeaderRule(name="X-Chain", value="first"),
        HeaderRule(name="X-Chain", value="second"),
    ], "request")
    assert hm.get_header(headers, "x-chain") == b"second"


def test_disabled_and_wrong_target_rules_are_skipped():
    headers = [(b"Host", b"a.test")]
    hm.apply_header_rules(headers, [
        HeaderRule(name="X-Off", value="1", enabled=False),
        HeaderRule(name="X-Response-Only", value="1", target="response"),
    ], "request")
    assert hm.get_header(headers, "x-off") is None
    assert hm.get_header(headers, "x-response-only") is None


def test_header_order_and_casing_of_untouched_headers_survive():
    headers = [(b"Host", b"a.test"), (b"X-Odd-Case", b"Yes"), (b"Accept", b"*/*")]
    hm.apply_header_rules(headers, [HeaderRule(name="X-Forwarded-For", value="1.2.3.4")],
                          "request")
    assert [n for n, _ in headers[:3]] == [b"Host", b"X-Odd-Case", b"Accept"]


# -------------------------------------------------------------- validation

def test_validation_rejects_dangerous_rules():
    for rule, expect in [
        ({"name": ""}, "needs a header name"),
        ({"name": "   "}, "needs a header name"),
        ({"name": "X Forwarded For"}, "not a valid header name"),
        ({"name": "X:Y"}, "not a valid header name"),
        ({"name": "Content-Length", "value": "0"}, "framing"),
        ({"name": "Transfer-Encoding", "value": "chunked"}, "framing"),
        ({"name": "X-A", "value": "v\r\nX-Injected: 1"}, "line break"),
        ({"name": "X-A", "value": "v\nX-Injected: 1"}, "line break"),
    ]:
        with pytest.raises(ValueError) as exc:
            validate_header_rules([rule])
        assert expect in str(exc.value), (rule, str(exc.value))


def test_validation_accepts_ordinary_rules():
    validate_header_rules([
        {"name": "X-Forwarded-For", "value": "10.0.0.1"},
        {"name": "X-Real-IP", "value": ""},
        {"name": "Forwarded", "value": 'for=10.0.0.1;proto=https'},
    ])


# ------------------------------------------------------------- proxy path

@pytest.fixture
async def proxied(tmp_path):
    from tests.test_proxy import Target

    db = Database(tmp_path / "h.sqlite3")
    store = SettingsStore(tmp_path / "s.json")
    store.settings.proxy_host = "127.0.0.1"
    store.settings.proxy_port = 0
    hub = EventHub()
    projects = ProjectManager(db, store, hub)
    await projects.load()
    interceptor = Interceptor(hub)
    proxy = ProxyServer(projects, CertificateAuthority(tmp_path / "ca"),
                        interceptor, hub, db)
    target = await Target().start()
    await proxy.start()
    port = proxy._servers[0].sockets[0].getsockname()[1]
    yield projects, db, proxy, target, port, interceptor
    await proxy.stop()
    await target.stop()
    db.close()


async def fetch(port, target_port, path="/x", extra=b""):
    from tests.test_proxy import raw_exchange
    return await raw_exchange(port, (
        f"GET http://127.0.0.1:{target_port}{path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{target_port}\r\n"
    ).encode() + extra + b"Connection: close\r\n\r\n")


async def test_request_header_reaches_the_origin_server(proxied):
    projects, db, _proxy, target, port, _ = proxied
    await projects.set_overrides(projects.active_id, {"header_rules": [
        {"enabled": True, "target": "request", "action": "set",
         "name": "X-Forwarded-For", "value": "203.0.113.7"},
    ]})
    await fetch(port, target.port)

    received = headers_of(target.received[0])
    assert hm.get_header(received, "x-forwarded-for") == b"203.0.113.7"
    # And history shows what was actually sent, not the client's original.
    row = (await db.list_flows(projects.active_id))["items"][0]
    stored = await db.get_flow(projects.active_id, row["id"])
    assert b"X-Forwarded-For: 203.0.113.7" in stored["raw_request"]


async def test_rule_overrides_a_header_the_client_already_sent(proxied):
    projects, _db, _proxy, target, port, _ = proxied
    await projects.set_overrides(projects.active_id, {"header_rules": [
        {"name": "X-Forwarded-For", "value": "10.9.9.9"},
    ]})
    await fetch(port, target.port, extra=b"X-Forwarded-For: 1.1.1.1\r\n")

    received = headers_of(target.received[0])
    assert hm.get_all_headers(received, "x-forwarded-for") == [b"10.9.9.9"]


async def test_remove_rule_strips_a_client_header(proxied):
    projects, _db, _proxy, target, port, _ = proxied
    await projects.set_overrides(projects.active_id, {"header_rules": [
        {"action": "remove", "name": "User-Agent"},
    ]})
    await fetch(port, target.port, extra=b"User-Agent: secret-scanner\r\n")
    assert hm.get_header(headers_of(target.received[0]), "user-agent") is None


async def test_response_rule_reaches_the_browser(proxied):
    projects, _db, _proxy, target, port, _ = proxied
    await projects.set_overrides(projects.active_id, {"header_rules": [
        {"target": "response", "action": "set",
         "name": "X-Injected-By", "value": "brup"},
        {"target": "response", "action": "remove", "name": "Content-Type"},
    ]})
    response = await fetch(port, target.port)
    assert b"X-Injected-By: brup" in response
    assert b"Content-Type:" not in response
    # Framing is untouched, so the body still arrives intact.
    assert b"target-saw:/x" in response


async def test_rules_are_per_project(proxied):
    projects, _db, _proxy, target, port, _ = proxied
    first = projects.active_id
    await projects.set_overrides(first, {"header_rules": [
        {"name": "X-Project", "value": "one"},
    ]})
    second = await projects.create("Second")
    await projects.activate(second["id"])

    await fetch(port, target.port, path="/second")
    assert hm.get_header(headers_of(target.received[-1]), "x-project") is None

    await projects.activate(first)
    await fetch(port, target.port, path="/first")
    assert hm.get_header(headers_of(target.received[-1]), "x-project") == b"one"


async def test_operator_still_sees_and_can_edit_the_rewritten_request(proxied):
    """Rules run before interception, so the held request is the real one."""
    import asyncio
    projects, _db, _proxy, target, port, interceptor = proxied
    await projects.set_overrides(projects.active_id, {
        "intercept_enabled": True,
        "header_rules": [{"name": "X-Forwarded-For", "value": "198.51.100.5"}],
    })

    task = asyncio.create_task(fetch(port, target.port))
    for _ in range(100):
        if interceptor.pending_count:
            break
        await asyncio.sleep(0.02)

    import base64
    item = interceptor.list_pending()[0]
    held = base64.b64decode(item["raw_b64"])
    assert b"X-Forwarded-For: 198.51.100.5" in held, "rule not visible in Intercept"

    # The operator's edit wins over the rule.
    interceptor.forward(item["id"], held.replace(b"198.51.100.5", b"192.0.2.99"))
    await task
    assert hm.get_header(headers_of(target.received[0]), "x-forwarded-for") == b"192.0.2.99"


# --------------------------------------------------------------- API layer

@pytest.fixture
async def client():
    from brup.main import app, state
    await state.projects.load()
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://t"
    ) as c:
        yield c, state


async def test_api_saves_and_validates_header_rules(client):
    c, state = client
    r = await c.put("/api/settings/project", json={"header_rules": [
        {"enabled": True, "target": "request", "action": "set",
         "name": "X-Forwarded-For", "value": "127.0.0.1"},
    ]})
    assert r.status_code == 200, r.text
    assert r.json()["effective"]["header_rules"][0]["name"] == "X-Forwarded-For"
    assert state.projects.settings.header_rules[0].value == "127.0.0.1"

    for bad, expect in [
        ([{"name": "Content-Length", "value": "1"}], "framing"),
        ([{"name": "bad header"}], "not a valid header name"),
        ([{"name": "X-A", "value": "a\r\nb: c"}], "line break"),
    ]:
        r = await c.put("/api/settings/project", json={"header_rules": bad})
        assert r.status_code == 400, bad
        assert expect in r.json()["detail"]

    # System tier is validated the same way.
    r = await c.put("/api/settings/system", json={"header_rules": [
        {"name": "Transfer-Encoding", "value": "chunked"},
    ]})
    assert r.status_code == 400 and "framing" in r.json()["detail"]

    await c.put("/api/settings/project", json={"header_rules": None})
