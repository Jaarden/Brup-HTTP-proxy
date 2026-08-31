"""API-surface tests driven through the real ASGI app."""
from __future__ import annotations

import base64
import os
import tempfile

import pytest

# The app builds its singletons at import time, so point them at a scratch dir.
os.environ.setdefault("BRUP_DATA_DIR", tempfile.mkdtemp(prefix="brup-apitest-"))

import httpx  # noqa: E402
from httpx import ASGITransport  # noqa: E402


@pytest.fixture
async def client():
    from brup.main import app, state
    # ASGITransport does not run the app's lifespan, so do its setup by hand.
    await state.projects.load()
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c, state


async def test_status_and_ca(client):
    c, _ = client
    r = await c.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    assert "proxy" in body and "ca" in body
    assert len(body["ca"]["fingerprint_sha256"].split(":")) == 32

    pem = await c.get("/api/ca/cert.pem")
    assert pem.status_code == 200
    assert pem.content.startswith(b"-----BEGIN CERTIFICATE-----")
    assert "attachment" in pem.headers["content-disposition"]

    der = await c.get("/api/ca/cert.der")
    assert der.status_code == 200 and der.content[:1] == b"\x30"


async def test_settings_describes_both_tiers(client):
    c, state = client
    body = (await c.get("/api/settings")).json()
    assert set(body) == {
        "effective", "system", "overrides", "overridable_keys", "project_id",
    }
    assert body["effective"]["invisible_proxy"] is False
    assert body["overrides"] == {}
    # Listener settings are system-only and must not be listed as overridable.
    assert "proxy_port" not in body["overridable_keys"]
    assert "intercept_enabled" in body["overridable_keys"]


async def test_system_settings_roundtrip_and_validation(client):
    c, state = client
    r = await c.put("/api/settings/system", json={"read_timeout": 12})
    assert r.status_code == 200, r.text
    assert r.json()["system"]["read_timeout"] == 12
    assert r.json()["effective"]["read_timeout"] == 12
    # Changing a non-listener setting must not bounce the listener.
    assert r.json()["restarted"] is False

    r = await c.put("/api/settings/system", json={
        "scope_exclude": [{"enabled": True, "pattern": "([unclosed"}],
    })
    assert r.status_code == 400
    assert "Invalid regex" in r.json()["detail"]

    await c.put("/api/settings/system", json={"read_timeout": 30})


async def test_project_overrides_win_and_can_be_cleared(client):
    c, state = client
    await c.put("/api/settings/system", json={"read_timeout": 30,
                                              "intercept_enabled": False})

    r = await c.put("/api/settings/project", json={
        "read_timeout": 3, "intercept_enabled": True,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["system"]["read_timeout"] == 30       # system untouched
    assert body["effective"]["read_timeout"] == 3     # project wins
    assert body["overrides"]["intercept_enabled"] is True
    # The live proxy must see the effective value.
    assert state.projects.settings.read_timeout == 3
    assert state.proxy.settings.intercept_enabled is True

    # An explicit null removes the override and the system value returns.
    r = await c.put("/api/settings/project", json={"read_timeout": None})
    assert "read_timeout" not in r.json()["overrides"]
    assert r.json()["effective"]["read_timeout"] == 30

    await c.put("/api/settings/project", json={"intercept_enabled": None})


async def test_listener_settings_cannot_be_overridden_per_project(client):
    c, _ = client
    r = await c.put("/api/settings/project", json={"proxy_port": 1234})
    assert r.status_code == 400
    assert "system-wide" in r.json()["detail"]
    r = await c.put("/api/settings/project", json={"no_such_setting": 1})
    assert r.status_code == 400
    assert "unknown setting" in r.json()["detail"]


async def test_intercept_endpoints_when_empty(client):
    c, _ = client
    r = await c.get("/api/intercept")
    assert r.status_code == 200 and r.json()["items"] == []
    assert (await c.post("/api/intercept/forward-all")).json()["forwarded"] == 0
    r = await c.post("/api/intercept/nope/forward", json={})
    assert r.status_code == 404


async def test_history_lifecycle(client):
    c, state = client
    flow_id = await state.db.insert_flow(
        project_id=state.projects.active_id,
        source="proxy", host="ok.test", port=443, tls=1, method="GET",
        target="/x", url="https://ok.test/x", status=200, req_len=10, resp_len=20,
        raw_request=b"GET /x HTTP/1.1\r\nHost: ok.test\r\n\r\n",
        raw_response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
    )
    r = await c.get("/api/history", params={"search": "ok.test"})
    assert r.status_code == 200 and r.json()["total"] >= 1

    r = await c.get(f"/api/history/{flow_id}")
    assert r.status_code == 200
    detail = r.json()
    assert base64.b64decode(detail["raw_request_b64"]).startswith(b"GET /x")
    assert b"hi" in base64.b64decode(detail["raw_response_b64"])

    r = await c.patch(f"/api/history/{flow_id}", json={"notes": "look here", "color": "red"})
    assert r.status_code == 200
    assert (await state.db.get_flow(state.projects.active_id, flow_id))["notes"] == "look here"

    assert (await c.get("/api/history/hosts")).status_code == 200
    assert (await c.get("/api/history/999999")).status_code == 404
    assert (await c.delete("/api/history")).status_code == 200
    assert (await c.get("/api/history")).json()["total"] == 0


async def test_gzip_response_is_decoded_for_display(client):
    c, state = client
    import gzip
    body = gzip.compress(b"secret-plaintext")
    raw = (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "
           + str(len(body)).encode() + b"\r\n\r\n" + body)
    flow_id = await state.db.insert_flow(
        project_id=state.projects.active_id,
        source="proxy", host="g.test", port=443, tls=1, method="GET",
        url="https://g.test/", status=200, raw_response=raw,
    )
    detail = (await c.get(f"/api/history/{flow_id}")).json()
    assert base64.b64decode(detail["decoded_body_b64"]) == b"secret-plaintext"


async def test_wordlists(client):
    c, _ = client
    r = await c.post("/api/wordlists", json={"name": "small", "content": "a\nb\n\nc\n"})
    assert r.status_code == 200 and r.json()["lines"] == 3

    names = [w["name"] for w in (await c.get("/api/wordlists")).json()]
    assert "small" in names
    assert (await c.get("/api/wordlists/small")).json()["content"].startswith("a\nb")
    assert (await c.get("/api/wordlists/missing")).status_code == 404
    assert (await c.delete("/api/wordlists/small")).status_code == 200


async def test_auto_mark_positions(client):
    c, _ = client
    raw = (b"POST /login?next=%2Fhome HTTP/1.1\r\nHost: ok.test\r\n"
           b"Cookie: sid=abc; theme=dark\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: 25\r\n\r\nuser=admin&pass=hunter2\r\n")
    r = await c.post("/api/intruder/mark", json={
        "raw_b64": base64.b64encode(raw).decode(),
    })
    assert r.status_code == 200, r.text
    marked = base64.b64decode(r.json()["raw_b64"])
    # Query, cookie and body parameter values all get positions.
    assert r.json()["positions"] == 5
    assert b"next=\xa7%2Fhome\xa7" in marked
    assert b"sid=\xa7abc\xa7" in marked
    assert b"user=\xa7admin\xa7" in marked

    # Clearing is idempotent and returns the original bytes.
    r2 = await c.post("/api/intruder/mark", json={
        "raw_b64": base64.b64encode(marked).decode(), "mode": "clear",
    })
    assert base64.b64decode(r2.json()["raw_b64"]) == raw
    assert r2.json()["positions"] == 0


async def test_intruder_rejects_bad_configs(client):
    c, _ = client
    unbalanced = base64.b64encode(b"GET /\xa7x HTTP/1.1\r\n\r\n").decode()
    r = await c.post("/api/intruder/preview", json={
        "host": "ok.test", "port": 80, "template_b64": unbalanced,
        "payload_sets": [{"kind": "list", "payloads": ["a"]}],
    })
    assert r.status_code == 400 and "Unbalanced" in r.json()["detail"]

    no_positions = base64.b64encode(b"GET / HTTP/1.1\r\n\r\n").decode()
    r = await c.post("/api/intruder/start", json={
        "host": "ok.test", "port": 80, "template_b64": no_positions,
        "payload_sets": [{"kind": "list", "payloads": ["a"]}],
    })
    assert r.status_code == 400 and "No payload positions" in r.json()["detail"]

    # pitchfork needs one payload set per position
    two_pos = base64.b64encode(b"GET /?a=\xa71\xa7&b=\xa72\xa7 HTTP/1.1\r\n\r\n").decode()
    r = await c.post("/api/intruder/start", json={
        "host": "ok.test", "port": 80, "template_b64": two_pos,
        "attack_type": "pitchfork",
        "payload_sets": [{"kind": "list", "payloads": ["a"]}],
    })
    assert r.status_code == 400 and "no requests" in r.json()["detail"]

    # An unknown attack id is a 404 whatever you try to do with it; project
    # scoping means "not in this project" reads the same as "does not exist".
    assert (await c.get("/api/intruder/deadbeef")).status_code == 404
    assert (await c.post("/api/intruder/deadbeef/pause")).status_code == 404
    assert (await c.delete("/api/intruder/deadbeef")).status_code == 404
    assert (await c.get("/api/intruder/deadbeef/results")).status_code == 404


async def test_repeater_rejects_empty_and_reports_errors(client):
    c, _ = client
    r = await c.post("/api/repeater/send", json={
        "host": "127.0.0.1", "port": 80, "raw_b64": base64.b64encode(b"  ").decode(),
    })
    assert r.status_code == 400

    # Port 1 on localhost will refuse; the failure must come back as data.
    r = await c.post("/api/repeater/send", json={
        "host": "127.0.0.1", "port": 1,
        "raw_b64": base64.b64encode(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").decode(),
    })
    assert r.status_code == 200
    assert r.json()["ok"] is False and r.json()["error"]
