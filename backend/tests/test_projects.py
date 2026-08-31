"""Project lifecycle, data isolation and the two-tier settings model."""
from __future__ import annotations

import base64
import os
import tempfile

import pytest

os.environ.setdefault("BRUP_DATA_DIR", tempfile.mkdtemp(prefix="brup-projtest-"))

import httpx  # noqa: E402
from httpx import ASGITransport  # noqa: E402

from brup.config import Settings, SettingsStore  # noqa: E402
from brup.db import Database, IncompatibleDatabase  # noqa: E402
from brup.events import EventHub  # noqa: E402
from brup.projects import ProjectError, ProjectManager  # noqa: E402


@pytest.fixture
async def mgr(tmp_path):
    db = Database(tmp_path / "p.sqlite3")
    store = SettingsStore(tmp_path / "settings.json")
    manager = ProjectManager(db, store, EventHub())
    await manager.load()
    yield manager, db, store
    db.close()


# ------------------------------------------------------------- lifecycle

async def test_load_bootstraps_a_default_project(mgr):
    manager, db, _ = mgr
    projects = await manager.list()
    assert len(projects) == 1
    assert manager.active_id == projects[0]["id"]
    # The choice is remembered so a restart reopens the same project.
    assert await db.get_meta("active_project") == manager.active_id


async def test_active_project_survives_a_reopen(mgr):
    manager, db, store = mgr
    second = await manager.create("Second")
    await manager.activate(second["id"])

    reopened = ProjectManager(db, store, EventHub())
    await reopened.load()
    assert reopened.active_id == second["id"]
    assert reopened.active["name"] == "Second"


async def test_create_rename_and_notes(mgr):
    manager, _, _ = mgr
    project = await manager.create("Client A")
    assert project["name"] == "Client A"

    renamed = await manager.rename(project["id"], "  Client B  ")
    assert renamed["name"] == "Client B"          # trimmed

    with pytest.raises(ProjectError):
        await manager.create("   ")
    with pytest.raises(ProjectError):
        await manager.rename(project["id"], "")

    noted = await manager.set_notes(project["id"], "in scope: *.example.com")
    assert noted["notes"] == "in scope: *.example.com"


async def test_cannot_delete_the_last_project(mgr):
    manager, _, _ = mgr
    with pytest.raises(ProjectError) as exc:
        await manager.delete(manager.active_id)
    assert "only project" in str(exc.value)


async def test_deleting_the_active_project_switches_away(mgr):
    manager, _, _ = mgr
    first = manager.active_id
    second = await manager.create("Second")
    await manager.activate(second["id"])

    now_active = await manager.delete(second["id"])
    assert now_active == first
    assert manager.active_id == first
    assert [p["id"] for p in await manager.list()] == [first]


async def test_create_can_copy_settings_from_another_project(mgr):
    manager, _, _ = mgr
    await manager.set_overrides(manager.active_id, {"read_timeout": 7})
    copy = await manager.create("Copy", copy_settings_from=manager.active_id)
    assert copy["overrides"] == {"read_timeout": 7}

    with pytest.raises(ProjectError):
        await manager.create("Bad", copy_settings_from="nope")


# ---------------------------------------------------------------- settings

async def test_project_overrides_layer_over_system(mgr):
    manager, _, store = mgr
    await manager.update_system({"read_timeout": 30, "intercept_enabled": False})
    assert manager.settings.read_timeout == 30

    await manager.set_overrides(manager.active_id, {"read_timeout": 2})
    assert manager.settings.read_timeout == 2
    assert store.settings.read_timeout == 30       # system untouched
    assert manager.settings.intercept_enabled is False

    # Clearing the override falls back to the system value.
    await manager.set_overrides(manager.active_id, {"read_timeout": None})
    assert manager.settings.read_timeout == 30
    assert manager.overrides == {}


async def test_each_project_keeps_its_own_overrides(mgr):
    manager, _, _ = mgr
    a = manager.active_id
    await manager.set_overrides(a, {"intercept_enabled": True})
    b = await manager.create("B")
    await manager.activate(b["id"])

    assert manager.settings.intercept_enabled is False   # B has no override
    await manager.set_overrides(b["id"], {"intercept_enabled": True,
                                         "read_timeout": 1})
    assert manager.settings.read_timeout == 1

    await manager.activate(a)
    assert manager.settings.intercept_enabled is True
    assert manager.settings.read_timeout == Settings().read_timeout


async def test_system_change_is_seen_immediately(mgr):
    manager, _, _ = mgr
    before = manager.settings.read_timeout
    await manager.update_system({"read_timeout": before + 5})
    assert manager.settings.read_timeout == before + 5


async def test_system_only_keys_are_refused(mgr):
    manager, _, _ = mgr
    for key, value in [("proxy_port", 1), ("proxy_host", "x"),
                       ("invisible_tls_port", 2), ("invisible_tls_enabled", True)]:
        with pytest.raises(ProjectError) as exc:
            await manager.set_overrides(manager.active_id, {key: value})
        assert "system-wide" in str(exc.value)

    with pytest.raises(ProjectError):
        await manager.set_overrides(manager.active_id, {"nonsense": 1})
    # A wrong type is caught at write time rather than at request time.
    with pytest.raises(ProjectError):
        await manager.set_overrides(manager.active_id, {"read_timeout": "soon"})


async def test_describe_settings_shape(mgr):
    manager, _, _ = mgr
    await manager.set_overrides(manager.active_id, {"intercept_enabled": True})
    described = manager.describe_settings()
    assert described["effective"]["intercept_enabled"] is True
    assert described["system"]["intercept_enabled"] is False
    assert described["overrides"] == {"intercept_enabled": True}
    assert "proxy_port" not in described["overridable_keys"]
    assert described["project_id"] == manager.active_id


# --------------------------------------------------------------- isolation

async def test_flows_are_isolated_between_projects(mgr):
    manager, db, _ = mgr
    a = manager.active_id
    b = (await manager.create("B"))["id"]

    await db.insert_flow(project_id=a, host="a.test", port=80, url="http://a.test/1",
                         method="GET", status=200)
    await db.insert_flow(project_id=b, host="b.test", port=80, url="http://b.test/1",
                         method="GET", status=200)

    assert (await db.list_flows(a))["total"] == 1
    assert (await db.list_flows(a))["items"][0]["host"] == "a.test"
    assert (await db.list_flows(b))["items"][0]["host"] == "b.test"
    assert [h["host"] for h in await db.hosts(a)] == ["a.test"]
    # Sitemap rows are derived from flows, so they inherit the isolation.
    assert [r["host"] for r in await db.sitemap_rows(a)] == ["a.test"]


async def test_a_flow_cannot_be_read_from_another_project(mgr):
    manager, db, _ = mgr
    a = manager.active_id
    b = (await manager.create("B"))["id"]
    flow_id = await db.insert_flow(project_id=a, host="a.test", port=80,
                                   url="http://a.test/x", method="GET")
    assert await db.get_flow(a, flow_id) is not None
    assert await db.get_flow(b, flow_id) is None


async def test_clear_and_trim_only_touch_one_project(mgr):
    manager, db, _ = mgr
    a = manager.active_id
    b = (await manager.create("B"))["id"]
    for i in range(5):
        await db.insert_flow(project_id=a, host="a.test", port=80,
                             url=f"http://a.test/{i}", method="GET")
        await db.insert_flow(project_id=b, host="b.test", port=80,
                             url=f"http://b.test/{i}", method="GET")

    await db.trim(a, 2)
    assert (await db.list_flows(a))["total"] == 2
    assert (await db.list_flows(b))["total"] == 5

    await db.clear_flows(a)
    assert (await db.list_flows(a))["total"] == 0
    assert (await db.list_flows(b))["total"] == 5


async def test_deleting_a_project_removes_all_its_data(mgr):
    manager, db, _ = mgr
    keep = manager.active_id
    doomed = (await manager.create("Doomed"))["id"]

    await db.insert_flow(project_id=doomed, host="d.test", port=80,
                         url="http://d.test/x", method="GET")
    await db.insert_flow(project_id=keep, host="k.test", port=80,
                         url="http://k.test/x", method="GET")
    await db.upsert_attack(id="atk1", project_id=doomed, created=1.0,
                           host="d.test", port=80, attack_type="sniper", total=1)
    await db.insert_result(attack_id="atk1", idx=0, payloads="p", status=200)
    await db.replace_tabs(doomed, [{"id": "t1", "name": "Tab", "raw": b"GET / HTTP/1.1"}])
    await db.replace_tabs(keep, [{"id": "t2", "name": "Keep", "raw": b"GET / HTTP/1.1"}])

    await manager.delete(doomed)

    assert (await db.list_flows(doomed))["total"] == 0
    assert await db.list_attacks(doomed) == []
    assert await db.list_results("atk1") == []      # results follow the attack
    assert await db.list_tabs(doomed) == []
    # The surviving project is untouched.
    assert (await db.list_flows(keep))["total"] == 1
    assert len(await db.list_tabs(keep)) == 1


async def test_repeater_tabs_roundtrip_and_replace(mgr):
    manager, db, _ = mgr
    pid = manager.active_id
    await db.replace_tabs(pid, [
        {"id": "t1", "name": "Login", "host": "a.test", "port": 443, "tls": True,
         "raw": b"POST /login HTTP/1.1\r\n\r\n", "trail": ["one", "two"]},
        {"id": "t2", "name": "Search", "host": "a.test", "port": 443, "tls": True,
         "raw": b"GET /q HTTP/1.1\r\n\r\n"},
    ])
    tabs = await db.list_tabs(pid)
    assert [t["name"] for t in tabs] == ["Login", "Search"]     # order preserved
    assert tabs[0]["raw"] == b"POST /login HTTP/1.1\r\n\r\n"
    assert tabs[0]["tls"] == 1 and tabs[0]["trail"] == ["one", "two"]

    # Replacing is a whole-list operation, so removals stick.
    await db.replace_tabs(pid, [{"id": "t2", "name": "Search", "raw": b"GET /q2 HTTP/1.1"}])
    tabs = await db.list_tabs(pid)
    assert [t["id"] for t in tabs] == ["t2"]
    assert tabs[0]["raw"] == b"GET /q2 HTTP/1.1"


async def test_attacks_marked_running_are_reset_on_reopen(mgr):
    manager, db, _ = mgr
    pid = manager.active_id
    await db.upsert_attack(id="live", project_id=pid, created=1.0, host="a.test",
                           port=80, attack_type="sniper", total=10, completed=4,
                           status="running")
    path = db.path
    db.close()

    reopened = Database(path)
    try:
        row = await reopened.get_attack("live")
        assert row["status"] == "stopped"
        assert "interrupted" in row["message"]
        assert row["completed"] == 4      # progress is kept
    finally:
        reopened.close()


async def test_pre_projects_database_is_refused(tmp_path):
    """An old database is rejected with instructions, not silently mangled."""
    import sqlite3
    path = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE flows (id INTEGER PRIMARY KEY, url TEXT)")
    conn.commit()
    conn.close()

    with pytest.raises(IncompatibleDatabase) as exc:
        Database(path)
    assert "docker compose down -v" in str(exc.value)


# --------------------------------------------------------------- API layer

@pytest.fixture
async def client():
    from brup.main import app, state
    await state.projects.load()
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://t"
    ) as c:
        yield c, state


async def test_project_api_crud_and_switching(client):
    c, state = client
    listing = (await c.get("/api/projects")).json()
    original = listing["active_id"]
    assert any(p["id"] == original for p in listing["items"])
    # Other test modules share this database, so compare against a baseline
    # rather than assuming the starting project is empty.
    baseline = (await c.get("/api/history")).json()["total"]

    created = (await c.post("/api/projects", json={"name": "API project"})).json()
    new_id = created["project"]["id"]
    assert created["active_id"] == new_id          # creating activates it
    assert state.projects.active_id == new_id

    # Traffic logged now belongs to the new project only.
    await state.db.insert_flow(project_id=new_id, host="new.test", port=80,
                               url="http://new.test/x", method="GET", status=200)
    assert (await c.get("/api/history")).json()["total"] == 1

    assert (await c.post(f"/api/projects/{original}/activate")).status_code == 200
    # Back in the first project, the new project's traffic is not visible.
    assert (await c.get("/api/history")).json()["total"] == baseline

    renamed = await c.patch(f"/api/projects/{new_id}", json={"name": "Renamed"})
    assert renamed.json()["name"] == "Renamed"

    counted = [p for p in (await c.get("/api/projects")).json()["items"]
               if p["id"] == new_id][0]
    assert counted["flow_count"] == 1

    deleted = await c.delete(f"/api/projects/{new_id}")
    assert deleted.status_code == 200
    assert deleted.json()["active_id"] == original
    assert (await c.delete(f"/api/projects/{new_id}")).status_code == 400

    assert (await c.post("/api/projects/nope/activate")).status_code == 400
    assert (await c.patch(f"/api/projects/{original}", json={})).status_code == 400


async def test_repeater_tabs_api_is_project_scoped(client):
    c, state = client
    first = state.projects.active_id
    raw = base64.b64encode(b"GET /one HTTP/1.1\r\nHost: a.test\r\n\r\n").decode()

    r = await c.put("/api/repeater/tabs", json=[
        {"id": "tab-1", "name": "One", "host": "a.test", "port": 443,
         "tls": True, "raw_b64": raw, "trail": []},
    ])
    assert r.status_code == 200 and r.json()["count"] == 1

    got = (await c.get("/api/repeater/tabs")).json()["items"]
    assert len(got) == 1
    assert got[0]["name"] == "One" and got[0]["tls"] is True
    assert base64.b64decode(got[0]["raw_b64"]).startswith(b"GET /one")

    other = (await c.post("/api/projects", json={"name": "Tabs B"})).json()
    assert (await c.get("/api/repeater/tabs")).json()["items"] == []

    await c.post(f"/api/projects/{first}/activate")
    assert len((await c.get("/api/repeater/tabs")).json()["items"]) == 1

    await c.put("/api/repeater/tabs", json=[])
    await c.delete(f"/api/projects/{other['project']['id']}")


async def test_status_reports_the_active_project(client):
    c, state = client
    body = (await c.get("/api/status")).json()
    assert body["project"]["id"] == state.projects.active_id
    assert "name" in body["project"]


async def test_held_request_survives_a_project_switch(tmp_path):
    """Switching project must not orphan a held message.

    Interception belongs to the single shared listener, so a request held under
    one project stays visible and forwardable after switching away - otherwise
    the browser connection hangs with no way to release it.
    """
    import asyncio
    from brup.ca import CertificateAuthority
    from brup.proxy.interceptor import Interceptor
    from brup.proxy.server import ProxyServer
    from tests.test_proxy import Target, raw_exchange

    db = Database(tmp_path / "held.sqlite3")
    store = SettingsStore(tmp_path / "s.json")
    store.settings.proxy_host = "127.0.0.1"
    store.settings.proxy_port = 0
    hub = EventHub()
    manager = ProjectManager(db, store, hub)
    await manager.load()
    interceptor = Interceptor(hub)
    proxy = ProxyServer(manager, CertificateAuthority(tmp_path / "ca"),
                        interceptor, hub, db)

    first = manager.active_id
    await manager.set_overrides(first, {"intercept_enabled": True})

    target = await Target().start()
    await proxy.start()
    port = proxy._servers[0].sockets[0].getsockname()[1]
    try:
        task = asyncio.create_task(raw_exchange(port, (
            f"GET http://127.0.0.1:{target.port}/held HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{target.port}\r\nConnection: close\r\n\r\n"
        ).encode()))
        for _ in range(100):
            if interceptor.pending_count:
                break
            await asyncio.sleep(0.02)
        assert interceptor.pending_count == 1

        item = interceptor.list_pending()[0]
        assert item["project_id"] == first

        # Switch to a different project while the message is still held.
        second = await manager.create("Second")
        await manager.activate(second["id"])
        assert manager.active_id == second["id"]

        # It is still listed, still tagged with the project that captured it,
        # and still forwardable.
        still = interceptor.list_pending()
        assert len(still) == 1
        assert still[0]["project_id"] == first
        assert interceptor.forward(item["id"])

        response = await task
        assert b"target-saw:/held" in response

        # It was logged against the project that captured it, not the new one.
        assert (await db.list_flows(first))["total"] == 1
        assert (await db.list_flows(second["id"]))["total"] == 0
    finally:
        await proxy.stop()
        await target.stop()
        db.close()
