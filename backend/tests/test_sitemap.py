"""Sitemap tree construction and its API."""
from __future__ import annotations

import os
import tempfile

import pytest

os.environ.setdefault("BRUP_DATA_DIR", tempfile.mkdtemp(prefix="brup-sitemap-"))

import httpx  # noqa: E402
from httpx import ASGITransport  # noqa: E402

from brup.config import ScopeRule, Settings  # noqa: E402
from brup.sitemap import build_sitemap  # noqa: E402


def rows(*specs):
    """specs: (url, method, status, n)"""
    out = []
    for i, (url, method, status, n) in enumerate(specs, start=1):
        out.append({
            "host": url.split("//")[1].split("/")[0].split(":")[0],
            "port": 443 if url.startswith("https") else 80,
            "tls": 1 if url.startswith("https") else 0,
            "url": url, "method": method, "status": status,
            "mime": "text/html", "last_id": i, "n": n,
        })
    return out


def find(nodes, name):
    for node in nodes:
        if node["name"] == name:
            return node
    raise AssertionError(f"{name!r} not among {[n['name'] for n in nodes]}")


def test_tree_shape_and_counts():
    hosts, truncated = build_sitemap(rows(
        ("https://a.test/", "GET", 200, 1),
        ("https://a.test/app/login", "GET", 200, 1),
        ("https://a.test/app/login", "POST", 302, 3),
        ("https://a.test/app/assets/main.css", "GET", 200, 1),
        ("http://b.test/x", "GET", 404, 1),
    ), Settings())

    assert not truncated
    assert [h["name"] for h in hosts] == ["https://a.test", "http://b.test"]

    a = find(hosts, "https://a.test")
    assert a["kind"] == "host"
    assert a["subtree_count"] == 6          # 1 + 1 + 3 + 1
    # The root document gets its own node, sorted first.
    assert a["children"][0]["name"] == "/"
    assert a["children"][0]["count"] == 1

    app = find(a["children"], "app")
    assert app["count"] == 0                # /app itself was never requested
    assert app["subtree_count"] == 5

    login = find(app["children"], "login")
    assert login["count"] == 4              # GET once + POST three times
    assert login["methods"] == ["GET", "POST"]
    assert login["statuses"] == [200, 302]
    assert login["path"] == "/app/login"
    assert login["url"] == "https://a.test/app/login"

    css = find(find(app["children"], "assets")["children"], "main.css")
    assert css["children"] == [] and css["count"] == 1


def test_http_and_https_are_separate_trees():
    hosts, _ = build_sitemap(rows(
        ("http://same.test/a", "GET", 200, 1),
        ("https://same.test/a", "GET", 200, 1),
    ), Settings())
    assert len(hosts) == 2
    assert {h["name"] for h in hosts} == {"http://same.test", "https://same.test"}
    assert {h["tls"] for h in hosts} == {True, False}
    assert {h["origin"] for h in hosts} == {"http://same.test", "https://same.test"}


def test_query_strings_collapse_onto_one_path_node():
    hosts, _ = build_sitemap(rows(
        ("https://q.test/s?p=1", "GET", 200, 1),
        ("https://q.test/s?p=2", "GET", 200, 1),
        ("https://q.test/s", "GET", 200, 1),
    ), Settings())
    node = find(find(hosts, "https://q.test")["children"], "s")
    assert node["count"] == 3


def test_trailing_slash_merges_with_the_same_path():
    hosts, _ = build_sitemap(rows(
        ("https://t.test/dir", "GET", 200, 1),
        ("https://t.test/dir/", "GET", 200, 1),
        ("https://t.test/dir/file", "GET", 200, 1),
    ), Settings())
    children = find(hosts, "https://t.test")["children"]
    assert [c["name"] for c in children] == ["dir"]
    assert children[0]["count"] == 2
    assert children[0]["subtree_count"] == 3


def test_scope_flag_and_ordering():
    settings = Settings(scope_include=[ScopeRule(pattern=r"^https://in\.test")])
    hosts, _ = build_sitemap(rows(
        ("https://out.test/a", "GET", 200, 1),
        ("https://in.test/a", "GET", 200, 1),
    ), settings)
    # In-scope hosts sort first so the target is at the top of the tree.
    assert [h["name"] for h in hosts] == ["https://in.test", "https://out.test"]
    assert find(hosts, "https://in.test")["in_scope"] is True
    assert find(hosts, "https://out.test")["in_scope"] is False

    filtered, _ = build_sitemap(rows(
        ("https://out.test/a", "GET", 200, 1),
        ("https://in.test/a", "GET", 200, 1),
    ), settings, in_scope_only=True)
    assert [h["name"] for h in filtered] == ["https://in.test"]


def test_non_http_urls_are_ignored():
    hosts, _ = build_sitemap(rows(("ftp://nope.test/x", "GET", 200, 1)), Settings())
    assert hosts == []


def test_node_budget_truncates_rather_than_exploding(monkeypatch):
    import brup.sitemap as sm
    monkeypatch.setattr(sm, "MAX_NODES", 3)
    hosts, truncated = sm.build_sitemap(rows(
        ("https://big.test/a/b/c/d/e/f", "GET", 200, 1),
    ), Settings())
    assert truncated is True
    assert hosts  # whatever fitted is still returned


# ------------------------------------------------------------------ the API

@pytest.fixture
async def client():
    from brup.main import app, state
    # ASGITransport does not run the app's lifespan, so do its setup by hand.
    await state.projects.load()
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://t"
    ) as c:
        await c.delete("/api/history")
        yield c, state


async def seed(state, url, method="GET", status=200):
    return await state.db.insert_flow(
        project_id=state.projects.active_id,
        source="proxy",
        host=url.split("//")[1].split("/")[0].split(":")[0],
        port=443 if url.startswith("https") else 80,
        tls=1 if url.startswith("https") else 0,
        method=method, target="/", url=url, status=status,
        req_len=10, resp_len=20, mime="text/html",
        raw_request=f"{method} {url} HTTP/1.1\r\n\r\n".encode(),
        raw_response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
    )


async def test_sitemap_endpoint(client):
    c, state = client
    await seed(state, "https://api.test/v1/users")
    await seed(state, "https://api.test/v1/users", "POST", 201)
    await seed(state, "https://api.test/v1/orders")

    body = (await c.get("/api/sitemap")).json()
    assert body["truncated"] is False
    host = body["hosts"][0]
    assert host["name"] == "https://api.test"
    assert host["subtree_count"] == 3
    v1 = host["children"][0]
    assert v1["name"] == "v1"
    assert sorted(child["name"] for child in v1["children"]) == ["orders", "users"]
    users = [child for child in v1["children"] if child["name"] == "users"][0]
    assert users["methods"] == ["GET", "POST"]


async def test_sitemap_items_recursive_and_exact(client):
    c, state = client
    await seed(state, "https://api.test/v1/users")
    await seed(state, "https://api.test/v1/users?page=2")
    await seed(state, "https://api.test/v1/users/42")

    deep = await c.get("/api/sitemap/items", params={
        "origin": "https://api.test", "path": "/v1/users", "recursive": True,
    })
    assert deep.json()["total"] == 3

    exact = await c.get("/api/sitemap/items", params={
        "origin": "https://api.test", "path": "/v1/users", "recursive": False,
    })
    urls = {item["url"] for item in exact.json()["items"]}
    # The path itself and its query variants, but not the child resource.
    assert urls == {"https://api.test/v1/users", "https://api.test/v1/users?page=2"}


async def test_prefix_filter_treats_wildcards_literally(client):
    c, state = client
    await seed(state, "https://w.test/a%b_c/real")
    await seed(state, "https://w.test/aXbYc/decoy")

    result = await c.get("/api/sitemap/items", params={
        "origin": "https://w.test", "path": "/a%b_c", "recursive": True,
    })
    urls = {item["url"] for item in result.json()["items"]}
    assert urls == {"https://w.test/a%b_c/real"}, urls


async def test_add_branch_to_scope(client):
    c, state = client
    try:
        r = await c.post("/api/sitemap/scope", json={
            "origin": "https://target.test", "kind": "include", "whole_host": True,
        })
        assert r.status_code == 200
        assert r.json()["added"] is True
        pattern = r.json()["pattern"]
        assert pattern == r"^https://target\.test"
        # It lands in the *project* overrides, leaving system settings alone.
        assert any(r["pattern"] == pattern
                   for r in state.projects.overrides["scope_include"])
        assert state.store.settings.scope_include == []
        assert any(rule.pattern == pattern
                   for rule in state.projects.settings.scope_include)

        # Adding the same branch twice is a no-op rather than a duplicate rule.
        again = await c.post("/api/sitemap/scope", json={
            "origin": "https://target.test", "kind": "include", "whole_host": True,
        })
        assert again.json()["added"] is False

        r = await c.post("/api/sitemap/scope", json={
            "origin": "https://target.test", "path": "/admin",
            "kind": "exclude", "whole_host": False,
        })
        assert r.json()["pattern"] == r"^https://target\.test/admin"

        assert (await c.post("/api/sitemap/scope", json={
            "origin": "https://x.test", "kind": "bogus",
        })).status_code == 400
    finally:
        await state.projects.set_overrides(
            state.projects.active_id,
            {"scope_include": None, "scope_exclude": None},
        )


def test_hosts_group_by_hostname_not_scheme():
    """Both trees for one host must sit together, not be split by scheme."""
    hosts, _ = build_sitemap(rows(
        ("https://a.test/x", "GET", 200, 1),
        ("http://b.test/x", "GET", 200, 1),
        ("http://a.test/x", "GET", 200, 1),
    ), Settings())
    assert [h["name"] for h in hosts] == [
        "http://a.test", "https://a.test", "http://b.test",
    ]
