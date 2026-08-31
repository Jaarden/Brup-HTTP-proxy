"""Builds a host/path tree out of logged proxy traffic.

The tree is derived from history rather than stored separately, so it always
reflects whatever is in the database and needs no extra bookkeeping on the hot
proxy path.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from . import http_message as hm
from .config import Settings, in_scope

MAX_NODES = 40_000


def _new_node(*, name: str, path: str, origin: str, host: str, port: int,
              tls: bool, kind: str) -> dict[str, Any]:
    return {
        "key": f"{origin}{path}",
        "name": name,
        "path": path,
        "origin": origin,
        "host": host,
        "port": port,
        "tls": tls,
        "kind": kind,
        "count": 0,
        "subtree_count": 0,
        "methods": set(),
        "statuses": set(),
        "mime": None,
        "last_id": None,
        "_children": {},
    }


def _child(parent: dict[str, Any], name: str, budget: list[int]) -> dict[str, Any] | None:
    existing = parent["_children"].get(name)
    if existing is not None:
        return existing
    if budget[0] <= 0:
        return None
    budget[0] -= 1
    # A trailing slash is not meaningful here: /a and /a/ are the same node.
    path = f"{parent['path'].rstrip('/')}/{name}" if name != "/" else "/"
    node = _new_node(
        name=name, path=path, origin=parent["origin"], host=parent["host"],
        port=parent["port"], tls=parent["tls"], kind="path",
    )
    parent["_children"][name] = node
    return node


def _accumulate(node: dict[str, Any], row: dict[str, Any]) -> None:
    node["count"] += int(row.get("n") or 1)
    if row.get("method"):
        node["methods"].add(row["method"])
    if row.get("status") is not None:
        node["statuses"].add(int(row["status"]))
    if row.get("mime") and not node["mime"]:
        node["mime"] = row["mime"]
    last = row.get("last_id")
    if last is not None and (node["last_id"] is None or last > node["last_id"]):
        node["last_id"] = last


def _finalise(node: dict[str, Any], settings: Settings) -> dict[str, Any]:
    children = [_finalise(child, settings) for child in node.pop("_children").values()]
    # Alphabetical, case-insensitive - the root document first where present.
    children.sort(key=lambda c: (c["name"] != "/", c["name"].lower()))
    node["children"] = children
    node["subtree_count"] = node["count"] + sum(c["subtree_count"] for c in children)
    node["methods"] = sorted(node["methods"])
    node["statuses"] = sorted(node["statuses"])
    node["url"] = node["origin"] + (node["path"] or "/")
    node["in_scope"] = in_scope(settings, node["url"])
    return node


def build_sitemap(
    rows: list[dict[str, Any]],
    settings: Settings,
    *,
    in_scope_only: bool = False,
) -> tuple[list[dict[str, Any]], bool]:
    """Turn aggregated history rows into a forest of host trees.

    Returns ``(hosts, truncated)``; truncated is true when the node budget ran
    out and some paths were left off the tree.
    """
    roots: dict[tuple[str, bool], dict[str, Any]] = {}
    budget = [MAX_NODES]
    truncated = False

    for row in rows:
        url = row.get("url") or ""
        if not url.lower().startswith(("http://", "https://")):
            continue
        if in_scope_only and not in_scope(settings, url):
            continue

        parts = urlsplit(url)
        netloc, path = parts.netloc, parts.path or "/"
        if not netloc:
            continue
        tls = parts.scheme.lower() == "https"

        key = (netloc, tls)
        host_node = roots.get(key)
        if host_node is None:
            host, port = hm.split_authority(netloc, 443 if tls else 80)
            origin = f"{parts.scheme}://{netloc}"
            host_node = _new_node(
                name=origin, path="", origin=origin,
                host=host, port=port, tls=tls, kind="host",
            )
            roots[key] = host_node

        segments = [segment for segment in path.split("/") if segment]
        if not segments:
            # The root document. Give it a visible node of its own.
            target = _child(host_node, "/", budget)
        else:
            target = host_node
            for segment in segments:
                nxt = _child(target, segment, budget)
                if nxt is None:
                    truncated = True
                    break
                target = nxt
        if target is None:
            truncated = True
            continue
        _accumulate(target, row)

    hosts = [_finalise(node, settings) for node in roots.values()]
    # Group by hostname first: sorting on the full origin would order by scheme
    # ("http://z" before "https://a"), which scatters a host's two trees.
    hosts.sort(key=lambda h: (not h["in_scope"], h["host"].lower(), h["port"], h["tls"]))
    return hosts, truncated
