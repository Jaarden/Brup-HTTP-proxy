"""SQLite storage.

Everything that belongs to a project carries a ``project_id``. A single database
file is used rather than one per project: the proxy is long-running, so swapping
scope is a variable change instead of closing and reopening a connection that
in-flight writes may still be holding.

All access is funnelled through a single-thread executor: sqlite3 is blocking,
and one writer thread keeps things simple and free of lock contention.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "4"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS projects (
    id        TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    created   REAL NOT NULL,
    updated   REAL NOT NULL,
    notes     TEXT NOT NULL DEFAULT '',
    overrides TEXT NOT NULL DEFAULT '{}',
    temporary INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS flows (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    TEXT    NOT NULL,
    ts            REAL    NOT NULL,
    source        TEXT    NOT NULL DEFAULT 'proxy',
    host          TEXT    NOT NULL,
    port          INTEGER NOT NULL,
    tls           INTEGER NOT NULL DEFAULT 0,
    method        TEXT,
    target        TEXT,
    url           TEXT,
    status        INTEGER,
    reason        TEXT,
    mime          TEXT,
    req_len       INTEGER DEFAULT 0,
    resp_len      INTEGER DEFAULT 0,
    duration_ms   REAL,
    was_edited    INTEGER DEFAULT 0,
    in_scope      INTEGER DEFAULT 1,
    notes         TEXT    DEFAULT '',
    color         TEXT    DEFAULT '',
    error         TEXT,
    raw_request   BLOB,
    raw_response  BLOB
);
CREATE INDEX IF NOT EXISTS idx_flows_project ON flows(project_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_flows_host    ON flows(project_id, host);

CREATE TABLE IF NOT EXISTS intruder_attacks (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL,
    created      REAL NOT NULL,
    updated      REAL NOT NULL,
    name         TEXT DEFAULT '',
    host         TEXT,
    port         INTEGER,
    tls          INTEGER DEFAULT 0,
    attack_type  TEXT,
    positions    INTEGER DEFAULT 0,
    total        INTEGER DEFAULT 0,
    completed    INTEGER DEFAULT 0,
    errors       INTEGER DEFAULT 0,
    status       TEXT DEFAULT 'running',
    message      TEXT DEFAULT '',
    config       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_attacks_project
    ON intruder_attacks(project_id, created DESC);

CREATE TABLE IF NOT EXISTS intruder_results (
    attack_id    TEXT    NOT NULL,
    idx          INTEGER NOT NULL,
    payloads     TEXT    NOT NULL,
    position     INTEGER,
    status       INTEGER,
    reason       TEXT,
    resp_len     INTEGER,
    words        INTEGER,
    duration_ms  REAL,
    error        TEXT,
    grep_hits    TEXT    DEFAULT '',
    raw_request  BLOB,
    raw_response BLOB,
    PRIMARY KEY (attack_id, idx)
);

CREATE TABLE IF NOT EXISTS repeater_tabs (
    id         TEXT PRIMARY KEY,
    project_id TEXT    NOT NULL,
    position   INTEGER NOT NULL DEFAULT 0,
    name       TEXT    NOT NULL DEFAULT '',
    host       TEXT    NOT NULL DEFAULT '',
    port       INTEGER NOT NULL DEFAULT 80,
    tls        INTEGER NOT NULL DEFAULT 0,
    raw        BLOB,
    trail      TEXT    NOT NULL DEFAULT '[]',
    updated    REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tabs_project ON repeater_tabs(project_id, position);

-- VPN profiles are system-wide: one network namespace means one tunnel.
CREATE TABLE IF NOT EXISTS vpn_profiles (
    id       TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    kind     TEXT NOT NULL,
    config   TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL DEFAULT '',
    notes    TEXT NOT NULL DEFAULT '',
    created  REAL NOT NULL
);

-- Wordlists are shared tooling rather than project findings, so they are global.
CREATE TABLE IF NOT EXISTS wordlists (
    name    TEXT PRIMARY KEY,
    ts      REAL NOT NULL,
    lines   INTEGER NOT NULL,
    content TEXT NOT NULL
);
"""

# Backslash is the LIKE escape character used by the URL prefix filters.
LIKE_ESCAPE = "ESCAPE '" + chr(92) + "'"

FLOW_LIST_COLUMNS = (
    "id, project_id, ts, source, host, port, tls, method, target, url, status, "
    "reason, mime, req_len, resp_len, duration_ms, was_edited, in_scope, notes, "
    "color, error"
)

ATTACK_COLUMNS = (
    "id, project_id, created, updated, name, host, port, tls, attack_type, "
    "positions, total, completed, errors, status, message"
)


class IncompatibleDatabase(RuntimeError):
    """Raised when an on-disk database predates project support."""


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="brup-db")
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._check_compatible()
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._add_missing_columns()
        self._purge_temporary_projects()
        self._set_meta("schema_version", SCHEMA_VERSION)
        # A run that was killed leaves attacks marked running; they are not.
        self._conn.execute(
            "UPDATE intruder_attacks SET status = 'stopped', "
            "message = 'interrupted by a restart' "
            "WHERE status IN ('running', 'paused')"
        )
        self._conn.commit()

    def _check_compatible(self) -> None:
        """Refuse to run against a pre-projects database instead of corrupting it."""
        tables = {
            row["name"]
            for row in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if "flows" not in tables:
            return
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(flows)")}
        if "project_id" not in columns:
            raise IncompatibleDatabase(
                f"{self.path} was written before projects existed and cannot be "
                "upgraded in place. Remove the data volume to start fresh: "
                "`docker compose down -v`."
            )

    def _add_missing_columns(self) -> None:
        """Additive schema changes, applied to databases created by older builds."""
        additions = [
            ("projects", "temporary", "INTEGER NOT NULL DEFAULT 0"),
        ]
        for table, column, decl in additions:
            existing = {
                row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})")
            }
            if existing and column not in existing:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        self._conn.commit()

    def _purge_temporary_projects(self) -> None:
        """Temporary projects last for one run, like Burp's temporary project."""
        rows = self._conn.execute(
            "SELECT id FROM projects WHERE temporary = 1"
        ).fetchall()
        for row in rows:
            self._delete_project(row["id"])

    async def _run(self, fn, *args):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, fn, *args)

    def close(self) -> None:
        self._executor.shutdown(wait=True)
        self._conn.close()

    # ------------------------------------------------------------------ meta
    def _set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value)
        )
        self._conn.commit()

    def _get_meta(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    async def set_meta(self, key: str, value: str) -> None:
        await self._run(self._set_meta, key, value)

    async def get_meta(self, key: str) -> str | None:
        return await self._run(self._get_meta, key)

    # -------------------------------------------------------------- projects
    def _list_projects(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT p.id, p.name, p.created, p.updated, p.notes, p.overrides, "
            "p.temporary, "
            "(SELECT COUNT(*) FROM flows f WHERE f.project_id = p.id) AS flow_count, "
            "(SELECT COUNT(*) FROM intruder_attacks a WHERE a.project_id = p.id) "
            "   AS attack_count "
            "FROM projects p ORDER BY p.created"
        ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["overrides"] = json.loads(item["overrides"] or "{}")
            out.append(item)
        return out

    async def list_projects(self) -> list[dict[str, Any]]:
        return await self._run(self._list_projects)

    def _create_project(self, name: str, overrides: str, temporary: int) -> dict[str, Any]:
        now = time.time()
        project_id = uuid.uuid4().hex[:12]
        self._conn.execute(
            "INSERT INTO projects (id, name, created, updated, overrides, temporary) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (project_id, name, now, now, overrides, temporary),
        )
        self._conn.commit()
        return {
            "id": project_id, "name": name, "created": now, "updated": now,
            "notes": "", "overrides": json.loads(overrides), "flow_count": 0,
            "attack_count": 0, "temporary": temporary,
        }

    async def create_project(
        self,
        name: str,
        overrides: dict[str, Any] | None = None,
        *,
        temporary: bool = False,
    ):
        return await self._run(
            self._create_project, name, json.dumps(overrides or {}), int(temporary)
        )

    def _get_project(self, project_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["overrides"] = json.loads(item["overrides"] or "{}")
        return item

    async def get_project(self, project_id: str):
        return await self._run(self._get_project, project_id)

    def _update_project(self, project_id: str, fields: dict[str, Any]) -> None:
        fields = {**fields, "updated": time.time()}
        assignments = ", ".join(f"{k} = ?" for k in fields)
        self._conn.execute(
            f"UPDATE projects SET {assignments} WHERE id = ?",
            [*fields.values(), project_id],
        )
        self._conn.commit()

    async def update_project(self, project_id: str, **fields: Any) -> None:
        if "overrides" in fields and not isinstance(fields["overrides"], str):
            fields["overrides"] = json.dumps(fields["overrides"])
        await self._run(self._update_project, project_id, fields)

    def _delete_project(self, project_id: str) -> None:
        # Results hang off attacks, so clear them via the attack ids first.
        self._conn.execute(
            "DELETE FROM intruder_results WHERE attack_id IN "
            "(SELECT id FROM intruder_attacks WHERE project_id = ?)",
            (project_id,),
        )
        for table in ("flows", "intruder_attacks", "repeater_tabs"):
            self._conn.execute(f"DELETE FROM {table} WHERE project_id = ?", (project_id,))
        self._conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        self._conn.commit()

    async def delete_project(self, project_id: str) -> None:
        await self._run(self._delete_project, project_id)

    # ----------------------------------------------------------------- flows
    def _insert_flow(self, data: dict[str, Any]) -> int:
        cols = ", ".join(data)
        holes = ", ".join("?" for _ in data)
        cur = self._conn.execute(
            f"INSERT INTO flows ({cols}) VALUES ({holes})", list(data.values())
        )
        self._conn.commit()
        return int(cur.lastrowid)

    async def insert_flow(self, **data: Any) -> int:
        data.setdefault("ts", time.time())
        return await self._run(self._insert_flow, data)

    def _update_flow(self, flow_id: int, data: dict[str, Any]) -> None:
        assignments = ", ".join(f"{k} = ?" for k in data)
        self._conn.execute(
            f"UPDATE flows SET {assignments} WHERE id = ?", [*data.values(), flow_id]
        )
        self._conn.commit()

    async def update_flow(self, flow_id: int, **data: Any) -> None:
        if data:
            await self._run(self._update_flow, flow_id, data)

    @staticmethod
    def _like_escape(value: str) -> str:
        """Neutralise LIKE wildcards so a literal URL prefix matches literally."""
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def _list_flows(self, filters: dict[str, Any]) -> dict[str, Any]:
        where = ["project_id = ?"]
        params: list[Any] = [filters["project_id"]]

        if prefix := filters.get("url_prefix"):
            escaped = self._like_escape(prefix)
            if filters.get("url_prefix_mode") == "exact":
                # Just this path, with or without a query string.
                where.append(f"(url = ? OR url LIKE ? {LIKE_ESCAPE})")
                params += [prefix, escaped + "?%"]
            else:
                where.append(f"url LIKE ? {LIKE_ESCAPE}")
                params.append(escaped + "%")
        if search := filters.get("search"):
            where.append("(url LIKE ? OR method LIKE ? OR host LIKE ?)")
            like = f"%{search}%"
            params += [like, like, like]
        if host := filters.get("host"):
            where.append("host = ?")
            params.append(host)
        if (status := filters.get("status")) is not None:
            where.append("status = ?")
            params.append(status)
        if method := filters.get("method"):
            where.append("UPPER(method) = ?")
            params.append(method.upper())
        if source := filters.get("source"):
            where.append("source = ?")
            params.append(source)
        if filters.get("in_scope_only"):
            where.append("in_scope = 1")
        clause = f"WHERE {' AND '.join(where)}"

        total = self._conn.execute(
            f"SELECT COUNT(*) AS n FROM flows {clause}", params
        ).fetchone()["n"]
        rows = self._conn.execute(
            f"SELECT {FLOW_LIST_COLUMNS} FROM flows {clause} "
            "ORDER BY id DESC LIMIT ? OFFSET ?",
            [*params, filters.get("limit", 200), filters.get("offset", 0)],
        ).fetchall()
        return {"total": total, "items": [dict(r) for r in rows]}

    async def list_flows(self, project_id: str, **filters: Any) -> dict[str, Any]:
        return await self._run(self._list_flows, {**filters, "project_id": project_id})

    def _get_flow(self, project_id: str, flow_id: int) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM flows WHERE id = ? AND project_id = ?", (flow_id, project_id)
        ).fetchone()
        return dict(row) if row else None

    async def get_flow(self, project_id: str, flow_id: int):
        return await self._run(self._get_flow, project_id, flow_id)

    def _clear_flows(self, project_id: str) -> None:
        self._conn.execute("DELETE FROM flows WHERE project_id = ?", (project_id,))
        self._conn.commit()

    async def clear_flows(self, project_id: str) -> None:
        await self._run(self._clear_flows, project_id)

    def _trim(self, project_id: str, keep: int) -> None:
        self._conn.execute(
            "DELETE FROM flows WHERE project_id = ? AND id NOT IN "
            "(SELECT id FROM flows WHERE project_id = ? ORDER BY id DESC LIMIT ?)",
            (project_id, project_id, keep),
        )
        self._conn.commit()

    async def trim(self, project_id: str, keep: int) -> None:
        await self._run(self._trim, project_id, keep)

    def _hosts(self, project_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT host, COUNT(*) AS n FROM flows WHERE project_id = ? "
            "GROUP BY host ORDER BY n DESC LIMIT 200",
            (project_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    async def hosts(self, project_id: str):
        return await self._run(self._hosts, project_id)

    def _sitemap_rows(self, project_id: str, limit: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT host, port, tls, url, method, status, mime, "
            "MAX(id) AS last_id, COUNT(*) AS n FROM flows "
            "WHERE project_id = ? AND url IS NOT NULL AND url != '' "
            "GROUP BY host, port, tls, url, method "
            "ORDER BY host, url LIMIT ?",
            (project_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    async def sitemap_rows(self, project_id: str, limit: int = 20000):
        return await self._run(self._sitemap_rows, project_id, limit)

    # ------------------------------------------------------- intruder attacks
    def _upsert_attack(self, data: dict[str, Any]) -> None:
        cols = ", ".join(data)
        holes = ", ".join("?" for _ in data)
        self._conn.execute(
            f"INSERT OR REPLACE INTO intruder_attacks ({cols}) VALUES ({holes})",
            list(data.values()),
        )
        self._conn.commit()

    async def upsert_attack(self, **data: Any) -> None:
        if "config" in data and not isinstance(data["config"], str):
            data["config"] = json.dumps(data["config"])
        data.setdefault("updated", time.time())
        await self._run(self._upsert_attack, data)

    def _list_attacks(self, project_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            f"SELECT {ATTACK_COLUMNS} FROM intruder_attacks WHERE project_id = ? "
            "ORDER BY created DESC",
            (project_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    async def list_attacks(self, project_id: str):
        return await self._run(self._list_attacks, project_id)

    def _get_attack(self, attack_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM intruder_attacks WHERE id = ?", (attack_id,)
        ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["config"] = json.loads(item["config"] or "{}")
        return item

    async def get_attack(self, attack_id: str):
        return await self._run(self._get_attack, attack_id)

    def _delete_attack(self, attack_id: str) -> None:
        self._conn.execute("DELETE FROM intruder_results WHERE attack_id = ?", (attack_id,))
        self._conn.execute("DELETE FROM intruder_attacks WHERE id = ?", (attack_id,))
        self._conn.commit()

    async def delete_attack(self, attack_id: str) -> None:
        await self._run(self._delete_attack, attack_id)

    # ------------------------------------------------------- intruder results
    def _insert_result(self, data: dict[str, Any]) -> None:
        cols = ", ".join(data)
        holes = ", ".join("?" for _ in data)
        self._conn.execute(
            f"INSERT OR REPLACE INTO intruder_results ({cols}) VALUES ({holes})",
            list(data.values()),
        )
        self._conn.commit()

    async def insert_result(self, **data: Any) -> None:
        await self._run(self._insert_result, data)

    def _list_results(self, attack_id: str, limit: int, offset: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT attack_id, idx, payloads, position, status, reason, resp_len, words, "
            "duration_ms, error, grep_hits FROM intruder_results "
            "WHERE attack_id = ? ORDER BY idx LIMIT ? OFFSET ?",
            (attack_id, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]

    async def list_results(self, attack_id: str, limit: int = 2000, offset: int = 0):
        return await self._run(self._list_results, attack_id, limit, offset)

    def _get_result(self, attack_id: str, idx: int) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM intruder_results WHERE attack_id = ? AND idx = ?",
            (attack_id, idx),
        ).fetchone()
        return dict(row) if row else None

    async def get_result(self, attack_id: str, idx: int):
        return await self._run(self._get_result, attack_id, idx)

    def _delete_results(self, attack_id: str) -> None:
        self._conn.execute("DELETE FROM intruder_results WHERE attack_id = ?", (attack_id,))
        self._conn.commit()

    async def delete_results(self, attack_id: str) -> None:
        await self._run(self._delete_results, attack_id)

    # --------------------------------------------------------- repeater tabs
    def _list_tabs(self, project_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, position, name, host, port, tls, raw, trail FROM repeater_tabs "
            "WHERE project_id = ? ORDER BY position, id",
            (project_id,),
        ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["raw"] = item["raw"] or b""
            item["trail"] = json.loads(item["trail"] or "[]")
            out.append(item)
        return out

    async def list_tabs(self, project_id: str):
        return await self._run(self._list_tabs, project_id)

    def _replace_tabs(self, project_id: str, tabs: list[dict[str, Any]]) -> None:
        """Whole-list replace: the UI owns tab order, so this stays in step with it."""
        self._conn.execute("DELETE FROM repeater_tabs WHERE project_id = ?", (project_id,))
        now = time.time()
        self._conn.executemany(
            "INSERT INTO repeater_tabs "
            "(id, project_id, position, name, host, port, tls, raw, trail, updated) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    tab["id"], project_id, i, tab.get("name", ""), tab.get("host", ""),
                    int(tab.get("port", 80)), int(bool(tab.get("tls"))),
                    tab.get("raw", b""), json.dumps(tab.get("trail", [])), now,
                )
                for i, tab in enumerate(tabs)
            ],
        )
        self._conn.commit()

    async def replace_tabs(self, project_id: str, tabs: list[dict[str, Any]]) -> None:
        await self._run(self._replace_tabs, project_id, tabs)

    # ----------------------------------------------------------- vpn profiles
    def _list_vpn_profiles(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM vpn_profiles ORDER BY created"
        ).fetchall()
        return [dict(r) for r in rows]

    async def list_vpn_profiles(self):
        return await self._run(self._list_vpn_profiles)

    def _get_vpn_profile(self, profile_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM vpn_profiles WHERE id = ?", (profile_id,)
        ).fetchone()
        return dict(row) if row else None

    async def get_vpn_profile(self, profile_id: str):
        return await self._run(self._get_vpn_profile, profile_id)

    def _save_vpn_profile(self, data: dict[str, Any]) -> None:
        cols = ", ".join(data)
        holes = ", ".join("?" for _ in data)
        self._conn.execute(
            f"INSERT OR REPLACE INTO vpn_profiles ({cols}) VALUES ({holes})",
            list(data.values()),
        )
        self._conn.commit()

    async def save_vpn_profile(self, **data: Any) -> None:
        await self._run(self._save_vpn_profile, data)

    def _delete_vpn_profile(self, profile_id: str) -> None:
        self._conn.execute("DELETE FROM vpn_profiles WHERE id = ?", (profile_id,))
        self._conn.commit()

    async def delete_vpn_profile(self, profile_id: str) -> None:
        await self._run(self._delete_vpn_profile, profile_id)

    # ------------------------------------------------------------- wordlists
    def _save_wordlist(self, name: str, content: str) -> dict[str, Any]:
        lines = len([ln for ln in content.splitlines() if ln.strip()])
        self._conn.execute(
            "INSERT OR REPLACE INTO wordlists (name, ts, lines, content) VALUES (?, ?, ?, ?)",
            (name, time.time(), lines, content),
        )
        self._conn.commit()
        return {"name": name, "lines": lines}

    async def save_wordlist(self, name: str, content: str):
        return await self._run(self._save_wordlist, name, content)

    def _list_wordlists(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT name, ts, lines FROM wordlists ORDER BY name"
        ).fetchall()
        return [dict(r) for r in rows]

    async def list_wordlists(self):
        return await self._run(self._list_wordlists)

    def _get_wordlist(self, name: str) -> str | None:
        row = self._conn.execute(
            "SELECT content FROM wordlists WHERE name = ?", (name,)
        ).fetchone()
        return row["content"] if row else None

    async def get_wordlist(self, name: str):
        return await self._run(self._get_wordlist, name)

    def _delete_wordlist(self, name: str) -> None:
        self._conn.execute("DELETE FROM wordlists WHERE name = ?", (name,))
        self._conn.commit()

    async def delete_wordlist(self, name: str) -> None:
        await self._run(self._delete_wordlist, name)
