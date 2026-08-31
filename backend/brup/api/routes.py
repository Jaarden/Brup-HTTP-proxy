"""HTTP API and WebSocket event feed."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import re
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from pydantic import BaseModel, Field

from .. import http_message as hm
from ..config import in_scope, validate_header_rules
from ..intruder import MARKER, AttackConfig, ParseError, fix_content_length
from ..netutil import decode_content
from ..projects import ProjectError
from ..proxy.upstream import send_request
from ..sitemap import build_sitemap
from ..vpn import VpnError, describe_config, detect_kind

router = APIRouter()


def _state():
    from ..main import state
    return state


def _pid() -> str:
    """Id of the active project. Everything project-scoped goes through here."""
    return _state().projects.active_id


def _b64(data: bytes | None) -> str | None:
    return base64.b64encode(data).decode() if data else None


def _unb64(value: str | None) -> bytes:
    return base64.b64decode(value) if value else b""


def _project_error(exc: ProjectError) -> HTTPException:
    return HTTPException(400, str(exc))


# ==========================================================================
# Status
# ==========================================================================

@router.get("/api/status")
async def get_status():
    st = _state()
    return {
        "proxy": st.proxy.state(),
        "ca": {
            "fingerprint_sha256": st.ca.fingerprint_sha256(),
            "not_valid_after": st.ca.not_valid_after(),
        },
        "project": st.projects.public(st.projects.active),
        # Carried here so the top bar stays current off the existing poll
        # rather than needing a request of its own.
        "vpn": st.vpn.status(),
        "ui_clients": st.hub.subscriber_count,
        "server_time": time.time(),
    }


# ==========================================================================
# Projects
# ==========================================================================

class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    copy_settings_from: str | None = None
    # A temporary project is discarded when BRUP restarts.
    temporary: bool = False


class ProjectPatch(BaseModel):
    name: str | None = None
    notes: str | None = None


@router.get("/api/projects")
async def list_projects():
    st = _state()
    return {"active_id": st.projects.active_id, "items": await st.projects.list()}


@router.post("/api/projects")
async def create_project(body: ProjectCreate, activate: bool = True):
    st = _state()
    try:
        project = await st.projects.create(
            body.name,
            copy_settings_from=body.copy_settings_from,
            temporary=body.temporary,
        )
        if activate:
            await st.projects.activate(project["id"])
    except ProjectError as exc:
        raise _project_error(exc) from exc
    return {"project": project, "active_id": st.projects.active_id}


@router.post("/api/projects/{project_id}/activate")
async def activate_project(project_id: str):
    st = _state()
    try:
        project = await st.projects.activate(project_id)
    except ProjectError as exc:
        raise _project_error(exc) from exc
    return {"project": project, "active_id": st.projects.active_id}


@router.post("/api/projects/{project_id}/keep")
async def keep_project(project_id: str):
    """Promote a temporary project so it survives a restart."""
    st = _state()
    try:
        return await st.projects.keep(project_id)
    except ProjectError as exc:
        raise _project_error(exc) from exc


@router.patch("/api/projects/{project_id}")
async def patch_project(project_id: str, body: ProjectPatch):
    st = _state()
    try:
        project = None
        if body.name is not None:
            project = await st.projects.rename(project_id, body.name)
        if body.notes is not None:
            project = await st.projects.set_notes(project_id, body.notes)
    except ProjectError as exc:
        raise _project_error(exc) from exc
    if project is None:
        raise HTTPException(400, "nothing to change")
    return project


@router.delete("/api/projects/{project_id}")
async def delete_project(project_id: str):
    st = _state()
    try:
        active = await st.projects.delete(project_id)
    except ProjectError as exc:
        raise _project_error(exc) from exc
    return {"deleted": project_id, "active_id": active}


# ==========================================================================
# Settings - two tiers: system-wide defaults, per-project overrides
# ==========================================================================

@router.get("/api/settings")
async def get_settings():
    """Effective settings plus both tiers, so the UI can show what is overridden."""
    return _state().projects.describe_settings()


@router.put("/api/settings/system")
async def put_system_settings(patch: dict[str, Any]):
    st = _state()
    old = st.store.settings

    for key in ("scope_include", "scope_exclude"):
        for rule in patch.get(key, []) or []:
            pattern = (rule or {}).get("pattern", "")
            if pattern:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise HTTPException(
                        400, f"Invalid regex in {key}: {pattern!r} - {exc}"
                    ) from exc

    if "header_rules" in patch:
        try:
            validate_header_rules(patch["header_rules"])
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    try:
        new = await st.projects.update_system(patch)
    except Exception as exc:  # noqa: BLE001 - surface validation errors verbatim
        raise HTTPException(400, f"Invalid settings: {exc}") from exc

    needs_restart = (
        old.proxy_host != new.proxy_host
        or old.proxy_port != new.proxy_port
        or old.invisible_tls_enabled != new.invisible_tls_enabled
        or old.invisible_tls_port != new.invisible_tls_port
    )
    if needs_restart:
        try:
            await st.proxy.restart()
        except OSError as exc:
            raise HTTPException(
                400, f"Settings saved, but the listener could not bind: {exc}"
            ) from exc

    return {
        **st.projects.describe_settings(),
        "restarted": needs_restart,
        "proxy": st.proxy.state(),
    }


@router.put("/api/settings/project")
async def put_project_settings(patch: dict[str, Any], project_id: str | None = None):
    """Patch the active (or named) project's overrides. A null value clears one."""
    st = _state()
    for key in ("scope_include", "scope_exclude"):
        for rule in patch.get(key, []) or []:
            pattern = (rule or {}).get("pattern", "")
            if pattern:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise HTTPException(
                        400, f"Invalid regex in {key}: {pattern!r} - {exc}"
                    ) from exc
    if "header_rules" in patch:
        try:
            validate_header_rules(patch["header_rules"])
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    try:
        project = await st.projects.set_overrides(project_id or _pid(), patch)
    except ProjectError as exc:
        raise _project_error(exc) from exc
    return {**st.projects.describe_settings(), "project": project}


@router.post("/api/proxy/{action}")
async def proxy_control(action: str):
    st = _state()
    if action not in ("start", "stop", "restart"):
        raise HTTPException(404, "unknown action")
    try:
        await getattr(st.proxy, action)()
    except OSError as exc:
        raise HTTPException(400, f"{action} failed: {exc}") from exc
    return st.proxy.state()


# ==========================================================================
# CA certificate (system-wide)
# ==========================================================================

@router.get("/api/ca/cert.pem")
async def ca_pem():
    return Response(
        _state().ca.cert_pem(),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="brup-ca.pem"'},
    )


@router.get("/api/ca/cert.der")
async def ca_der():
    return Response(
        _state().ca.cert_der(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": 'attachment; filename="brup-ca.der"'},
    )


# ==========================================================================
# Proxy history
# ==========================================================================

@router.get("/api/history")
async def list_history(
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    search: str = "",
    host: str = "",
    method: str = "",
    status: int | None = None,
    source: str = "",
    in_scope_only: bool = False,
):
    return await _state().db.list_flows(
        _pid(), limit=limit, offset=offset, search=search, host=host,
        method=method, status=status, source=source, in_scope_only=in_scope_only,
    )


@router.get("/api/history/hosts")
async def history_hosts():
    return await _state().db.hosts(_pid())


@router.delete("/api/history")
async def clear_history():
    await _state().db.clear_flows(_pid())
    _state().hub.publish("history_cleared", None)
    return {"ok": True}


def _decoded_body(raw: bytes | None) -> dict[str, Any]:
    """Split a raw response and content-decode its body for display."""
    if not raw:
        return {}
    try:
        resp = hm.parse_response(raw)
    except hm.ParseError:
        return {}
    body, error = decode_content(resp.header("content-encoding"), resp.body)
    if body == resp.body and error is None:
        return {}
    return {"decoded_body_b64": _b64(body), "decode_error": error}


@router.get("/api/history/{flow_id}")
async def get_history_item(flow_id: int):
    flow = await _state().db.get_flow(_pid(), flow_id)
    if flow is None:
        raise HTTPException(404, "no such flow in this project")
    raw_response = flow.pop("raw_response", None)
    raw_request = flow.pop("raw_request", None)
    return {
        **flow,
        "raw_request_b64": _b64(raw_request),
        "raw_response_b64": _b64(raw_response),
        **_decoded_body(raw_response),
    }


class FlowAnnotation(BaseModel):
    notes: str | None = None
    color: str | None = None


@router.patch("/api/history/{flow_id}")
async def annotate_flow(flow_id: int, body: FlowAnnotation):
    st = _state()
    if await st.db.get_flow(_pid(), flow_id) is None:
        raise HTTPException(404, "no such flow in this project")
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    if fields:
        await st.db.update_flow(flow_id, **fields)
    return {"ok": True, **fields}


# ==========================================================================
# Sitemap
# ==========================================================================

@router.get("/api/sitemap")
async def get_sitemap(
    limit: int = Query(20000, ge=1, le=200000),
    in_scope_only: bool = False,
):
    """Host/path tree derived from the active project's history."""
    st = _state()
    rows = await st.db.sitemap_rows(_pid(), limit)
    hosts, truncated = build_sitemap(
        rows, st.projects.settings, in_scope_only=in_scope_only
    )
    return {
        "hosts": hosts,
        "truncated": truncated or len(rows) >= limit,
        "rows_considered": len(rows),
    }


@router.get("/api/sitemap/items")
async def sitemap_items(
    origin: str = Query(..., description="scheme://host[:port]"),
    path: str = "",
    recursive: bool = True,
    limit: int = Query(300, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    """Logged items at (or under) one node of the tree."""
    prefix = origin.rstrip("/") + (path or "/")
    return await _state().db.list_flows(
        _pid(),
        url_prefix=prefix,
        url_prefix_mode="subtree" if recursive else "exact",
        limit=limit,
        offset=offset,
    )


class ScopeAddition(BaseModel):
    origin: str
    path: str = ""
    kind: str = "include"      # include | exclude
    whole_host: bool = True


@router.post("/api/sitemap/scope")
async def add_to_scope(body: ScopeAddition):
    """Add a sitemap branch to the active project's scope rules."""
    st = _state()
    if body.kind not in ("include", "exclude"):
        raise HTTPException(400, "kind must be 'include' or 'exclude'")
    target = body.origin.rstrip("/") + ("" if body.whole_host else (body.path or ""))
    pattern = "^" + re.escape(target)

    field = f"scope_{body.kind}"
    effective = st.projects.settings
    rules = [rule.model_dump() for rule in getattr(effective, field)]
    if any(rule["pattern"] == pattern for rule in rules):
        return {"added": False, "pattern": pattern,
                **st.projects.describe_settings()}
    rules.append({"enabled": True, "pattern": pattern})
    try:
        await st.projects.set_overrides(_pid(), {field: rules})
    except ProjectError as exc:
        raise _project_error(exc) from exc
    return {"added": True, "pattern": pattern, **st.projects.describe_settings()}


# ==========================================================================
# Interception
# ==========================================================================

@router.get("/api/intercept")
async def list_intercepts():
    st = _state()
    return {
        "enabled": st.projects.settings.intercept_enabled,
        "items": st.interceptor.list_pending(),
    }


class InterceptDecision(BaseModel):
    raw_b64: str | None = None


@router.post("/api/intercept/forward-all")
async def forward_all():
    return {"forwarded": _state().interceptor.forward_all()}


@router.post("/api/intercept/drop-all")
async def drop_all():
    return {"dropped": _state().interceptor.drop_all()}


@router.post("/api/intercept/{item_id}/forward")
async def forward_one(item_id: str, body: InterceptDecision):
    raw = _unb64(body.raw_b64) if body.raw_b64 else None
    if not _state().interceptor.forward(item_id, raw):
        raise HTTPException(404, "this message is no longer held")
    return {"ok": True}


@router.post("/api/intercept/{item_id}/drop")
async def drop_one(item_id: str):
    if not _state().interceptor.drop(item_id):
        raise HTTPException(404, "this message is no longer held")
    return {"ok": True}


# ==========================================================================
# Repeater
# ==========================================================================

class RepeaterRequest(BaseModel):
    host: str
    port: int = 80
    tls: bool = False
    raw_b64: str
    update_content_length: bool = False
    log: bool = True


@router.post("/api/repeater/send")
async def repeater_send(body: RepeaterRequest):
    st = _state()
    settings = st.projects.settings
    raw = _unb64(body.raw_b64)
    if not raw.strip():
        raise HTTPException(400, "empty request")
    if body.update_content_length:
        raw = fix_content_length(raw)

    blocked = st.vpn.killswitch_error(settings)
    if blocked:
        return {
            "ok": False, "error": blocked, "duration_ms": 0.0, "status": None,
            "reason": None, "length": 0, "raw_response_b64": None, "flow_id": None,
        }

    result = await send_request(body.host, body.port, body.tls, raw, settings)

    try:
        req = hm.parse_request(raw)
        url = hm.build_url(body.tls, body.host, body.port, req.target)
        method = req.method.decode("latin-1", "replace")
        target = req.target.decode("latin-1", "replace")
    except hm.ParseError:
        url, method, target = f"//{body.host}:{body.port}", "?", "?"

    flow_id = None
    if body.log and settings.logging_enabled:
        resp = result.response
        cap = settings.max_stored_body
        flow_id = await st.db.insert_flow(
            project_id=_pid(),
            source="repeater", host=body.host, port=body.port, tls=int(body.tls),
            method=method, target=target, url=url,
            status=resp.status if resp else None,
            reason=resp.reason.decode("latin-1", "replace") if resp else None,
            mime=((resp.header("content-type") or b"").decode("latin-1", "replace")
                  .split(";")[0].strip() if resp else None),
            req_len=len(raw), resp_len=len(result.raw_response),
            duration_ms=result.duration_ms, error=result.error,
            in_scope=int(in_scope(settings, url)),
            raw_request=raw,
            raw_response=result.raw_response[:cap] if result.raw_response else None,
        )
        st.hub.publish("flow_new", {
            "id": flow_id, "ts": time.time(), "source": "repeater",
            "host": body.host, "port": body.port, "tls": body.tls,
            "method": method, "url": url,
            "status": resp.status if resp else None,
            "resp_len": len(result.raw_response),
            "duration_ms": result.duration_ms, "error": result.error,
        })

    return {
        "ok": result.ok,
        "error": result.error,
        "duration_ms": round(result.duration_ms, 1),
        "status": result.response.status if result.response else None,
        "reason": (result.response.reason.decode("latin-1", "replace")
                   if result.response else None),
        "length": len(result.raw_response),
        "raw_response_b64": _b64(result.raw_response),
        "flow_id": flow_id,
        **_decoded_body(result.raw_response or None),
    }


class RepeaterTab(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    name: str = ""
    host: str = ""
    port: int = 80
    tls: bool = False
    raw_b64: str = ""
    trail: list[str] = Field(default_factory=list)


@router.get("/api/repeater/tabs")
async def get_repeater_tabs():
    """Repeater tabs belonging to the active project."""
    tabs = await _state().db.list_tabs(_pid())
    return {
        "items": [
            {
                "id": tab["id"],
                "name": tab["name"],
                "host": tab["host"],
                "port": tab["port"],
                "tls": bool(tab["tls"]),
                "raw_b64": _b64(tab["raw"]) or "",
                "trail": tab["trail"],
            }
            for tab in tabs
        ]
    }


@router.put("/api/repeater/tabs")
async def put_repeater_tabs(tabs: list[RepeaterTab]):
    """Replace the whole ordered tab list; the UI owns the ordering."""
    if len(tabs) > 200:
        raise HTTPException(400, "too many Repeater tabs (limit 200)")
    await _state().db.replace_tabs(_pid(), [
        {
            "id": tab.id, "name": tab.name, "host": tab.host, "port": tab.port,
            "tls": tab.tls, "raw": _unb64(tab.raw_b64),
            "trail": tab.trail[-25:],
        }
        for tab in tabs
    ])
    return {"ok": True, "count": len(tabs)}


# ==========================================================================
# Intruder
# ==========================================================================

async def _attack_or_404(attack_id: str) -> dict:
    st = _state()
    for summary in await st.intruder.list_attacks():
        if summary["id"] == attack_id:
            return summary
    raise HTTPException(404, "no such attack in this project")


@router.post("/api/intruder/preview")
async def intruder_preview(config: AttackConfig):
    try:
        return await _state().intruder.preview(config)
    except ParseError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/intruder/start")
async def intruder_start(config: AttackConfig):
    try:
        attack = await _state().intruder.start(config)
    except ParseError as exc:
        raise HTTPException(400, str(exc)) from exc
    return attack.summary()


@router.get("/api/intruder")
async def intruder_list():
    return await _state().intruder.list_attacks()


@router.get("/api/intruder/{attack_id}")
async def intruder_get(attack_id: str):
    return await _attack_or_404(attack_id)


@router.get("/api/intruder/{attack_id}/results")
async def intruder_results(
    attack_id: str,
    limit: int = Query(2000, ge=1, le=20000),
    offset: int = Query(0, ge=0),
):
    await _attack_or_404(attack_id)
    rows = await _state().db.list_results(attack_id, limit, offset)
    for row in rows:
        row["payloads"] = row["payloads"].split("\x1f") if row["payloads"] else []
        row["grep_hits"] = row["grep_hits"].split(",") if row["grep_hits"] else []
    return {"items": rows}


@router.get("/api/intruder/{attack_id}/results/{idx}")
async def intruder_result(attack_id: str, idx: int):
    await _attack_or_404(attack_id)
    row = await _state().db.get_result(attack_id, idx)
    if row is None:
        raise HTTPException(404, "no such result")
    raw_request = row.pop("raw_request", None)
    raw_response = row.pop("raw_response", None)
    row["payloads"] = row["payloads"].split("\x1f") if row["payloads"] else []
    row["grep_hits"] = row["grep_hits"].split(",") if row["grep_hits"] else []
    return {
        **row,
        "raw_request_b64": _b64(raw_request),
        "raw_response_b64": _b64(raw_response),
        **_decoded_body(raw_response),
    }


@router.post("/api/intruder/{attack_id}/{action}")
async def intruder_control(attack_id: str, action: str):
    st = _state()
    if action not in ("pause", "resume", "stop"):
        raise HTTPException(404, "unknown action")
    await _attack_or_404(attack_id)
    if not getattr(st.intruder, action)(attack_id):
        raise HTTPException(400, f"cannot {action} this attack in its current state")
    return await _attack_or_404(attack_id)


@router.delete("/api/intruder/{attack_id}")
async def intruder_delete(attack_id: str):
    await _attack_or_404(attack_id)
    if not await _state().intruder.delete(attack_id):
        raise HTTPException(404, "no such attack")
    return {"ok": True}


class MarkPositionsRequest(BaseModel):
    raw_b64: str
    mode: str = "auto"   # auto | clear


@router.post("/api/intruder/mark")
async def mark_positions(body: MarkPositionsRequest):
    """Auto-mark payload positions, mirroring Burp's default guess.

    Marks every query-string and body parameter value, plus cookie values.
    """
    raw = _unb64(body.raw_b64)
    stripped = raw.replace(MARKER, b"")
    if body.mode == "clear":
        return {"raw_b64": _b64(stripped) or "", "positions": 0}

    try:
        req = hm.parse_request(stripped)
    except hm.ParseError as exc:
        raise HTTPException(400, f"cannot parse request: {exc}") from exc

    def mark_pairs(blob: bytes, sep: bytes) -> tuple[bytes, int]:
        count = 0
        out = []
        for pair in blob.split(sep):
            name, eq, value = pair.partition(b"=")
            if eq and value:
                out.append(name + b"=" + MARKER + value + MARKER)
                count += 1
            else:
                out.append(pair)
        return sep.join(out), count

    total = 0
    target = req.target
    if b"?" in target:
        path, _, query = target.partition(b"?")
        marked, n = mark_pairs(query, b"&")
        target = path + b"?" + marked
        total += n
    req.target = target

    for i, (name, value) in enumerate(req.headers):
        if name.lower() == b"cookie" and value:
            marked, n = mark_pairs(value, b";")
            req.headers[i] = (name, marked)
            total += n

    ctype = (req.header("content-type") or b"").lower()
    if req.body and b"x-www-form-urlencoded" in ctype:
        marked, n = mark_pairs(req.body, b"&")
        req.body = marked
        total += n

    return {"raw_b64": _b64(req.raw) or "", "positions": total}


# ==========================================================================
# VPN (system-wide: one network namespace means one tunnel)
# ==========================================================================

def _vpn_error(exc: VpnError) -> HTTPException:
    return HTTPException(400, str(exc))


class VpnProfileBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    config: str
    username: str = ""
    password: str = ""
    notes: str = ""
    kind: str | None = None


class VpnConnectBody(BaseModel):
    profile_id: str


class VpnInspectBody(BaseModel):
    config: str


@router.get("/api/vpn")
async def vpn_overview():
    st = _state()
    return {
        "status": st.vpn.status(),
        "profiles": await st.vpn.list_profiles(),
        "log": st.vpn.log_tail(60),
    }


@router.get("/api/vpn/log")
async def vpn_log(limit: int = Query(200, ge=1, le=400)):
    return {"lines": _state().vpn.log_tail(limit)}


@router.post("/api/vpn/inspect")
async def vpn_inspect(body: VpnInspectBody):
    """Detect the type of a pasted config and report what it will do."""
    try:
        kind = detect_kind(body.config)
    except VpnError as exc:
        raise _vpn_error(exc) from exc
    return {"kind": kind, **describe_config(kind, body.config)}


@router.get("/api/vpn/profiles")
async def vpn_profiles():
    return await _state().vpn.list_profiles()


@router.post("/api/vpn/profiles")
async def vpn_save_profile(body: VpnProfileBody):
    st = _state()
    try:
        return await st.vpn.save_profile(
            name=body.name, config=body.config, username=body.username,
            password=body.password, notes=body.notes,
            kind=body.kind,  # type: ignore[arg-type]
        )
    except VpnError as exc:
        raise _vpn_error(exc) from exc


@router.delete("/api/vpn/profiles/{profile_id}")
async def vpn_delete_profile(profile_id: str):
    try:
        await _state().vpn.delete_profile(profile_id)
    except VpnError as exc:
        raise _vpn_error(exc) from exc
    return {"ok": True}


@router.post("/api/vpn/connect")
async def vpn_connect(body: VpnConnectBody):
    st = _state()
    try:
        return await st.vpn.connect(body.profile_id)
    except VpnError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/vpn/disconnect")
async def vpn_disconnect():
    return await _state().vpn.disconnect()


@router.post("/api/vpn/check")
async def vpn_check():
    """Confirm the tunnel carries traffic by asking an external service."""
    try:
        return await _state().vpn.check_exit_ip()
    except VpnError as exc:
        raise _vpn_error(exc) from exc


# ==========================================================================
# Wordlists (shared across projects)
# ==========================================================================

class WordlistBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    content: str


@router.get("/api/wordlists")
async def list_wordlists():
    return await _state().db.list_wordlists()


@router.post("/api/wordlists")
async def save_wordlist(body: WordlistBody):
    return await _state().db.save_wordlist(body.name.strip(), body.content)


@router.get("/api/wordlists/{name}")
async def get_wordlist(name: str):
    content = await _state().db.get_wordlist(name)
    if content is None:
        raise HTTPException(404, "no such wordlist")
    return {"name": name, "content": content}


@router.delete("/api/wordlists/{name}")
async def delete_wordlist(name: str):
    await _state().db.delete_wordlist(name)
    return {"ok": True}


# ==========================================================================
# Live event feed
# ==========================================================================

@router.websocket("/ws")
async def websocket_feed(ws: WebSocket):
    await ws.accept()
    st = _state()
    queue = st.hub.subscribe()
    await ws.send_json({"type": "hello", "data": st.proxy.state()})

    async def drain_client() -> None:
        # We do not expect inbound messages; this just detects disconnects.
        while True:
            await ws.receive_text()

    reader = asyncio.create_task(drain_client())
    getter = asyncio.create_task(queue.get())
    try:
        while True:
            done, _ = await asyncio.wait(
                {reader, getter}, return_when=asyncio.FIRST_COMPLETED
            )
            if reader in done:
                return  # client went away
            if getter in done:
                message = getter.result()
                # Only replace the getter once its result is safely in hand, so
                # no event is pulled off the queue and then dropped.
                getter = asyncio.create_task(queue.get())
                await ws.send_text(message)
    except (WebSocketDisconnect, RuntimeError, ConnectionError):
        pass
    finally:
        st.hub.unsubscribe(queue)
        for task in (reader, getter):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
