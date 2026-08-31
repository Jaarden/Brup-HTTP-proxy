"""The intercepting proxy listeners.

Two listeners are managed:

* the **main listener** speaks ordinary forward-proxy HTTP (``CONNECT`` plus
  absolute-form request targets) and, when invisible mode is on, also accepts
  origin-form requests from clients that do not know they are proxied;
* the optional **invisible TLS listener** terminates TLS directly using an
  SNI-selected certificate, for transparently redirected port 443 traffic.

Keeping invisible HTTPS on its own port avoids having to sniff a ClientHello out
of an already-buffered stream, which asyncio makes awkward and error-prone.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import time
from dataclasses import dataclass, field

from .. import http_message as hm
from ..ca import CertificateAuthority
from ..config import Settings, in_scope, should_intercept
from ..db import Database
from ..events import EventHub
from ..projects import ProjectManager
from ..netutil import STREAM_LIMIT, close_writer, tunnel, upgrade_to_tls
from ..vpn import VpnManager
from .interceptor import Interceptor
from .upstream import send_request

log = logging.getLogger("brup.proxy")

TRIM_EVERY = 500


@dataclass
class ProxyStats:
    requests: int = 0
    responses: int = 0
    dropped: int = 0
    errors: int = 0
    connections: int = 0
    started_at: float | None = None
    listeners: list[str] = field(default_factory=list)


def _error_response(status: int, reason: str, detail: str) -> bytes:
    body = (
        f"<!doctype html><html><head><title>BRUP {status}</title></head>"
        f"<body style=\"font:14px system-ui;padding:2rem\">"
        f"<h1>{status} {reason}</h1><p>{detail}</p>"
        f"<p style=\"color:#888\">BRUP intercepting proxy</p></body></html>"
    ).encode()
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return head + body


def _wants_close(req: hm.Request, resp: hm.Response | None) -> bool:
    if req.version.upper() == b"HTTP/1.0":
        conn = req.header("connection") or b""
        if b"keep-alive" not in conn.lower():
            return True
    for message in (req, resp):
        if message is None:
            continue
        conn = message.header("connection") or b""
        if b"close" in conn.lower():
            return True
    if resp is not None and resp.version.upper() == b"HTTP/1.0":
        conn = resp.header("connection") or b""
        if b"keep-alive" not in conn.lower():
            return True
    return False


class ProxyServer:
    def __init__(
        self,
        projects: ProjectManager,
        ca: CertificateAuthority,
        interceptor: Interceptor,
        hub: EventHub,
        db: Database,
        vpn: VpnManager | None = None,
    ):
        self.projects = projects
        self.vpn = vpn
        self.ca = ca
        self.interceptor = interceptor
        self.hub = hub
        self.db = db
        self.stats = ProxyStats()
        self._servers: list[asyncio.Server] = []
        self._tasks: set[asyncio.Task] = set()
        self._since_trim = 0

    @property
    def settings(self) -> Settings:
        """Effective settings: system defaults with the active project's overrides."""
        return self.projects.settings

    @property
    def project_id(self) -> str:
        return self.projects.active_id

    @property
    def running(self) -> bool:
        return bool(self._servers)

    # ------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        if self._servers:
            return
        cfg = self.settings
        listeners: list[str] = []

        main = await asyncio.start_server(
            lambda r, w: self._spawn(self._handle_plain(r, w)),
            cfg.proxy_host, cfg.proxy_port,
            limit=STREAM_LIMIT,
            reuse_address=True,
        )
        self._servers.append(main)
        listeners.append(f"http://{cfg.proxy_host}:{cfg.proxy_port}")

        if cfg.invisible_tls_enabled:
            try:
                tls_server = await asyncio.start_server(
                    lambda r, w: self._spawn(self._handle_tls_listener(r, w)),
                    cfg.proxy_host, cfg.invisible_tls_port,
                    ssl=self.ca.sni_context(),
                    limit=STREAM_LIMIT,
                    reuse_address=True,
                )
                self._servers.append(tls_server)
                listeners.append(f"tls://{cfg.proxy_host}:{cfg.invisible_tls_port}")
            except OSError as exc:
                log.error("invisible TLS listener failed to bind: %s", exc)

        self.stats.started_at = time.time()
        self.stats.listeners = listeners
        log.info("proxy listening on %s", ", ".join(listeners))
        self.hub.publish("proxy_state", self.state())

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
        for server in self._servers:
            try:
                await server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        self._servers.clear()
        for task in list(self._tasks):
            task.cancel()
        self.stats.listeners = []
        self.stats.started_at = None
        self.hub.publish("proxy_state", self.state())

    async def restart(self) -> None:
        await self.stop()
        await self.start()

    def state(self) -> dict:
        return {
            "running": self.running,
            "listeners": self.stats.listeners,
            "started_at": self.stats.started_at,
            "requests": self.stats.requests,
            "responses": self.stats.responses,
            "dropped": self.stats.dropped,
            "errors": self.stats.errors,
            "connections": self.stats.connections,
            "pending_intercepts": self.interceptor.pending_count,
        }

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ------------------------------------------------------ connection entry
    async def _handle_plain(self, reader, writer) -> None:
        """Main listener: forward-proxy semantics, plus invisible HTTP."""
        self.stats.connections += 1
        try:
            await self._serve_requests(reader, writer, tls=False, fixed_host=None)
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("unhandled error on proxy connection")
        finally:
            await close_writer(writer)

    async def _handle_tls_listener(self, reader, writer) -> None:
        """Invisible HTTPS listener: TLS is already terminated for us."""
        self.stats.connections += 1
        sni = None
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is not None:
            sni = getattr(ssl_object, "brup_sni", None)
        try:
            await self._serve_requests(
                reader, writer, tls=True,
                fixed_host=(sni, 443) if sni else None,
            )
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("unhandled error on TLS proxy connection")
        finally:
            await close_writer(writer)

    # ------------------------------------------------------- request pumping
    async def _serve_requests(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        tls: bool,
        fixed_host: tuple[str, int] | None,
    ) -> None:
        """Read requests off one client connection until it should close."""
        while True:
            try:
                head = await hm.read_head(reader)
            except (hm.ParseError, ConnectionError, OSError, ssl.SSLError):
                return
            if head is None:
                return  # clean EOF: the client is done with this connection

            try:
                req = hm.parse_request(head + b"\r\n\r\n")
            except hm.ParseError as exc:
                writer.write(_error_response(400, "Bad Request", f"Malformed request: {exc}"))
                await writer.drain()
                return

            if req.method.upper() == b"CONNECT":
                await self._handle_connect(req, reader, writer)
                return  # the connection is consumed by the tunnel either way

            target = self._resolve_target(req, tls=tls, fixed_host=fixed_host)
            if target is None:
                writer.write(_error_response(
                    400, "Bad Request",
                    "This request has no absolute URI and no Host header, so BRUP "
                    "cannot tell where to send it. Configure the client to use BRUP "
                    "as its HTTP proxy, or enable invisible proxying in Settings.",
                ))
                await writer.drain()
                return
            host, port, is_tls = target

            # A client may ask to be told before it streams a body.
            expect = req.header("expect") or b""
            if b"100-continue" in expect.lower():
                writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                await writer.drain()

            try:
                body, was_chunked = await hm.read_body(reader, req.headers, is_response=False)
            except (hm.ParseError, ConnectionError, OSError, asyncio.IncompleteReadError):
                return
            req.body = body
            hm.normalise_framing(req.headers, body, was_chunked)

            keep_alive = await self._exchange(
                req, writer, host=host, port=port, tls=is_tls
            )
            if not keep_alive:
                return

    def _resolve_target(
        self,
        req: hm.Request,
        *,
        tls: bool,
        fixed_host: tuple[str, int] | None,
    ) -> tuple[str, int, bool] | None:
        """Work out where a request is actually headed."""
        if req.is_absolute_form:
            scheme, _, rest = req.target.partition(b"://")
            is_tls = scheme.lower() == b"https"
            authority = rest.split(b"/", 1)[0]
            host, port = hm.split_authority(authority, 443 if is_tls else 80)
            return host, port, is_tls

        # Origin-form. Legitimate after CONNECT / on the TLS listener, and in
        # invisible mode where the client thinks it is talking to the server.
        if fixed_host is not None:
            # The CONNECT target (or the SNI name) is authoritative: the Host
            # header must not be able to redirect the request elsewhere.
            return fixed_host[0], fixed_host[1], tls

        if not self.settings.invisible_proxy:
            return None

        host_header = req.header("host")
        if host_header:
            host, port = hm.split_authority(host_header, 443 if tls else 80)
            if host:
                return host, port, tls
        default = self.settings.invisible_default_host.strip()
        if default:
            host, port = hm.split_authority(default, 443 if tls else 80)
            return host, port, tls
        return None

    # ------------------------------------------------------------- one round
    async def _exchange(
        self,
        req: hm.Request,
        writer: asyncio.StreamWriter,
        *,
        host: str,
        port: int,
        tls: bool,
    ) -> bool:
        """Run one request/response round trip. Returns whether to keep alive."""
        settings = self.settings
        # Both are snapshotted deliberately: an intercepted request can sit
        # awaiting the operator across a project switch or a settings change,
        # and it must be handled and logged as it was when it arrived.
        project_id = self.project_id
        url = hm.build_url(tls, host, port, req.target)
        scoped = in_scope(settings, url)
        self.stats.requests += 1

        if settings.header_rules:
            hm.apply_header_rules(req.headers, settings.header_rules, "request")

        raw_request = req.raw
        edited = False

        if settings.intercept_requests and should_intercept(settings, url):
            decision, new_raw = await self.interceptor.hold(
                kind="request", project_id=project_id, flow_id=None,
                host=host, port=port, tls=tls,
                url=url, method=req.method.decode("latin-1", "replace"),
                raw=raw_request,
            )
            if decision == "drop":
                self.stats.dropped += 1
                await self._log_dropped(project_id, host, port, tls, url,
                                        req, raw_request)
                return False
            if new_raw != raw_request:
                edited = True
                raw_request = new_raw
                try:
                    # Re-parse so keep-alive, framing and the logged URL all
                    # follow the edited bytes rather than the original.
                    req = hm.parse_request(raw_request)
                    url = hm.build_url(tls, host, port, req.target)
                    scoped = in_scope(settings, url)
                except hm.ParseError:
                    pass

        flow_id = None
        should_log = settings.logging_enabled and (scoped or settings.log_out_of_scope)
        if should_log:
            flow_id = await self.db.insert_flow(
                project_id=project_id,
                source="proxy", host=host, port=port, tls=int(tls),
                method=req.method.decode("latin-1", "replace"),
                target=req.target.decode("latin-1", "replace"),
                url=url, req_len=len(raw_request), was_edited=int(edited),
                in_scope=int(scoped),
                raw_request=raw_request,
            )
            self.hub.publish("flow_new", {
                "id": flow_id, "ts": time.time(), "source": "proxy",
                "host": host, "port": port, "tls": tls,
                "method": req.method.decode("latin-1", "replace"),
                "url": url, "req_len": len(raw_request),
                "was_edited": int(edited), "in_scope": int(scoped),
            })

        blocked = self.vpn.killswitch_error(settings) if self.vpn else None
        if blocked:
            self.stats.errors += 1
            if flow_id is not None:
                await self.db.update_flow(flow_id, error=blocked)
                self.hub.publish("flow_update", {"id": flow_id, "error": blocked})
            writer.write(_error_response(502, "Bad Gateway", blocked))
            await writer.drain()
            return False

        result = await send_request(host, port, tls, raw_request, settings)

        if not result.ok:
            self.stats.errors += 1
            if flow_id is not None:
                await self.db.update_flow(flow_id, error=result.error,
                                          duration_ms=result.duration_ms)
                self.hub.publish("flow_update", {
                    "id": flow_id, "error": result.error,
                    "duration_ms": result.duration_ms,
                })
            writer.write(_error_response(
                502, "Bad Gateway",
                f"BRUP could not reach {host}:{port} &mdash; {result.error}",
            ))
            await writer.drain()
            return False

        raw_response = result.raw_response
        resp = result.response
        assert resp is not None

        if settings.header_rules:
            if hm.apply_header_rules(resp.headers, settings.header_rules, "response"):
                raw_response = resp.raw

        if settings.intercept_responses and should_intercept(settings, url):
            decision, new_raw = await self.interceptor.hold(
                kind="response", project_id=project_id, flow_id=flow_id,
                host=host, port=port, tls=tls,
                url=url, method=req.method.decode("latin-1", "replace"),
                raw=raw_response, status=resp.status,
            )
            if decision == "drop":
                self.stats.dropped += 1
                if flow_id is not None:
                    await self.db.update_flow(flow_id, error="response dropped")
                    self.hub.publish("flow_update",
                                     {"id": flow_id, "error": "response dropped"})
                return False
            if new_raw != raw_response:
                raw_response = new_raw
                try:
                    resp = hm.parse_response(raw_response)
                except hm.ParseError:
                    pass

        try:
            writer.write(raw_response)
            await writer.drain()
        except (ConnectionError, OSError, ssl.SSLError):
            return False

        self.stats.responses += 1
        if flow_id is not None:
            mime = (resp.header("content-type") or b"").decode("latin-1", "replace")
            update = {
                "status": resp.status,
                "reason": resp.reason.decode("latin-1", "replace"),
                "mime": mime.split(";")[0].strip(),
                "resp_len": len(raw_response),
                "duration_ms": result.duration_ms,
            }
            body_cap = settings.max_stored_body
            stored = raw_response if len(raw_response) <= body_cap else raw_response[:body_cap]
            await self.db.update_flow(flow_id, raw_response=stored, **update)
            self.hub.publish("flow_update", {"id": flow_id, **update})
            await self._maybe_trim(project_id)

        return not _wants_close(req, resp)

    async def _log_dropped(self, project_id, host, port, tls, url,
                           req, raw_request) -> None:
        if not self.settings.logging_enabled:
            return
        flow_id = await self.db.insert_flow(
            project_id=project_id,
            source="proxy", host=host, port=port, tls=int(tls),
            method=req.method.decode("latin-1", "replace"),
            target=req.target.decode("latin-1", "replace"),
            url=url, req_len=len(raw_request), raw_request=raw_request,
            error="dropped by operator",
        )
        self.hub.publish("flow_new", {
            "id": flow_id, "ts": time.time(), "source": "proxy", "host": host,
            "port": port, "tls": tls,
            "method": req.method.decode("latin-1", "replace"),
            "url": url, "error": "dropped by operator",
        })

    async def _maybe_trim(self, project_id: str) -> None:
        self._since_trim += 1
        if self._since_trim >= TRIM_EVERY:
            self._since_trim = 0
            await self.db.trim(project_id, self.settings.max_history)

    # --------------------------------------------------------------- CONNECT
    async def _handle_connect(
        self, req: hm.Request, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        host, port = hm.split_authority(req.target, 443)
        if not host:
            writer.write(_error_response(400, "Bad Request", "CONNECT needs host:port"))
            await writer.drain()
            return

        if self._is_passthrough(host):
            await self._passthrough(host, port, writer, reader)
            return

        writer.write(b"HTTP/1.1 200 Connection established\r\n"
                     b"Proxy-Agent: BRUP\r\n\r\n")
        await writer.drain()

        try:
            await upgrade_to_tls(
                reader, writer, self.ca.context_for(host), server_side=True
            )
        except (ssl.SSLError, OSError, asyncio.TimeoutError) as exc:
            # Usually the client rejecting our CA - a very common first-run issue.
            log.info("TLS handshake with client failed for %s: %s", host, exc)
            return

        await self._serve_requests(reader, writer, tls=True, fixed_host=(host, port))

    def _is_passthrough(self, host: str) -> bool:
        host = host.lower()
        for rule in self.settings.tls_passthrough_hosts:
            rule = rule.strip().lower()
            if not rule:
                continue
            if rule.startswith("*."):
                if host == rule[2:] or host.endswith(rule[1:]):
                    return True
            elif host == rule:
                return True
        return False

    async def _passthrough(self, host, port, client_writer, client_reader) -> None:
        """Blind-tunnel a CONNECT without touching the TLS inside it."""
        server_writer = None
        try:
            async with asyncio.timeout(self.settings.connect_timeout):
                server_reader, server_writer = await asyncio.open_connection(
                    host, port, limit=STREAM_LIMIT
                )
        except (OSError, asyncio.TimeoutError) as exc:
            client_writer.write(_error_response(
                502, "Bad Gateway", f"Pass-through to {host}:{port} failed: {exc}"))
            await client_writer.drain()
            return
        client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await client_writer.drain()
        try:
            await tunnel(client_reader, client_writer, server_reader, server_writer)
        finally:
            await close_writer(server_writer)
