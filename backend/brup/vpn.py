"""Route the proxy's outbound traffic through an OpenVPN or WireGuard tunnel.

The tunnel is brought up inside BRUP's own network namespace, so once it is a
full tunnel every upstream connection the proxy makes goes through it. There is
one namespace, so there is one tunnel at a time - which is why VPN settings are
system-wide rather than per project.

The web UI stays reachable because Docker's bridge subnet keeps a more specific
route than the tunnel's default route.
"""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import os
import re
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from .config import Settings, SettingsStore
from .db import Database
from .events import EventHub

log = logging.getLogger("brup.vpn")

WG_INTERFACE = "brup0"
# wg-quick calls `sysctl -w`, which cannot succeed against Docker's read-only
# /proc/sys. The shim reports success when the value already matches (compose
# sets it at start-up) and defers to the real sysctl otherwise.
SHIM_DIR = "/usr/local/libexec/brup"
RUN_DIR = Path("/run/brup-vpn")
LOG_LINES = 400
CONNECT_TIMEOUT = 45.0

Kind = Literal["openvpn", "wireguard"]
State = Literal["disconnected", "connecting", "connected", "failed"]


class VpnError(Exception):
    """Operator-facing problem with a VPN profile or connection."""


# --------------------------------------------------------------------------
# Profile parsing and validation
# --------------------------------------------------------------------------

class VpnProfile(BaseModel):
    id: str
    name: str
    kind: Kind
    config: str
    username: str = ""
    password: str = ""
    notes: str = ""
    created: float = 0.0

    def public(self, *, include_config: bool = False) -> dict[str, Any]:
        """Profile for the UI. Secrets are never sent back out."""
        data = {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "notes": self.notes,
            "created": self.created,
            "has_credentials": bool(self.username or self.password),
            "username": self.username,
            **describe_config(self.kind, self.config),
        }
        if include_config:
            data["config"] = self.config
        return data


def detect_kind(config: str) -> Kind:
    """Work out which client a pasted configuration is for."""
    text = config.lower()
    if "[interface]" in text and "privatekey" in text:
        return "wireguard"
    openvpn_markers = ("remote ", "client\n", "dev tun", "<ca>", "proto udp", "proto tcp")
    if any(marker in text for marker in openvpn_markers):
        return "openvpn"
    raise VpnError(
        "Could not tell whether this is an OpenVPN or WireGuard configuration. "
        "A WireGuard file has an [Interface] section with a PrivateKey; an "
        "OpenVPN file has a 'remote' line."
    )


def _wg_sections(config: str) -> dict[str, list[dict[str, str]]]:
    sections: dict[str, list[dict[str, str]]] = {"interface": [], "peer": []}
    current: dict[str, str] | None = None
    for raw in config.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip().lower()
            current = {}
            sections.setdefault(name, []).append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        current[key.strip().lower()] = value.strip()
    return sections


def describe_config(kind: Kind, config: str) -> dict[str, Any]:
    """Summarise a config for display, and flag anything that will surprise."""
    warnings: list[str] = []
    info: dict[str, Any] = {"endpoints": [], "full_tunnel": False, "needs_credentials": False}

    if kind == "wireguard":
        sections = _wg_sections(config)
        interfaces = sections.get("interface") or []
        peers = sections.get("peer") or []
        iface = interfaces[0] if interfaces else {}
        info["address"] = iface.get("address", "")
        info["dns"] = iface.get("dns", "")
        allowed_all = False
        for peer in peers:
            if peer.get("endpoint"):
                info["endpoints"].append(peer["endpoint"])
            allowed = peer.get("allowedips", "")
            nets = [n.strip() for n in allowed.split(",") if n.strip()]
            for net in nets:
                with contextlib.suppress(ValueError):
                    if ipaddress.ip_network(net, strict=False).prefixlen == 0:
                        allowed_all = True
        info["full_tunnel"] = allowed_all
        if not interfaces:
            warnings.append("No [Interface] section found.")
        elif not iface.get("privatekey"):
            warnings.append("The [Interface] section has no PrivateKey.")
        if not iface.get("address"):
            warnings.append("The [Interface] section has no Address, so the tunnel "
                            "cannot be assigned an IP.")
        if not peers:
            warnings.append("No [Peer] section found.")
        elif not info["endpoints"]:
            warnings.append("The peer has no Endpoint, so there is nothing to connect to.")
        if not allowed_all:
            warnings.append(
                "AllowedIPs does not include 0.0.0.0/0, so this is a split tunnel: "
                "only some traffic will go through the VPN."
            )
    else:
        remotes = re.findall(
            r"^[ \t]*remote[ \t]+(\S+)(?:[ \t]+(\d+))?[ \t]*$", config, re.MULTILINE
        )
        info["endpoints"] = [f"{host}:{port}" if port else host for host, port in remotes]
        info["needs_credentials"] = bool(
            re.search(r"^[ \t]*auth-user-pass[ \t]*$", config, re.MULTILINE)
        )
        info["full_tunnel"] = bool(
            re.search(r"redirect-gateway", config)
        )
        if not remotes:
            warnings.append("No 'remote' line found, so there is no server to connect to.")
        if not info["full_tunnel"]:
            warnings.append(
                "No 'redirect-gateway' directive. Unless the server pushes it, only "
                "some traffic will go through the VPN."
            )
        if re.search(r"^[ \t]*auth-user-pass[ \t]+\S+", config, re.MULTILINE):
            warnings.append(
                "'auth-user-pass' points at a file that will not exist here. Remove "
                "the filename and enter the username and password below instead."
            )
    info["warnings"] = warnings
    return info


def missing_tooling(kind: Kind) -> list[str]:
    needed = ["ip"]
    needed += ["openvpn"] if kind == "openvpn" else ["wg", "wg-quick"]
    return [tool for tool in needed if shutil.which(tool) is None]


# --------------------------------------------------------------------------
# Connection manager
# --------------------------------------------------------------------------

class VpnManager:
    def __init__(self, db: Database, store: SettingsStore, hub: EventHub):
        self.db = db
        self.store = store
        self.hub = hub
        self.state: State = "disconnected"
        self.message = ""
        self.active_profile_id: str | None = None
        self.connected_at: float | None = None
        self.exit_ip: str | None = None
        self.exit_ip_checked: float | None = None
        self._log: list[str] = []
        self._process: asyncio.subprocess.Process | None = None
        self._reader: asyncio.Task | None = None
        self._kind: Kind | None = None
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------- accessors
    @property
    def settings(self) -> Settings:
        return self.store.settings

    @property
    def is_connected(self) -> bool:
        return self.state == "connected"

    def killswitch_error(self, settings: Settings) -> str | None:
        """Why an outbound request must be refused, or None if it may proceed."""
        if not settings.vpn_required:
            return None
        if self.is_connected:
            return None
        return (
            "VPN kill switch is on and the tunnel is "
            f"{self.state}. Refusing to send this request outside the VPN. "
            "Connect the VPN, or turn off 'Require VPN' in System settings."
        )

    def _emit(self, line: str) -> None:
        stamped = f"{time.strftime('%H:%M:%S')} {line.rstrip()}"
        self._log.append(stamped)
        del self._log[:-LOG_LINES]
        log.debug("vpn: %s", line.rstrip())

    def status(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "message": self.message,
            "kind": self._kind,
            "active_profile_id": self.active_profile_id,
            "connected_at": self.connected_at,
            "interface": WG_INTERFACE if self._kind == "wireguard" else "tun0",
            "exit_ip": self.exit_ip,
            "exit_ip_checked": self.exit_ip_checked,
            "required": self.settings.vpn_required,
            "tooling_missing": missing_tooling(self._kind) if self._kind else [],
        }

    def log_tail(self, limit: int = 200) -> list[str]:
        return self._log[-limit:]

    # -------------------------------------------------------------- profiles
    async def list_profiles(self) -> list[dict[str, Any]]:
        rows = await self.db.list_vpn_profiles()
        return [VpnProfile(**row).public() for row in rows]

    async def get_profile(self, profile_id: str) -> VpnProfile:
        row = await self.db.get_vpn_profile(profile_id)
        if row is None:
            raise VpnError("no such VPN profile")
        return VpnProfile(**row)

    async def save_profile(
        self,
        *,
        name: str,
        config: str,
        username: str = "",
        password: str = "",
        notes: str = "",
        kind: Kind | None = None,
        profile_id: str | None = None,
    ) -> dict[str, Any]:
        name = name.strip()
        if not name:
            raise VpnError("the profile needs a name")
        if not config.strip():
            raise VpnError("the configuration is empty")
        resolved = kind or detect_kind(config)

        profile = VpnProfile(
            id=profile_id or uuid.uuid4().hex[:12],
            name=name,
            kind=resolved,
            config=config,
            username=username,
            password=password,
            notes=notes,
            created=time.time(),
        )
        await self.db.save_vpn_profile(**profile.model_dump())
        self.hub.publish("vpn_profiles_changed", None)
        return profile.public()

    async def delete_profile(self, profile_id: str) -> None:
        if profile_id == self.active_profile_id and self.state != "disconnected":
            raise VpnError("disconnect this profile before deleting it")
        await self.db.delete_vpn_profile(profile_id)
        self.hub.publish("vpn_profiles_changed", None)

    # ------------------------------------------------------------ connecting
    def preflight(self, kind: Kind) -> None:
        """Check the container can actually bring a tunnel up, and say why not."""
        missing = missing_tooling(kind)
        if missing:
            raise VpnError(
                f"missing tools in the container: {', '.join(missing)}. Rebuild "
                "the image so the VPN clients are installed."
            )
        if not Path("/dev/net/tun").exists():
            raise VpnError(
                "/dev/net/tun is not present. Give the container the tun device and "
                "NET_ADMIN - see the VPN section of the README."
            )

    async def connect(self, profile_id: str) -> dict[str, Any]:
        async with self._lock:
            if self.state in ("connecting", "connected"):
                raise VpnError(
                    f"already {self.state}; disconnect first. Only one tunnel can be "
                    "up at a time because there is a single network namespace."
                )
            profile = await self.get_profile(profile_id)
            self.preflight(profile.kind)

            self._log.clear()
            self.state = "connecting"
            self.message = ""
            self.exit_ip = None
            self.exit_ip_checked = None
            self.active_profile_id = profile.id
            self._kind = profile.kind
            self._publish()

            RUN_DIR.mkdir(parents=True, exist_ok=True)
            try:
                if profile.kind == "wireguard":
                    await self._connect_wireguard(profile)
                else:
                    await self._connect_openvpn(profile)
            except VpnError as exc:
                self.state = "failed"
                self.message = str(exc)
                await self._teardown()
                self._publish()
                raise
            except Exception as exc:  # noqa: BLE001
                self.state = "failed"
                self.message = f"{type(exc).__name__}: {exc}"
                self._emit(f"error: {self.message}")
                await self._teardown()
                self._publish()
                raise VpnError(self.message) from exc

            self.state = "connected"
            self.connected_at = time.time()
            self.message = ""
            self._emit("tunnel is up")
            self._publish()
            return self.status()

    def _publish(self) -> None:
        self.hub.publish("vpn_state", self.status())

    async def _run(self, argv: list[str], *, env: dict[str, str] | None = None,
                   timeout: float = 30.0) -> tuple[int, str]:
        self._emit(f"$ {' '.join(argv)}")
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, **(env or {})},
        )
        try:
            out, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            raise VpnError(f"{argv[0]} timed out after {timeout:g}s")
        text = (out or b"").decode("utf-8", "replace")
        for line in text.splitlines():
            self._emit(line)
        return process.returncode or 0, text

    # ------------------------------------------------------------ WireGuard
    async def _connect_wireguard(self, profile: VpnProfile) -> None:
        # wg-quick derives the interface name from the filename.
        wg_dir = Path("/etc/wireguard")
        wg_dir.mkdir(parents=True, exist_ok=True)
        target = wg_dir / f"{WG_INTERFACE}.conf"

        # DNS is handled here rather than by wg-quick, which needs resolvconf.
        dns_servers: list[str] = []
        lines: list[str] = []
        for raw in profile.config.splitlines():
            if raw.strip().lower().startswith("dns"):
                _, _, value = raw.partition("=")
                dns_servers += [v.strip() for v in value.split(",") if v.strip()]
                continue
            lines.append(raw)
        target.write_text("\n".join(lines) + "\n")
        target.chmod(0o600)

        wg_env = {"PATH": f"{SHIM_DIR}:{os.environ.get('PATH', '/usr/sbin:/usr/bin:/sbin:/bin')}"}
        code, text = await self._run(["wg-quick", "up", WG_INTERFACE], env=wg_env)
        if code != 0:
            lowered = text.lower()
            if "module" in lowered or "not supported" in lowered or "protocol not supported" in lowered:
                # The host kernel module is not reachable from here; fall back to
                # the userspace implementation.
                self._emit("kernel WireGuard unavailable, retrying with wireguard-go")
                with contextlib.suppress(Exception):
                    await self._run(["wg-quick", "down", WG_INTERFACE],
                                    env=wg_env, timeout=15)

                code, text = await self._run(
                    ["wg-quick", "up", WG_INTERFACE],
                    env={**wg_env,
                         "WG_QUICK_USERSPACE_IMPLEMENTATION": "wireguard-go",
                         "WG_SUDO": "1"},
                )
            if code != 0:
                raise VpnError(
                    "wg-quick failed. The log below has the details; the usual "
                    "causes are a missing NET_ADMIN capability or a bad key."
                )
        if dns_servers and self.settings.vpn_override_dns:
            self._write_resolv_conf(dns_servers)

    # -------------------------------------------------------------- OpenVPN
    async def _connect_openvpn(self, profile: VpnProfile) -> None:
        config_path = RUN_DIR / "openvpn.conf"
        # Strip an auth-user-pass filename; the credentials below replace it.
        # Only the filename is dropped; the rest of the line-based config,
        # including directives such as redirect-gateway, must survive intact.
        config = re.sub(r"^[ \t]*auth-user-pass[ \t]+\S+[ \t]*$", "auth-user-pass",
                        profile.config, flags=re.MULTILINE)
        config_path.write_text(config + "\n")
        config_path.chmod(0o600)

        argv = ["openvpn", "--config", str(config_path)]
        if profile.username or profile.password:
            auth_path = RUN_DIR / "openvpn.auth"
            auth_path.write_text(f"{profile.username}\n{profile.password}\n")
            auth_path.chmod(0o600)
            argv += ["--auth-user-pass", str(auth_path)]
        argv += ["--verb", "3"]

        self._emit(f"$ {' '.join(argv)}")
        self._process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        ready = asyncio.Event()
        failed: list[str] = []

        async def pump() -> None:
            assert self._process is not None and self._process.stdout is not None
            while True:
                raw = await self._process.stdout.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").rstrip()
                self._emit(line)
                if "Initialization Sequence Completed" in line:
                    ready.set()
                elif "AUTH_FAILED" in line:
                    failed.append("authentication rejected by the server")
                    ready.set()
                elif "Cannot open TUN/TAP" in line:
                    failed.append("cannot open the tun device (needs NET_ADMIN)")
                    ready.set()
            if not ready.is_set():
                failed.append("openvpn exited before the tunnel came up")
                ready.set()

        self._reader = asyncio.create_task(pump())
        try:
            await asyncio.wait_for(ready.wait(), timeout=CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            await self._stop_process()
            raise VpnError(
                f"openvpn did not finish connecting within {CONNECT_TIMEOUT:g}s"
            )
        if failed:
            await self._stop_process()
            raise VpnError(f"openvpn failed: {failed[0]}")

    def _write_resolv_conf(self, servers: list[str]) -> None:
        """Point DNS at the tunnel so lookups do not leak to the local resolver."""
        try:
            path = Path("/etc/resolv.conf")
            backup = RUN_DIR / "resolv.conf.orig"
            if not backup.exists():
                backup.write_text(path.read_text())
            path.write_text(
                "# written by BRUP while the VPN is up\n"
                + "".join(f"nameserver {s}\n" for s in servers)
            )
            self._emit(f"DNS set to {', '.join(servers)}")
        except OSError as exc:
            self._emit(f"could not update /etc/resolv.conf: {exc}")

    def _restore_resolv_conf(self) -> None:
        backup = RUN_DIR / "resolv.conf.orig"
        if not backup.exists():
            return
        try:
            Path("/etc/resolv.conf").write_text(backup.read_text())
            backup.unlink()
            self._emit("DNS restored")
        except OSError as exc:
            self._emit(f"could not restore /etc/resolv.conf: {exc}")

    async def _stop_process(self) -> None:
        if self._process is not None and self._process.returncode is None:
            self._process.terminate()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._process.wait(), timeout=10)
            if self._process.returncode is None:
                self._process.kill()
                with contextlib.suppress(Exception):
                    await self._process.wait()
        self._process = None
        if self._reader is not None:
            self._reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader
            self._reader = None

    # --------------------------------------------------------- disconnecting
    async def _teardown(self) -> None:
        """Undo whatever a connect attempt managed to set up."""
        if self._kind == "wireguard":
            env = {"PATH": f"{SHIM_DIR}:{os.environ.get('PATH', '/usr/sbin:/usr/bin')}"}
            with contextlib.suppress(Exception):
                await self._run(["wg-quick", "down", WG_INTERFACE], env=env, timeout=20)
        await self._stop_process()
        self._restore_resolv_conf()
        self.connected_at = None
        self.exit_ip = None
        self.exit_ip_checked = None
        # Nothing is up, so no profile is live. The UI decides whether to offer
        # Connect from this, and a stale value leaves it with neither Connect
        # nor Disconnect to show.
        self.active_profile_id = None

    async def disconnect(self) -> dict[str, Any]:
        async with self._lock:
            await self._teardown()
            self.state = "disconnected"
            self.message = ""
            self._kind = None
            self._emit("tunnel is down")
            self._publish()
            return self.status()

    async def shutdown(self) -> None:
        if self.state != "disconnected":
            with contextlib.suppress(Exception):
                await self.disconnect()

    # ----------------------------------------------------------- exit IP check
    async def check_exit_ip(self, url: str | None = None) -> dict[str, Any]:
        """Ask an external service what IP the traffic appears to come from.

        Deliberately a manual action: it contacts a third party, which is the
        only way to confirm from in here that the tunnel is really carrying
        traffic.
        """
        from .proxy.upstream import send_request

        target = (url or self.settings.vpn_exit_ip_url).strip()
        if not target:
            raise VpnError("no exit-IP check URL is configured")
        match = re.match(r"^(https?)://([^/]+)(/.*)?$", target)
        if not match:
            raise VpnError(f"not a usable URL: {target!r}")
        scheme, authority, path = match.groups()
        tls = scheme == "https"
        host, _, port_text = authority.partition(":")
        port = int(port_text) if port_text else (443 if tls else 80)

        raw = (
            f"GET {path or '/'} HTTP/1.1\r\nHost: {authority}\r\n"
            "User-Agent: BRUP-vpn-check\r\nAccept: text/plain\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        result = await send_request(host, port, tls, raw, self.settings)
        if not result.ok:
            self._emit(f"exit IP check failed: {result.error}")
            raise VpnError(f"exit IP check failed: {result.error}")

        body = result.response.body.decode("utf-8", "replace").strip() if result.response else ""
        found = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", body)
        self.exit_ip = found.group(0) if found else (body[:60] or None)
        self.exit_ip_checked = time.time()
        self._emit(f"exit IP looks like {self.exit_ip}")
        self._publish()
        return {"exit_ip": self.exit_ip, "checked": self.exit_ip_checked, "url": target}

    # ----------------------------------------------------------- autoconnect
    async def autoconnect(self) -> None:
        profile_id = self.settings.vpn_autoconnect.strip()
        if not profile_id:
            return
        try:
            await self.connect(profile_id)
        except VpnError as exc:
            log.error("VPN autoconnect failed: %s", exc)
            self.message = str(exc)
            self.state = "failed"
            self._publish()
