"""VPN profile parsing, validation and the kill switch.

Bringing up a real tunnel needs a real VPN provider, so what is tested here is
everything around it: detection, the warnings the operator is shown, profile
storage, and - most importantly - that the kill switch actually stops traffic.
"""
from __future__ import annotations

import os
import tempfile

import pytest

os.environ.setdefault("BRUP_DATA_DIR", tempfile.mkdtemp(prefix="brup-vpntest-"))

import httpx  # noqa: E402
from httpx import ASGITransport  # noqa: E402

from brup.config import Settings, SettingsStore  # noqa: E402
from brup.db import Database  # noqa: E402
from brup.events import EventHub  # noqa: E402
from brup.vpn import (  # noqa: E402
    VpnError, VpnManager, describe_config, detect_kind,
)

WG_FULL = """
[Interface]
PrivateKey = aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvaGVsbG8=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = d29ybGR3b3JsZHdvcmxkd29ybGR3b3JsZHdvcmxkd29ybGQ=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
"""

WG_SPLIT = WG_FULL.replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.2.0.0/24")

OVPN_FULL = """
client
dev tun
proto udp
remote vpn.example.com 1194
auth-user-pass
redirect-gateway def1
<ca>
-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
</ca>
"""


@pytest.fixture
async def vpn(tmp_path):
    db = Database(tmp_path / "vpn.sqlite3")
    store = SettingsStore(tmp_path / "s.json")
    manager = VpnManager(db, store, EventHub())
    yield manager, db, store
    db.close()


# ------------------------------------------------------------- detection

def test_detects_wireguard_and_openvpn():
    assert detect_kind(WG_FULL) == "wireguard"
    assert detect_kind(OVPN_FULL) == "openvpn"
    assert detect_kind("remote 1.2.3.4 1194\ndev tun\n") == "openvpn"


def test_unrecognised_config_explains_itself():
    with pytest.raises(VpnError) as exc:
        detect_kind("just some text\n")
    message = str(exc.value)
    assert "[Interface]" in message and "remote" in message


# ------------------------------------------------------------ description

def test_wireguard_full_tunnel_is_recognised():
    info = describe_config("wireguard", WG_FULL)
    assert info["full_tunnel"] is True
    assert info["endpoints"] == ["vpn.example.com:51820"]
    assert info["address"] == "10.2.0.2/32"
    assert info["dns"] == "10.2.0.1"
    assert info["warnings"] == []


def test_wireguard_split_tunnel_warns():
    info = describe_config("wireguard", WG_SPLIT)
    assert info["full_tunnel"] is False
    assert any("split tunnel" in w for w in info["warnings"])


def test_wireguard_missing_pieces_are_reported():
    info = describe_config("wireguard", "[Interface]\nAddress = 10.0.0.2/32\n")
    joined = " ".join(info["warnings"])
    assert "no PrivateKey" in joined
    assert "No [Peer]" in joined


def test_openvpn_description_and_credentials_flag():
    info = describe_config("openvpn", OVPN_FULL)
    assert info["full_tunnel"] is True
    assert info["endpoints"] == ["vpn.example.com:1194"]
    assert info["needs_credentials"] is True
    assert info["warnings"] == []


def test_openvpn_without_redirect_gateway_warns():
    info = describe_config("openvpn", "client\ndev tun\nremote a.example.com 1194\n")
    assert info["full_tunnel"] is False
    assert any("redirect-gateway" in w for w in info["warnings"])


def test_openvpn_auth_file_reference_warns():
    info = describe_config("openvpn", OVPN_FULL.replace(
        "auth-user-pass", "auth-user-pass /etc/creds.txt"))
    assert any("will not exist" in w for w in info["warnings"])


def test_openvpn_without_remote_warns():
    info = describe_config("openvpn", "client\ndev tun\n")
    assert any("No 'remote'" in w for w in info["warnings"])


# --------------------------------------------------------------- profiles

async def test_profile_roundtrip_and_secret_handling(vpn):
    manager, _, _ = vpn
    saved = await manager.save_profile(
        name="  Provider NL  ", config=WG_FULL, username="user", password="secret",
    )
    assert saved["name"] == "Provider NL"        # trimmed
    assert saved["kind"] == "wireguard"
    assert saved["has_credentials"] is True
    # The listing never carries the config or the password.
    assert "config" not in saved and "password" not in saved

    listed = await manager.list_profiles()
    assert [p["name"] for p in listed] == ["Provider NL"]
    assert "password" not in listed[0]

    # The stored profile does keep them, for connecting.
    stored = await manager.get_profile(saved["id"])
    assert stored.password == "secret"
    assert stored.config == WG_FULL


async def test_profile_validation(vpn):
    manager, _, _ = vpn
    with pytest.raises(VpnError):
        await manager.save_profile(name="  ", config=WG_FULL)
    with pytest.raises(VpnError):
        await manager.save_profile(name="empty", config="   ")
    with pytest.raises(VpnError):
        await manager.save_profile(name="junk", config="not a vpn config")
    with pytest.raises(VpnError):
        await manager.get_profile("nope")


async def test_delete_profile(vpn):
    manager, _, _ = vpn
    saved = await manager.save_profile(name="Gone", config=OVPN_FULL)
    await manager.delete_profile(saved["id"])
    assert await manager.list_profiles() == []


async def test_cannot_delete_a_connected_profile(vpn):
    manager, _, _ = vpn
    saved = await manager.save_profile(name="Live", config=WG_FULL)
    manager.active_profile_id = saved["id"]
    manager.state = "connected"
    with pytest.raises(VpnError) as exc:
        await manager.delete_profile(saved["id"])
    assert "disconnect" in str(exc.value)


async def test_connect_refuses_when_already_up(vpn):
    manager, _, _ = vpn
    saved = await manager.save_profile(name="Live", config=WG_FULL)
    manager.state = "connected"
    with pytest.raises(VpnError) as exc:
        await manager.connect(saved["id"])
    assert "one tunnel" in str(exc.value)


# ------------------------------------------------------------ kill switch

def test_killswitch_allows_traffic_when_not_required(vpn):
    manager, _, _ = vpn
    settings = Settings(vpn_required=False)
    assert manager.state == "disconnected"
    assert manager.killswitch_error(settings) is None


def test_killswitch_blocks_when_required_and_down(vpn):
    manager, _, _ = vpn
    settings = Settings(vpn_required=True)
    for state in ("disconnected", "connecting", "failed"):
        manager.state = state
        blocked = manager.killswitch_error(settings)
        assert blocked is not None
        assert state in blocked
        assert "Refusing to send" in blocked


def test_killswitch_allows_traffic_once_connected(vpn):
    manager, _, _ = vpn
    manager.state = "connected"
    assert manager.killswitch_error(Settings(vpn_required=True)) is None


async def test_status_shape(vpn):
    manager, _, _ = vpn
    status = manager.status()
    assert status["state"] == "disconnected"
    assert status["required"] is False
    assert status["exit_ip"] is None


# ---------------------------------------------------- kill switch, live path

async def test_proxy_refuses_to_send_when_killswitch_trips(tmp_path):
    """The whole point: with the switch on and no tunnel, nothing goes out."""
    import asyncio
    from brup.ca import CertificateAuthority
    from brup.projects import ProjectManager
    from brup.proxy.interceptor import Interceptor
    from brup.proxy.server import ProxyServer
    from tests.test_proxy import Target, raw_exchange

    db = Database(tmp_path / "ks.sqlite3")
    store = SettingsStore(tmp_path / "s.json")
    store.settings.proxy_host = "127.0.0.1"
    store.settings.proxy_port = 0
    hub = EventHub()
    projects = ProjectManager(db, store, hub)
    await projects.load()
    manager = VpnManager(db, store, hub)
    proxy = ProxyServer(projects, CertificateAuthority(tmp_path / "ca"),
                        Interceptor(hub), hub, db, manager)

    target = await Target().start()
    await proxy.start()
    port = proxy._servers[0].sockets[0].getsockname()[1]
    request = (
        f"GET http://127.0.0.1:{target.port}/leak HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{target.port}\r\nConnection: close\r\n\r\n"
    ).encode()
    try:
        # Switch off: the request goes out normally.
        assert b"200 OK" in await raw_exchange(port, request)
        assert len(target.received) == 1

        # Switch on with no tunnel: the request is refused, not forwarded.
        await projects.update_system({"vpn_required": True})
        response = await raw_exchange(port, request)
        assert b"502 Bad Gateway" in response
        assert b"kill switch" in response
        assert len(target.received) == 1, "request leaked past the kill switch"

        # The refusal is recorded against the flow rather than lost.
        rows = (await db.list_flows(projects.active_id))["items"]
        assert "kill switch" in (rows[0]["error"] or "")

        # Pretending the tunnel is up lets traffic flow again.
        manager.state = "connected"
        assert b"200 OK" in await raw_exchange(port, request)
        assert len(target.received) == 2
    finally:
        await proxy.stop()
        await target.stop()
        db.close()


async def test_intruder_records_killswitch_instead_of_sending(tmp_path):
    import base64
    from brup.intruder import AttackConfig, AttackManager, PayloadSet
    from brup.projects import ProjectManager
    from tests.test_proxy import Target

    db = Database(tmp_path / "ks2.sqlite3")
    store = SettingsStore(tmp_path / "s.json")
    hub = EventHub()
    projects = ProjectManager(db, store, hub)
    await projects.load()
    await projects.update_system({"vpn_required": True})
    manager = VpnManager(db, store, hub)
    attacks = AttackManager(projects, db, hub, manager)

    target = await Target().start()
    try:
        template = (f"GET /\xa7a\xa7 HTTP/1.1\r\nHost: 127.0.0.1:{target.port}\r\n"
                    "Connection: close\r\n\r\n").encode("latin-1")
        attack = await attacks.start(AttackConfig(
            host="127.0.0.1", port=target.port,
            template_b64=base64.b64encode(template).decode(),
            attack_type="battering_ram",
            payload_sets=[PayloadSet(kind="list", payloads=["x", "y"])],
            concurrency=1,
        ))
        for _ in range(200):
            if attack.status in ("finished", "error", "stopped"):
                break
            await asyncio.sleep(0.05)
        assert attack.status == "finished"
        assert attack.errors == 2
        rows = await db.list_results(attack.id)
        assert all("kill switch" in (r["error"] or "") for r in rows)
        assert target.received == [], "Intruder leaked past the kill switch"
    finally:
        await target.stop()
        db.close()


import asyncio  # noqa: E402  (used by the tests above)


# --------------------------------------------------------------- API layer

@pytest.fixture
async def client():
    from brup.main import app, state
    await state.projects.load()
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://t"
    ) as c:
        yield c, state


async def test_vpn_api(client):
    c, state = client
    overview = (await c.get("/api/vpn")).json()
    assert overview["status"]["state"] == "disconnected"
    assert isinstance(overview["profiles"], list)

    inspected = (await c.post("/api/vpn/inspect", json={"config": WG_FULL})).json()
    assert inspected["kind"] == "wireguard"
    assert inspected["full_tunnel"] is True

    bad = await c.post("/api/vpn/inspect", json={"config": "nonsense"})
    assert bad.status_code == 400

    created = await c.post("/api/vpn/profiles", json={
        "name": "API VPN", "config": OVPN_FULL,
        "username": "u", "password": "p",
    })
    assert created.status_code == 200, created.text
    profile = created.json()
    assert profile["kind"] == "openvpn"
    assert profile["needs_credentials"] is True
    assert "password" not in profile

    listed = (await c.get("/api/vpn/profiles")).json()
    assert any(p["id"] == profile["id"] for p in listed)

    # Connecting needs real tooling and a real endpoint; the failure must be a
    # clean 400 with an explanation rather than a crash.
    attempt = await c.post("/api/vpn/connect", json={"profile_id": profile["id"]})
    assert attempt.status_code == 400
    assert attempt.json()["detail"]

    assert (await c.post("/api/vpn/disconnect")).status_code == 200
    assert (await c.delete(f"/api/vpn/profiles/{profile['id']}")).status_code == 200
    assert (await c.post("/api/vpn/connect", json={"profile_id": "nope"})).status_code == 400


async def test_vpn_settings_are_system_only(client):
    c, _ = client
    r = await c.put("/api/settings/project", json={"vpn_required": True})
    assert r.status_code == 400
    assert "system-wide" in r.json()["detail"]

    r = await c.put("/api/settings/system", json={"vpn_required": True})
    assert r.status_code == 200
    assert r.json()["effective"]["vpn_required"] is True
    await c.put("/api/settings/system", json={"vpn_required": False})


def test_line_patterns_do_not_run_past_their_line():
    """A directive on the next line must not be swallowed.

    `auth-user-pass` followed by `redirect-gateway def1` once matched as
    "auth-user-pass <file>", which both produced a bogus warning and, on
    connect, deleted the redirect-gateway line - quietly downgrading a full
    tunnel to a split one.
    """
    info = describe_config("openvpn", OVPN_FULL)
    assert info["needs_credentials"] is True
    assert info["full_tunnel"] is True
    assert info["warnings"] == []

    # A real filename reference is still detected.
    with_file = OVPN_FULL.replace("auth-user-pass", "auth-user-pass /etc/creds")
    assert any("will not exist" in w for w in describe_config("openvpn", with_file)["warnings"])

    # And `remote` parsing stops at the end of its own line.
    assert describe_config("openvpn", "remote\nvpn.example.com\n")["endpoints"] == []
    assert describe_config(
        "openvpn", "remote a.example.com 443\nremote b.example.com\n"
    )["endpoints"] == ["a.example.com:443", "b.example.com"]


async def test_connect_rewrite_keeps_the_rest_of_the_config(vpn, monkeypatch, tmp_path):
    """Stripping the auth filename must not touch any other directive."""
    import brup.vpn as vpn_module
    manager, _, _ = vpn
    monkeypatch.setattr(vpn_module, "RUN_DIR", tmp_path / "run")
    # The test host need not have the tun device or the VPN binaries.
    monkeypatch.setattr(manager, "preflight", lambda kind: None)

    async def no_route():
        return None

    # connect() reads the host default route first; that is not what this test
    # is about, and it would otherwise hit the stubbed subprocess launcher.
    monkeypatch.setattr(manager, "_read_default_route", no_route)

    captured: dict[str, list[str]] = {}

    async def fake_exec(*argv, **kwargs):
        captured["argv"] = list(argv)
        raise RuntimeError("stop here: the config file is already written")

    monkeypatch.setattr(vpn_module.asyncio, "create_subprocess_exec", fake_exec)

    profile = await manager.save_profile(
        name="Rewrite", config=OVPN_FULL.replace("auth-user-pass", "auth-user-pass /x"),
        username="u", password="p",
    )
    with pytest.raises(VpnError):
        await manager.connect(profile["id"])

    written = (tmp_path / "run" / "openvpn.conf").read_text()
    assert "redirect-gateway def1" in written, "a directive was lost in the rewrite"
    assert "remote vpn.example.com 1194" in written
    assert "auth-user-pass /x" not in written
    assert "\nauth-user-pass\n" in written
    # Credentials go to a separate file passed on the command line.
    assert (tmp_path / "run" / "openvpn.auth").read_text() == "u\np\n"


async def test_preflight_explains_a_missing_tun_device(vpn, monkeypatch):
    import brup.vpn as vpn_module
    manager, _, _ = vpn
    monkeypatch.setattr(vpn_module, "missing_tooling", lambda kind: [])

    class NoTun:
        def __init__(self, *_a):
            pass

        def exists(self):
            return False

    monkeypatch.setattr(vpn_module, "Path", NoTun)
    with pytest.raises(VpnError) as exc:
        manager.preflight("wireguard")
    assert "/dev/net/tun" in str(exc.value) and "NET_ADMIN" in str(exc.value)


async def test_preflight_explains_missing_binaries(vpn, monkeypatch):
    import brup.vpn as vpn_module
    manager, _, _ = vpn
    monkeypatch.setattr(vpn_module, "missing_tooling", lambda kind: ["openvpn"])
    with pytest.raises(VpnError) as exc:
        manager.preflight("openvpn")
    assert "openvpn" in str(exc.value) and "Rebuild" in str(exc.value)


async def test_disconnect_clears_the_active_profile(vpn):
    """A stale active_profile_id left the UI with no Connect button to press.

    The card decides which profile is "live" from active_profile_id, so if that
    survives a disconnect the profile looks connected, its Connect button is
    hidden, and there is no way to start it again.
    """
    manager, _, _ = vpn
    profile = await manager.save_profile(name="Reconnectable", config=WG_FULL)

    # Simulate a successful connect followed by the user disconnecting.
    manager.active_profile_id = profile["id"]
    manager._kind = "wireguard"
    manager.state = "connected"
    manager.connected_at = 123.0
    manager.exit_ip = "203.0.113.9"

    await manager.disconnect()

    status = manager.status()
    assert status["state"] == "disconnected"
    assert status["active_profile_id"] is None, "profile still looks live"
    assert status["connected_at"] is None
    assert status["exit_ip"] is None

    # And connecting again is permitted rather than rejected as "already up".
    with pytest.raises(VpnError) as exc:
        await manager.connect(profile["id"])
    assert "one tunnel" not in str(exc.value)


async def test_failed_connect_can_be_retried(vpn, monkeypatch, tmp_path):
    """After a failure the tunnel is torn down and the profile is no longer live."""
    import brup.vpn as vpn_module
    manager, _, _ = vpn
    monkeypatch.setattr(vpn_module, "RUN_DIR", tmp_path / "run")
    monkeypatch.setattr(manager, "preflight", lambda kind: None)

    teardowns: list[int] = []
    real_teardown = manager._teardown

    async def counting_teardown():
        teardowns.append(1)
        await real_teardown()

    monkeypatch.setattr(manager, "_teardown", counting_teardown)

    async def boom(profile):
        raise VpnError("endpoint unreachable")

    monkeypatch.setattr(manager, "_connect_wireguard", boom)

    profile = await manager.save_profile(name="Flaky", config=WG_FULL)
    for _ in range(2):
        with pytest.raises(VpnError) as exc:
            await manager.connect(profile["id"])
        assert "endpoint unreachable" in str(exc.value)
        status = manager.status()
        assert status["state"] == "failed"
        # The message explains what happened, and nothing is left claiming to
        # be connected, so the operator can simply try again.
        assert "endpoint unreachable" in status["message"]
        assert status["active_profile_id"] is None

    assert len(teardowns) == 2, "a failed attempt must clean up after itself"


async def test_status_endpoint_carries_vpn_state_for_the_top_bar(client):
    """The top bar reads VPN state off /api/status, so it must be there."""
    c, state = client
    body = (await c.get("/api/status")).json()
    assert "vpn" in body
    vpn = body["vpn"]
    assert vpn["state"] == "disconnected"
    for key in ("required", "exit_ip", "kind", "message"):
        assert key in vpn

    # The badge shows "blocking" from these two fields together, so both must
    # travel on the same payload.
    await c.put("/api/settings/system", json={"vpn_required": True})
    vpn = (await c.get("/api/status")).json()["vpn"]
    assert vpn["required"] is True and vpn["state"] != "connected"
    await c.put("/api/settings/system", json={"vpn_required": False})


async def test_exit_ip_is_reported_and_cleared_with_the_tunnel(vpn):
    """The badge shows the exit IP, so it must not outlive the tunnel."""
    manager, _, _ = vpn
    manager.state = "connected"
    manager._kind = "wireguard"
    manager.exit_ip = "203.0.113.7"
    manager.exit_ip_checked = 1.0
    assert manager.status()["exit_ip"] == "203.0.113.7"

    await manager.disconnect()
    # A stale address in the top bar would be actively misleading.
    assert manager.status()["exit_ip"] is None


# ------------------------------------------------- inbound reply bypass
#
# A full tunnel replaces the default route, which also swallows replies to
# connections that arrived from elsewhere: the UI and the proxy port stop
# answering anyone but a loopback client, because Docker masquerades those into
# the bridge subnet where a more specific route still applies. These cover the
# routing logic; the end-to-end behaviour needs a real tunnel and NET_ADMIN.

DEFAULT_ROUTE_OUTPUT = "default via 172.24.0.1 dev eth0 \n"


def record_runs(manager, monkeypatch, *, route_output=DEFAULT_ROUTE_OUTPUT,
                fail_on=None):
    """Capture the commands the manager would run instead of running them."""
    calls: list[list[str]] = []

    async def fake_run(argv, *, env=None, timeout=30.0):
        calls.append(list(argv))
        if fail_on is not None and fail_on in " ".join(argv):
            return 1, "boom"
        if argv[:4] == ["ip", "-4", "route", "show"]:
            return 0, route_output
        return 0, ""

    monkeypatch.setattr(manager, "_run", fake_run)
    return calls


async def test_reads_the_host_default_route(vpn, monkeypatch):
    manager, _, _ = vpn
    record_runs(manager, monkeypatch)
    assert await manager._read_default_route() == ("172.24.0.1", "eth0")


async def test_default_route_parsing_tolerates_extra_fields(vpn, monkeypatch):
    manager, _, _ = vpn
    record_runs(manager, monkeypatch,
                route_output="default via 10.0.0.1 dev ens18 proto dhcp metric 100\n")
    assert await manager._read_default_route() == ("10.0.0.1", "ens18")


async def test_no_default_route_is_handled(vpn, monkeypatch):
    manager, _, _ = vpn
    record_runs(manager, monkeypatch, route_output="")
    assert await manager._read_default_route() is None

    # Installing the bypass without one is a no-op with an explanation, not a
    # crash - the tunnel itself is still fine.
    manager._bypass = None
    calls = record_runs(manager, monkeypatch, route_output="")
    await manager._install_inbound_bypass()
    assert calls == []
    assert any("skipping inbound bypass" in line for line in manager.log_tail())


async def test_bypass_marks_inbound_connections_and_routes_them_home(vpn, monkeypatch):
    manager, _, _ = vpn
    manager._bypass = ("172.24.0.1", "eth0")
    calls = record_runs(manager, monkeypatch)
    await manager._install_inbound_bypass()

    joined = [" ".join(c) for c in calls]
    # A table holding the original default route...
    assert "ip route replace default via 172.24.0.1 dev eth0 table 51821" in joined
    # ...selected by a mark that is not WireGuard's own (51820 / 0xca6c)...
    assert "ip rule add fwmark 0x4252 lookup 51821 pref 100" in joined
    assert not any("51820" in c for c in joined)
    # ...set on connections arriving from the host side...
    assert any("PREROUTING -i eth0" in c and "--ctstate NEW" in c
               and "CONNMARK --set-mark 0x4252" in c for c in joined)
    # ...and restored on the way out, but only for that mark, so WireGuard's
    # own fwmark on its encrypted packets is left alone.
    assert any("-A OUTPUT" in c and "--mark 0x4252" in c
               and "MARK --set-mark 0x4252" in c for c in joined)
    assert any("inbound connections will reply via the host route" in line
               for line in manager.log_tail())


async def test_a_failed_bypass_step_cleans_up_and_keeps_the_tunnel(vpn, monkeypatch):
    """A kernel without the conntrack match must not take the tunnel down."""
    manager, _, _ = vpn
    manager._bypass = ("172.24.0.1", "eth0")
    calls = record_runs(manager, monkeypatch, fail_on="conntrack")
    await manager._install_inbound_bypass()

    joined = [" ".join(c) for c in calls]
    # It backed out what it had already added.
    assert any("ip rule del fwmark 0x4252" in c for c in joined)
    assert any("ip route flush table 51821" in c for c in joined)
    assert any("reaching BRUP from another machine may fail" in line
               for line in manager.log_tail())


async def test_teardown_removes_the_bypass(vpn, monkeypatch):
    manager, _, _ = vpn
    manager._bypass = ("172.24.0.1", "eth0")
    manager._kind = "wireguard"
    calls = record_runs(manager, monkeypatch)
    monkeypatch.setattr(manager, "_stop_process", lambda: asyncio.sleep(0))
    monkeypatch.setattr(manager, "_restore_resolv_conf", lambda: None)

    await manager._teardown()

    joined = [" ".join(c) for c in calls]
    assert any("-t mangle -D OUTPUT" in c for c in joined)
    assert any("-t mangle -D PREROUTING" in c for c in joined)
    assert any("ip rule del fwmark 0x4252" in c for c in joined)
    assert any("ip route flush table 51821" in c for c in joined)
    # Removal happens before the tunnel goes down, so the rules never outlive it.
    assert joined.index("iptables -t mangle -D OUTPUT -m connmark --mark 0x4252 "
                        "-j MARK --set-mark 0x4252") \
        < next(i for i, c in enumerate(joined) if "wg-quick down" in c)


async def test_bypass_removal_is_safe_without_a_captured_route(vpn, monkeypatch):
    manager, _, _ = vpn
    manager._bypass = None
    calls = record_runs(manager, monkeypatch)
    await manager._remove_inbound_bypass()
    assert calls == []


# ------------------------------------------------- automatic exit-IP check

async def test_the_exit_ip_is_checked_automatically_on_connect(vpn, monkeypatch):
    """Verifying the exit address is the completion of connecting, not a chore."""
    manager, _, store = vpn
    manager._bypass = None
    monkeypatch.setattr(manager, "preflight", lambda kind: None)

    async def fake_wireguard(profile):
        return None

    monkeypatch.setattr(manager, "_connect_wireguard", fake_wireguard)

    calls: list[int] = []

    async def fake_check(url=None):
        calls.append(1)
        manager.exit_ip = "203.0.113.5"
        return {"exit_ip": manager.exit_ip}

    monkeypatch.setattr(manager, "check_exit_ip", fake_check)

    profile = await manager.save_profile(name="Auto", config=WG_FULL)
    await manager.connect(profile["id"])
    # It runs in the background, so connect() does not wait on an external
    # service; give the task a turn.
    for _ in range(50):
        if calls:
            break
        await asyncio.sleep(0.02)
    assert calls == [1], "the exit IP was not checked automatically"
    assert manager.status()["exit_ip"] == "203.0.113.5"


async def test_the_automatic_check_can_be_turned_off(vpn, monkeypatch):
    manager, _, store = vpn
    manager._bypass = None
    monkeypatch.setattr(manager, "preflight", lambda kind: None)

    async def fake_wireguard(profile):
        return None

    monkeypatch.setattr(manager, "_connect_wireguard", fake_wireguard)

    calls: list[str] = []

    async def fake_check(url=None):
        calls.append("checked")
        return {}

    monkeypatch.setattr(manager, "check_exit_ip", fake_check)
    profile = await manager.save_profile(name="Quiet", config=WG_FULL)

    # Off by setting.
    store.update({"vpn_auto_check_exit_ip": False})
    await manager.connect(profile["id"])
    await asyncio.sleep(0.15)
    assert calls == [], "checked despite the setting being off"
    await manager.disconnect()

    # Off by clearing the URL, so nothing is contacted at all.
    store.update({"vpn_auto_check_exit_ip": True, "vpn_exit_ip_url": ""})
    await manager.connect(profile["id"])
    await asyncio.sleep(0.15)
    assert calls == [], "checked despite there being no URL"


async def test_a_failing_automatic_check_leaves_the_tunnel_up(vpn, monkeypatch):
    """The check is confirmation, not a precondition."""
    manager, _, _ = vpn
    manager._bypass = None
    monkeypatch.setattr(manager, "preflight", lambda kind: None)

    async def fake_wireguard(profile):
        return None

    monkeypatch.setattr(manager, "_connect_wireguard", fake_wireguard)

    async def boom(url=None):
        raise VpnError("nothing answered")

    monkeypatch.setattr(manager, "check_exit_ip", boom)

    profile = await manager.save_profile(name="Flaky check", config=WG_FULL)
    status = await manager.connect(profile["id"])
    assert status["state"] == "connected"
    await asyncio.sleep(0.15)
    assert manager.state == "connected", "a failed check took the tunnel down"
    assert manager.status()["exit_ip"] is None
    assert any("automatic exit IP check failed" in line
               for line in manager.log_tail())
