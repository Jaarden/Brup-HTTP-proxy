"""Runtime settings, persisted as JSON so they survive a container restart."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

DATA_DIR = Path(os.environ.get("BRUP_DATA_DIR", "/data"))


class ScopeRule(BaseModel):
    enabled: bool = True
    pattern: str = ""


# Headers that carry the message framing. Rewriting them on the proxy path would
# desynchronise the exchange, so rules may not touch them; Repeater gives raw
# control for anyone who actually wants to send a bad length.
PROTECTED_HEADERS: frozenset[str] = frozenset({
    "content-length",
    "transfer-encoding",
})

_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class HeaderRule(BaseModel):
    """Rewrite one header on proxied traffic."""

    enabled: bool = True
    target: Literal["request", "response"] = "request"
    # set: replace it, or add it when absent. add: append another instance.
    # remove: delete every instance.
    action: Literal["set", "add", "remove"] = "set"
    name: str = ""
    value: str = ""


def validate_header_rules(rules: list[dict[str, Any]] | None) -> None:
    """Reject rules that would corrupt a message. Raises ValueError."""
    for raw in rules or []:
        rule = raw if isinstance(raw, dict) else {}
        name = str(rule.get("name", "")).strip()
        value = str(rule.get("value", ""))
        if not name:
            raise ValueError("a header rule needs a header name")
        if not _TOKEN_RE.match(name):
            raise ValueError(
                f"{name!r} is not a valid header name - use letters, digits and "
                "-_. without spaces or colons"
            )
        if name.lower() in PROTECTED_HEADERS:
            raise ValueError(
                f"{name} sets the message framing and cannot be rewritten here. "
                "Use Repeater if you need to send a deliberately wrong one."
            )
        if "\r" in value or "\n" in value or "\r" in name or "\n" in name:
            raise ValueError(
                "header names and values cannot contain a line break - that would "
                "inject extra headers. Use Repeater for raw control."
            )


class Settings(BaseModel):
    # --- listeners -------------------------------------------------------
    proxy_host: str = "0.0.0.0"
    proxy_port: int = 9081
    invisible_proxy: bool = False
    invisible_tls_enabled: bool = False
    invisible_tls_port: int = 9444
    # Whether h2 is advertised to clients. A listener property, so system-wide.
    listen_http2: bool = True
    # Host a request is assumed to target when an invisible-mode client sends
    # neither an absolute URI nor a Host header.
    invisible_default_host: str = ""

    # --- interception ----------------------------------------------------
    intercept_enabled: bool = False
    intercept_requests: bool = True
    intercept_responses: bool = False
    # Requests whose URL matches any of these are never held, even when
    # interception is on. Keeps static asset noise out of the way.
    intercept_skip_extensions: list[str] = Field(
        default_factory=lambda: [
            "css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico",
            "woff", "woff2", "ttf", "eot", "map", "webp", "avif",
        ]
    )

    # --- scope -----------------------------------------------------------
    scope_include: list[ScopeRule] = Field(default_factory=list)
    scope_exclude: list[ScopeRule] = Field(default_factory=list)

    # --- header rewriting ------------------------------------------------
    # Applied to proxied traffic only, before interception, so the operator
    # sees and can edit the request that will actually be sent.
    header_rules: list[HeaderRule] = Field(default_factory=list)

    # --- http/2 ----------------------------------------------------------
    # Whether h2 is offered upstream. Turn it off to force a target onto
    # HTTP/1.1 and compare how it behaves.
    upstream_http2: bool = True

    # --- upstream --------------------------------------------------------
    upstream_proxy: str = ""          # e.g. http://corp-proxy:3128
    upstream_verify_tls: bool = False
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    tls_passthrough_hosts: list[str] = Field(default_factory=list)

    # --- vpn -------------------------------------------------------------
    # System-wide: the tunnel lives in BRUP's single network namespace, so it
    # cannot differ per project.
    vpn_required: bool = False          # kill switch
    vpn_autoconnect: str = ""           # profile id to bring up at startup
    vpn_override_dns: bool = True
    vpn_exit_ip_url: str = "https://api.ipify.org"
    # Check the exit address as soon as a tunnel comes up. This is an outbound
    # request to whatever vpn_exit_ip_url names, so it is a setting rather than
    # unconditional; clearing the URL disables the check entirely.
    vpn_auto_check_exit_ip: bool = True

    # --- history ---------------------------------------------------------
    logging_enabled: bool = True
    log_out_of_scope: bool = True
    max_history: int = 50_000
    max_stored_body: int = 2 * 1024 * 1024


# Settings that decide how BRUP binds its listeners. They are shared by every
# project and need the listener restarting, so a project cannot override them.
SYSTEM_ONLY_KEYS: frozenset[str] = frozenset({
    "proxy_host",
    "proxy_port",
    "invisible_tls_enabled",
    "invisible_tls_port",
    "listen_http2",
    # There is one network namespace, so one tunnel: a project cannot have its
    # own VPN, and must not be able to switch off the kill switch.
    "vpn_required",
    "vpn_autoconnect",
    "vpn_override_dns",
    "vpn_exit_ip_url",
    "vpn_auto_check_exit_ip",
})

PROJECT_OVERRIDABLE_KEYS: frozenset[str] = (
    frozenset(Settings.model_fields) - SYSTEM_ONLY_KEYS
)


def merge_settings(system: Settings, overrides: dict[str, Any]) -> Settings:
    """Effective settings: the system defaults with a project's overrides applied."""
    data = system.model_dump()
    for key, value in (overrides or {}).items():
        if key in PROJECT_OVERRIDABLE_KEYS:
            data[key] = value
    return Settings.model_validate(data)


def validate_overrides(overrides: dict[str, Any]) -> dict[str, Any]:
    """Reject unknown or system-only keys, and check the result still validates.

    Raises ValueError with a message meant for the operator.
    """
    cleaned: dict[str, Any] = {}
    for key, value in (overrides or {}).items():
        if key in SYSTEM_ONLY_KEYS:
            raise ValueError(
                f"{key!r} is a system-wide setting and cannot be overridden per "
                "project - it decides how the listener binds."
            )
        if key not in PROJECT_OVERRIDABLE_KEYS:
            raise ValueError(f"unknown setting {key!r}")
        if value is None:
            continue  # an explicit null clears the override
        cleaned[key] = value
    # Surfaces type errors now rather than at request time.
    merge_settings(Settings(), cleaned)
    return cleaned


class SettingsStore:
    """Holds the *system* settings, persisted as JSON."""

    def __init__(self, path: Path | None = None):
        self.path = path or (DATA_DIR / "settings.json")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.settings = self._load()

    def _load(self) -> Settings:
        if self.path.exists():
            try:
                return Settings.model_validate_json(self.path.read_text())
            except Exception:  # noqa: BLE001 - a corrupt file must not brick startup
                self.path.replace(self.path.with_suffix(".json.bad"))
        return Settings()

    def save(self) -> None:
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.settings.model_dump(), indent=2))
        tmp.replace(self.path)

    def update(self, patch: dict) -> Settings:
        merged = self.settings.model_dump() | patch
        self.settings = Settings.model_validate(merged)
        self.save()
        return self.settings


def _compile(rules: list[ScopeRule]) -> list[re.Pattern[str]]:
    out = []
    for rule in rules:
        if not rule.enabled or not rule.pattern.strip():
            continue
        try:
            out.append(re.compile(rule.pattern, re.IGNORECASE))
        except re.error:
            continue  # invalid regexes are reported by the API, not enforced here
    return out


def in_scope(settings: Settings, url: str) -> bool:
    includes = _compile(settings.scope_include)
    excludes = _compile(settings.scope_exclude)
    if includes and not any(p.search(url) for p in includes):
        return False
    return not any(p.search(url) for p in excludes)


def should_intercept(settings: Settings, url: str) -> bool:
    if not settings.intercept_enabled or not in_scope(settings, url):
        return False
    path = url.split("?", 1)[0].split("#", 1)[0]
    _, _, last = path.rpartition("/")
    if "." in last:
        ext = last.rsplit(".", 1)[1].lower()
        if ext in {e.lower().lstrip(".") for e in settings.intercept_skip_extensions}:
            return False
    return True
