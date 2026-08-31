"""Intruder: templated request fuzzing.

A request template carries payload positions delimited by a marker byte
(``\\xa7``, shown as ``§`` - the same convention Burp uses). The four classic
attack types decide how payload sets map onto those positions.
"""
from __future__ import annotations

import asyncio
import base64 as b64mod
import hashlib
import itertools
import logging
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Iterator, Literal

from pydantic import BaseModel, Field

from . import http2
from .config import Settings
from .db import Database
from .events import EventHub
from .projects import ProjectManager
from .proxy.upstream import UpstreamResult, send_h2_request, send_request
from .vpn import VpnManager

log = logging.getLogger("brup.intruder")

MARKER = b"\xa7"
MAX_REQUESTS = 250_000
PERSIST_EVERY = 50
UNRESERVED = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"

AttackType = Literal["sniper", "battering_ram", "pitchfork", "cluster_bomb"]


class ParseError(Exception):
    pass


# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------

def parse_positions(template: bytes) -> tuple[list[bytes], list[bytes]]:
    """Split a template into literal chunks and the base values of positions.

    ``a§X§b§Y§c`` -> literals ``[a, b, c]``, bases ``[X, Y]``.
    """
    parts = template.split(MARKER)
    if len(parts) % 2 == 0:
        raise ParseError(
            "Unbalanced payload markers: every position needs an opening and a "
            "closing §."
        )
    return parts[0::2], parts[1::2]


def build_request(literals: list[bytes], values: list[bytes]) -> bytes:
    chunks = [literals[0]]
    for i, value in enumerate(values):
        chunks.append(value)
        chunks.append(literals[i + 1])
    return b"".join(chunks)


def fix_content_length(raw: bytes) -> bytes:
    """Rewrite Content-Length to match the body, touching nothing else.

    Done textually rather than by re-serialising so deliberately malformed
    requests survive intact.
    """
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        return raw
    head, body = raw[:sep], raw[sep + 4:]
    lines = head.split(b"\r\n")
    out: list[bytes] = []
    found = False
    for line in lines:
        if line.lower().startswith(b"content-length:"):
            if found:
                continue  # collapse duplicates
            out.append(b"Content-Length: " + str(len(body)).encode())
            found = True
        else:
            out.append(line)
    if not found and body:
        out.append(b"Content-Length: " + str(len(body)).encode())
    return b"\r\n".join(out) + b"\r\n\r\n" + body


# --------------------------------------------------------------------------
# Payloads
# --------------------------------------------------------------------------

class PayloadRule(BaseModel):
    kind: Literal[
        "prefix", "suffix", "upper", "lower", "reverse", "strip",
        "url_encode", "url_encode_all", "base64", "hex",
        "md5", "sha1", "sha256",
    ]
    value: str = ""
    enabled: bool = True


class PayloadSet(BaseModel):
    kind: Literal["list", "numbers", "brute"] = "list"
    # kind == "list"
    payloads: list[str] = Field(default_factory=list)
    wordlist: str = ""
    # kind == "numbers"
    number_from: float = 1
    number_to: float = 100
    number_step: float = 1
    # kind == "brute"
    charset: str = "abcdefghijklmnopqrstuvwxyz"
    min_length: int = 1
    max_length: int = 3
    rules: list[PayloadRule] = Field(default_factory=list)
    # Populated by AttackManager when ``wordlist`` names a stored list.
    wordlist_content: str | None = None

    def base_values(self) -> list[str]:
        if self.kind == "numbers":
            values = []
            step = self.number_step or 1
            current = self.number_from
            # Guard against a zero/backwards step producing an infinite list.
            if (self.number_to - self.number_from) * step < 0:
                step = -step
            count = 0
            while count < MAX_REQUESTS:
                if step > 0 and current > self.number_to:
                    break
                if step < 0 and current < self.number_to:
                    break
                values.append(
                    str(int(current)) if float(current).is_integer() else str(current)
                )
                current += step
                count += 1
            return values
        if self.kind == "brute":
            chars = self.charset or "abc"
            lo = max(1, self.min_length)
            hi = max(lo, self.max_length)
            values = []
            for length in range(lo, hi + 1):
                for combo in itertools.product(chars, repeat=length):
                    values.append("".join(combo))
                    if len(values) >= MAX_REQUESTS:
                        return values
            return values
        source = (
            self.wordlist_content.splitlines()
            if self.wordlist_content is not None
            else self.payloads
        )
        return [ln for ln in source if ln != ""]

    def values(self) -> list[str]:
        return [apply_rules(v, self.rules) for v in self.base_values()]


def apply_rules(payload: str, rules: list[PayloadRule]) -> str:
    out = payload
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.kind == "prefix":
            out = rule.value + out
        elif rule.kind == "suffix":
            out = out + rule.value
        elif rule.kind == "upper":
            out = out.upper()
        elif rule.kind == "lower":
            out = out.lower()
        elif rule.kind == "reverse":
            out = out[::-1]
        elif rule.kind == "strip":
            out = out.strip()
        elif rule.kind == "url_encode":
            out = urllib.parse.quote(out, safe="")
        elif rule.kind == "url_encode_all":
            out = "".join(f"%{b:02X}" for b in out.encode("utf-8", "surrogateescape"))
        elif rule.kind == "base64":
            out = b64mod.b64encode(out.encode("utf-8", "surrogateescape")).decode()
        elif rule.kind == "hex":
            out = out.encode("utf-8", "surrogateescape").hex()
        elif rule.kind in ("md5", "sha1", "sha256"):
            digest = hashlib.new(rule.kind, out.encode("utf-8", "surrogateescape"))
            out = digest.hexdigest()
    return out


def url_encode_unsafe(value: bytes) -> bytes:
    """Percent-encode everything outside the unreserved set."""
    return b"".join(
        bytes([b]) if b in UNRESERVED else f"%{b:02X}".encode() for b in value
    )


# --------------------------------------------------------------------------
# Attack configuration and job generation
# --------------------------------------------------------------------------

class AttackConfig(BaseModel):
    host: str
    port: int
    tls: bool = False
    template_b64: str
    attack_type: AttackType = "sniper"
    payload_sets: list[PayloadSet] = Field(default_factory=list)
    concurrency: int = 8
    delay_ms: int = 0
    update_content_length: bool = True
    url_encode_payloads: bool = True
    grep_match: list[str] = Field(default_factory=list)
    max_requests: int = 20_000
    name: str = ""


@dataclass
class Job:
    index: int
    values: list[bytes]
    display: list[str]
    position: int | None


def generate_jobs(
    attack_type: AttackType,
    bases: list[bytes],
    sets: list[list[str]],
    *,
    url_encode: bool,
    limit: int,
) -> Iterator[Job]:
    """Yield one Job per request the attack should send."""
    n = len(bases)

    def enc(value: str) -> bytes:
        raw = value.encode("utf-8", "surrogateescape")
        return url_encode_unsafe(raw) if url_encode else raw

    index = 0
    if attack_type == "sniper":
        payloads = sets[0] if sets else []
        for pos in range(n):
            for value in payloads:
                if index >= limit:
                    return
                values = list(bases)
                values[pos] = enc(value)
                yield Job(index, values, [value], pos)
                index += 1

    elif attack_type == "battering_ram":
        payloads = sets[0] if sets else []
        for value in payloads:
            if index >= limit:
                return
            encoded = enc(value)
            yield Job(index, [encoded] * n, [value], None)
            index += 1

    elif attack_type == "pitchfork":
        usable = sets[:n]
        if len(usable) < n or not usable:
            return
        for combo in zip(*usable):
            if index >= limit:
                return
            values = [enc(v) for v in combo]
            yield Job(index, values, list(combo), None)
            index += 1

    else:  # cluster_bomb
        usable = sets[:n]
        if len(usable) < n or not usable:
            return
        for combo in itertools.product(*usable):
            if index >= limit:
                return
            values = [enc(v) for v in combo]
            yield Job(index, values, list(combo), None)
            index += 1


def count_jobs(attack_type: AttackType, positions: int, sets: list[list[str]]) -> int:
    if positions == 0:
        return 0
    if attack_type == "sniper":
        return positions * (len(sets[0]) if sets else 0)
    if attack_type == "battering_ram":
        return len(sets[0]) if sets else 0
    usable = sets[:positions]
    if len(usable) < positions or not usable:
        return 0
    if attack_type == "pitchfork":
        return min(len(s) for s in usable)
    total = 1
    for s in usable:
        total *= len(s)
        if total > MAX_REQUESTS:
            return MAX_REQUESTS
    return total


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

@dataclass
class Attack:
    id: str
    project_id: str
    config: AttackConfig
    total: int
    literals: list[bytes]
    bases: list[bytes]
    sets: list[list[str]]
    created: float = field(default_factory=time.time)
    completed: int = 0
    errors: int = 0
    status: str = "running"          # running | paused | finished | stopped | error
    message: str = ""
    task: asyncio.Task | None = field(default=None, repr=False)
    _pause: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    def summary(self) -> dict:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "name": self.config.name,
            "host": self.config.host,
            "port": self.config.port,
            "tls": self.config.tls,
            "attack_type": self.config.attack_type,
            "positions": len(self.bases),
            "total": self.total,
            "completed": self.completed,
            "errors": self.errors,
            "status": self.status,
            "message": self.message,
            "created": self.created,
        }


class AttackManager:
    def __init__(
        self,
        projects: ProjectManager,
        db: Database,
        hub: EventHub,
        vpn: VpnManager | None = None,
    ):
        self.projects = projects
        self.db = db
        self.hub = hub
        self.vpn = vpn
        # Live attacks only; the database is the record of what has ever run.
        self.attacks: dict[str, Attack] = {}

    @property
    def settings(self) -> Settings:
        return self.projects.settings

    async def preview(self, config: AttackConfig) -> dict:
        """Validate a config and report what the attack would do."""
        template = b64mod.b64decode(config.template_b64)
        literals, bases = parse_positions(template)
        sets = await self._resolve_sets(config)
        total = count_jobs(config.attack_type, len(bases), sets)
        samples = []
        for job in generate_jobs(
            config.attack_type, bases, sets,
            url_encode=config.url_encode_payloads, limit=3,
        ):
            raw = build_request(literals, job.values)
            if config.update_content_length:
                raw = fix_content_length(raw)
            samples.append({
                "index": job.index,
                "payloads": job.display,
                "raw_b64": b64mod.b64encode(raw).decode(),
            })
        return {
            "positions": len(bases),
            "position_bases": [b.decode("latin-1", "replace") for b in bases],
            "set_sizes": [len(s) for s in sets],
            "total": total,
            "capped_at": config.max_requests,
            "will_send": min(total, config.max_requests),
            "samples": samples,
        }

    async def _resolve_sets(self, config: AttackConfig) -> list[list[str]]:
        sets: list[list[str]] = []
        for payload_set in config.payload_sets:
            if payload_set.kind == "list" and payload_set.wordlist:
                content = await self.db.get_wordlist(payload_set.wordlist)
                payload_set = payload_set.model_copy(
                    update={"wordlist_content": content or ""}
                )
            sets.append(payload_set.values())
        return sets

    async def start(self, config: AttackConfig) -> Attack:
        template = b64mod.b64decode(config.template_b64)
        literals, bases = parse_positions(template)
        if not bases:
            raise ParseError(
                "No payload positions marked. Select text in the request and add "
                "a position (§) first."
            )
        sets = await self._resolve_sets(config)
        if not sets or not any(sets):
            raise ParseError("No payloads configured.")

        total = min(count_jobs(config.attack_type, len(bases), sets), config.max_requests)
        if total == 0:
            raise ParseError(
                f"This combination produces no requests. {config.attack_type} needs "
                f"one payload set per position ({len(bases)} marked)."
            )

        attack = Attack(
            id=uuid.uuid4().hex[:12],
            project_id=self.projects.active_id,
            config=config,
            total=total,
            literals=literals,
            bases=bases,
            sets=sets,
        )
        attack._pause.set()
        self.attacks[attack.id] = attack
        await self._persist(attack)
        attack.task = asyncio.create_task(self._run(attack))
        self.hub.publish("intruder_started", attack.summary())
        return attack

    async def _persist(self, attack: Attack) -> None:
        """Mirror an attack's state into the database so it survives a restart."""
        await self.db.upsert_attack(
            id=attack.id,
            project_id=attack.project_id,
            created=attack.created,
            name=attack.config.name,
            host=attack.config.host,
            port=attack.config.port,
            tls=int(attack.config.tls),
            attack_type=attack.config.attack_type,
            positions=len(attack.bases),
            total=attack.total,
            completed=attack.completed,
            errors=attack.errors,
            status=attack.status,
            message=attack.message,
            config=attack.config.model_dump(),
        )

    async def _run(self, attack: Attack) -> None:
        config = attack.config
        queue: asyncio.Queue[Job | None] = asyncio.Queue(maxsize=config.concurrency * 4)

        async def producer() -> None:
            for job in generate_jobs(
                config.attack_type, attack.bases, attack.sets,
                url_encode=config.url_encode_payloads, limit=attack.total,
            ):
                await queue.put(job)
            for _ in range(max(1, config.concurrency)):
                await queue.put(None)

        async def worker() -> None:
            while True:
                job = await queue.get()
                if job is None:
                    return
                await attack._pause.wait()
                if attack.status in ("stopped", "error"):
                    return
                await self._run_job(attack, job)
                if config.delay_ms > 0:
                    await asyncio.sleep(config.delay_ms / 1000)

        try:
            workers = [asyncio.create_task(worker()) for _ in range(max(1, config.concurrency))]
            await asyncio.gather(producer(), *workers)
            if attack.status == "running":
                attack.status = "finished"
        except asyncio.CancelledError:
            attack.status = "stopped"
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("intruder attack %s failed", attack.id)
            attack.status = "error"
            attack.message = f"{type(exc).__name__}: {exc}"
        finally:
            await self._persist(attack)
            self.hub.publish("intruder_done", attack.summary())

    async def _run_job(self, attack: Attack, job: Job) -> None:
        config = attack.config
        raw = build_request(attack.literals, job.values)
        if config.update_content_length:
            raw = fix_content_length(raw)

        blocked = self.vpn.killswitch_error(self.settings) if self.vpn else None
        if blocked:
            result = UpstreamResult(error=blocked)
        elif http2.looks_like_h2_text(raw):
            # The template is written in the HTTP/2 form, so send it as HTTP/2.
            try:
                headers, body = http2.request_from_text(raw)
            except http2.Http2Error as exc:
                result = UpstreamResult(error=f"unusable HTTP/2 request: {exc}")
            else:
                result = await send_h2_request(
                    config.host, config.port, headers, body, self.settings
                )
        else:
            result = await send_request(
                config.host, config.port, config.tls, raw, self.settings
            )

        status = reason = None
        resp_len = words = None
        grep_hits: list[str] = []
        if result.h2_headers is not None:
            status = result.status
            reason = ""
            raw_response = http2.response_to_text(result.h2_headers, result.h2_body)
            resp_len = len(raw_response)
            words = len(result.h2_body.split())
            for needle in config.grep_match:
                if needle and needle.encode("utf-8", "surrogateescape") in raw_response:
                    grep_hits.append(needle)
        elif result.response is not None:
            status = result.response.status
            reason = result.response.reason.decode("latin-1", "replace")
            resp_len = len(result.raw_response)
            words = len(result.response.body.split())
            for needle in config.grep_match:
                if needle and needle.encode("utf-8", "surrogateescape") in result.raw_response:
                    grep_hits.append(needle)
        if result.error:
            attack.errors += 1

        attack.completed += 1
        row = {
            "attack_id": attack.id,
            "idx": job.index,
            "payloads": "\x1f".join(job.display),
            "position": job.position,
            "status": status,
            "reason": reason,
            "resp_len": resp_len,
            "words": words,
            "duration_ms": round(result.duration_ms, 1),
            "error": result.error,
            "grep_hits": ",".join(grep_hits),
        }
        stored_response = result.raw_response or None
        if result.h2_headers is not None:
            stored_response = http2.response_to_text(result.h2_headers, result.h2_body)
        await self.db.insert_result(
            **row,
            raw_request=raw,
            raw_response=stored_response,
        )
        if attack.completed % PERSIST_EVERY == 0:
            await self._persist(attack)
        self.hub.publish("intruder_result", {
            **row,
            "payloads": job.display,
            "grep_hits": grep_hits,
            "completed": attack.completed,
            "total": attack.total,
        })

    # ------------------------------------------------------------ management
    def get(self, attack_id: str) -> Attack | None:
        return self.attacks.get(attack_id)

    def pause(self, attack_id: str) -> bool:
        attack = self.attacks.get(attack_id)
        if not attack or attack.status != "running":
            return False
        attack._pause.clear()
        attack.status = "paused"
        asyncio.create_task(self._persist(attack))
        self.hub.publish("intruder_state", attack.summary())
        return True

    def resume(self, attack_id: str) -> bool:
        attack = self.attacks.get(attack_id)
        if not attack or attack.status != "paused":
            return False
        attack._pause.set()
        attack.status = "running"
        asyncio.create_task(self._persist(attack))
        self.hub.publish("intruder_state", attack.summary())
        return True

    def stop(self, attack_id: str) -> bool:
        attack = self.attacks.get(attack_id)
        if not attack:
            return False
        attack.status = "stopped"
        attack._pause.set()  # let blocked workers observe the new status
        if attack.task and not attack.task.done():
            attack.task.cancel()
        asyncio.create_task(self._persist(attack))
        self.hub.publish("intruder_state", attack.summary())
        return True

    async def delete(self, attack_id: str) -> bool:
        stored = await self.db.get_attack(attack_id)
        live = self.attacks.pop(attack_id, None)
        if stored is None and live is None:
            return False
        if live is not None and live.task and not live.task.done():
            live.task.cancel()
        await self.db.delete_attack(attack_id)   # also clears its results
        return True

    async def list_attacks(self) -> list[dict]:
        """Attacks in the active project, newest first.

        The database is the record of what has run; live attacks overwrite their
        stored row so in-flight progress is accurate.
        """
        rows = await self.db.list_attacks(self.projects.active_id)
        out = []
        for row in rows:
            live = self.attacks.get(row["id"])
            if live is not None:
                out.append(live.summary())
                continue
            out.append({
                "id": row["id"],
                "project_id": row["project_id"],
                "name": row["name"] or "",
                "host": row["host"],
                "port": row["port"],
                "tls": bool(row["tls"]),
                "attack_type": row["attack_type"],
                "positions": row["positions"],
                "total": row["total"],
                "completed": row["completed"],
                "errors": row["errors"],
                "status": row["status"],
                "message": row["message"] or "",
                "created": row["created"],
            })
        return out
