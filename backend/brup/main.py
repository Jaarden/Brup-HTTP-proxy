"""BRUP application entry point: API, WebSocket feed and static UI."""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .ca import CertificateAuthority
from .config import DATA_DIR, SettingsStore
from .db import Database, IncompatibleDatabase
from .events import EventHub
from .intruder import AttackManager
from .proxy.interceptor import Interceptor
from .projects import ProjectManager
from .proxy.server import ProxyServer
from .vpn import VpnManager

logging.basicConfig(
    level=os.environ.get("BRUP_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("brup")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


class AppState:
    """Container for the long-lived singletons the API reaches into."""

    def __init__(self) -> None:
        self.store = SettingsStore()          # system-wide tier
        self.ca = CertificateAuthority(DATA_DIR / "ca")
        self.db = Database(DATA_DIR / "brup.sqlite3")
        self.hub = EventHub()
        self.projects = ProjectManager(self.db, self.store, self.hub)
        self.vpn = VpnManager(self.db, self.store, self.hub)
        self.interceptor = Interceptor(self.hub)
        self.proxy = ProxyServer(
            self.projects, self.ca, self.interceptor, self.hub, self.db, self.vpn
        )
        self.intruder = AttackManager(self.projects, self.db, self.hub, self.vpn)


try:
    state = AppState()
except IncompatibleDatabase as exc:  # pragma: no cover - startup guard
    log.error("%s", exc)
    raise SystemExit(1) from exc


@asynccontextmanager
async def lifespan(_app: FastAPI):
    log.info("BRUP starting; data dir %s", DATA_DIR)
    log.info("CA fingerprint SHA-256 %s", state.ca.fingerprint_sha256())
    await state.projects.load()
    await state.vpn.autoconnect()
    try:
        await state.proxy.start()
    except OSError as exc:
        log.error("could not start proxy listener: %s", exc)
    yield
    await state.proxy.stop()
    await state.vpn.shutdown()
    state.db.close()


app = FastAPI(title="BRUP", version="1.0.0", lifespan=lifespan)

from .api.routes import router  # noqa: E402  (import after app/state exist)

app.include_router(router)


if STATIC_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        """Serve the built UI, falling back to index.html for client routes."""
        candidate = (STATIC_DIR / full_path).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(STATIC_DIR):
            return FileResponse(candidate)
        return FileResponse(STATIC_DIR / "index.html")
else:
    @app.get("/", include_in_schema=False)
    async def no_ui():
        return {
            "detail": "UI bundle not found. Build the frontend or use the API at /api.",
        }
