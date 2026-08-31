"""Projects: isolated workspaces, each with its own settings overrides.

A project owns its proxy history, sitemap, Repeater tabs and Intruder attacks.
The CA and the listener configuration are system-wide, because there is one
listener process and one certificate authority serving every project.
"""
from __future__ import annotations

import logging
from typing import Any

from .config import (
    PROJECT_OVERRIDABLE_KEYS,
    Settings,
    SettingsStore,
    merge_settings,
    validate_overrides,
)
from .db import Database
from .events import EventHub

log = logging.getLogger("brup.projects")

ACTIVE_KEY = "active_project"
# The project created when there is none is temporary, like Burp's: work is
# discarded on restart unless you explicitly keep it or make your own project.
# Named for what it is, since "Default" would not hint that it vanishes.
BOOTSTRAP_NAME = "Temporary project"


class ProjectError(Exception):
    """Operator-facing problem with a project operation."""


class ProjectManager:
    """Owns the active project and the effective settings derived from it.

    The proxy reads ``.settings`` on every request, so the merged result is
    cached and only rebuilt when the system settings or the active project's
    overrides actually change.
    """

    def __init__(self, db: Database, system: SettingsStore, hub: EventHub):
        self.db = db
        self.system = system
        self.hub = hub
        self._active_id: str | None = None
        self._active: dict[str, Any] | None = None
        self._cached: Settings | None = None
        self._cached_base: Settings | None = None

    # ------------------------------------------------------------- lifecycle
    async def load(self) -> None:
        """Pick up the previously active project, creating one if needed.

        Temporary projects were already purged when the database was opened, so
        arriving here with none means the last run had nothing permanent.
        """
        projects = await self.db.list_projects()
        if not projects:
            created = await self.db.create_project(BOOTSTRAP_NAME, temporary=True)
            projects = [created]
            log.info("created %s (temporary; discarded on restart)", BOOTSTRAP_NAME)

        wanted = await self.db.get_meta(ACTIVE_KEY)
        chosen = next((p for p in projects if p["id"] == wanted), projects[0])
        await self._set_active(chosen["id"], announce=False)

    async def _set_active(self, project_id: str, *, announce: bool = True) -> None:
        project = await self.db.get_project(project_id)
        if project is None:
            raise ProjectError(f"no project with id {project_id!r}")
        self._active_id = project_id
        self._active = project
        self.invalidate()
        await self.db.set_meta(ACTIVE_KEY, project_id)
        log.info("active project: %s (%s)", project["name"], project_id)
        if announce:
            self.hub.publish("project_changed", {
                "active_id": project_id,
                "project": self.public(project),
                "settings": self.settings.model_dump(),
            })

    # -------------------------------------------------------------- accessors
    @property
    def active_id(self) -> str:
        if self._active_id is None:
            raise ProjectError("no active project; ProjectManager.load() not run")
        return self._active_id

    @property
    def active(self) -> dict[str, Any]:
        if self._active is None:
            raise ProjectError("no active project; ProjectManager.load() not run")
        return self._active

    @property
    def overrides(self) -> dict[str, Any]:
        return dict(self.active.get("overrides") or {})

    @property
    def settings(self) -> Settings:
        """Effective settings for the active project.

        Read on every proxied request, so the merge is cached. The cache is also
        keyed on the identity of the system Settings object, which SettingsStore
        replaces wholesale on update - that catches a stale cache even if
        somebody forgets to call invalidate().
        """
        system = self.system.settings
        if self._cached is None or self._cached_base is not system:
            self._cached = merge_settings(system, self.overrides)
            self._cached_base = system
        return self._cached

    def invalidate(self) -> None:
        """Drop the merged-settings cache after a settings change."""
        self._cached = None
        self._cached_base = None

    @staticmethod
    def public(project: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": project["id"],
            "name": project["name"],
            "created": project["created"],
            "updated": project["updated"],
            "notes": project.get("notes", ""),
            "overrides": project.get("overrides") or {},
            "temporary": bool(project.get("temporary")),
            "flow_count": project.get("flow_count", 0),
            "attack_count": project.get("attack_count", 0),
        }

    async def list(self) -> list[dict[str, Any]]:
        return [self.public(p) for p in await self.db.list_projects()]

    # ------------------------------------------------------------ operations
    async def create(
        self,
        name: str,
        *,
        copy_settings_from: str | None = None,
        temporary: bool = False,
    ):
        name = name.strip()
        if not name:
            raise ProjectError("a project needs a name")
        overrides: dict[str, Any] = {}
        if copy_settings_from:
            source = await self.db.get_project(copy_settings_from)
            if source is None:
                raise ProjectError("the project to copy settings from no longer exists")
            overrides = dict(source.get("overrides") or {})
        project = await self.db.create_project(name, overrides, temporary=temporary)
        self.hub.publish("projects_changed", None)
        return self.public(project)

    async def keep(self, project_id: str):
        """Turn a temporary project into a permanent one."""
        project = await self.db.get_project(project_id)
        if project is None:
            raise ProjectError("no such project")
        if not project.get("temporary"):
            raise ProjectError("this project is already permanent")
        await self.db.update_project(project_id, temporary=0)
        if project_id == self._active_id:
            self._active = await self.db.get_project(project_id)
        self.hub.publish("projects_changed", None)
        return self.public(await self.db.get_project(project_id))

    async def activate(self, project_id: str):
        if project_id == self._active_id:
            return self.public(self.active)
        await self._set_active(project_id)
        return self.public(self.active)

    async def rename(self, project_id: str, name: str):
        name = name.strip()
        if not name:
            raise ProjectError("a project needs a name")
        if await self.db.get_project(project_id) is None:
            raise ProjectError("no such project")
        await self.db.update_project(project_id, name=name)
        if project_id == self._active_id:
            self._active = await self.db.get_project(project_id)
        self.hub.publish("projects_changed", None)
        return self.public(await self.db.get_project(project_id))

    async def set_notes(self, project_id: str, notes: str):
        await self.db.update_project(project_id, notes=notes)
        if project_id == self._active_id:
            self._active = await self.db.get_project(project_id)
        return self.public(await self.db.get_project(project_id))

    async def set_overrides(self, project_id: str, patch: dict[str, Any]):
        """Merge a patch into a project's overrides. A null value clears a key."""
        project = await self.db.get_project(project_id)
        if project is None:
            raise ProjectError("no such project")

        merged = dict(project.get("overrides") or {})
        for key, value in (patch or {}).items():
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value
        try:
            cleaned = validate_overrides(merged)
        except ValueError as exc:
            raise ProjectError(str(exc)) from exc

        await self.db.update_project(project_id, overrides=cleaned)
        if project_id == self._active_id:
            self._active = await self.db.get_project(project_id)
            self.invalidate()
            self.hub.publish("settings_changed", self.settings.model_dump())
        self.hub.publish("projects_changed", None)
        return self.public(await self.db.get_project(project_id))

    async def delete(self, project_id: str) -> str:
        """Delete a project. Returns the id that is active afterwards."""
        projects = await self.db.list_projects()
        if len(projects) <= 1:
            raise ProjectError(
                "This is the only project, so it cannot be deleted. Create another "
                "one first, or clear this project's history instead."
            )
        if not any(p["id"] == project_id for p in projects):
            raise ProjectError("no such project")

        await self.db.delete_project(project_id)

        if project_id == self._active_id:
            remaining = await self.db.list_projects()
            await self._set_active(remaining[0]["id"])
        self.hub.publish("projects_changed", None)
        return self.active_id

    # ---------------------------------------------------------- system tier
    async def update_system(self, patch: dict[str, Any]) -> Settings:
        new = self.system.update(patch)
        self.invalidate()
        self.hub.publish("settings_changed", self.settings.model_dump())
        return new

    def describe_settings(self) -> dict[str, Any]:
        """Everything the UI needs to render both tiers and what is overridden."""
        return {
            "effective": self.settings.model_dump(),
            "system": self.system.settings.model_dump(),
            "overrides": self.overrides,
            "overridable_keys": sorted(PROJECT_OVERRIDABLE_KEYS),
            "project_id": self._active_id,
        }
