"""FastMCP server that exposes incident tools for one Kener v4 instance.

Configure it with environment variables:

  KENER_URL                  Base URL of the Kener instance (required).
  KENER_API_KEY              Kener API key. Create one under Manage > API Keys.
  KENER_API_KEY_CMD          Or: a command that prints the API key, for example
                             "op read op://Vault/Item/api_key". It runs on first use.
  KENER_API_KEY_CMD_TIMEOUT  Seconds to wait for that command (default 30).
  KENER_NAME                 Short name for this instance, used in messages (optional).
  KENER_INSTRUCTIONS         Extra text for the agent, such as who reads the page.

Set exactly one of KENER_API_KEY and KENER_API_KEY_CMD. The --url, --api-key-cmd
and --name flags override the matching variables.

For more than one instance, register one server per instance.
"""

import argparse
import asyncio
import json
import os
import re
import sys
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

import httpx
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from . import __version__
from .auth import DEFAULT_CMD_TIMEOUT, ApiKeyError, ApiKeyProvider
from .client import (
    DEFAULT_TIMEOUT,
    Impact,
    IncidentState,
    KenerClient,
    KenerError,
    MaintenanceEventStatus,
    MaintenanceImpact,
    MaintenanceStatus,
    MonitorStatus,
    YesNo,
)

READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}
WRITE = {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True}
DESTRUCTIVE = {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True}

MASKED_SECRET = "********"
REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS_INDEX_URL = "https://kener.ing/docs/v4/llms.txt"
DOCS_RAW_PREFIX = "https://kener.ing/docs/raw/v4/"

TYPE_DATA_SECRET_FIELDS = ("body", "proxy", "connectionString", "secretString", "tlsKey")
SITE_SECRET_KEYS = frozenset(
    {
        "secret",
        "client_secret",
        "clientsecret",
        "secret_key",
        "secretkey",
        "api_key",
        "apikey",
        "token",
        "password",
    }
)

BACKUP_REMINDER = (
    "Call export_config before running this tool so the current configuration is backed up."
)

NOTIFY_CAVEAT = (
    "Posting an incident update notifies subscribers by email on Kener 4.1.8 and later "
    "(on Kener 4.1.7 and earlier, API updates did not email subscribers: rajnandan1/kener#886)."
)


class SettingsError(Exception):
    """A required environment variable is missing or not valid."""


@dataclass(frozen=True)
class Settings:
    url: str
    api_key: str | None = None
    api_key_cmd: str | None = None
    api_key_cmd_timeout: float = DEFAULT_CMD_TIMEOUT
    name: str | None = None
    instructions: str | None = None

    def __post_init__(self) -> None:
        parts = urlsplit(self.url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise SettingsError("KENER_URL must be an https:// or http:// URL.")
        if parts.username or parts.password:
            raise SettingsError("KENER_URL must not contain a user name or password.")
        if bool(self.api_key) == bool(self.api_key_cmd):
            raise SettingsError("Set exactly one of KENER_API_KEY and KENER_API_KEY_CMD.")

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None, **overrides: str | None) -> "Settings":
        env = os.environ if env is None else env

        def get(key: str) -> str | None:
            override = overrides.get(key.removeprefix("KENER_").lower())
            value = override if override is not None else env.get(key, "")
            return value.strip() or None

        url = get("KENER_URL")
        if not url:
            raise SettingsError("KENER_URL is not set.")
        timeout = get("KENER_API_KEY_CMD_TIMEOUT")
        try:
            timeout_s = float(timeout) if timeout else DEFAULT_CMD_TIMEOUT
        except ValueError:
            raise SettingsError("KENER_API_KEY_CMD_TIMEOUT must be a number.") from None
        api_key_cmd = get("KENER_API_KEY_CMD")
        return cls(
            url=url.rstrip("/"),
            # A command given as a flag wins over a key in the environment.
            api_key=None if overrides.get("api_key_cmd") else get("KENER_API_KEY"),
            api_key_cmd=api_key_cmd,
            api_key_cmd_timeout=timeout_s,
            name=get("KENER_NAME"),
            instructions=get("KENER_INSTRUCTIONS"),
        )

    def key_provider(self) -> ApiKeyProvider:
        return ApiKeyProvider(self.api_key, self.api_key_cmd, self.api_key_cmd_timeout)

    @property
    def label(self) -> str:
        return self.name or self.url


def _iso(ts: int | None) -> str | None:
    return datetime.fromtimestamp(ts, UTC).isoformat() if ts else None


def _now() -> int:
    return int(datetime.now(UTC).timestamp())


def _incident_summary(inc: dict) -> dict:
    return {
        "id": inc["id"],
        "title": inc["title"],
        "state": inc["state"],
        "started_at": _iso(inc.get("start_date_time")),
        "ended_at": _iso(inc.get("end_date_time")),
        "source": inc.get("incident_source"),
        "monitors": inc.get("monitors", []),
        "url": inc.get("url"),
    }


def _comment_summary(c: dict) -> dict:
    return {
        "id": c["id"],
        "state": c["state"],
        "comment": c["comment"],
        "at": _iso(c.get("timestamp")),
    }


def _monitor_summary(m: dict) -> dict:
    # Never return type_data or monitor_settings_json in list_monitors: they hold
    # target URLs, request headers and other monitor secrets.
    return {
        "tag": m["tag"],
        "name": m["name"],
        "status": m.get("status"),
        "monitor_type": m.get("monitor_type"),
        "category": m.get("category_name"),
        "hidden": m.get("is_hidden") == "YES",
        "description": m.get("description"),
    }


def _mask_type_data(type_data: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(type_data, dict):
        return {}
    out = dict(type_data)
    for field in TYPE_DATA_SECRET_FIELDS:
        val = out.get(field)
        if val is not None and val != "":
            out[field] = MASKED_SECRET
    headers = out.get("headers")
    if isinstance(headers, list):
        masked_headers = []
        for h in headers:
            if isinstance(h, dict):
                h_copy = dict(h)
                if h_copy.get("value"):
                    h_copy["value"] = MASKED_SECRET
                masked_headers.append(h_copy)
            else:
                masked_headers.append(h)
        out["headers"] = masked_headers
    return out


def _mask_monitor(m: dict, pages: list[str] | None = None) -> dict:
    out = {
        "id": m.get("id"),
        "tag": m["tag"],
        "name": m["name"],
        "description": m.get("description"),
        "image": m.get("image"),
        "cron": m.get("cron"),
        "default_status": m.get("default_status"),
        "status": m.get("status"),
        "category_name": m.get("category_name"),
        "monitor_type": m.get("monitor_type"),
        "type_data": _mask_type_data(m.get("type_data")),
        "include_degraded_in_downtime": m.get("include_degraded_in_downtime"),
        "is_hidden": m.get("is_hidden"),
        "confirmation_threshold": m.get("confirmation_threshold"),
        "monitor_settings_json": m.get("monitor_settings_json"),
        "external_url": m.get("external_url"),
    }
    if pages is not None:
        out["pages"] = pages
    return out


def _is_secret_key_name(key: str) -> bool:
    norm = key.strip().lower().replace("-", "_").replace(" ", "_")
    return norm in SITE_SECRET_KEYS or any(
        norm.endswith(f"_{s}") or norm.startswith(f"{s}_") for s in ("secret", "password", "token")
    )


def _mask_site_value(key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (
                MASKED_SECRET
                if _is_secret_key_name(k) and v not in (None, "")
                else _mask_site_value(k, v)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_mask_site_value(key, item) for item in value]
    if _is_secret_key_name(key) and value not in (None, ""):
        return MASKED_SECRET
    return value


def _contains_masked_secret(value: Any) -> bool:
    if value == MASKED_SECRET:
        return True
    if isinstance(value, dict):
        return any(
            _contains_masked_secret(k) or _contains_masked_secret(v) for k, v in value.items()
        )
    if isinstance(value, list):
        return any(_contains_masked_secret(item) for item in value)
    return False


def _extract_page_monitor_tags(page: dict) -> list[str]:
    return [m["monitor_tag"] if isinstance(m, dict) else m for m in (page.get("monitors") or [])]


def _monitor_pages(pages: list[dict], tag: str) -> list[str]:
    return [p["page_path"] for p in pages if tag in _extract_page_monitor_tags(p)]


def _page_summary(p: dict) -> dict:
    return {
        "id": p.get("id"),
        "page_path": p["page_path"],
        "page_title": p.get("page_title"),
        "page_header": p.get("page_header"),
        "page_subheader": p.get("page_subheader"),
        "page_logo": p.get("page_logo"),
        "page_settings": p.get("page_settings"),
        "monitors": _extract_page_monitor_tags(p),
    }


def _maintenance_event_summary(e: dict) -> dict:
    return {
        "id": e["id"],
        "maintenance_id": e.get("maintenance_id"),
        "status": e.get("status"),
        "started_at": _iso(e.get("start_date_time")),
        "ended_at": _iso(e.get("end_date_time")),
        "start_date_time": e.get("start_date_time"),
        "end_date_time": e.get("end_date_time"),
        "url": e.get("url"),
    }


def _maintenance_summary(m: dict, events: list[dict] | None = None) -> dict:
    out = {
        "id": m["id"],
        "title": m["title"],
        "description": m.get("description"),
        "status": m.get("status"),
        "started_at": _iso(m.get("start_date_time")),
        "start_date_time": m.get("start_date_time"),
        "rrule": m.get("rrule"),
        "duration_seconds": m.get("duration_seconds"),
        "monitors": m.get("monitors", []),
        "url": m.get("url"),
    }
    if events is not None:
        out["events"] = [_maintenance_event_summary(e) for e in events]
    return out


_LLMS_ENTRY_RE = re.compile(
    r"^-\s+\[(?P<title>[^\]]+)\]\((?P<url>https?://[^\s)]+)\)(?::\s*(?P<desc>.*))?$"
)


def _parse_llms_txt(text: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        match = _LLMS_ENTRY_RE.match(line)
        if not match:
            continue
        url = match.group("url")
        slug = ""
        if url.startswith(DOCS_RAW_PREFIX) and url.endswith(".md"):
            slug = url[len(DOCS_RAW_PREFIX) : -3]
        entries.append(
            {
                "title": match.group("title"),
                "slug": slug,
                "url": url,
                "description": (match.group("desc") or "").strip(),
            }
        )
    return entries


MonitorTag = Annotated[str, Field(description="Monitor tag (from list_monitors).", min_length=1)]
PagePath = Annotated[
    str,
    Field(description="Page path segment, or '~home' for the home page.", min_length=1),
]
IncidentId = Annotated[int, Field(description="Kener incident ID.", ge=1)]
MaintenanceId = Annotated[int, Field(description="Kener maintenance ID.", ge=1)]


def create_server(settings: Settings, keys: ApiKeyProvider | None = None) -> FastMCP:
    keys = keys or settings.key_provider()
    instructions = (
        f"Manage incidents on the Kener status page at {settings.url}. "
        "Updates are public: they appear on the status page and reach any integration "
        "that reads Kener."
    )
    if settings.instructions:
        instructions += "\n\n" + settings.instructions
    mcp = FastMCP(
        f"kener-{settings.name}" if settings.name else "kener",
        instructions=instructions,
        version=__version__,
    )

    @asynccontextmanager
    async def kener() -> AsyncIterator[KenerClient]:
        try:
            api_key = await keys.get()
        except ApiKeyError as e:
            raise ToolError(f"[{settings.label}] {e}") from None
        client = KenerClient(settings.url, api_key)
        try:
            yield client
        except KenerError as e:
            if e.status_code == 401 and keys.uses_command:
                # The key may have been rotated. Run the command again next time.
                keys.invalidate()
            raise ToolError(f"[{settings.label}] {e}") from None
        finally:
            await client.aclose()

    @mcp.tool(annotations=READ_ONLY)
    async def list_monitors(
        include_hidden: Annotated[bool, Field(description="Include hidden monitors.")] = False,
    ) -> list[dict]:
        """List the monitors on this Kener instance (tag, name, status, type, category).

        Use the tags with create_incident.
        """
        async with kener() as k:
            monitors = await k.list_monitors()
        out = [_monitor_summary(m) for m in monitors]
        return out if include_hidden else [m for m in out if not m["hidden"]]

    @mcp.tool(annotations=READ_ONLY)
    async def list_incidents(
        include_resolved: Annotated[
            bool, Field(description="Also return RESOLVED incidents.")
        ] = False,
        limit: Annotated[int, Field(description="Maximum incidents to return.", ge=1)] = 20,
    ) -> list[dict]:
        """List incidents, newest first. By default only open (not RESOLVED) incidents."""
        async with kener() as k:
            incidents = await k.list_incidents()
        if not include_resolved:
            incidents = [i for i in incidents if i["state"] != "RESOLVED"]
        incidents.sort(key=lambda i: i.get("start_date_time") or 0, reverse=True)
        return [_incident_summary(i) for i in incidents[:limit]]

    @mcp.tool(annotations=READ_ONLY)
    async def get_incident(incident_id: IncidentId) -> dict:
        """Get one incident with its update timeline (oldest first)."""
        async with kener() as k:
            incident = await k.get_incident(incident_id)
            comments = await k.list_comments(incident_id)
        out = _incident_summary(incident)
        comments.sort(key=lambda c: (c.get("timestamp") or 0, c["id"]))
        out["updates"] = [_comment_summary(c) for c in comments]
        return out

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Post a public update on an incident and set its state. The state becomes "
            "the incident's current state. To close an incident, use resolve_incident. "
            f"{BACKUP_REMINDER} {NOTIFY_CAVEAT}"
        ),
    )
    async def post_incident_update(
        incident_id: IncidentId,
        comment: Annotated[
            str, Field(description="Update text shown on the status page.", min_length=1)
        ],
        state: Annotated[IncidentState, Field(description="New incident state.")],
    ) -> dict:
        async with kener() as k:
            created = await k.add_comment(incident_id, comment.strip(), state)
            incident = await k.get_incident(incident_id)
        return {"update": _comment_summary(created), "incident": _incident_summary(incident)}

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Resolve an incident. Kener has no separate resolve call: this posts an "
            "update with state RESOLVED, which closes the incident and sets its end "
            f"time. {BACKUP_REMINDER} {NOTIFY_CAVEAT}"
        ),
    )
    async def resolve_incident(
        incident_id: IncidentId,
        comment: Annotated[str, Field(description="Closing update text.", min_length=1)] = (
            "This incident has been resolved."
        ),
    ) -> dict:
        async with kener() as k:
            created = await k.add_comment(incident_id, comment.strip(), "RESOLVED")
            incident = await k.get_incident(incident_id)
        return {"update": _comment_summary(created), "incident": _incident_summary(incident)}

    @mcp.tool(
        annotations=WRITE,
        description=(
            "Create a public incident, starting now, in state INVESTIGATING. Optionally "
            "attach monitors (tags from list_monitors) and post a first update. " + NOTIFY_CAVEAT
        ),
    )
    async def create_incident(
        title: Annotated[str, Field(description="Incident title.", min_length=1)],
        monitor_tags: Annotated[
            list[str] | None, Field(description="Monitor tags the incident affects.")
        ] = None,
        impact: Annotated[Impact, Field(description="Impact on each listed monitor.")] = "DOWN",
        first_update: Annotated[
            str | None, Field(description="Optional first update text.")
        ] = None,
        state: Annotated[
            IncidentState, Field(description="State for the first update.")
        ] = "INVESTIGATING",
    ) -> dict:
        monitors = [{"monitor_tag": t, "impact": impact} for t in monitor_tags or []]
        async with kener() as k:
            incident = await k.create_incident(title.strip(), _now(), monitors)
            out: dict = {"incident": _incident_summary(incident)}
            if first_update and first_update.strip():
                created = await k.add_comment(incident["id"], first_update.strip(), state)
                out["update"] = _comment_summary(created)
                out["incident"] = _incident_summary(await k.get_incident(incident["id"]))
        return out

    @mcp.tool(annotations=READ_ONLY)
    async def get_monitor(tag: MonitorTag) -> dict:
        """Get full details for one monitor (secrets in type_data are masked) and its pages."""
        async with kener() as k:
            monitor, pages = await asyncio.gather(k.get_monitor(tag), k.list_pages())
        return _mask_monitor(monitor, pages=_monitor_pages(pages, tag))

    @mcp.tool(annotations=READ_ONLY)
    async def list_pages() -> list[dict]:
        """List all status pages (including '~home') and their ordered monitor tags."""
        async with kener() as k:
            pages = await k.list_pages()
        return [_page_summary(p) for p in pages]

    @mcp.tool(annotations=READ_ONLY)
    async def get_page(page_path: PagePath) -> dict:
        """Get one status page (use '~home' for the home page) and its settings and monitors."""
        async with kener() as k:
            page = await k.get_page(page_path)
        return _page_summary(page)

    @mcp.tool(annotations=READ_ONLY)
    async def list_maintenances(
        status: Annotated[
            MaintenanceStatus | None,
            Field(description="Filter by maintenance status ('ACTIVE' or 'INACTIVE')."),
        ] = None,
        monitor_tag: Annotated[
            str | None, Field(description="Filter to maintenances affecting this monitor tag.")
        ] = None,
    ) -> list[dict]:
        """List scheduled or recurring maintenances, newest start_date_time first."""
        async with kener() as k:
            maintenances = await k.list_maintenances(status=status, monitor_tag=monitor_tag)
        maintenances.sort(key=lambda m: m.get("start_date_time") or 0, reverse=True)
        return [_maintenance_summary(m) for m in maintenances]

    @mcp.tool(annotations=READ_ONLY)
    async def get_maintenance(maintenance_id: MaintenanceId) -> dict:
        """Get one maintenance definition with its scheduled/past events."""
        async with kener() as k:
            maintenance, events = await asyncio.gather(
                k.get_maintenance(maintenance_id),
                k.list_maintenance_events(maintenance_id),
            )
        events.sort(key=lambda e: e.get("start_date_time") or 0, reverse=True)
        return _maintenance_summary(maintenance, events=events)

    @mcp.tool(annotations=READ_ONLY)
    async def get_site_config(
        key: Annotated[
            str | None,
            Field(
                description=(
                    "Optional site config key (e.g. 'title', 'siteName', 'categories', 'nav', "
                    "'hero', 'colors', 'announcement'). Omit to return all site configuration keys."
                )
            ),
        ] = None,
    ) -> dict:
        """Get site-wide Kener configuration (all keys, or one specific key). Secrets are masked."""
        async with kener() as k:
            if key:
                item = await k.get_site_data_key(key.strip())
                return {
                    "key": item["key"],
                    "value": _mask_site_value(item["key"], item.get("value")),
                    "data_type": item.get("data_type"),
                }
            items = await k.get_site_data()
        return {
            "site_data": {
                item["key"]: {
                    "value": _mask_site_value(item["key"], item.get("value")),
                    "data_type": item.get("data_type"),
                }
                for item in items
            }
        }

    @mcp.tool(annotations=READ_ONLY)
    async def kener_docs(
        topic: Annotated[
            str | None,
            Field(
                description=(
                    "Optional topic slug or search query (e.g. 'monitors/api', "
                    "'maintenances/rrule-patterns', 'setup/site-configuration'). "
                    "Omit to list all available v4 documentation topics."
                )
            ),
        ] = None,
    ) -> dict:
        """Fetch official Kener v4 documentation from kener.ing (llms.txt index or raw markdown)."""
        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": f"kener-mcp/{__version__}"},
            follow_redirects=True,
        ) as http:
            try:
                idx_resp = await http.get(DOCS_INDEX_URL)
                idx_resp.raise_for_status()
            except httpx.HTTPError as e:
                raise ToolError(f"Failed to fetch Kener docs index: {type(e).__name__}") from None
            entries = _parse_llms_txt(idx_resp.text)
            if not topic or not topic.strip():
                return {"index_url": DOCS_INDEX_URL, "topics": entries}

            q = topic.strip().lower().removesuffix(".md").strip("/")
            exact = next(
                (e for e in entries if e["slug"].lower() == q or e["title"].lower() == q),
                None,
            )
            matches = (
                [exact]
                if exact
                else [
                    e
                    for e in entries
                    if q in e["slug"].lower()
                    or q in e["title"].lower()
                    or q in e["description"].lower()
                ]
            )
            if not matches:
                return {
                    "query": topic,
                    "matches": [],
                    "available_slugs": [e["slug"] for e in entries if e["slug"]],
                }
            chosen = matches[0]
            if not chosen["url"].endswith(".md"):
                return {"topic": chosen, "other_matches": matches[1:]}
            try:
                doc_resp = await http.get(chosen["url"])
                doc_resp.raise_for_status()
            except httpx.HTTPError as e:
                raise ToolError(
                    f"Failed to fetch Kener doc '{chosen['slug']}': {type(e).__name__}"
                ) from None
            return {
                "topic": chosen,
                "content": doc_resp.text,
                "other_matches": matches[1:],
            }

    @mcp.tool(annotations=READ_ONLY)
    async def get_config_overview(
        stale_incident_days: Annotated[
            int,
            Field(
                description="Flag open incidents older than this many days (default 7).",
                ge=1,
            ),
        ] = 7,
    ) -> dict:
        """Return a complete overview of the Kener instance and detect configuration anomalies."""
        async with kener() as k:
            monitors, pages, incidents, maintenances, site_items = await asyncio.gather(
                k.list_monitors(),
                k.list_pages(),
                k.list_incidents(),
                k.list_maintenances(),
                k.get_site_data(),
            )
            active_maintenances = [m for m in maintenances if m.get("status") == "ACTIVE"]
            events_by_maint: dict[int, list[dict]] = {}
            if active_maintenances:
                event_lists = await asyncio.gather(
                    *(k.list_maintenance_events(m["id"]) for m in active_maintenances)
                )
                for m, evs in zip(active_maintenances, event_lists, strict=True):
                    events_by_maint[m["id"]] = evs

        now_ts = _now()
        stale_cutoff = now_ts - stale_incident_days * 86400

        # Map monitor tags to pages
        pages_by_monitor: dict[str, list[str]] = {m["tag"]: [] for m in monitors}
        for p in pages:
            p_path = p["page_path"]
            for pm in p.get("monitors") or []:
                m_tag = pm["monitor_tag"] if isinstance(pm, dict) else pm
                pages_by_monitor.setdefault(m_tag, []).append(p_path)

        # Extract configured categories from site_data
        site_map = {item["key"]: item.get("value") for item in site_items}
        raw_categories = site_map.get("categories")
        configured_categories: set[str] = set()
        if isinstance(raw_categories, list):
            for c in raw_categories:
                if isinstance(c, dict) and isinstance(c.get("name"), str):
                    configured_categories.add(c["name"])

        used_categories = {
            m["category_name"]
            for m in monitors
            if isinstance(m.get("category_name"), str) and m["category_name"]
        }

        orphan_monitors = [m["tag"] for m in monitors if not pages_by_monitor.get(m["tag"])]
        inactive_monitors = [m["tag"] for m in monitors if m.get("status") != "ACTIVE"]
        hidden_monitors = [m["tag"] for m in monitors if m.get("is_hidden") == "YES"]
        monitors_without_cron = [
            m["tag"]
            for m in monitors
            if m.get("monitor_type") not in ("NONE", "HEARTBEAT") and not m.get("cron")
        ]
        monitors_with_unknown_category = [
            {"tag": m["tag"], "category": m["category_name"]}
            for m in monitors
            if configured_categories
            and m.get("category_name")
            and m["category_name"] not in configured_categories
        ]
        unused_categories = sorted(configured_categories - used_categories)

        open_incidents = [i for i in incidents if i.get("state") != "RESOLVED"]
        stale_open_incidents = [
            _incident_summary(i)
            for i in open_incidents
            if (i.get("start_date_time") or now_ts) <= stale_cutoff
        ]
        incidents_without_monitors = [
            _incident_summary(i) for i in open_incidents if not i.get("monitors")
        ]

        active_maintenances_without_upcoming_events = []
        for m in active_maintenances:
            evs = events_by_maint.get(m["id"], [])
            has_upcoming = any(
                e.get("status") in ("SCHEDULED", "READY", "ONGOING")
                or (e.get("end_date_time") or 0) > now_ts
                for e in evs
            )
            if not has_upcoming:
                active_maintenances_without_upcoming_events.append(_maintenance_summary(m))

        return {
            "site": {
                "title": site_map.get("title"),
                "siteName": site_map.get("siteName"),
                "siteURL": site_map.get("siteURL"),
                "categories": raw_categories if isinstance(raw_categories, list) else [],
            },
            "counts": {
                "monitors": len(monitors),
                "pages": len(pages),
                "open_incidents": len(open_incidents),
                "total_incidents": len(incidents),
                "active_maintenances": len(active_maintenances),
                "total_maintenances": len(maintenances),
            },
            "monitors": [
                {
                    **_monitor_summary(m),
                    "cron": m.get("cron"),
                    "pages": pages_by_monitor.get(m["tag"], []),
                }
                for m in monitors
            ],
            "pages": [_page_summary(p) for p in pages],
            "open_incidents": [_incident_summary(i) for i in open_incidents],
            "active_maintenances": [_maintenance_summary(m) for m in active_maintenances],
            "anomalies": {
                "orphan_monitors": orphan_monitors,
                "inactive_monitors": inactive_monitors,
                "hidden_monitors": hidden_monitors,
                "monitors_without_cron": monitors_without_cron,
                "monitors_with_unknown_category": monitors_with_unknown_category,
                "unused_categories": unused_categories,
                "stale_open_incidents": stale_open_incidents,
                "incidents_without_monitors": incidents_without_monitors,
                "active_maintenances_without_upcoming_events": (
                    active_maintenances_without_upcoming_events
                ),
            },
        }

    @mcp.tool(
        annotations=WRITE,
        description=(
            "Export the entire Kener configuration (site_data, pages, monitors, incidents, "
            "maintenances) to a timestamped local JSON file. By default secrets are masked "
            "with '********', which makes the file safe to inspect but NOT a restorable backup. "
            "When include_secrets is true, raw secrets returned by Kener are written outside the "
            "repository with chmod 600 permissions and are never returned in the tool output."
        ),
    )
    async def export_config(
        output_dir: Annotated[
            str | None,
            Field(
                description=(
                    "Directory where kener-backup-YYYYMMDD-HHMMSS.json will be written. "
                    "When include_secrets is true, defaults to the system temp directory and "
                    "must be outside the kener-mcp repository."
                )
            ),
        ] = None,
        include_secrets: Annotated[
            bool,
            Field(
                description=(
                    "If true, keep unmasked secrets in the written file (written outside the "
                    "repo with chmod 600). Defaults to false (secrets masked with '********')."
                )
            ),
        ] = False,
    ) -> dict:
        if output_dir:
            target_dir = Path(output_dir).expanduser().resolve()
        elif include_secrets:
            target_dir = Path(tempfile.gettempdir()).resolve()
        else:
            target_dir = Path.cwd().resolve()

        if include_secrets and (target_dir == REPO_ROOT or REPO_ROOT in target_dir.parents):
            raise ToolError(
                "When include_secrets=True, output_dir must be outside the kener-mcp repository."
            )

        async with kener() as k:
            monitors, pages, incidents, maintenances, site_items = await asyncio.gather(
                k.list_monitors(),
                k.list_pages(),
                k.list_incidents(),
                k.list_maintenances(),
                k.get_site_data(),
            )

        now_dt = datetime.now(UTC)
        stamp = now_dt.strftime("%Y%m%d-%H%M%S")
        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = target_dir / f"kener-backup-{stamp}.json"

        exported_monitors = monitors if include_secrets else [_mask_monitor(m) for m in monitors]
        exported_site = [
            {
                "key": item["key"],
                "value": (
                    item.get("value")
                    if include_secrets
                    else _mask_site_value(item["key"], item.get("value"))
                ),
                "data_type": item.get("data_type"),
            }
            for item in site_items
        ]

        payload = {
            "exported_at": now_dt.isoformat(),
            "kener_url": settings.url,
            "secrets_masked": not include_secrets,
            "restorable": include_secrets,
            "note": (
                "Contains raw secrets returned by the Kener API (chmod 600). Note that Kener "
                "4.1.7+ masks OIDC/captcha secrets and Kener 4.1.11+ masks monitor secrets "
                "server-side."
                if include_secrets
                else "Secrets in monitors.type_data and site_data are masked with '********'. "
                "This file is NOT a directly restorable backup."
            ),
            "site_data": exported_site,
            "pages": pages,
            "monitors": exported_monitors,
            "incidents": incidents,
            "maintenances": maintenances,
        }

        data_bytes = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        if include_secrets:
            fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, data_bytes)
            finally:
                os.close(fd)
            os.chmod(file_path, 0o600)
        else:
            file_path.write_bytes(data_bytes)

        return {
            "path": str(file_path),
            "exported_at": payload["exported_at"],
            "secrets_masked": not include_secrets,
            "restorable": include_secrets,
            "warning": payload["note"],
            "counts": {
                "site_data": len(exported_site),
                "pages": len(pages),
                "monitors": len(exported_monitors),
                "incidents": len(incidents),
                "maintenances": len(maintenances),
            },
        }

    # --- Step 2: Create & Update tools --------------------------------------

    @mcp.tool(
        annotations=WRITE,
        description=(
            "Create a new monitor and automatically attach it to the specified status pages "
            "(defaults to ['~home'] so the monitor is visible on the home page; pass [] to "
            "leave it unattached). Secrets in the returned type_data are masked."
        ),
    )
    async def create_monitor(
        tag: Annotated[
            str,
            Field(
                description="Unique monitor tag (lowercase alphanumeric, hyphens, underscores).",
                min_length=1,
            ),
        ],
        name: Annotated[str, Field(description="Display name of the monitor.", min_length=1)],
        monitor_type: Annotated[
            str,
            Field(
                description=(
                    "Monitor type (e.g. 'API', 'PING', 'DNS', 'TCP', 'GROUP', 'SSL', 'SQL', "
                    "'HEARTBEAT', 'GAMEDIG', 'NONE')."
                )
            ),
        ] = "API",
        type_data: Annotated[
            dict[str, Any] | None,
            Field(description="Type-specific configuration (e.g. url, method, timeout, eval)."),
        ] = None,
        cron: Annotated[
            str, Field(description="Cron expression (defaults to every minute '* * * * *').")
        ] = "* * * * *",
        default_status: Annotated[
            str, Field(description="Default status ('UP', 'DOWN', 'DEGRADED', or 'NONE').")
        ] = "UP",
        status: Annotated[
            MonitorStatus, Field(description="Initial status ('ACTIVE' or 'INACTIVE').")
        ] = "ACTIVE",
        category_name: Annotated[
            str | None, Field(description="Category name (e.g. 'Home' or a site category).")
        ] = None,
        description: Annotated[
            str | None, Field(description="Optional description shown on the status page.")
        ] = None,
        image: Annotated[
            str | None, Field(description="Optional monitor logo URL or path.")
        ] = None,
        is_hidden: Annotated[
            YesNo, Field(description="'YES' to hide from public pages, 'NO' otherwise.")
        ] = "NO",
        include_degraded_in_downtime: Annotated[
            YesNo, Field(description="'YES' to count DEGRADED towards downtime, 'NO' otherwise.")
        ] = "NO",
        confirmation_threshold: Annotated[
            int,
            Field(description="Consecutive failures before changing status (1..60).", ge=1, le=60),
        ] = 1,
        external_url: Annotated[
            str | None, Field(description="Optional external URL linked from the monitor.")
        ] = None,
        monitor_settings_json: Annotated[
            dict[str, Any] | None, Field(description="Optional monitor_settings_json object.")
        ] = None,
        page_paths: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Pages where this monitor should be displayed (defaults to ['~home']; "
                    "pass [] to attach to no page)."
                )
            ),
        ] = None,
    ) -> dict:
        if type_data is not None and _contains_masked_secret(type_data):
            raise ToolError(
                "type_data must not contain masked placeholder '********'; "
                "provide the real secret value."
            )
        body: dict[str, Any] = {
            "tag": tag.strip(),
            "name": name.strip(),
            "monitor_type": monitor_type,
            "cron": cron,
            "default_status": default_status,
            "status": status,
            "is_hidden": is_hidden,
            "include_degraded_in_downtime": include_degraded_in_downtime,
            "confirmation_threshold": confirmation_threshold,
        }
        if type_data is not None:
            body["type_data"] = type_data
        if category_name is not None:
            body["category_name"] = category_name
        if description is not None:
            body["description"] = description
        if image is not None:
            body["image"] = image
        if external_url is not None:
            body["external_url"] = external_url
        if monitor_settings_json is not None:
            body["monitor_settings_json"] = monitor_settings_json

        target_pages = ["~home"] if page_paths is None else list(dict.fromkeys(page_paths))
        async with kener() as k:
            created = await k.create_monitor(body)
            created_tag = created["tag"]
            for p_path in target_pages:
                page = await k.get_page(p_path)
                existing_tags = _extract_page_monitor_tags(page)
                if created_tag not in existing_tags:
                    await k.update_page(p_path, {"monitors": [*existing_tags, created_tag]})
            pages = await k.list_pages()
        return _mask_monitor(created, pages=_monitor_pages(pages, created_tag))

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Update an existing monitor and/or the pages where it is displayed. "
            "Rejects any '********' placeholder in type_data so masked values never overwrite "
            "real secrets in Kener's shallow merge. Returns before/after configs. "
            f"{BACKUP_REMINDER}"
        ),
    )
    async def update_monitor(
        tag: MonitorTag,
        name: Annotated[str | None, Field(description="New display name.")] = None,
        description: Annotated[str | None, Field(description="New description.")] = None,
        image: Annotated[str | None, Field(description="New image URL or path.")] = None,
        cron: Annotated[str | None, Field(description="New cron expression.")] = None,
        default_status: Annotated[
            str | None, Field(description="New default status ('UP', 'DOWN', 'DEGRADED', 'NONE').")
        ] = None,
        status: Annotated[
            MonitorStatus | None, Field(description="New status ('ACTIVE' or 'INACTIVE').")
        ] = None,
        category_name: Annotated[str | None, Field(description="New category name.")] = None,
        monitor_type: Annotated[str | None, Field(description="New monitor type.")] = None,
        type_data: Annotated[
            dict[str, Any] | None,
            Field(
                description=(
                    "Partial or full type_data object (shallow-merged by Kener). "
                    "Must NEVER contain '********'; omit unchanged secret fields."
                )
            ),
        ] = None,
        is_hidden: Annotated[YesNo | None, Field(description="'YES' or 'NO'.")] = None,
        confirmation_threshold: Annotated[
            int | None,
            Field(description="Consecutive failures threshold (1..60).", ge=1, le=60),
        ] = None,
        external_url: Annotated[str | None, Field(description="New external URL.")] = None,
        monitor_settings_json: Annotated[
            dict[str, Any] | None,
            Field(description="Partial or full monitor_settings_json object."),
        ] = None,
        page_paths: Annotated[
            list[str] | None,
            Field(
                description=(
                    "If provided, sets the exact list of pages where this monitor is displayed."
                )
            ),
        ] = None,
    ) -> dict:
        if type_data is not None and _contains_masked_secret(type_data):
            raise ToolError(
                "type_data must not contain masked placeholder '********'; "
                "omit unchanged secret fields or provide the real secret value."
            )
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name.strip()
        if description is not None:
            body["description"] = description
        if image is not None:
            body["image"] = image
        if cron is not None:
            body["cron"] = cron
        if default_status is not None:
            body["default_status"] = default_status
        if status is not None:
            body["status"] = status
        if category_name is not None:
            body["category_name"] = category_name
        if monitor_type is not None:
            body["monitor_type"] = monitor_type
        if type_data is not None:
            body["type_data"] = type_data
        if is_hidden is not None:
            body["is_hidden"] = is_hidden
        if confirmation_threshold is not None:
            body["confirmation_threshold"] = confirmation_threshold
        if external_url is not None:
            body["external_url"] = external_url
        if monitor_settings_json is not None:
            body["monitor_settings_json"] = monitor_settings_json

        if not body and page_paths is None:
            raise ToolError("Provide at least one field to update or page_paths.")

        async with kener() as k:
            old_monitor, old_pages = await asyncio.gather(k.get_monitor(tag), k.list_pages())
            before = _mask_monitor(old_monitor, pages=_monitor_pages(old_pages, tag))
            updated_monitor = await k.update_monitor(tag, body) if body else old_monitor

            if page_paths is not None:
                desired = list(dict.fromkeys(page_paths))
                known_paths = {p["page_path"] for p in old_pages}
                for p in old_pages:
                    p_path = p["page_path"]
                    tags = _extract_page_monitor_tags(p)
                    if p_path in desired and tag not in tags:
                        await k.update_page(p_path, {"monitors": [*tags, tag]})
                    elif p_path not in desired and tag in tags:
                        await k.update_page(p_path, {"monitors": [t for t in tags if t != tag]})
                for p_path in desired:
                    if p_path not in known_paths:
                        page = await k.get_page(p_path)
                        tags = _extract_page_monitor_tags(page)
                        if tag not in tags:
                            await k.update_page(p_path, {"monitors": [*tags, tag]})
                new_pages = await k.list_pages()
            else:
                new_pages = old_pages

        after = _mask_monitor(updated_monitor, pages=_monitor_pages(new_pages, tag))
        return {"before": before, "after": after}

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Pause or resume a monitor by setting its status to 'INACTIVE' (paused=True) "
            f"or 'ACTIVE' (paused=False). Returns before/after configs. {BACKUP_REMINDER}"
        ),
    )
    async def pause_monitor(
        tag: MonitorTag,
        paused: Annotated[
            bool, Field(description="True to pause ('INACTIVE'), False to resume ('ACTIVE').")
        ] = True,
    ) -> dict:
        new_status: MonitorStatus = "INACTIVE" if paused else "ACTIVE"
        async with kener() as k:
            before = await k.get_monitor(tag)
            after = await k.update_monitor(tag, {"status": new_status})
        return {"before": _mask_monitor(before), "after": _mask_monitor(after)}

    @mcp.tool(
        annotations=WRITE,
        description="Create a new status page and optionally attach an ordered list of monitors.",
    )
    async def create_page(
        page_path: Annotated[
            str,
            Field(
                description="URL path slug (lowercase alphanumeric, hyphens, underscores).",
                min_length=1,
            ),
        ],
        page_title: Annotated[
            str, Field(description="Browser tab title for the page.", min_length=1)
        ],
        page_header: Annotated[
            str, Field(description="Heading text displayed on the page.", min_length=1)
        ],
        page_subheader: Annotated[
            str | None, Field(description="Optional subheader text (markdown supported).")
        ] = None,
        page_logo: Annotated[
            str | None, Field(description="Optional page logo URL or path.")
        ] = None,
        monitors: Annotated[
            list[str] | None,
            Field(description="Ordered list of monitor tags to display on this page."),
        ] = None,
        page_settings: Annotated[
            dict[str, Any] | None, Field(description="Optional page_settings JSON object.")
        ] = None,
    ) -> dict:
        body: dict[str, Any] = {
            "page_path": page_path.strip(),
            "page_title": page_title.strip(),
            "page_header": page_header.strip(),
        }
        if page_subheader is not None:
            body["page_subheader"] = page_subheader
        if page_logo is not None:
            body["page_logo"] = page_logo
        if monitors is not None:
            body["monitors"] = monitors
        if page_settings is not None:
            body["page_settings"] = page_settings
        async with kener() as k:
            created = await k.create_page(body)
        return _page_summary(created)

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Update an existing status page (use '~home' for the home page). "
            f"Returns before/after page configs. {BACKUP_REMINDER}"
        ),
    )
    async def update_page(
        page_path: PagePath,
        page_title: Annotated[str | None, Field(description="New page title.")] = None,
        page_header: Annotated[str | None, Field(description="New page header.")] = None,
        page_subheader: Annotated[str | None, Field(description="New page subheader.")] = None,
        page_logo: Annotated[str | None, Field(description="New page logo URL or path.")] = None,
        page_settings: Annotated[
            dict[str, Any] | None,
            Field(description="Partial or full page_settings object (deep-merged by Kener)."),
        ] = None,
        monitors: Annotated[
            list[str] | None,
            Field(description="If provided, replaces the ordered list of monitor tags."),
        ] = None,
        new_page_path: Annotated[
            str | None,
            Field(description="Optional new URL slug for the page (not allowed for '~home')."),
        ] = None,
    ) -> dict:
        body: dict[str, Any] = {}
        if new_page_path is not None:
            body["page_path"] = new_page_path.strip()
        if page_title is not None:
            body["page_title"] = page_title.strip()
        if page_header is not None:
            body["page_header"] = page_header.strip()
        if page_subheader is not None:
            body["page_subheader"] = page_subheader
        if page_logo is not None:
            body["page_logo"] = page_logo
        if page_settings is not None:
            body["page_settings"] = page_settings
        if monitors is not None:
            body["monitors"] = monitors
        if not body:
            raise ToolError("Provide at least one field to update.")

        async with kener() as k:
            before = await k.get_page(page_path)
            after = await k.update_page(page_path, body)
        return {"before": _page_summary(before), "after": _page_summary(after)}

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Replace the ordered list of monitor tags displayed on a status page "
            f"(use '~home' for the home page). Returns before/after page configs. {BACKUP_REMINDER}"
        ),
    )
    async def set_page_monitors(
        page_path: PagePath,
        monitor_tags: Annotated[
            list[str],
            Field(description="Ordered list of unique monitor tags to display on this page."),
        ],
    ) -> dict:
        if len(set(monitor_tags)) != len(monitor_tags):
            raise ToolError("monitor_tags must not contain duplicate tags.")
        async with kener() as k:
            before = await k.get_page(page_path)
            after = await k.update_page(page_path, {"monitors": monitor_tags})
        return {"before": _page_summary(before), "after": _page_summary(after)}

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Update an incident's metadata (title, timestamps, or affected monitors). "
            "Note: incident state cannot be changed here; use post_incident_update or "
            f"resolve_incident to change state. Returns before/after configs. {BACKUP_REMINDER}"
        ),
    )
    async def update_incident(
        incident_id: IncidentId,
        title: Annotated[str | None, Field(description="New incident title.")] = None,
        start_date_time: Annotated[
            int | None, Field(description="New start timestamp in UTC seconds.", ge=1)
        ] = None,
        end_date_time: Annotated[
            int | None, Field(description="New end timestamp in UTC seconds.", ge=1)
        ] = None,
        monitor_tags: Annotated[
            list[str] | None,
            Field(description="If provided, replaces the list of affected monitor tags."),
        ] = None,
        impact: Annotated[
            Impact,
            Field(description="Impact applied to monitor_tags when monitor_tags is provided."),
        ] = "DOWN",
    ) -> dict:
        body: dict[str, Any] = {}
        if title is not None:
            body["title"] = title.strip()
        if start_date_time is not None:
            body["start_date_time"] = start_date_time
        if end_date_time is not None:
            body["end_date_time"] = end_date_time
        if monitor_tags is not None:
            body["monitors"] = [{"monitor_tag": t, "impact": impact} for t in monitor_tags]
        if not body:
            raise ToolError("Provide at least one field to update.")

        async with kener() as k:
            before = await k.get_incident(incident_id)
            after = await k.update_incident(incident_id, body)
        return {"before": _incident_summary(before), "after": _incident_summary(after)}

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Edit an existing incident update/comment (text, state, or timestamp). "
            f"Returns before/after comment summaries and the incident. {BACKUP_REMINDER} "
            f"{NOTIFY_CAVEAT}"
        ),
    )
    async def update_incident_comment(
        incident_id: IncidentId,
        comment_id: Annotated[int, Field(description="Comment ID (from get_incident).", ge=1)],
        comment: Annotated[str | None, Field(description="Updated comment text.")] = None,
        state: Annotated[
            IncidentState | None, Field(description="Updated state for this comment.")
        ] = None,
        timestamp: Annotated[
            int | None, Field(description="Updated timestamp in UTC seconds.", ge=1)
        ] = None,
    ) -> dict:
        body: dict[str, Any] = {}
        if comment is not None:
            body["comment"] = comment.strip()
        if state is not None:
            body["state"] = state
        if timestamp is not None:
            body["timestamp"] = timestamp
        if not body:
            raise ToolError("Provide at least one field to update.")

        async with kener() as k:
            before = await k.get_comment(incident_id, comment_id)
            after = await k.update_comment(incident_id, comment_id, body)
            incident = await k.get_incident(incident_id)
        return {
            "before": _comment_summary(before),
            "after": _comment_summary(after),
            "incident": _incident_summary(incident),
        }

    @mcp.tool(
        annotations=WRITE,
        description=(
            "Create a scheduled or recurring maintenance window. Use rrule='FREQ=MINUTELY;COUNT=1' "
            "for a one-time maintenance, or an iCalendar RRULE (e.g. 'FREQ=WEEKLY;BYDAY=SU') "
            "for recurring maintenances."
        ),
    )
    async def create_maintenance(
        title: Annotated[str, Field(description="Maintenance title.", min_length=1)],
        start_date_time: Annotated[int, Field(description="Start timestamp in UTC seconds.", ge=1)],
        duration_seconds: Annotated[
            int, Field(description="Duration of the maintenance window in seconds.", ge=1)
        ],
        rrule: Annotated[
            str,
            Field(
                description=(
                    "iCalendar RRULE string (defaults to 'FREQ=MINUTELY;COUNT=1' for one-off)."
                )
            ),
        ] = "FREQ=MINUTELY;COUNT=1",
        description: Annotated[
            str | None, Field(description="Optional maintenance description (markdown supported).")
        ] = None,
        monitor_tags: Annotated[
            list[str] | None, Field(description="Monitor tags affected by this maintenance.")
        ] = None,
        impact: Annotated[
            MaintenanceImpact,
            Field(
                description="Impact on affected monitors ('MAINTENANCE', 'DOWN', 'DEGRADED', 'UP')."
            ),
        ] = "MAINTENANCE",
    ) -> dict:
        body: dict[str, Any] = {
            "title": title.strip(),
            "start_date_time": start_date_time,
            "duration_seconds": duration_seconds,
            "rrule": rrule.strip(),
        }
        if description is not None:
            body["description"] = description
        if monitor_tags is not None:
            body["monitors"] = [{"monitor_tag": t, "impact": impact} for t in monitor_tags]
        async with kener() as k:
            created = await k.create_maintenance(body)
            events = await k.list_maintenance_events(created["id"])
        return _maintenance_summary(created, events=events)

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Update an existing maintenance definition. Returns before/after configs. "
            f"{BACKUP_REMINDER}"
        ),
    )
    async def update_maintenance(
        maintenance_id: MaintenanceId,
        title: Annotated[str | None, Field(description="New maintenance title.")] = None,
        description: Annotated[
            str | None, Field(description="New maintenance description.")
        ] = None,
        start_date_time: Annotated[
            int | None, Field(description="New start timestamp in UTC seconds.", ge=1)
        ] = None,
        duration_seconds: Annotated[
            int | None, Field(description="New duration in seconds.", ge=1)
        ] = None,
        rrule: Annotated[str | None, Field(description="New iCalendar RRULE string.")] = None,
        status: Annotated[
            MaintenanceStatus | None, Field(description="'ACTIVE' or 'INACTIVE'.")
        ] = None,
        monitor_tags: Annotated[
            list[str] | None,
            Field(description="If provided, replaces the list of affected monitor tags."),
        ] = None,
        impact: Annotated[
            MaintenanceImpact,
            Field(description="Impact applied to monitor_tags when monitor_tags is provided."),
        ] = "MAINTENANCE",
    ) -> dict:
        body: dict[str, Any] = {}
        if title is not None:
            body["title"] = title.strip()
        if description is not None:
            body["description"] = description
        if start_date_time is not None:
            body["start_date_time"] = start_date_time
        if duration_seconds is not None:
            body["duration_seconds"] = duration_seconds
        if rrule is not None:
            body["rrule"] = rrule.strip()
        if status is not None:
            body["status"] = status
        if monitor_tags is not None:
            body["monitors"] = [{"monitor_tag": t, "impact": impact} for t in monitor_tags]
        if not body:
            raise ToolError("Provide at least one field to update.")

        async with kener() as k:
            before = await k.get_maintenance(maintenance_id)
            after = await k.update_maintenance(maintenance_id, body)
        return {"before": _maintenance_summary(before), "after": _maintenance_summary(after)}

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Update a single maintenance occurrence/event. Kener supports two mutually exclusive "
            "modes: either set status ('COMPLETED' or 'CANCELLED') alone, OR set both "
            "start_date_time and end_date_time to reschedule the window. Returns before/after "
            f"event configs. {BACKUP_REMINDER}"
        ),
    )
    async def update_maintenance_event(
        maintenance_id: MaintenanceId,
        event_id: Annotated[
            int, Field(description="Maintenance event ID (from get_maintenance).", ge=1)
        ],
        status: Annotated[
            MaintenanceEventStatus | None,
            Field(
                description=(
                    "Set to 'COMPLETED' or 'CANCELLED' (cannot be combined with "
                    "start_date_time/end_date_time)."
                )
            ),
        ] = None,
        start_date_time: Annotated[
            int | None,
            Field(description="New start timestamp in UTC seconds (requires end_date_time).", ge=1),
        ] = None,
        end_date_time: Annotated[
            int | None,
            Field(description="New end timestamp in UTC seconds (requires start_date_time).", ge=1),
        ] = None,
    ) -> dict:
        has_status = status is not None
        has_times = start_date_time is not None or end_date_time is not None
        if has_status and has_times:
            raise ToolError(
                "Provide either status ('COMPLETED'/'CANCELLED') OR both start_date_time and "
                "end_date_time, not both."
            )
        if not has_status and (start_date_time is None or end_date_time is None):
            raise ToolError(
                "Provide either status ('COMPLETED'/'CANCELLED') or both start_date_time and "
                "end_date_time."
            )
        body: dict[str, Any] = (
            {"status": status}
            if has_status
            else {"start_date_time": start_date_time, "end_date_time": end_date_time}
        )
        async with kener() as k:
            before = await k.get_maintenance_event(maintenance_id, event_id)
            after = await k.update_maintenance_event(maintenance_id, event_id, body)
        return {
            "before": _maintenance_event_summary(before),
            "after": _maintenance_event_summary(after),
        }

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Update a site-wide configuration key (e.g. 'title', 'siteName', 'categories', "
            "'nav', 'hero', 'colors', 'announcement'). Rejects '********' placeholders and "
            f"returns before/after values with secrets masked. {BACKUP_REMINDER}"
        ),
    )
    async def update_site_config(
        key: Annotated[
            str,
            Field(
                description=(
                    "Site config key (e.g. 'title', 'siteName', 'categories', 'nav', 'hero', "
                    "'colors', 'announcement')."
                ),
                min_length=1,
            ),
        ],
        value: Annotated[
            Any,
            Field(description="New value for the key (string, list, dict, etc.)."),
        ],
    ) -> dict:
        clean_key = key.strip()
        if _contains_masked_secret(value):
            raise ToolError("value must not contain masked placeholder '********'.")
        async with kener() as k:
            try:
                before_item = await k.get_site_data_key(clean_key)
                before_out: dict | None = {
                    "key": before_item["key"],
                    "value": _mask_site_value(before_item["key"], before_item.get("value")),
                    "data_type": before_item.get("data_type"),
                }
            except KenerError as e:
                if e.status_code != 404:
                    raise
                before_out = None
            after_item = await k.update_site_data_key(clean_key, value)
        after_out = {
            "key": after_item["key"],
            "value": _mask_site_value(after_item["key"], after_item.get("value")),
            "data_type": after_item.get("data_type"),
        }
        return {"before": before_out, "after": after_out}

    # --- Step 3: Delete tools (exact single identifier only) ----------------

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Permanently delete a single monitor by its exact tag. WARNING: All uptime history "
            "(monitoring_data) for this monitor is permanently deleted along with the monitor "
            "and its page, incident, maintenance, and alert associations. "
            f"{BACKUP_REMINDER}"
        ),
    )
    async def delete_monitor(tag: MonitorTag) -> dict:
        clean_tag = tag.strip()
        async with kener() as k:
            res = await k.delete_monitor(clean_tag)
        return {"deleted_tag": clean_tag, "message": res.get("message")}

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Permanently delete a single status page by its exact page_path (cannot delete "
            f"'~home'). Monitors on the page are not deleted. {BACKUP_REMINDER}"
        ),
    )
    async def delete_page(page_path: PagePath) -> dict:
        clean_path = page_path.strip()
        if clean_path == "~home":
            raise ToolError("The home page ('~home') cannot be deleted.")
        async with kener() as k:
            res = await k.delete_page(clean_path)
        return {"deleted_page_path": clean_path, "message": res.get("message")}

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Permanently delete a single incident and all its update comments by exact "
            f"incident_id. {BACKUP_REMINDER}"
        ),
    )
    async def delete_incident(incident_id: IncidentId) -> dict:
        async with kener() as k:
            res = await k.delete_incident(incident_id)
        return {"deleted_incident_id": incident_id, "message": res.get("message")}

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Delete (deactivate) a single incident update comment by exact incident_id and "
            f"comment_id. {BACKUP_REMINDER}"
        ),
    )
    async def delete_incident_comment(
        incident_id: IncidentId,
        comment_id: Annotated[int, Field(description="Comment ID (from get_incident).", ge=1)],
    ) -> dict:
        async with kener() as k:
            res = await k.delete_comment(incident_id, comment_id)
        return {
            "incident_id": incident_id,
            "deleted_comment_id": comment_id,
            "message": res.get("message"),
        }

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Permanently delete a single maintenance definition and all its scheduled/past "
            f"events by exact maintenance_id. {BACKUP_REMINDER}"
        ),
    )
    async def delete_maintenance(maintenance_id: MaintenanceId) -> dict:
        async with kener() as k:
            res = await k.delete_maintenance(maintenance_id)
        return {"deleted_maintenance_id": maintenance_id, "message": res.get("message")}

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Permanently delete a single maintenance event occurrence by exact maintenance_id "
            f"and event_id. {BACKUP_REMINDER}"
        ),
    )
    async def delete_maintenance_event(
        maintenance_id: MaintenanceId,
        event_id: Annotated[
            int, Field(description="Maintenance event ID (from get_maintenance).", ge=1)
        ],
    ) -> dict:
        async with kener() as k:
            res = await k.delete_maintenance_event(maintenance_id, event_id)
        return {
            "maintenance_id": maintenance_id,
            "deleted_event_id": event_id,
            "message": res.get("message"),
        }

    return mcp


async def _check(settings: Settings) -> int:
    try:
        api_key = await settings.key_provider().get()
        async with KenerClient(settings.url, api_key) as k:
            monitors = await k.list_monitors()
            incidents = await k.list_incidents()
    except (ApiKeyError, KenerError) as e:
        print(f"{settings.label}: FAILED - {e}", file=sys.stderr)
        return 1
    open_count = sum(1 for i in incidents if i["state"] != "RESOLVED")
    print(f"{settings.label}: ok ({len(monitors)} monitors, {open_count} open incidents)")
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="kener-mcp",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", help="Kener base URL (overrides KENER_URL).")
    parser.add_argument(
        "--api-key-cmd", help="Command that prints the API key (overrides KENER_API_KEY_CMD)."
    )
    parser.add_argument("--name", help="Short instance name (overrides KENER_NAME).")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("check", help="Test the URL and API key, then exit.")
    args = parser.parse_args(argv)

    try:
        settings = Settings.from_env(url=args.url, api_key_cmd=args.api_key_cmd, name=args.name)
    except SettingsError as e:
        print(f"kener-mcp: {e}", file=sys.stderr)
        sys.exit(2)

    if args.command == "check":
        sys.exit(asyncio.run(_check(settings)))
    create_server(settings).run(show_banner=False)


if __name__ == "__main__":
    main()
