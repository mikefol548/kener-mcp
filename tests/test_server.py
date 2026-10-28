import json
import shlex
import sys

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from kener_mcp.auth import ApiKeyError, ApiKeyProvider
from kener_mcp.server import Settings, SettingsError, create_server

BASE = "https://status.example.com"
API = f"{BASE}/api/v4"
KEY = "test-key-123"


def incident(id=7, state="INVESTIGATING", start=1_760_000_000, end=None, **kw):
    return {
        "id": id,
        "title": f"Incident {id}",
        "start_date_time": start,
        "end_date_time": end,
        "state": state,
        "incident_source": "API",
        "monitors": [],
        "created_at": "2026-10-18T00:00:00.000Z",
        "updated_at": "2026-10-18T00:00:00.000Z",
        "url": f"{BASE}/incidents/{id}",
        **kw,
    }


def comment(id=1, incident_id=7, text="Looking into it", state="INVESTIGATING", ts=1_760_000_060):
    return {
        "id": id,
        "incident_id": incident_id,
        "comment": text,
        "timestamp": ts,
        "state": state,
        "created_at": "2026-10-18T00:00:00.000Z",
        "updated_at": "2026-10-18T00:00:00.000Z",
    }


@pytest.fixture
def server():
    return create_server(Settings(url=BASE, api_key=KEY, name="test"))


@pytest.fixture
def api():
    with respx.mock(base_url=API, assert_all_called=False) as mock:
        yield mock


async def call(server, tool, args=None):
    async with Client(server) as client:
        return (await client.call_tool(tool, args or {})).structured_content


def sent_json(route):
    return json.loads(route.calls.last.request.content)


# --- settings -------------------------------------------------------------


def test_settings_from_env():
    s = Settings.from_env(
        {"KENER_URL": "https://x.example.com/", "KENER_API_KEY": "k", "KENER_NAME": "cp"}
    )
    assert s.url == "https://x.example.com"
    assert s.name == "cp"


U = "https://x.example.com"


@pytest.mark.parametrize(
    "env, msg",
    [
        ({"KENER_API_KEY": "k"}, "KENER_URL is not set"),
        ({"KENER_URL": "x.example.com", "KENER_API_KEY": "k"}, "must be an https"),
        ({"KENER_URL": "https://u:p@x.example.com", "KENER_API_KEY": "k"}, "user name"),
        ({"KENER_URL": U}, "exactly one"),
        ({"KENER_URL": U, "KENER_API_KEY": "k", "KENER_API_KEY_CMD": "echo k"}, "exactly one"),
        (
            {"KENER_URL": U, "KENER_API_KEY_CMD": "echo k", "KENER_API_KEY_CMD_TIMEOUT": "x"},
            "must be a number",
        ),
    ],
)
def test_settings_errors(env, msg):
    with pytest.raises(SettingsError, match=msg):
        Settings.from_env(env)


def test_flags_override_env():
    s = Settings.from_env(
        {"KENER_URL": U, "KENER_API_KEY": "k"},
        url="https://y.example.com",
        api_key_cmd="echo k2",
        name="flag",
    )
    assert (s.url, s.api_key, s.api_key_cmd, s.name) == (
        "https://y.example.com",
        None,
        "echo k2",
        "flag",
    )


# --- API key command --------------------------------------------------------


def py_cmd(code):
    return f"{shlex.quote(sys.executable)} -c {shlex.quote(code)}"


async def test_key_cmd_runs_once_and_caches(tmp_path):
    counter = tmp_path / "n"
    code = f"import pathlib; p=pathlib.Path({str(counter)!r}); p.write_text(p.read_text()+'x' if p.exists() else 'x'); print('cmd-key')"  # noqa: E501
    keys = ApiKeyProvider(api_key_cmd=py_cmd(code))
    assert await keys.get() == "cmd-key"
    assert await keys.get() == "cmd-key"
    assert counter.read_text() == "x"
    keys.invalidate()
    await keys.get()
    assert counter.read_text() == "xx"


@pytest.mark.parametrize(
    "code, msg",
    [
        ("import sys; sys.stderr.write('locked'); sys.exit(3)", "exit code 3: locked"),
        ("print('')", "printed nothing"),
        ("print('a b')", "more than one value"),
    ],
)
async def test_key_cmd_errors(code, msg):
    with pytest.raises(ApiKeyError, match=msg):
        await ApiKeyProvider(api_key_cmd=py_cmd(code)).get()


async def test_key_cmd_failure_does_not_leak_stdout():
    code = "import sys; print('SECRET-PART'); sys.exit(1)"
    with pytest.raises(ApiKeyError) as exc:
        await ApiKeyProvider(api_key_cmd=py_cmd(code)).get()
    assert "SECRET-PART" not in str(exc.value)


async def test_key_cmd_timeout():
    keys = ApiKeyProvider(api_key_cmd=py_cmd("import time; time.sleep(5)"), timeout=0.3)
    with pytest.raises(ApiKeyError, match="did not finish"):
        await keys.get()


async def test_key_cmd_missing_binary():
    with pytest.raises(ApiKeyError, match="Could not run"):
        await ApiKeyProvider(api_key_cmd="no-such-binary-kener-mcp").get()


async def test_server_uses_cmd_key_and_reruns_after_401(api, tmp_path):
    counter = tmp_path / "n"
    code = f"import pathlib; p=pathlib.Path({str(counter)!r}); n=len(p.read_text()) if p.exists() else 0; p.write_text('x'*(n+1)); print(f'key{{n+1}}')"  # noqa: E501
    server = create_server(Settings(url=BASE, api_key_cmd=py_cmd(code), name="test"))
    route = api.get("/monitors")
    route.side_effect = [
        httpx.Response(401, json={"error": {"code": "UNAUTHORIZED", "message": "Invalid API key"}}),
        httpx.Response(200, json={"monitors": []}),
    ]
    with pytest.raises(ToolError, match="Invalid API key"):
        await call(server, "list_monitors")
    await call(server, "list_monitors")
    auths = [c.request.headers["authorization"] for c in route.calls]
    assert auths == ["Bearer key1", "Bearer key2"]


# --- request shapes ---------------------------------------------------------


async def test_bearer_auth_and_user_agent(server, api):
    route = api.get("/monitors").respond(json={"monitors": []})
    await call(server, "list_monitors")
    req = route.calls.last.request
    assert req.headers["authorization"] == f"Bearer {KEY}"
    assert req.headers["user-agent"].startswith("kener-mcp/")


async def test_list_monitors_hides_type_data_and_hidden(server, api):
    api.get("/monitors").respond(
        json={
            "monitors": [
                {
                    "tag": "web",
                    "name": "Website",
                    "status": "ACTIVE",
                    "monitor_type": "API",
                    "category_name": "Home",
                    "is_hidden": "NO",
                    "description": None,
                    "type_data": {"url": "https://secret", "headers": [{"key": "X-Token"}]},
                    "monitor_settings_json": {"x": 1},
                },
                {"tag": "h", "name": "Hidden", "is_hidden": "YES"},
            ]
        }
    )
    out = await call(server, "list_monitors")
    assert [m["tag"] for m in out["result"]] == ["web"]
    assert "type_data" not in json.dumps(out)
    out = await call(server, "list_monitors", {"include_hidden": True})
    assert [m["tag"] for m in out["result"]] == ["web", "h"]


async def test_list_incidents_open_only_newest_first(server, api):
    api.get("/incidents").respond(
        json={
            "incidents": [
                incident(1, start=100),
                incident(2, state="RESOLVED", start=200, end=300),
                incident(3, state="MONITORING", start=400),
            ]
        }
    )
    out = (await call(server, "list_incidents"))["result"]
    assert [i["id"] for i in out] == [3, 1]
    out = (await call(server, "list_incidents", {"include_resolved": True, "limit": 2}))["result"]
    assert [i["id"] for i in out] == [3, 2]


async def test_get_incident_includes_timeline(server, api):
    api.get("/incidents/7").respond(json={"incident": incident(7)})
    api.get("/incidents/7/comments").respond(
        json={"comments": [comment(2, ts=200), comment(1, ts=100)]}
    )
    out = await call(server, "get_incident", {"incident_id": 7})
    assert [u["id"] for u in out["updates"]] == [1, 2]
    assert out["started_at"].startswith("2025-")


async def test_post_update_uses_comment_and_state_fields(server, api):
    route = api.post("/incidents/7/comments").respond(
        201, json={"comment": comment(5, text="Found it", state="IDENTIFIED")}
    )
    api.get("/incidents/7").respond(json={"incident": incident(7, state="IDENTIFIED")})
    out = await call(
        server,
        "post_incident_update",
        {"incident_id": 7, "comment": "  Found it  ", "state": "IDENTIFIED"},
    )
    # Kener's docs say "message"/"status"; the 4.1.7 server reads "comment"/"state".
    assert sent_json(route) == {"comment": "Found it", "state": "IDENTIFIED"}
    assert out["incident"]["state"] == "IDENTIFIED"


async def test_post_update_rejects_bad_state(server, api):
    with pytest.raises(ToolError):
        await call(
            server, "post_incident_update", {"incident_id": 7, "comment": "x", "state": "FIXED"}
        )


async def test_resolve_posts_resolved_comment(server, api):
    route = api.post("/incidents/7/comments").respond(
        201, json={"comment": comment(6, state="RESOLVED")}
    )
    api.get("/incidents/7").respond(
        json={"incident": incident(7, state="RESOLVED", end=1_760_000_600)}
    )
    out = await call(server, "resolve_incident", {"incident_id": 7})
    assert sent_json(route) == {"comment": "This incident has been resolved.", "state": "RESOLVED"}
    assert out["incident"]["ended_at"] is not None


async def test_create_incident_with_monitors_and_first_update(server, api):
    create = api.post("/incidents").respond(201, json={"incident": incident(9)})
    add = api.post("/incidents/9/comments").respond(201, json={"comment": comment(1, 9)})
    api.get("/incidents/9").respond(json={"incident": incident(9)})
    out = await call(
        server,
        "create_incident",
        {
            "title": "API down",
            "monitor_tags": ["api", "web"],
            "impact": "DEGRADED",
            "first_update": "Looking into it",
        },
    )
    body = sent_json(create)
    assert body["title"] == "API down"
    assert isinstance(body["start_date_time"], int)
    assert body["monitors"] == [
        {"monitor_tag": "api", "impact": "DEGRADED"},
        {"monitor_tag": "web", "impact": "DEGRADED"},
    ]
    assert sent_json(add) == {"comment": "Looking into it", "state": "INVESTIGATING"}
    assert out["incident"]["id"] == 9 and out["update"]["id"] == 1


async def test_create_incident_minimal_sends_no_monitors_or_comment(server, api):
    create = api.post("/incidents").respond(201, json={"incident": incident(9)})
    add = api.post("/incidents/9/comments")
    await call(server, "create_incident", {"title": "Planned work"})
    assert "monitors" not in sent_json(create)
    assert not add.called


# --- errors -----------------------------------------------------------------


async def test_kener_error_message_is_surfaced(server, api):
    api.get("/incidents/99").respond(
        404, json={"error": {"code": "NOT_FOUND", "message": "Incident with id '99' not found"}}
    )
    api.get("/incidents/99/comments").respond(404, json={})
    with pytest.raises(ToolError, match=r"\[test\] Kener returned 404: Incident with id '99'"):
        await call(server, "get_incident", {"incident_id": 99})


async def test_network_error_does_not_leak_key(server, api):
    api.get("/monitors").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(ToolError) as exc:
        await call(server, "list_monitors")
    assert KEY not in str(exc.value)
    assert "ConnectError" in str(exc.value)


async def test_write_tools_are_marked_not_read_only(server):
    async with Client(server) as client:
        tools = {t.name: t for t in await client.list_tools()}
    read_tools = (
        "list_monitors",
        "get_monitor",
        "list_pages",
        "get_page",
        "list_incidents",
        "get_incident",
        "list_maintenances",
        "get_maintenance",
        "get_site_config",
        "kener_docs",
        "get_config_overview",
    )
    for name in read_tools:
        assert tools[name].annotations.read_only_hint is True
        assert tools[name].annotations.destructive_hint is False
    write_tools = (
        "create_incident",
        "export_config",
        "create_monitor",
        "create_page",
        "create_maintenance",
    )
    for name in write_tools:
        assert tools[name].annotations.read_only_hint is False
        assert tools[name].annotations.destructive_hint is False
    destructive_tools = (
        "post_incident_update",
        "resolve_incident",
        "update_monitor",
        "pause_monitor",
        "update_page",
        "set_page_monitors",
        "update_incident",
        "update_incident_comment",
        "update_maintenance",
        "update_maintenance_event",
        "update_site_config",
        "delete_monitor",
        "delete_page",
        "delete_incident",
        "delete_incident_comment",
        "delete_maintenance",
        "delete_maintenance_event",
    )
    for name in destructive_tools:
        assert tools[name].annotations.read_only_hint is False
        assert tools[name].annotations.destructive_hint is True
        assert "export_config" in (tools[name].description or "")
    assert "uptime history" in (tools["delete_monitor"].description or "")
    assert "monitoring_data" in (tools["delete_monitor"].description or "")
    for name in (
        "create_incident",
        "post_incident_update",
        "resolve_incident",
        "update_incident_comment",
    ):
        assert "4.1.8" in (tools[name].description or "")
        assert "subscribers" in (tools[name].description or "")
    assert "incident_id" in tools["post_incident_update"].input_schema["required"]


async def test_server_reports_own_version(server):
    from kener_mcp import __version__

    async with Client(server) as client:
        info = client.server_info
    assert (info.name, info.version) == ("kener-test", __version__)


# --- Step 1: read tools, kener_docs, get_config_overview, export_config -----


async def test_get_monitor_masks_secrets_and_lists_pages(server, api):
    api.get("/monitors/web").respond(
        json={
            "monitor": {
                "id": 3,
                "tag": "web",
                "name": "Website",
                "status": "ACTIVE",
                "monitor_type": "API",
                "category_name": "Core",
                "cron": "* * * * *",
                "default_status": "UP",
                "is_hidden": "NO",
                "include_degraded_in_downtime": "NO",
                "confirmation_threshold": 2,
                "type_data": {
                    "url": "https://lovelace.gg/health",
                    "method": "POST",
                    "headers": [
                        {"key": "Authorization", "value": "Bearer super-secret-token"},
                        {"key": "X-Empty", "value": ""},
                    ],
                    "body": '{"secret_payload": 1}',
                    "proxy": "http://u:pw@proxy.internal:3128",
                    "connectionString": "postgresql://u:pw@db:5432/app",
                    "secretString": "hb-secret-1234",
                    "tlsKey": "-----BEGIN PRIVATE KEY-----",
                },
                "monitor_settings_json": {"uptime_formula_numerator": "up"},
                "external_url": "https://lovelace.gg",
            }
        }
    )
    api.get("/pages").respond(
        json={
            "pages": [
                {
                    "id": 1,
                    "page_path": "~home",
                    "page_title": "Home",
                    "page_header": "Status",
                    "monitors": [{"monitor_tag": "web", "position": 0}],
                },
                {
                    "id": 2,
                    "page_path": "internal",
                    "page_title": "Internal",
                    "page_header": "Internal",
                    "monitors": [{"monitor_tag": "other", "position": 0}],
                },
            ]
        }
    )
    out = await call(server, "get_monitor", {"tag": "web"})
    assert out["tag"] == "web"
    assert out["pages"] == ["~home"]
    td = out["type_data"]
    assert td["url"] == "https://lovelace.gg/health"
    assert td["headers"] == [
        {"key": "Authorization", "value": "********"},
        {"key": "X-Empty", "value": ""},
    ]
    for field in ("body", "proxy", "connectionString", "secretString", "tlsKey"):
        assert td[field] == "********"
    dumped = json.dumps(out)
    assert "super-secret-token" not in dumped
    assert "hb-secret-1234" not in dumped
    assert "PRIVATE KEY" not in dumped


async def test_list_and_get_pages(server, api):
    page_obj = {
        "id": 1,
        "page_path": "~home",
        "page_title": "Home",
        "page_header": "Service Status",
        "page_subheader": "All services",
        "page_logo": None,
        "page_settings": {"monitor_layout_style": "default-list"},
        "monitors": [
            {"monitor_tag": "web", "position": 0},
            {"monitor_tag": "api", "position": 1},
        ],
    }
    api.get("/pages").respond(json={"pages": [page_obj]})
    api.get("/pages/~home").respond(json={"page": page_obj})

    pages = (await call(server, "list_pages"))["result"]
    assert len(pages) == 1
    assert pages[0]["page_path"] == "~home"
    assert pages[0]["monitors"] == ["web", "api"]

    single = await call(server, "get_page", {"page_path": "~home"})
    assert single["page_title"] == "Home"
    assert single["monitors"] == ["web", "api"]


async def test_list_and_get_maintenances(server, api):
    m1 = {
        "id": 10,
        "title": "DB Upgrade",
        "description": "Upgrading Postgres",
        "start_date_time": 1_760_000_000,
        "rrule": "FREQ=MINUTELY;COUNT=1",
        "duration_seconds": 3600,
        "status": "ACTIVE",
        "monitors": [{"monitor_tag": "db", "impact": "MAINTENANCE"}],
        "url": f"{BASE}/maintenances/10?type=maintenance",
    }
    route = api.get("/maintenances").respond(json={"maintenances": [m1]})
    out = (await call(server, "list_maintenances", {"status": "ACTIVE", "monitor_tag": "db"}))[
        "result"
    ]
    assert route.calls.last.request.url.params["status"] == "ACTIVE"
    assert route.calls.last.request.url.params["monitor_tag"] == "db"
    assert out[0]["id"] == 10

    api.get("/maintenances/10").respond(json={"maintenance": m1})
    api.get("/maintenances/10/events").respond(
        json={
            "events": [
                {
                    "id": 101,
                    "maintenance_id": 10,
                    "start_date_time": 1_760_000_000,
                    "end_date_time": 1_760_003_600,
                    "status": "SCHEDULED",
                    "url": f"{BASE}/maintenances/101",
                }
            ],
            "page": 1,
            "limit": 100,
        }
    )
    detail = await call(server, "get_maintenance", {"maintenance_id": 10})
    assert detail["id"] == 10
    assert [e["id"] for e in detail["events"]] == [101]


async def test_get_site_config_masks_secrets(server, api):
    api.get("/site").respond(
        json={
            "site_data": [
                {"key": "title", "value": "Lovelace Status", "data_type": "string"},
                {
                    "key": "oidcSettings",
                    "value": {"issuer": "https://auth.example.com", "client_secret": "oidc-sec-99"},
                    "data_type": "object",
                },
                {
                    "key": "captcha.turnstile",
                    "value": {"requirements": {"Site Key": "pub", "Secret Key": "turnstile-sec"}},
                    "data_type": "object",
                },
            ]
        }
    )
    api.get("/site/oidcSettings").respond(
        json={
            "key": "oidcSettings",
            "value": {"issuer": "https://auth.example.com", "client_secret": "oidc-sec-99"},
            "data_type": "object",
        }
    )
    all_cfg = await call(server, "get_site_config")
    assert all_cfg["site_data"]["title"]["value"] == "Lovelace Status"
    assert all_cfg["site_data"]["oidcSettings"]["value"]["client_secret"] == "********"
    assert (
        all_cfg["site_data"]["captcha.turnstile"]["value"]["requirements"]["Secret Key"]
        == "********"
    )
    assert "oidc-sec-99" not in json.dumps(all_cfg)
    assert "turnstile-sec" not in json.dumps(all_cfg)

    one_cfg = await call(server, "get_site_config", {"key": "oidcSettings"})
    assert one_cfg["value"]["client_secret"] == "********"


async def test_kener_docs_index_and_topic(server):
    llms_txt = (
        "# Kener\n\n## Docs\n\n"
        "- [API Reference](https://kener.ing/docs/spec/v4/): Interactive API reference\n"
        "- [API Monitor](https://kener.ing/docs/raw/v4/monitors/api.md): Monitor HTTP endpoints\n"
        "- [RRULE Patterns](https://kener.ing/docs/raw/v4/maintenances/rrule-patterns.md): "
        "Recurrence rules\n"
    )
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://kener.ing/docs/v4/llms.txt").respond(200, text=llms_txt)
        mock.get("https://kener.ing/docs/raw/v4/monitors/api.md").respond(
            200, text="# API Monitor\nUse eval function."
        )

        idx = await call(server, "kener_docs")
        assert len(idx["topics"]) == 3
        assert idx["topics"][1]["slug"] == "monitors/api"

        doc = await call(server, "kener_docs", {"topic": "monitors/api"})
        assert doc["topic"]["slug"] == "monitors/api"
        assert "Use eval function." in doc["content"]

        none = await call(server, "kener_docs", {"topic": "nonexistent-xyz"})
        assert none["matches"] == []


async def test_get_config_overview_detects_anomalies(server, api):
    now = 1_760_000_000
    eight_days_ago = now - 8 * 86400
    two_days_ago = now - 2 * 86400

    api.get("/monitors").respond(
        json={
            "monitors": [
                {
                    "tag": "web",
                    "name": "Web",
                    "status": "ACTIVE",
                    "monitor_type": "API",
                    "category_name": "Home",
                    "cron": "* * * * *",
                    "is_hidden": "NO",
                },
                {
                    "tag": "orphan",
                    "name": "Orphan",
                    "status": "INACTIVE",
                    "monitor_type": "API",
                    "category_name": "GhostCat",
                    "cron": None,
                    "is_hidden": "YES",
                },
            ]
        }
    )
    api.get("/pages").respond(
        json={
            "pages": [
                {
                    "id": 1,
                    "page_path": "~home",
                    "page_title": "Home",
                    "page_header": "Home",
                    "monitors": [{"monitor_tag": "web", "position": 0}],
                }
            ]
        }
    )
    api.get("/incidents").respond(
        json={
            "incidents": [
                incident(1, state="INVESTIGATING", start=eight_days_ago, monitors=[]),
                incident(
                    2,
                    state="IDENTIFIED",
                    start=two_days_ago,
                    monitors=[{"monitor_tag": "web", "impact": "DOWN"}],
                ),
            ]
        }
    )
    api.get("/maintenances").respond(
        json={
            "maintenances": [
                {
                    "id": 5,
                    "title": "Old Active Maint",
                    "start_date_time": eight_days_ago,
                    "rrule": "FREQ=MINUTELY;COUNT=1",
                    "duration_seconds": 600,
                    "status": "ACTIVE",
                    "monitors": [],
                }
            ]
        }
    )
    api.get("/maintenances/5/events").respond(
        json={
            "events": [
                {
                    "id": 50,
                    "maintenance_id": 5,
                    "start_date_time": eight_days_ago,
                    "end_date_time": eight_days_ago + 600,
                    "status": "COMPLETED",
                }
            ],
            "page": 1,
            "limit": 100,
        }
    )
    api.get("/site").respond(
        json={
            "site_data": [
                {"key": "title", "value": "Lovelace", "data_type": "string"},
                {
                    "key": "categories",
                    "value": [{"name": "Home"}, {"name": "UnusedCat"}],
                    "data_type": "object",
                },
            ]
        }
    )

    # Patch _now in kener_mcp.server so stale threshold calculation is deterministic
    import kener_mcp.server as srv_mod

    orig_now = srv_mod._now
    srv_mod._now = lambda: now
    try:
        out = await call(server, "get_config_overview", {"stale_incident_days": 7})
    finally:
        srv_mod._now = orig_now

    anom = out["anomalies"]
    assert anom["orphan_monitors"] == ["orphan"]
    assert anom["inactive_monitors"] == ["orphan"]
    assert anom["hidden_monitors"] == ["orphan"]
    assert anom["monitors_without_cron"] == ["orphan"]
    assert anom["monitors_with_unknown_category"] == [{"tag": "orphan", "category": "GhostCat"}]
    assert anom["unused_categories"] == ["UnusedCat"]
    assert [i["id"] for i in anom["stale_open_incidents"]] == [1]
    assert [i["id"] for i in anom["incidents_without_monitors"]] == [1]
    assert [m["id"] for m in anom["active_maintenances_without_upcoming_events"]] == [5]


async def test_export_config_masked_and_include_secrets(server, api, tmp_path):
    api.get("/monitors").respond(
        json={
            "monitors": [
                {
                    "id": 1,
                    "tag": "web",
                    "name": "Web",
                    "monitor_type": "API",
                    "type_data": {
                        "url": "https://example.com",
                        "headers": [{"key": "X-Auth", "value": "raw-header-secret"}],
                        "secretString": "raw-hb-secret",
                    },
                }
            ]
        }
    )
    api.get("/pages").respond(json={"pages": []})
    api.get("/incidents").respond(json={"incidents": []})
    api.get("/maintenances").respond(json={"maintenances": []})
    api.get("/site").respond(
        json={
            "site_data": [
                {
                    "key": "oidcSettings",
                    "value": {"client_secret": "raw-oidc-secret"},
                    "data_type": "object",
                }
            ]
        }
    )

    # 1. Default masked export
    masked_out = await call(server, "export_config", {"output_dir": str(tmp_path)})
    assert masked_out["secrets_masked"] is True
    assert masked_out["restorable"] is False
    assert "NOT a directly restorable backup" in masked_out["warning"]
    masked_file = json.loads((tmp_path / masked_out["path"].split("/")[-1]).read_text())
    assert "raw-header-secret" not in json.dumps(masked_file)
    assert "raw-hb-secret" not in json.dumps(masked_file)
    assert "raw-oidc-secret" not in json.dumps(masked_file)
    assert masked_file["monitors"][0]["type_data"]["secretString"] == "********"

    # 2. include_secrets=True inside repo must be rejected
    from kener_mcp.server import REPO_ROOT

    with pytest.raises(ToolError, match="outside the kener-mcp repository"):
        await call(
            server,
            "export_config",
            {"output_dir": str(REPO_ROOT), "include_secrets": True},
        )

    # 3. include_secrets=True outside repo writes chmod 600 and never leaks secrets in output
    secret_dir = tmp_path / "secure"
    sec_out = await call(
        server,
        "export_config",
        {"output_dir": str(secret_dir), "include_secrets": True},
    )
    assert sec_out["secrets_masked"] is False
    assert sec_out["restorable"] is True
    assert "raw-header-secret" not in json.dumps(sec_out)
    assert "raw-hb-secret" not in json.dumps(sec_out)
    assert "raw-oidc-secret" not in json.dumps(sec_out)

    from pathlib import Path

    sec_path = Path(sec_out["path"])
    assert (sec_path.stat().st_mode & 0o777) == 0o600
    sec_file = json.loads(sec_path.read_text())
    assert sec_file["monitors"][0]["type_data"]["secretString"] == "raw-hb-secret"


# --- Step 2: create & update tools ------------------------------------------


async def test_create_monitor_attaches_to_pages_and_masks_secrets(server, api):
    created_mon = {
        "id": 11,
        "tag": "mcp-test-api",
        "name": "MCP Test API",
        "monitor_type": "API",
        "cron": "* * * * *",
        "default_status": "UP",
        "status": "ACTIVE",
        "is_hidden": "NO",
        "include_degraded_in_downtime": "NO",
        "confirmation_threshold": 1,
        "type_data": {
            "url": "https://lovelace.gg/ping",
            "method": "GET",
            "headers": [{"key": "Authorization", "value": "Bearer create-secret"}],
        },
    }
    post_route = api.post("/monitors").respond(201, json={"monitor": created_mon})
    api.get("/pages/~home").respond(
        json={
            "page": {
                "id": 1,
                "page_path": "~home",
                "page_title": "Home",
                "page_header": "Home",
                "monitors": [{"monitor_tag": "web", "position": 0}],
            }
        }
    )
    patch_page = api.patch("/pages/~home").respond(
        json={
            "page": {
                "id": 1,
                "page_path": "~home",
                "page_title": "Home",
                "page_header": "Home",
                "monitors": [
                    {"monitor_tag": "web", "position": 0},
                    {"monitor_tag": "mcp-test-api", "position": 1},
                ],
            }
        }
    )
    api.get("/pages").respond(
        json={
            "pages": [
                {
                    "id": 1,
                    "page_path": "~home",
                    "page_title": "Home",
                    "page_header": "Home",
                    "monitors": [
                        {"monitor_tag": "web", "position": 0},
                        {"monitor_tag": "mcp-test-api", "position": 1},
                    ],
                }
            ]
        }
    )

    out = await call(
        server,
        "create_monitor",
        {
            "tag": "mcp-test-api",
            "name": "MCP Test API",
            "type_data": {
                "url": "https://lovelace.gg/ping",
                "method": "GET",
                "headers": [{"key": "Authorization", "value": "Bearer create-secret"}],
            },
        },
    )
    assert sent_json(post_route)["cron"] == "* * * * *"
    assert sent_json(patch_page) == {"monitors": ["web", "mcp-test-api"]}
    assert out["pages"] == ["~home"]
    assert out["type_data"]["headers"] == [{"key": "Authorization", "value": "********"}]
    assert "create-secret" not in json.dumps(out)


async def test_update_monitor_rejects_masked_secret_placeholder(server, api):
    patch_route = api.patch("/monitors/web")

    # 1. Masked secret in top-level type_data field (e.g. secretString / body / connectionString)
    with pytest.raises(ToolError, match=r"must not contain masked placeholder '\*\*\*\*\*\*\*\*'"):
        await call(
            server,
            "update_monitor",
            {"tag": "web", "type_data": {"url": "https://x.io", "secretString": "********"}},
        )

    # 2. Masked secret nested inside headers[].value
    with pytest.raises(ToolError, match=r"must not contain masked placeholder '\*\*\*\*\*\*\*\*'"):
        await call(
            server,
            "update_monitor",
            {
                "tag": "web",
                "type_data": {
                    "url": "https://x.io",
                    "headers": [{"key": "Authorization", "value": "********"}],
                },
            },
        )

    assert not patch_route.called


async def test_update_monitor_returns_before_after_and_updates_pages(server, api):
    old_mon = {
        "id": 3,
        "tag": "web",
        "name": "Old Web",
        "status": "ACTIVE",
        "monitor_type": "API",
        "cron": "* * * * *",
        "type_data": {
            "url": "https://old.lovelace.gg",
            "headers": [{"key": "X-Token", "value": "secret-tok-1"}],
        },
    }
    new_mon = {
        **old_mon,
        "name": "New Web",
        "type_data": {
            "url": "https://new.lovelace.gg",
            "headers": [{"key": "X-Token", "value": "secret-tok-1"}],
        },
    }
    api.get("/monitors/web").respond(json={"monitor": old_mon})
    patch_mon = api.patch("/monitors/web").respond(json={"monitor": new_mon})
    api.get("/pages").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "pages": [
                        {
                            "id": 1,
                            "page_path": "~home",
                            "monitors": [{"monitor_tag": "web", "position": 0}],
                        },
                        {"id": 2, "page_path": "internal", "monitors": []},
                    ]
                },
            ),
            httpx.Response(
                200,
                json={
                    "pages": [
                        {"id": 1, "page_path": "~home", "monitors": []},
                        {
                            "id": 2,
                            "page_path": "internal",
                            "monitors": [{"monitor_tag": "web", "position": 0}],
                        },
                    ]
                },
            ),
        ]
    )
    patch_home = api.patch("/pages/~home").respond(
        json={"page": {"id": 1, "page_path": "~home", "monitors": []}}
    )
    patch_internal = api.patch("/pages/internal").respond(
        json={
            "page": {
                "id": 2,
                "page_path": "internal",
                "monitors": [{"monitor_tag": "web", "position": 0}],
            }
        }
    )

    out = await call(
        server,
        "update_monitor",
        {
            "tag": "web",
            "name": "New Web",
            "type_data": {"url": "https://new.lovelace.gg"},
            "page_paths": ["internal"],
        },
    )
    assert sent_json(patch_mon) == {
        "name": "New Web",
        "type_data": {"url": "https://new.lovelace.gg"},
    }
    assert sent_json(patch_home) == {"monitors": []}
    assert sent_json(patch_internal) == {"monitors": ["web"]}
    assert out["before"]["name"] == "Old Web"
    assert out["before"]["pages"] == ["~home"]
    assert out["after"]["name"] == "New Web"
    assert out["after"]["pages"] == ["internal"]
    assert "secret-tok-1" not in json.dumps(out)


async def test_pause_monitor_toggles_status(server, api):
    api.get("/monitors/web").respond(
        json={"monitor": {"id": 3, "tag": "web", "name": "Web", "status": "ACTIVE"}}
    )
    patch_route = api.patch("/monitors/web").respond(
        json={"monitor": {"id": 3, "tag": "web", "name": "Web", "status": "INACTIVE"}}
    )
    out = await call(server, "pause_monitor", {"tag": "web", "paused": True})
    assert sent_json(patch_route) == {"status": "INACTIVE"}
    assert out["before"]["status"] == "ACTIVE"
    assert out["after"]["status"] == "INACTIVE"


async def test_create_update_page_and_set_page_monitors(server, api):
    api.post("/pages").respond(
        201,
        json={
            "page": {
                "id": 5,
                "page_path": "eu",
                "page_title": "Europe",
                "page_header": "EU Services",
                "monitors": [{"monitor_tag": "web", "position": 0}],
            }
        },
    )
    created = await call(
        server,
        "create_page",
        {
            "page_path": "eu",
            "page_title": "Europe",
            "page_header": "EU Services",
            "monitors": ["web"],
        },
    )
    assert created["page_path"] == "eu"
    assert created["monitors"] == ["web"]

    api.get("/pages/eu").respond(
        json={
            "page": {
                "id": 5,
                "page_path": "eu",
                "page_title": "Europe",
                "page_header": "EU Services",
                "monitors": [{"monitor_tag": "web", "position": 0}],
            }
        }
    )
    patch_route = api.patch("/pages/eu").respond(
        json={
            "page": {
                "id": 5,
                "page_path": "eu",
                "page_title": "Europe Updated",
                "page_header": "EU Services",
                "monitors": [
                    {"monitor_tag": "api", "position": 0},
                    {"monitor_tag": "web", "position": 1},
                ],
            }
        }
    )
    updated = await call(
        server,
        "update_page",
        {"page_path": "eu", "page_title": "Europe Updated"},
    )
    assert sent_json(patch_route) == {"page_title": "Europe Updated"}
    assert updated["before"]["page_title"] == "Europe"
    assert updated["after"]["page_title"] == "Europe Updated"

    reordered = await call(
        server,
        "set_page_monitors",
        {"page_path": "eu", "monitor_tags": ["api", "web"]},
    )
    assert sent_json(patch_route) == {"monitors": ["api", "web"]}
    assert reordered["before"]["monitors"] == ["web"]
    assert reordered["after"]["monitors"] == ["api", "web"]

    with pytest.raises(ToolError, match="duplicate tags"):
        await call(
            server,
            "set_page_monitors",
            {"page_path": "eu", "monitor_tags": ["web", "web"]},
        )


async def test_update_incident_and_comment(server, api):
    api.get("/incidents/7").respond(json={"incident": incident(7, title="Old Title")})
    patch_inc = api.patch("/incidents/7").respond(
        json={
            "incident": incident(
                7,
                title="New Title",
                monitors=[{"monitor_tag": "api", "impact": "DEGRADED"}],
            )
        }
    )
    inc_out = await call(
        server,
        "update_incident",
        {"incident_id": 7, "title": "New Title", "monitor_tags": ["api"], "impact": "DEGRADED"},
    )
    assert sent_json(patch_inc) == {
        "title": "New Title",
        "monitors": [{"monitor_tag": "api", "impact": "DEGRADED"}],
    }
    assert inc_out["before"]["title"] == "Old Title"
    assert inc_out["after"]["title"] == "New Title"

    api.get("/incidents/7/comments/2").respond(
        json={"comment": comment(2, 7, text="Typo text", state="INVESTIGATING")}
    )
    patch_com = api.patch("/incidents/7/comments/2").respond(
        json={"comment": comment(2, 7, text="Fixed text", state="IDENTIFIED")}
    )
    com_out = await call(
        server,
        "update_incident_comment",
        {"incident_id": 7, "comment_id": 2, "comment": "Fixed text", "state": "IDENTIFIED"},
    )
    assert sent_json(patch_com) == {"comment": "Fixed text", "state": "IDENTIFIED"}
    assert com_out["before"]["comment"] == "Typo text"
    assert com_out["after"]["comment"] == "Fixed text"


async def test_create_and_update_maintenance_and_events(server, api):
    maint_obj = {
        "id": 12,
        "title": "Router Upgrade",
        "description": "Core router reboot",
        "start_date_time": 1_760_010_000,
        "duration_seconds": 1800,
        "rrule": "FREQ=MINUTELY;COUNT=1",
        "status": "ACTIVE",
        "monitors": [{"monitor_tag": "web", "impact": "MAINTENANCE"}],
    }
    post_maint = api.post("/maintenances").respond(201, json={"maintenance": maint_obj})
    api.get("/maintenances/12/events").respond(
        json={
            "events": [
                {
                    "id": 120,
                    "maintenance_id": 12,
                    "start_date_time": 1_760_010_000,
                    "end_date_time": 1_760_011_800,
                    "status": "SCHEDULED",
                }
            ],
            "page": 1,
            "limit": 100,
        }
    )
    created = await call(
        server,
        "create_maintenance",
        {
            "title": "Router Upgrade",
            "start_date_time": 1_760_010_000,
            "duration_seconds": 1800,
            "monitor_tags": ["web"],
        },
    )
    assert sent_json(post_maint)["rrule"] == "FREQ=MINUTELY;COUNT=1"
    assert created["id"] == 12
    assert len(created["events"]) == 1

    api.get("/maintenances/12").respond(json={"maintenance": maint_obj})
    patch_maint = api.patch("/maintenances/12").respond(
        json={"maintenance": {**maint_obj, "duration_seconds": 3600}}
    )
    updated = await call(
        server,
        "update_maintenance",
        {"maintenance_id": 12, "duration_seconds": 3600},
    )
    assert sent_json(patch_maint) == {"duration_seconds": 3600}
    assert updated["before"]["duration_seconds"] == 1800
    assert updated["after"]["duration_seconds"] == 3600

    # Event update validation (mutually exclusive modes)
    with pytest.raises(ToolError, match="not both"):
        await call(
            server,
            "update_maintenance_event",
            {
                "maintenance_id": 12,
                "event_id": 120,
                "status": "CANCELLED",
                "start_date_time": 1_760_010_000,
                "end_date_time": 1_760_011_800,
            },
        )

    api.get("/maintenances/12/events/120").respond(
        json={
            "event": {
                "id": 120,
                "maintenance_id": 12,
                "start_date_time": 1_760_010_000,
                "end_date_time": 1_760_011_800,
                "status": "SCHEDULED",
            }
        }
    )
    patch_ev = api.patch("/maintenances/12/events/120").respond(
        json={
            "event": {
                "id": 120,
                "maintenance_id": 12,
                "start_date_time": 1_760_010_000,
                "end_date_time": 1_760_011_800,
                "status": "CANCELLED",
            }
        }
    )
    ev_out = await call(
        server,
        "update_maintenance_event",
        {"maintenance_id": 12, "event_id": 120, "status": "CANCELLED"},
    )
    assert sent_json(patch_ev) == {"status": "CANCELLED"}
    assert ev_out["before"]["status"] == "SCHEDULED"
    assert ev_out["after"]["status"] == "CANCELLED"


async def test_update_site_config_masks_secrets_and_rejects_placeholder(server, api):
    with pytest.raises(ToolError, match="masked placeholder"):
        await call(
            server,
            "update_site_config",
            {"key": "oidcSettings", "value": {"client_secret": "********"}},
        )

    api.get("/site/title").respond(
        json={"key": "title", "value": "Old Title", "data_type": "string"}
    )
    patch_site = api.patch("/site/title").respond(
        json={"key": "title", "value": "New Title", "data_type": "string"}
    )
    out = await call(server, "update_site_config", {"key": "title", "value": "New Title"})
    assert sent_json(patch_site) == {"value": "New Title"}
    assert out["before"]["value"] == "Old Title"
    assert out["after"]["value"] == "New Title"


# --- Step 3: delete tools ---------------------------------------------------


async def test_delete_monitor_and_page(server, api):
    del_mon = api.delete("/monitors/mcp-test-api").respond(
        json={"message": "Monitor with tag 'mcp-test-api' deleted successfully"}
    )
    mon_out = await call(server, "delete_monitor", {"tag": "mcp-test-api"})
    assert del_mon.called
    assert mon_out == {
        "deleted_tag": "mcp-test-api",
        "message": "Monitor with tag 'mcp-test-api' deleted successfully",
    }

    with pytest.raises(ToolError, match="home page"):
        await call(server, "delete_page", {"page_path": "~home"})

    del_page = api.delete("/pages/eu").respond(
        json={"message": "Page with path 'eu' deleted successfully"}
    )
    page_out = await call(server, "delete_page", {"page_path": "eu"})
    assert del_page.called
    assert page_out == {
        "deleted_page_path": "eu",
        "message": "Page with path 'eu' deleted successfully",
    }


async def test_delete_incident_comment_and_maintenance(server, api):
    del_com = api.delete("/incidents/7/comments/2").respond(
        json={"message": "Comment with id '2' deleted successfully"}
    )
    com_out = await call(server, "delete_incident_comment", {"incident_id": 7, "comment_id": 2})
    assert del_com.called
    assert com_out["deleted_comment_id"] == 2

    del_inc = api.delete("/incidents/7").respond(
        json={"message": "Incident with id '7' deleted successfully"}
    )
    inc_out = await call(server, "delete_incident", {"incident_id": 7})
    assert del_inc.called
    assert inc_out["deleted_incident_id"] == 7

    del_ev = api.delete("/maintenances/12/events/120").respond(
        json={"message": "Event with id '120' deleted successfully"}
    )
    ev_out = await call(server, "delete_maintenance_event", {"maintenance_id": 12, "event_id": 120})
    assert del_ev.called
    assert ev_out["deleted_event_id"] == 120

    del_maint = api.delete("/maintenances/12").respond(
        json={"message": "Maintenance with id '12' deleted successfully"}
    )
    maint_out = await call(server, "delete_maintenance", {"maintenance_id": 12})
    assert del_maint.called
    assert maint_out["deleted_maintenance_id"] == 12
