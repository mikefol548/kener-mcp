# kener-mcp

[![PyPI](https://img.shields.io/pypi/v/kener-mcp)](https://pypi.org/project/kener-mcp/) [![CI](https://github.com/alphaomegateam/kener-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/alphaomegateam/kener-mcp/actions/workflows/ci.yml)

An [MCP](https://modelcontextprotocol.io) server for [Kener](https://github.com/rajnandan1/kener) v4 status pages. It lets an AI agent (Claude Code, Claude Desktop, or any MCP client) inspect and administer monitors, status pages, incidents, maintenances, and site-wide configuration.

Tested against Kener 4.1.9.

## Tools

### Overview, Backup & Documentation

| Tool | What it does | Mode |
|------|--------------|------|
| `get_config_overview` | Returns a full instance summary (site, monitors, pages, open incidents, active maintenances) and flags configuration anomalies (orphan/inactive/hidden monitors, missing cron, unknown/unused categories, stale open incidents older than `stale_incident_days` [default 7], active maintenances without upcoming events). | Read-only |
| `export_config` | Exports `site_data`, `pages`, `monitors`, `incidents`, and `maintenances` to a timestamped `kener-backup-YYYYMMDD-HHMMSS.json` file. Secrets are masked with `********` by default (not a restorable backup); `include_secrets=true` writes raw secrets outside the repo with `chmod 600` and never echoes them in tool output. | Write |
| `kener_docs` | Fetches the official Kener v4 documentation index (`llms.txt`) or raw Markdown for a topic (e.g. `monitors/api`, `maintenances/rrule-patterns`). | Read-only |

### Monitors

| Tool | What it does | Mode |
|------|--------------|------|
| `list_monitors` | Lists monitors (tag, name, status, type, category). Never returns `type_data` or `monitor_settings_json`. | Read-only |
| `get_monitor` | Gets one monitor's full configuration (with secrets in `type_data` masked) and the list of `pages` where it appears. | Read-only |
| `create_monitor` | Creates a monitor (`cron="* * * * *"` by default) and attaches it to `page_paths` (`["~home"]` by default). | Write |
| `update_monitor` | Updates a monitor and/or its `page_paths`. Rejects any `********` placeholder in `type_data` and returns `before`/`after` configs. | Destructive |
| `pause_monitor` | Pauses (`status="INACTIVE"`) or resumes (`status="ACTIVE"`) a monitor and returns `before`/`after` configs. | Destructive |
| `delete_monitor` | Permanently deletes one monitor by exact `tag`, **including all its uptime history (`monitoring_data`)** and page/incident/maintenance/alert links. | Destructive |

### Pages

| Tool | What it does | Mode |
|------|--------------|------|
| `list_pages` | Lists all status pages (including `~home`) and their ordered monitor tags. | Read-only |
| `get_page` | Gets one status page (`~home` for the home page) with its settings and monitors. | Read-only |
| `create_page` | Creates a status page and optionally attaches an ordered list of monitor tags. | Write |
| `update_page` | Updates a page's titles, logo, `page_settings`, or slug, returning `before`/`after` configs. | Destructive |
| `set_page_monitors` | Replaces the ordered list of monitor tags on a page, returning `before`/`after` configs. | Destructive |
| `delete_page` | Permanently deletes one status page by exact `page_path` (cannot delete `~home`). | Destructive |

### Incidents & Updates

| Tool | What it does | Mode |
|------|--------------|------|
| `list_incidents` | Lists incidents, newest first. Only open incidents unless `include_resolved` is true. | Read-only |
| `get_incident` | Gets one incident with its update timeline. | Read-only |
| `create_incident` | Creates an incident starting now (`INVESTIGATING`), optionally attaches monitors and posts a first update. | Write |
| `post_incident_update` | Posts a public update on an incident and sets its state (`INVESTIGATING`, `IDENTIFIED`, `MONITORING`, `RESOLVED`). | Destructive |
| `resolve_incident` | Posts a `RESOLVED` update, which closes the incident and sets its end time. | Destructive |
| `update_incident` | Updates an incident's title, timestamps, or affected monitors, returning `before`/`after` configs. | Destructive |
| `update_incident_comment` | Edits an existing incident update comment, returning `before`/`after` summaries. | Destructive |
| `delete_incident` | Permanently deletes one incident and its comments by exact `incident_id`. | Destructive |
| `delete_incident_comment` | Deletes (deactivates) one incident comment by exact `incident_id` and `comment_id`. | Destructive |

### Maintenances & Events

| Tool | What it does | Mode |
|------|--------------|------|
| `list_maintenances` | Lists maintenances, optionally filtered by `status` or `monitor_tag`. | Read-only |
| `get_maintenance` | Gets one maintenance definition and its scheduled/past events. | Read-only |
| `create_maintenance` | Creates a one-time (`FREQ=MINUTELY;COUNT=1`) or recurring (iCalendar `RRULE`) maintenance. | Write |
| `update_maintenance` | Updates a maintenance definition and returns `before`/`after` configs. | Destructive |
| `update_maintenance_event` | Updates one maintenance occurrence: either sets `status` (`COMPLETED`/`CANCELLED`) or reschedules `start_date_time` + `end_date_time`. | Destructive |
| `delete_maintenance` | Permanently deletes one maintenance and all its events by exact `maintenance_id`. | Destructive |
| `delete_maintenance_event` | Permanently deletes one maintenance event by exact `maintenance_id` and `event_id`. | Destructive |

### Site Configuration & Categories

| Tool | What it does | Mode |
|------|--------------|------|
| `get_site_config` | Gets all site-wide settings (`GET /site`) or a single key (`GET /site/{key}`), with secrets masked. | Read-only |
| `update_site_config` | Updates a site configuration key (such as `title`, `siteName`, `categories`, `nav`, `hero`, `colors`, `announcement`), returning `before`/`after` configs. | Destructive |

Every tool carries explicit MCP annotations:
- **Read-only**: `readOnlyHint=true`, `destructiveHint=false`
- **Write (pure addition / local export)**: `readOnlyHint=false`, `destructiveHint=false`
- **Destructive (in-place modification or single-ID deletion)**: `readOnlyHint=false`, `destructiveHint=true` (tool descriptions instruct the agent to run `export_config` first).

## Configuration

One server serves one Kener instance. To use more than one instance, register one server per instance, each with its own URL and key.

| Variable | Required | Description |
|----------|----------|-------------|
| `KENER_URL` | Yes | Base URL of the Kener instance, for example `https://status.example.com`. |
| `KENER_API_KEY` | One of these two | A Kener API key. Create one in the Kener dashboard under **Manage > API Keys**. |
| `KENER_API_KEY_CMD` | One of these two | A command that prints the API key on stdout, for example `op read op://Vault/Item/api_key`. See [API key command](#api-key-command). |
| `KENER_API_KEY_CMD_TIMEOUT` | No | Seconds to wait for the key command. Default `30`. |
| `KENER_NAME` | No | A short name for the instance. It is used in the server name and in error messages. |
| `KENER_INSTRUCTIONS` | No | Extra text for the agent, for example "This page is client-facing; updates also post to the client's Slack." |

The `--url`, `--api-key-cmd`, and `--name` flags override the matching variables. There is no `--api-key` flag, because process lists show command-line arguments.

### API key command

Use `KENER_API_KEY_CMD` (or `--api-key-cmd`) to get the key from a secret manager, so that the key is not in your MCP config:

- The command runs on the first tool call, not at server start. A slow or locked secret manager does not block the MCP handshake.
- The key is kept in memory. If Kener rejects it (HTTP 401), the next tool call runs the command again, so a rotated key is picked up.
- The command is split like a shell command line (`shlex`) but does not run in a shell. Pipes, `$VARS`, and `~` are not expanded. For those, point it at a script.
- The command must print only the key. If it fails, the error shows its exit code and stderr, never its stdout.

Examples:

```bash
# 1Password
KENER_API_KEY_CMD='op read "op://Infra/Kener API key/api_key"'
# macOS Keychain
KENER_API_KEY_CMD='security find-generic-password -s kener -w'
# pass
KENER_API_KEY_CMD='pass show kener/api-key'
```

## Install

```bash
uv tool install kener-mcp
```

Or run it without installing: `uvx kener-mcp`. With pip: `pip install kener-mcp`.

Then check the URL and key:

```bash
KENER_URL=https://status.example.com KENER_API_KEY=... kener-mcp check
```

## Register with Claude Code

```bash
claude mcp add kener -s user \
  -e KENER_URL=https://status.example.com \
  -e KENER_API_KEY=your-key \
  -- kener-mcp
```

For two instances, add two servers:

```bash
claude mcp add kener-prod -s user -e KENER_URL=https://status.example.com -e KENER_API_KEY=... -- kener-mcp
claude mcp add kener-staging -s user -e KENER_URL=https://status-staging.example.com -e KENER_API_KEY=... -- kener-mcp
```

With a key command instead of a stored key:

```bash
claude mcp add kener -s user -- kener-mcp \
  --url https://status.example.com \
  --api-key-cmd 'op read "op://Infra/Kener API key/api_key"'
```

## Register with Claude Desktop (or another MCP client)

```json
{
  "mcpServers": {
    "kener": {
      "command": "kener-mcp",
      "env": {
        "KENER_URL": "https://status.example.com",
        "KENER_API_KEY": "your-key"
      }
    }
  }
}
```

## Kener API notes

These notes describe Kener 4.1.9 (and adjacent 4.1.x releases) as read from the Kener source code:

- **Incident comments (`comment`/`state`)**: An update is `POST /api/v4/incidents/{id}/comments` with `{"comment": "...", "state": "..."}`. Some Kener docs show `message` and `status`, which the server rejects.
- **Resolving incidents**: There is no dedicated resolve endpoint. Posting a comment with `state: "RESOLVED"` sets the incident state to `RESOLVED` and sets `end_date_time`. `PATCH /api/v4/incidents/{id}` cannot change `state`.
- **Subscriber email notifications**: Starting in **Kener 4.1.8**, incident updates posted through `/api/v4` email subscribers just like dashboard updates. On Kener 4.1.7 and earlier, API updates did not notify subscribers ([rajnandan1/kener#886](https://github.com/rajnandan1/kener/issues/886)).
- **Secrets in `/monitors` and `/site` & shallow merge on `PATCH /monitors/{tag}`**:
  - Kener 4.1.7+ masks OIDC (`client_secret`) and captcha (`requirements["Secret Key"]`) secrets in `GET /api/v4/site`, whereas monitor secrets in `type_data` (`headers[].value`, `body`, `proxy`, `connectionString`, `secretString`, `tlsKey`) are returned in plain text until **Kener 4.1.11** (which masks them server-side with `"********"`).
  - `PATCH /api/v4/monitors/{tag}` performs a shallow merge (`{...existingTypeData, ...body.type_data}`). On Kener < 4.1.11 it does not restore `"********"` placeholders from the database. `kener-mcp` always masks secrets in tool outputs (`get_monitor`, `get_site_config`, default `export_config`) and **strictly rejects `"********"`** in `update_monitor`, `create_monitor`, and `update_site_config` so masked placeholders never overwrite real secrets.
- **Monitor creation defaults & page visibility**:
  - `POST /api/v4/monitors` defaults `cron` to `null` if omitted (unlike the dashboard which defaults to `"* * * * *"`) and does not accept a `pages` field—leaving a newly created monitor invisible on public status pages until attached to a page. `create_monitor` in `kener-mcp` defaults `cron` to `"* * * * *"` and automatically attaches the new monitor to `page_paths` (`["~home"]` by default).
  - Deleting a monitor (`DELETE /api/v4/monitors/{tag}`) permanently deletes all of its historical uptime data (`monitoring_data`) in addition to the monitor definition.
- **Pages (`~home` and `monitors` shape)**:
  - The home page (`page_path: ""` in the database) is addressed as `~home` in `/api/v4/pages/~home` and cannot be deleted or have its `page_path` changed.
  - `GET /api/v4/pages` returns `monitors` as `[{"monitor_tag": "web", "position": 0}, ...]`, whereas `POST /api/v4/pages` and `PATCH /api/v4/pages/{page_path}` expect `monitors` as an ordered array of tag strings `["web", "api"]` (no duplicates).
- **Maintenance events (`PATCH /api/v4/maintenances/{id}/events/{event_id}`)**:
  - Supports two mutually exclusive modes: either update `status` (`"COMPLETED"` or `"CANCELLED"`) alone, OR update both `start_date_time` and `end_date_time` together. Sending both in the same request returns `400 Bad Request`.
- **Dashboard-only features not exposed on `/api/v4`**:
  - Alert configurations (`monitor_alerts_config`), notification triggers (`triggers` for webhook/Discord/Slack/email), and on-demand monitor execution (`testMonitor`) exist only on internal `/manage/api` routes authenticated by a browser session cookie (`kener-user`) and RBAC permissions—they are not accessible with a Bearer API key. `kener-mcp` intentionally uses only the official `/api/v4` surface and does not expose `alert` or `test_monitor` tools.

## Development

```bash
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

The tests use [respx](https://lundberg.github.io/respx/) to check the HTTP request shapes. They call no real Kener instance.

## Releasing

1. Bump the version: `uv version --bump patch` (or `minor` / `major`).
2. Move the `Unreleased` notes in `CHANGELOG.md` under the new version.
3. Commit, push, and wait for CI to pass.
4. Publish a GitHub release with the tag `v<version>`, for example `gh release create v0.1.1 --generate-notes`.

The `Release` workflow then checks that the tag matches the version in `pyproject.toml`, runs the tests, builds the package, and publishes it to PyPI with [Trusted Publishing](https://docs.pypi.org/trusted-publishers/).

## License

MIT. See [LICENSE](LICENSE).
