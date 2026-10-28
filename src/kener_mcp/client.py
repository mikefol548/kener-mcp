"""Thin async client for the Kener v4 REST API (tested against Kener 4.1.9)."""

from typing import Any, Literal

import httpx

from . import __version__

IncidentState = Literal["INVESTIGATING", "IDENTIFIED", "MONITORING", "RESOLVED"]
Impact = Literal["DOWN", "DEGRADED", "MAINTENANCE"]
MaintenanceImpact = Literal["UP", "DOWN", "DEGRADED", "MAINTENANCE"]
MaintenanceStatus = Literal["ACTIVE", "INACTIVE"]
MaintenanceEventStatus = Literal["COMPLETED", "CANCELLED"]
MonitorStatus = Literal["ACTIVE", "INACTIVE"]
YesNo = Literal["YES", "NO"]

DEFAULT_TIMEOUT = 20.0


class KenerError(Exception):
    """Kener returned an error, or could not be reached."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class KenerClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/api/v4",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": f"kener-mcp/{__version__}",
            },
            timeout=timeout,
            transport=transport,
        )

    async def __aenter__(self) -> "KenerClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            resp = await self._http.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            # The message names the URL only. Headers (and the key) stay out of it.
            raise KenerError(f"Request to {e.request.url} failed: {type(e).__name__}") from None
        if resp.is_success:
            return resp.json() if resp.content else {}
        message = resp.reason_phrase
        try:
            message = resp.json()["error"]["message"]
        except (ValueError, KeyError, TypeError):
            pass
        raise KenerError(f"Kener returned {resp.status_code}: {message}", resp.status_code)

    # --- Monitors -----------------------------------------------------------

    async def list_monitors(self) -> list[dict]:
        return (await self._request("GET", "/monitors"))["monitors"]

    async def get_monitor(self, tag: str) -> dict:
        return (await self._request("GET", f"/monitors/{tag}"))["monitor"]

    async def create_monitor(self, body: dict[str, Any]) -> dict:
        return (await self._request("POST", "/monitors", json=body))["monitor"]

    async def update_monitor(self, tag: str, body: dict[str, Any]) -> dict:
        return (await self._request("PATCH", f"/monitors/{tag}", json=body))["monitor"]

    async def delete_monitor(self, tag: str) -> dict:
        return await self._request("DELETE", f"/monitors/{tag}")

    # --- Pages --------------------------------------------------------------

    async def list_pages(self) -> list[dict]:
        return (await self._request("GET", "/pages"))["pages"]

    async def get_page(self, page_path: str) -> dict:
        return (await self._request("GET", f"/pages/{page_path}"))["page"]

    async def create_page(self, body: dict[str, Any]) -> dict:
        return (await self._request("POST", "/pages", json=body))["page"]

    async def update_page(self, page_path: str, body: dict[str, Any]) -> dict:
        return (await self._request("PATCH", f"/pages/{page_path}", json=body))["page"]

    async def delete_page(self, page_path: str) -> dict:
        return await self._request("DELETE", f"/pages/{page_path}")

    # --- Incidents ----------------------------------------------------------

    async def list_incidents(self) -> list[dict]:
        return (await self._request("GET", "/incidents"))["incidents"]

    async def get_incident(self, incident_id: int) -> dict:
        return (await self._request("GET", f"/incidents/{incident_id}"))["incident"]

    async def list_comments(self, incident_id: int) -> list[dict]:
        return (await self._request("GET", f"/incidents/{incident_id}/comments"))["comments"]

    async def get_comment(self, incident_id: int, comment_id: int) -> dict:
        return (await self._request("GET", f"/incidents/{incident_id}/comments/{comment_id}"))[
            "comment"
        ]

    async def add_comment(
        self,
        incident_id: int,
        comment: str,
        state: IncidentState,
        timestamp: int | None = None,
    ) -> dict:
        # Kener reads "comment" and "state". Its docs show "message"/"status",
        # which the server rejects.
        body: dict[str, Any] = {"comment": comment, "state": state}
        if timestamp is not None:
            body["timestamp"] = timestamp
        return (await self._request("POST", f"/incidents/{incident_id}/comments", json=body))[
            "comment"
        ]

    async def update_comment(self, incident_id: int, comment_id: int, body: dict[str, Any]) -> dict:
        return (
            await self._request(
                "PATCH", f"/incidents/{incident_id}/comments/{comment_id}", json=body
            )
        )["comment"]

    async def delete_comment(self, incident_id: int, comment_id: int) -> dict:
        return await self._request("DELETE", f"/incidents/{incident_id}/comments/{comment_id}")

    async def create_incident(
        self,
        title: str,
        start_date_time: int,
        monitors: list[dict] | None = None,
    ) -> dict:
        body: dict[str, Any] = {"title": title, "start_date_time": start_date_time}
        if monitors:
            body["monitors"] = monitors
        return (await self._request("POST", "/incidents", json=body))["incident"]

    async def update_incident(self, incident_id: int, body: dict[str, Any]) -> dict:
        return (await self._request("PATCH", f"/incidents/{incident_id}", json=body))["incident"]

    async def delete_incident(self, incident_id: int) -> dict:
        return await self._request("DELETE", f"/incidents/{incident_id}")

    # --- Maintenances -------------------------------------------------------

    async def list_maintenances(
        self,
        status: MaintenanceStatus | None = None,
        monitor_tag: str | None = None,
    ) -> list[dict]:
        params: dict[str, str] = {}
        if status:
            params["status"] = status
        if monitor_tag:
            params["monitor_tag"] = monitor_tag
        return (await self._request("GET", "/maintenances", params=params or None))["maintenances"]

    async def get_maintenance(self, maintenance_id: int) -> dict:
        return (await self._request("GET", f"/maintenances/{maintenance_id}"))["maintenance"]

    async def create_maintenance(self, body: dict[str, Any]) -> dict:
        return (await self._request("POST", "/maintenances", json=body))["maintenance"]

    async def update_maintenance(self, maintenance_id: int, body: dict[str, Any]) -> dict:
        return (await self._request("PATCH", f"/maintenances/{maintenance_id}", json=body))[
            "maintenance"
        ]

    async def delete_maintenance(self, maintenance_id: int) -> dict:
        return await self._request("DELETE", f"/maintenances/{maintenance_id}")

    async def list_maintenance_events(
        self, maintenance_id: int, page: int = 1, limit: int = 100
    ) -> list[dict]:
        return (
            await self._request(
                "GET",
                f"/maintenances/{maintenance_id}/events",
                params={"page": page, "limit": limit},
            )
        )["events"]

    async def get_maintenance_event(self, maintenance_id: int, event_id: int) -> dict:
        return (await self._request("GET", f"/maintenances/{maintenance_id}/events/{event_id}"))[
            "event"
        ]

    async def update_maintenance_event(
        self, maintenance_id: int, event_id: int, body: dict[str, Any]
    ) -> dict:
        return (
            await self._request(
                "PATCH", f"/maintenances/{maintenance_id}/events/{event_id}", json=body
            )
        )["event"]

    async def delete_maintenance_event(self, maintenance_id: int, event_id: int) -> dict:
        return await self._request("DELETE", f"/maintenances/{maintenance_id}/events/{event_id}")

    # --- Site configuration -------------------------------------------------

    async def get_site_data(self) -> list[dict]:
        return (await self._request("GET", "/site"))["site_data"]

    async def get_site_data_key(self, key: str) -> dict:
        return await self._request("GET", f"/site/{key}")

    async def update_site_data_key(self, key: str, value: Any) -> dict:
        return await self._request("PATCH", f"/site/{key}", json={"value": value})
