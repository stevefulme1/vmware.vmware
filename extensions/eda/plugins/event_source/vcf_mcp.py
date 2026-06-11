"""
vcf_mcp.py - Ansible EDA event source plugin for VMware VCF MCP integration.

Connects to a VMware VCF Operations / MCP server and polls for alerts,
events, resource state changes, and compliance status updates. Emits
normalized events onto the EDA rule engine queue.

Copyright (c) 2026 Red Hat, Inc.
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

import aiohttp

DOCUMENTATION = r"""
---
module: vcf_mcp
short_description: >-
    Poll VMware VCF Operations / MCP server for alerts, events, and
    compliance changes.
description:
    - >-
      An Ansible Event-Driven Automation (EDA) event source plugin that
      integrates with VMware Cloud Foundation (VCF) Management Control
      Plane (MCP) servers.
    - >-
      The plugin authenticates with the VCF Operations REST API, then
      continuously polls configurable endpoints for alerts, operational
      events, resource state changes, and compliance status updates.
    - >-
      Events are deduplicated, normalized, and placed on the EDA queue
      for consumption by rulebooks.
    - >-
      VMware MCP server implementations expose 40+ tools for monitoring,
      troubleshooting, and compliance checking of VCF environments. This
      plugin surfaces the relevant operational data as EDA events.
version_added: "1.0.0"
author:
    - "Red Hat Ansible Team"
options:
    mcp_hostname:
        description:
            - >-
              Hostname or IP address of the VCF Operations / MCP server.
              Do not include the scheme (https is assumed).
        type: str
        required: true
    mcp_username:
        description:
            - Username for VCF Operations API authentication.
        type: str
        required: true
    mcp_password:
        description:
            - Password for VCF Operations API authentication.
        type: str
        required: true
        no_log: true
    validate_certs:
        description:
            - Whether to validate TLS certificates when connecting.
        type: bool
        default: true
    poll_interval:
        description:
            - Number of seconds between polling cycles.
        type: int
        default: 30
    endpoints:
        description:
            - >-
              List of API endpoint categories to poll.
              Valid values are C(alerts), C(events), C(resources), and
              C(compliance).
        type: list
        elements: str
        default:
            - alerts
            - events
    severity_filter:
        description:
            - >-
              Optional list of severity levels to include. Events whose
              severity is not in this list are silently dropped.
              Example values: C(CRITICAL), C(IMMEDIATE), C(WARNING),
              C(INFORMATION).
        type: list
        elements: str
    resource_kinds:
        description:
            - >-
              Optional list of resource kinds (types) to include. When
              set, only events related to matching resource types are
              emitted.
        type: list
        elements: str
    include_compliance:
        description:
            - >-
              Convenience flag. When C(true), the C(compliance) endpoint
              is appended to I(endpoints) if not already present.
        type: bool
        default: false
    max_events_per_poll:
        description:
            - Maximum number of events to emit per poll cycle per endpoint.
        type: int
        default: 50
"""

EXAMPLES = r"""
- name: Poll VCF MCP for critical alerts
  vmware.vmware.vcf_mcp:
    mcp_hostname: vcf-ops.example.com
    mcp_username: admin
    mcp_password: "{{ vcf_password }}"
    validate_certs: false
    poll_interval: 60
    endpoints:
      - alerts
      - events
      - compliance
    severity_filter:
      - CRITICAL
      - IMMEDIATE
    max_events_per_poll: 100
"""

logger = logging.getLogger("vcf_mcp")

# ---------------------------------------------------------------------------
# Endpoint metadata
# ---------------------------------------------------------------------------
ENDPOINT_CONFIG: dict[str, dict[str, Any]] = {
    "alerts": {
        "path": "/api/alerts",
        "event_type": "vcf_alert",
        "id_field": "alertId",
        "severity_field": "criticality",
        "resource_field": "resourceId",
        "resource_kind_field": "resourceKind",
        "message_field": "alertMessage",
        "timestamp_field": "startTimeUTC",
    },
    "events": {
        "path": "/api/events",
        "event_type": "vcf_event",
        "id_field": "eventId",
        "severity_field": "severity",
        "resource_field": "resourceId",
        "resource_kind_field": "resourceKind",
        "message_field": "message",
        "timestamp_field": "timestamp",
    },
    "resources": {
        "path": "/api/resources",
        "event_type": "vcf_resource_change",
        "id_field": "resourceId",
        "severity_field": "severity",
        "resource_field": "resourceId",
        "resource_kind_field": "resourceKind",
        "message_field": "resourceName",
        "timestamp_field": "lastModifiedTime",
    },
    "compliance": {
        "path": "/api/compliance",
        "event_type": "vcf_compliance",
        "id_field": "complianceId",
        "severity_field": "severity",
        "resource_field": "resourceId",
        "resource_kind_field": "resourceKind",
        "message_field": "complianceMessage",
        "timestamp_field": "evaluationTime",
    },
}

VALID_ENDPOINTS = set(ENDPOINT_CONFIG.keys())

# How many seconds before token expiry we should proactively refresh.
_TOKEN_REFRESH_MARGIN = 300  # 5 minutes


# ---------------------------------------------------------------------------
# Helper classes
# ---------------------------------------------------------------------------
class _TokenManager:
    """Manages bearer-token lifecycle against the VCF auth endpoint."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
    ) -> None:
        self._base_url = base_url
        self._username = username
        self._password = password
        self._session = session
        self._token: str | None = None
        self._expires_at: float = 0.0

    @property
    def is_valid(self) -> bool:
        return (
            self._token is not None
            and time.monotonic() < self._expires_at - _TOKEN_REFRESH_MARGIN
        )

    async def get_token(self) -> str:
        """Return a valid bearer token, refreshing if necessary."""
        if not self.is_valid:
            await self._acquire_token()
        assert self._token is not None
        return self._token

    async def _acquire_token(self) -> None:
        """Authenticate against the VCF Operations auth endpoint."""
        url = f"{self._base_url}/api/auth/token/acquire"
        payload = {
            "username": self._username,
            "password": self._password,
        }
        logger.info("Acquiring new authentication token from %s", url)
        try:
            async with self._session.post(url, json=payload) as resp:
                resp.raise_for_status()
                data = await resp.json()
                self._token = data.get("token") or data.get("accessToken")
                if not self._token:
                    raise ValueError(
                        "Auth response did not contain 'token' or 'accessToken'. "
                        f"Keys received: {list(data.keys())}"
                    )
                # VCF tokens typically expire in 3600s. Honour the response
                # value if provided, otherwise assume 1 hour.
                expires_in = int(data.get("expiresIn", data.get("validity", 3600)))
                self._expires_at = time.monotonic() + expires_in
                logger.info(
                    "Token acquired successfully (expires in %ds)", expires_in
                )
        except aiohttp.ClientResponseError as exc:
            logger.error(
                "Authentication failed: HTTP %s - %s", exc.status, exc.message
            )
            raise
        except Exception:
            logger.exception("Unexpected error during authentication")
            raise

    async def release(self) -> None:
        """Best-effort token revocation on shutdown."""
        if self._token is None:
            return
        url = f"{self._base_url}/api/auth/token/release"
        try:
            headers = {"Authorization": f"Bearer {self._token}"}
            async with self._session.post(url, headers=headers) as resp:
                if resp.status < 300:
                    logger.info("Token released successfully")
                else:
                    logger.warning(
                        "Token release returned HTTP %s", resp.status
                    )
        except Exception:
            logger.debug("Token release failed (non-critical)", exc_info=True)
        finally:
            self._token = None
            self._expires_at = 0.0


class _EventDeduplicator:
    """Track seen event IDs to suppress duplicates across polls."""

    def __init__(self, max_size: int = 10_000) -> None:
        self._seen: dict[str, float] = {}
        self._max_size = max_size

    def is_new(self, event_id: str) -> bool:
        if event_id in self._seen:
            return False
        self._seen[event_id] = time.monotonic()
        self._prune()
        return True

    def _prune(self) -> None:
        """Keep the cache bounded by evicting oldest entries."""
        if len(self._seen) <= self._max_size:
            return
        sorted_ids = sorted(self._seen, key=self._seen.get)  # type: ignore[arg-type]
        to_remove = len(self._seen) - self._max_size
        for eid in sorted_ids[:to_remove]:
            del self._seen[eid]


# ---------------------------------------------------------------------------
# Event normalisation
# ---------------------------------------------------------------------------
def _normalize_event(
    raw: dict[str, Any],
    endpoint_name: str,
    cfg: dict[str, str],
) -> dict[str, Any]:
    """Map a raw API object into the canonical EDA event schema."""
    event_id = str(raw.get(cfg["id_field"], ""))
    severity = raw.get(cfg["severity_field"], "UNKNOWN")
    resource_name = raw.get("resourceName", raw.get(cfg["resource_field"], ""))
    resource_kind = raw.get(cfg["resource_kind_field"], "")
    message = raw.get(cfg["message_field"], "")
    raw_ts = raw.get(cfg["timestamp_field"])

    # Attempt to produce an ISO-8601 timestamp.
    if isinstance(raw_ts, (int, float)):
        timestamp = datetime.fromtimestamp(
            raw_ts / 1000 if raw_ts > 1e12 else raw_ts,
            tz=timezone.utc,
        ).isoformat()
    elif isinstance(raw_ts, str):
        timestamp = raw_ts
    else:
        timestamp = datetime.now(tz=timezone.utc).isoformat()

    normalized: dict[str, Any] = {
        "source_type": "vcf_mcp",
        "event_type": cfg["event_type"],
        "event_id": event_id,
        "timestamp": timestamp,
        "severity": str(severity).upper(),
        "resource_name": resource_name,
        "resource_type": resource_kind,
        "message": message,
        "mcp_endpoint": endpoint_name,
        "raw_event": raw,
    }

    # Endpoint-specific enrichment.
    if endpoint_name == "alerts":
        normalized["alert_criticality"] = severity
    if endpoint_name == "compliance":
        normalized["compliance_status"] = raw.get(
            "complianceStatus", raw.get("status", "UNKNOWN")
        )

    return normalized


# ---------------------------------------------------------------------------
# Polling logic
# ---------------------------------------------------------------------------
async def _poll_endpoint(
    session: aiohttp.ClientSession,
    token_manager: _TokenManager,
    base_url: str,
    endpoint_name: str,
    deduplicator: _EventDeduplicator,
    severity_filter: list[str] | None,
    resource_kinds: list[str] | None,
    max_events: int,
) -> list[dict[str, Any]]:
    """Fetch and normalise new events from a single endpoint."""
    cfg = ENDPOINT_CONFIG[endpoint_name]
    url = f"{base_url}{cfg['path']}"
    token = await token_manager.get_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    logger.debug("Polling %s", url)
    try:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 401:
                # Token may have been revoked server-side; force refresh.
                logger.warning("Received 401; forcing token refresh")
                token = await token_manager.get_token()
                headers["Authorization"] = f"Bearer {token}"
                async with session.get(url, headers=headers) as retry_resp:
                    retry_resp.raise_for_status()
                    data = await retry_resp.json()
            else:
                resp.raise_for_status()
                data = await resp.json()
    except aiohttp.ClientResponseError as exc:
        logger.error(
            "HTTP error polling %s: %s %s", endpoint_name, exc.status, exc.message
        )
        return []
    except Exception:
        logger.exception("Error polling endpoint %s", endpoint_name)
        return []

    # The API may return a top-level list or an object wrapping a list.
    if isinstance(data, dict):
        items = (
            data.get("items")
            or data.get("alerts")
            or data.get("events")
            or data.get("resources")
            or data.get("results")
            or data.get("complianceResults")
            or []
        )
    elif isinstance(data, list):
        items = data
    else:
        logger.warning("Unexpected response type from %s: %s", endpoint_name, type(data))
        return []

    events: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue

        event = _normalize_event(item, endpoint_name, cfg)

        # Deduplication.
        if not event["event_id"] or not deduplicator.is_new(event["event_id"]):
            continue

        # Severity filter.
        if severity_filter and event["severity"] not in severity_filter:
            continue

        # Resource kind filter.
        if resource_kinds and event["resource_type"] not in resource_kinds:
            continue

        events.append(event)
        if len(events) >= max_events:
            break

    logger.info(
        "Endpoint %s: fetched %d items, emitting %d new events",
        endpoint_name,
        len(items),
        len(events),
    )
    return events


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
async def main(queue: asyncio.Queue, args: dict[str, Any]) -> None:  # noqa: C901
    """EDA event source entry point.

    Parameters
    ----------
    queue:
        The asyncio queue provided by the EDA controller. Normalized
        events are placed here for rulebook evaluation.
    args:
        Configuration dictionary populated from the rulebook source
        definition.
    """
    # ---- Validate and unpack arguments ----
    mcp_hostname: str = args["mcp_hostname"]
    mcp_username: str = args["mcp_username"]
    mcp_password: str = args["mcp_password"]
    validate_certs: bool = args.get("validate_certs", True)
    poll_interval: int = int(args.get("poll_interval", 30))
    endpoints: list[str] = list(args.get("endpoints", ["alerts", "events"]))
    severity_filter: list[str] | None = args.get("severity_filter")
    resource_kinds: list[str] | None = args.get("resource_kinds")
    include_compliance: bool = args.get("include_compliance", False)
    max_events_per_poll: int = int(args.get("max_events_per_poll", 50))

    # Normalise severity filter to upper case.
    if severity_filter:
        severity_filter = [s.upper() for s in severity_filter]

    # Honour include_compliance convenience flag.
    if include_compliance and "compliance" not in endpoints:
        endpoints.append("compliance")

    # Validate requested endpoints.
    invalid = set(endpoints) - VALID_ENDPOINTS
    if invalid:
        raise ValueError(
            f"Invalid endpoint(s): {invalid}. Valid values: {VALID_ENDPOINTS}"
        )

    base_url = f"https://{mcp_hostname}"
    ssl_context: bool | None = None if validate_certs else False

    logger.info(
        "Starting vcf_mcp event source: host=%s endpoints=%s interval=%ds",
        mcp_hostname,
        endpoints,
        poll_interval,
    )

    connector = aiohttp.TCPConnector(ssl=ssl_context)
    timeout = aiohttp.ClientTimeout(total=60)
    session = aiohttp.ClientSession(connector=connector, timeout=timeout)
    token_manager = _TokenManager(base_url, mcp_username, mcp_password, session)
    deduplicator = _EventDeduplicator()

    try:
        # Initial authentication to fail fast on bad credentials.
        await token_manager.get_token()

        while True:
            poll_start = time.monotonic()

            for ep in endpoints:
                try:
                    events = await _poll_endpoint(
                        session=session,
                        token_manager=token_manager,
                        base_url=base_url,
                        endpoint_name=ep,
                        deduplicator=deduplicator,
                        severity_filter=severity_filter,
                        resource_kinds=resource_kinds,
                        max_events=max_events_per_poll,
                    )
                    for event in events:
                        await queue.put(event)
                        logger.debug(
                            "Queued event %s from %s",
                            event.get("event_id"),
                            ep,
                        )
                except Exception:
                    logger.exception("Error processing endpoint %s", ep)

            # Sleep for the remaining poll interval, accounting for
            # time spent polling.
            elapsed = time.monotonic() - poll_start
            sleep_time = max(0, poll_interval - elapsed)
            logger.debug("Poll cycle complete in %.1fs; sleeping %.1fs", elapsed, sleep_time)
            await asyncio.sleep(sleep_time)

    except asyncio.CancelledError:
        logger.info("vcf_mcp event source received cancellation")
    except Exception:
        logger.exception("Fatal error in vcf_mcp event source")
        raise
    finally:
        logger.info("Shutting down vcf_mcp event source")
        await token_manager.release()
        await session.close()
        # Allow underlying connections to close gracefully.
        await asyncio.sleep(0.25)


if __name__ == "__main__":
    """Allow standalone testing: python vcf_mcp.py"""

    class _TestQueue:
        async def put(self, item: Any) -> None:
            print(f"EVENT: {item.get('event_type')} | {item.get('event_id')} | {item.get('message')}")

    print("vcf_mcp: standalone execution is for syntax validation only.")
    print("Provide mcp_hostname, mcp_username, mcp_password via args dict.")
