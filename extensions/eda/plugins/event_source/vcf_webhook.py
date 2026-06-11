"""
vcf_webhook.py - Event source plugin for Ansible EDA (Event-Driven Ansible).

Receives webhook notifications from VMware VCF Automation (vRealize Automation)
and VCF Operations (vRealize Operations / Aria Operations) via an async HTTP
server, normalises them into a common schema, and places them on the EDA event
queue.

Usage in a rulebook
-------------------

.. code-block:: yaml

    - name: Listen for VCF webhooks
      hosts: all
      sources:
        - vmware.vmware.vcf_webhook:
            host: 0.0.0.0
            port: 5000
            token: "{{ vcf_webhook_token }}"
            # hmac_secret: "{{ vcf_hmac_secret }}"
            # hmac_header: X-Signature-256
            # certfile: /etc/pki/tls/certs/webhook.crt
            # keyfile: /etc/pki/tls/private/webhook.key
            # source_filter: automation   # "automation", "operations", or omit for both
      rules:
        - name: Handle VCF event
          condition: event.source_type is defined
          action:
            debug:

Arguments
---------

host : str, default ``"0.0.0.0"``
    Address to bind the HTTP listener to.
port : int, default ``5000``
    TCP port for the HTTP listener.
token : str, optional
    If set, every request must carry an ``Authorization: Bearer <token>``
    header whose value matches this string.
hmac_secret : str, optional
    If set, every request body is verified against an HMAC-SHA256 signature
    transmitted in the header specified by *hmac_header*.
hmac_header : str, default ``"X-Signature-256"``
    Header name that carries the HMAC-SHA256 hex digest when *hmac_secret*
    is configured.  The value may optionally be prefixed with ``sha256=``.
certfile : str, optional
    Path to a PEM-encoded TLS certificate.  When both *certfile* and
    *keyfile* are provided the server uses HTTPS.
keyfile : str, optional
    Path to the PEM-encoded TLS private key corresponding to *certfile*.
source_filter : str, optional
    Restrict which source types are accepted.  ``"automation"`` accepts only
    VCF Automation payloads, ``"operations"`` accepts only VCF Operations
    payloads.  When omitted (the default) both are accepted.

Routes
------

``POST /events``
    General-purpose endpoint.  The plugin auto-detects the payload source.
``POST /vcf/automation``
    Accepts VCF Automation payloads exclusively.
``POST /vcf/operations``
    Accepts VCF Operations payloads exclusively.
``GET /health``
    Returns ``{"status": "ok"}`` -- useful for load-balancer probes.

Normalised event schema
-----------------------

Every event placed on the EDA queue contains at minimum:

.. code-block:: json

    {
        "source_type": "vcf_automation | vcf_operations",
        "event_type": "<event or alert type>",
        "timestamp": "<ISO-8601 timestamp>",
        "severity": "<severity string>",
        "object_name": "<resource or object name>",
        "object_type": "<resource or object type>",
        "message": "<human-readable summary>",
        "alert_id": "<alert / event ID>",
        "status": "<status string>",
        "raw_payload": { ... }
    }
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from aiohttp import web

LOGGER = logging.getLogger("vcf_webhook")

DOCUMENTATION = r"""
module: vcf_webhook
short_description: Receive webhook events from VCF Automation and VCF Operations
description:
  - Run an asynchronous HTTP server that ingests webhook payloads from
    VMware VCF Automation (vRealize Automation) and VCF Operations
    (vRealize Operations / Aria Operations).
  - Payloads are normalised into a common event schema and forwarded
    to the EDA rule engine.
  - Supports bearer-token authentication, HMAC-SHA256 signature
    verification, and optional TLS termination.
version_added: "1.0.0"
options:
  host:
    description: Network address to bind the HTTP listener to.
    type: str
    default: "0.0.0.0"
  port:
    description: TCP port for the HTTP listener.
    type: int
    default: 5000
  token:
    description:
      - Bearer token for request authentication.
      - When set, every incoming request must include an
        C(Authorization: Bearer <token>) header.
    type: str
  hmac_secret:
    description:
      - Shared secret for HMAC-SHA256 payload signature verification.
      - When set, every incoming request must include a valid signature
        in the header specified by I(hmac_header).
    type: str
  hmac_header:
    description: HTTP header that carries the HMAC-SHA256 hex digest.
    type: str
    default: "X-Signature-256"
  certfile:
    description:
      - Path to a PEM-encoded TLS certificate file.
      - Both I(certfile) and I(keyfile) must be provided to enable TLS.
    type: str
  keyfile:
    description:
      - Path to the PEM-encoded TLS private key for I(certfile).
    type: str
  source_filter:
    description:
      - Restrict accepted source types.
      - C(automation) accepts only VCF Automation payloads.
      - C(operations) accepts only VCF Operations payloads.
      - Omit to accept both.
    type: str
    choices: ["automation", "operations"]
"""

# ---------------------------------------------------------------------------
# Payload detection and normalisation
# ---------------------------------------------------------------------------

SOURCE_AUTOMATION = "vcf_automation"
SOURCE_OPERATIONS = "vcf_operations"


def _detect_source(payload: Dict[str, Any]) -> Optional[str]:
    """Heuristically determine whether a payload originates from
    VCF Automation or VCF Operations based on characteristic keys."""

    # VCF Automation markers
    automation_keys = {"eventId", "eventType", "resourceName", "resourceType"}
    # VCF Operations markers
    operations_keys = {"alertId", "alertName", "objectName", "objectType"}

    auto_score = len(automation_keys & payload.keys())
    ops_score = len(operations_keys & payload.keys())

    if auto_score > ops_score and auto_score >= 2:
        return SOURCE_AUTOMATION
    if ops_score > auto_score and ops_score >= 2:
        return SOURCE_OPERATIONS
    if auto_score >= 2:
        return SOURCE_AUTOMATION
    if ops_score >= 2:
        return SOURCE_OPERATIONS

    return None


def _ts_to_iso(value: Any) -> str:
    """Best-effort conversion of a timestamp value to ISO-8601 string."""
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, (int, float)):
        # Assume epoch milliseconds if the number is large enough.
        if value > 1e12:
            value = value / 1000.0
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    return str(value)


def _normalise_automation(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a VCF Automation webhook payload."""
    properties = payload.get("properties", {})
    custom_props = payload.get("customProperties", {})

    message_parts = []
    event_type = payload.get("eventType", "unknown")
    resource_name = payload.get("resourceName", "")
    if event_type:
        message_parts.append(event_type)
    if resource_name:
        message_parts.append(f"on {resource_name}")

    return {
        "source_type": SOURCE_AUTOMATION,
        "event_type": event_type,
        "timestamp": _ts_to_iso(payload.get("timestamp")),
        "severity": properties.get("severity", custom_props.get("severity", "info")),
        "object_name": resource_name,
        "object_type": payload.get("resourceType", ""),
        "message": " ".join(message_parts) if message_parts else "",
        "alert_id": payload.get("eventId", ""),
        "status": payload.get("status", ""),
        "raw_payload": payload,
    }


def _normalise_operations(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a VCF Operations webhook payload."""
    symptoms = payload.get("symptoms", [])
    symptom_messages = [
        s.get("message", s.get("name", "")) for s in symptoms if isinstance(s, dict)
    ]
    message = payload.get("alertName", "")
    if symptom_messages:
        message = f"{message}: {'; '.join(symptom_messages)}"

    return {
        "source_type": SOURCE_OPERATIONS,
        "event_type": payload.get("alertName", payload.get("alertType", "unknown")),
        "timestamp": _ts_to_iso(
            payload.get("updateDate", payload.get("startDate"))
        ),
        "severity": payload.get("severity", "unknown"),
        "object_name": payload.get("objectName", ""),
        "object_type": payload.get("objectType", ""),
        "message": message,
        "alert_id": payload.get("alertId", ""),
        "status": payload.get("status", ""),
        "raw_payload": payload,
    }


def normalise_event(
    payload: Dict[str, Any], force_source: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Detect the source and return a normalised event dict, or *None*
    if the source could not be determined."""
    source = force_source or _detect_source(payload)
    if source == SOURCE_AUTOMATION:
        return _normalise_automation(payload)
    if source == SOURCE_OPERATIONS:
        return _normalise_operations(payload)
    return None


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------


def _verify_token(request: web.Request, expected_token: str) -> bool:
    """Return True if the request carries a valid Bearer token."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return False
    return hmac.compare_digest(auth_header[7:], expected_token)


def _verify_hmac(
    body: bytes, secret: str, request: web.Request, header_name: str
) -> bool:
    """Return True if the HMAC-SHA256 signature in *header_name* is valid."""
    signature = request.headers.get(header_name, "")
    if not signature:
        return False
    # Strip optional "sha256=" prefix.
    if signature.lower().startswith("sha256="):
        signature = signature[7:]
    expected = hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature.lower())


def _authenticate(
    request: web.Request,
    body: bytes,
    token: Optional[str],
    hmac_secret: Optional[str],
    hmac_header: str,
) -> Optional[web.Response]:
    """Run configured authentication checks.  Returns an error response
    if authentication fails, otherwise *None*."""
    if token and not _verify_token(request, token):
        LOGGER.warning(
            "Rejected request from %s: invalid bearer token",
            request.remote,
        )
        return web.json_response(
            {"error": "Unauthorized"}, status=401
        )
    if hmac_secret and not _verify_hmac(body, hmac_secret, request, hmac_header):
        LOGGER.warning(
            "Rejected request from %s: invalid HMAC signature",
            request.remote,
        )
        return web.json_response(
            {"error": "Forbidden: signature mismatch"}, status=403
        )
    return None


# ---------------------------------------------------------------------------
# Request handlers
# ---------------------------------------------------------------------------


async def _handle_webhook(
    request: web.Request,
    queue: asyncio.Queue,
    token: Optional[str],
    hmac_secret: Optional[str],
    hmac_header: str,
    source_filter: Optional[str],
    force_source: Optional[str] = None,
) -> web.Response:
    """Core handler shared by all POST endpoints."""
    body = await request.read()

    # --- Authentication ---
    auth_err = _authenticate(request, body, token, hmac_secret, hmac_header)
    if auth_err is not None:
        return auth_err

    # --- Parse JSON ---
    try:
        payload: Dict[str, Any] = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        LOGGER.error(
            "Malformed JSON from %s: %s", request.remote, exc
        )
        return web.json_response(
            {"error": "Bad Request: invalid JSON"}, status=400
        )

    if not isinstance(payload, dict):
        LOGGER.error(
            "Expected JSON object from %s, got %s",
            request.remote,
            type(payload).__name__,
        )
        return web.json_response(
            {"error": "Bad Request: expected JSON object"}, status=400
        )

    # --- Normalise ---
    event = normalise_event(payload, force_source=force_source)
    if event is None:
        LOGGER.warning(
            "Unable to detect source type from %s payload keys: %s",
            request.remote,
            list(payload.keys()),
        )
        return web.json_response(
            {"error": "Unrecognised payload structure"}, status=422
        )

    # --- Source filter ---
    if source_filter:
        allowed_source = (
            SOURCE_AUTOMATION if source_filter == "automation" else SOURCE_OPERATIONS
        )
        if event["source_type"] != allowed_source:
            LOGGER.info(
                "Dropped %s event due to source_filter=%s",
                event["source_type"],
                source_filter,
            )
            return web.json_response(
                {"status": "filtered", "source_type": event["source_type"]},
                status=200,
            )

    # --- Enqueue ---
    await queue.put(event)
    LOGGER.info(
        "Enqueued %s event: type=%s object=%s",
        event["source_type"],
        event["event_type"],
        event["object_name"],
    )
    return web.json_response({"status": "accepted"}, status=202)


def _build_app(
    queue: asyncio.Queue,
    token: Optional[str],
    hmac_secret: Optional[str],
    hmac_header: str,
    source_filter: Optional[str],
) -> web.Application:
    """Construct the aiohttp application with all routes."""

    app = web.Application()

    # --- Health check ---
    async def health(_request: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    # --- Generic endpoint (auto-detect) ---
    async def post_events(request: web.Request) -> web.Response:
        return await _handle_webhook(
            request, queue, token, hmac_secret, hmac_header, source_filter
        )

    # --- Dedicated VCF Automation endpoint ---
    async def post_automation(request: web.Request) -> web.Response:
        return await _handle_webhook(
            request,
            queue,
            token,
            hmac_secret,
            hmac_header,
            source_filter,
            force_source=SOURCE_AUTOMATION,
        )

    # --- Dedicated VCF Operations endpoint ---
    async def post_operations(request: web.Request) -> web.Response:
        return await _handle_webhook(
            request,
            queue,
            token,
            hmac_secret,
            hmac_header,
            source_filter,
            force_source=SOURCE_OPERATIONS,
        )

    app.router.add_get("/health", health)
    app.router.add_post("/events", post_events)
    app.router.add_post("/vcf/automation", post_automation)
    app.router.add_post("/vcf/operations", post_operations)

    return app


# ---------------------------------------------------------------------------
# EDA entry point
# ---------------------------------------------------------------------------


async def main(queue: asyncio.Queue, args: Dict[str, Any]) -> None:
    """EDA event source entry point.

    Parameters
    ----------
    queue : asyncio.Queue
        The EDA event queue to place normalised events onto.
    args : dict
        Plugin arguments supplied from the rulebook source definition.
    """
    host: str = str(args.get("host", "0.0.0.0"))
    port: int = int(args.get("port", 5000))
    token: Optional[str] = args.get("token")
    hmac_secret: Optional[str] = args.get("hmac_secret")
    hmac_header: str = str(args.get("hmac_header", "X-Signature-256"))
    certfile: Optional[str] = args.get("certfile")
    keyfile: Optional[str] = args.get("keyfile")
    source_filter: Optional[str] = args.get("source_filter")

    if source_filter and source_filter not in ("automation", "operations"):
        LOGGER.warning(
            "Invalid source_filter '%s'; accepting all sources", source_filter
        )
        source_filter = None

    app = _build_app(queue, token, hmac_secret, hmac_header, source_filter)

    # --- Optional TLS ---
    ssl_context: Optional[ssl.SSLContext] = None
    if certfile and keyfile:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile, keyfile)
        LOGGER.info("TLS enabled: cert=%s key=%s", certfile, keyfile)

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, host, port, ssl_context=ssl_context)
    proto = "https" if ssl_context else "http"
    LOGGER.info("VCF webhook listener starting on %s://%s:%d", proto, host, port)

    try:
        await site.start()
        # Block forever (EDA will cancel us on shutdown).
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        LOGGER.info("Shutting down VCF webhook listener")
    finally:
        await runner.cleanup()
        LOGGER.info("VCF webhook listener stopped")


# ---------------------------------------------------------------------------
# Standalone testing helper
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    """Allow running the plugin outside EDA for local testing.

    .. code-block:: bash

        python vcf_webhook.py              # defaults
        python vcf_webhook.py --port 8080  # custom port
    """
    import argparse

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(description="VCF webhook listener (standalone)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--token", default=None)
    parser.add_argument("--hmac-secret", default=None)
    parser.add_argument("--hmac-header", default="X-Signature-256")
    parser.add_argument("--certfile", default=None)
    parser.add_argument("--keyfile", default=None)
    parser.add_argument("--source-filter", default=None)
    cli_args = parser.parse_args()

    _queue: asyncio.Queue = asyncio.Queue()

    async def _printer() -> None:
        while True:
            event = await _queue.get()
            print(json.dumps(event, indent=2, default=str))

    async def _run() -> None:
        asyncio.create_task(_printer())
        await main(
            _queue,
            {
                "host": cli_args.host,
                "port": cli_args.port,
                "token": cli_args.token,
                "hmac_secret": cli_args.hmac_secret,
                "hmac_header": cli_args.hmac_header,
                "certfile": cli_args.certfile,
                "keyfile": cli_args.keyfile,
                "source_filter": cli_args.source_filter,
            },
        )

    asyncio.run(_run())
