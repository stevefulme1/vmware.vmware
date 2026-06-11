"""
vcenter_events.py - EDA event source plugin for VMware vCenter events.

Polls the vCenter EventManager API via pyVmomi and emits normalized events
to Ansible EDA rulebooks for real-time infrastructure automation.

Usage in a rulebook::

    sources:
      - vmware.vmware.vcenter_events:
          vcenter_hostname: vcenter.example.com
          vcenter_username: administrator@vsphere.local
          vcenter_password: "{{ vcenter_password }}"
          validate_certs: false
          poll_interval: 10
          event_types:
            - VmPoweredOnEvent
            - VmPoweredOffEvent
          max_events: 100
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import ssl
import traceback
from datetime import datetime, timezone
from typing import Any

try:
    from pyVim.connect import Disconnect, SmartConnect
    from pyVmomi import vim, vmodl

    HAS_PYVMOMI = True
except ImportError:
    HAS_PYVMOMI = False


DOCUMENTATION = r"""
---
module: vcenter_events
short_description: Poll VMware vCenter EventManager for infrastructure events
description:
  - This EDA event source plugin connects to a VMware vCenter Server and
    continuously polls the EventManager for new events.
  - Events are normalized and emitted to the EDA rulebook engine, enabling
    automated responses to VM lifecycle changes, host state transitions,
    alarm triggers, and other vSphere operations.
  - Supports filtering by event type, datacenter, and configurable poll
    intervals for fine-grained event selection.
version_added: "1.0.0"
author:
  - Red Hat Ansible Automation Platform Team
options:
  vcenter_hostname:
    description:
      - The hostname or IP address of the vCenter Server to connect to.
    type: str
    required: true
  vcenter_username:
    description:
      - The username for authenticating to the vCenter Server.
    type: str
    required: true
  vcenter_password:
    description:
      - The password for authenticating to the vCenter Server.
    type: str
    required: true
    secret: true
  validate_certs:
    description:
      - Whether to validate SSL certificates when connecting to vCenter.
      - Set to C(false) for self-signed certificates.
    type: bool
    default: true
  poll_interval:
    description:
      - The interval in seconds between event poll cycles.
    type: int
    default: 10
  event_types:
    description:
      - A list of vCenter event type names to include.
      - When specified, only events matching these types are emitted.
      - Mutually exclusive behavior with O(exclude_event_types); if both
        are provided, O(event_types) takes precedence.
    type: list
    elements: str
    required: false
  exclude_event_types:
    description:
      - A list of vCenter event type names to exclude.
      - Events matching these types are silently dropped.
    type: list
    elements: str
    required: false
  datacenter:
    description:
      - Restrict event collection to a specific datacenter by name.
    type: str
    required: false
  max_events:
    description:
      - Maximum number of events to retrieve per poll cycle.
      - Increase for busy environments; decrease to limit processing load.
    type: int
    default: 100
"""

EXAMPLES = r"""
- name: Monitor all VM power events
  hosts: all
  sources:
    - vmware.vmware.vcenter_events:
        vcenter_hostname: "{{ vcenter_host }}"
        vcenter_username: "{{ vcenter_user }}"
        vcenter_password: "{{ vcenter_pass }}"
        validate_certs: false
        poll_interval: 10
        event_types:
          - VmPoweredOnEvent
          - VmPoweredOffEvent
          - VmSuspendedEvent
  rules:
    - name: React to VM power-on
      condition: event.vcenter_events.event_type == "VmPoweredOnEvent"
      action:
        run_playbook:
          name: handle_vm_poweron.yml

- name: Monitor host maintenance events
  hosts: all
  sources:
    - vmware.vmware.vcenter_events:
        vcenter_hostname: "{{ vcenter_host }}"
        vcenter_username: "{{ vcenter_user }}"
        vcenter_password: "{{ vcenter_pass }}"
        validate_certs: false
        event_types:
          - EnteringMaintenanceModeEvent
          - ExitMaintenanceModeEvent
        max_events: 50
  rules:
    - name: Alert on maintenance mode entry
      condition: event.vcenter_events.event_type == "EnteringMaintenanceModeEvent"
      action:
        run_playbook:
          name: maintenance_alert.yml
"""

logger = logging.getLogger("vcenter_events")

# ---------------------------------------------------------------------------
# Supported vCenter event types
# ---------------------------------------------------------------------------

SUPPORTED_EVENT_TYPES: list[str] = [
    # VM lifecycle
    "VmPoweredOnEvent",
    "VmPoweredOffEvent",
    "VmSuspendedEvent",
    "VmCreatedEvent",
    "VmRemovedEvent",
    "VmClonedEvent",
    "VmMigratedEvent",
    "VmRelocatedEvent",
    "VmReconfiguredEvent",
    "VmRenamedEvent",
    "VmBeingDeployedEvent",
    # Snapshots
    "VmSnapshotCreatedEvent",
    "VmSnapshotDeletedEvent",
    "VmSnapshotRevertedEvent",
    # Host
    "HostConnectedEvent",
    "HostDisconnectedEvent",
    "EnteringMaintenanceModeEvent",
    "ExitMaintenanceModeEvent",
    "HostAddedEvent",
    "HostRemovedEvent",
    # Cluster
    "DrsVmMigratedEvent",
    "ClusterCreatedEvent",
    "ClusterDestroyedEvent",
    # Storage
    "DatastoreDiscoveredEvent",
    "DatastoreRemovedOnHostEvent",
    # Alarm
    "AlarmCreatedEvent",
    "AlarmRemovedEvent",
    "AlarmStatusChangedEvent",
    # Task
    "TaskEvent",
    # Template
    "VmBeingDeployedFromTemplateEvent",
]

# Map event type names to severity levels for normalized output.
_SEVERITY_MAP: dict[str, str] = {
    "VmPoweredOnEvent": "info",
    "VmPoweredOffEvent": "warning",
    "VmSuspendedEvent": "warning",
    "VmCreatedEvent": "info",
    "VmRemovedEvent": "warning",
    "VmClonedEvent": "info",
    "VmMigratedEvent": "info",
    "VmRelocatedEvent": "info",
    "VmReconfiguredEvent": "info",
    "VmRenamedEvent": "info",
    "VmBeingDeployedEvent": "info",
    "VmSnapshotCreatedEvent": "info",
    "VmSnapshotDeletedEvent": "info",
    "VmSnapshotRevertedEvent": "warning",
    "HostConnectedEvent": "info",
    "HostDisconnectedEvent": "critical",
    "EnteringMaintenanceModeEvent": "warning",
    "ExitMaintenanceModeEvent": "info",
    "HostAddedEvent": "info",
    "HostRemovedEvent": "warning",
    "DrsVmMigratedEvent": "info",
    "ClusterCreatedEvent": "info",
    "ClusterDestroyedEvent": "warning",
    "DatastoreDiscoveredEvent": "info",
    "DatastoreRemovedOnHostEvent": "warning",
    "AlarmCreatedEvent": "info",
    "AlarmRemovedEvent": "info",
    "AlarmStatusChangedEvent": "warning",
    "TaskEvent": "info",
    "VmBeingDeployedFromTemplateEvent": "info",
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _get_ssl_context(validate_certs: bool) -> ssl.SSLContext:
    """Return an SSL context suitable for pyVmomi connections."""
    if validate_certs:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _connect_vcenter(
    hostname: str,
    username: str,
    password: str,
    validate_certs: bool,
) -> vim.ServiceInstance:
    """
    Establish a connection to vCenter and return the ServiceInstance.

    Raises
    ------
    ConnectionError
        If the connection cannot be established.
    """
    logger.info("Connecting to vCenter at %s as %s", hostname, username)
    ssl_context = _get_ssl_context(validate_certs)

    try:
        si = SmartConnect(
            host=hostname,
            user=username,
            pwd=password,
            sslContext=ssl_context,
        )
        atexit.register(Disconnect, si)
        logger.info("Successfully connected to vCenter %s", hostname)
        return si
    except vim.fault.InvalidLogin as exc:
        raise ConnectionError(
            f"Invalid credentials for vCenter {hostname}: {exc.msg}"
        ) from exc
    except Exception as exc:
        raise ConnectionError(
            f"Failed to connect to vCenter {hostname}: {exc}"
        ) from exc


def _build_event_filter(
    si: vim.ServiceInstance,
    event_types: list[str] | None,
    datacenter_name: str | None,
    begin_time: datetime,
    max_events: int,
) -> vim.event.EventFilterSpec:
    """Build an EventFilterSpec for the EventManager query."""
    filter_spec = vim.event.EventFilterSpec()

    # Time filter - only events after begin_time
    time_spec = vim.event.EventFilterSpec.ByTime()
    time_spec.beginTime = begin_time
    filter_spec.time = time_spec

    # Max count
    filter_spec.maxCount = max_events

    # Event type filter
    if event_types:
        filter_spec.eventTypeId = []
        for etype in event_types:
            event_type_id = vim.event.EventFilterSpec.EventTypeId()
            event_type_id.eventTypeId = etype
            filter_spec.eventTypeId.append(event_type_id)

    # Datacenter filter
    if datacenter_name:
        content = si.RetrieveContent()
        container = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.Datacenter], True
        )
        try:
            for dc in container.view:
                if dc.name == datacenter_name:
                    entity_spec = vim.event.EventFilterSpec.ByEntity()
                    entity_spec.entity = dc
                    entity_spec.recursion = (
                        vim.event.EventFilterSpec.RecursionOption.all
                    )
                    filter_spec.entity = entity_spec
                    logger.info(
                        "Filtering events to datacenter: %s", datacenter_name
                    )
                    break
            else:
                logger.warning(
                    "Datacenter '%s' not found; collecting events from all "
                    "datacenters",
                    datacenter_name,
                )
        finally:
            container.Destroy()

    return filter_spec


def _normalize_event(event: Any) -> dict[str, Any]:
    """
    Convert a raw pyVmomi event object into a normalized dictionary.

    Returns a flat dict with well-known keys suitable for rulebook conditions.
    """
    event_type = type(event).__name__

    # Extract VM information when available
    vm_name = ""
    vm_uuid = ""
    if hasattr(event, "vm") and event.vm:
        vm_ref = event.vm
        vm_name = getattr(vm_ref, "name", "") or ""
        # vm.vm is the ManagedObjectReference
        if hasattr(vm_ref, "vm") and vm_ref.vm:
            try:
                vm_uuid = getattr(vm_ref.vm, "config", None)
                if vm_uuid and hasattr(vm_uuid, "uuid"):
                    vm_uuid = vm_uuid.uuid
                else:
                    vm_uuid = ""
            except Exception:
                vm_uuid = ""

    # Extract host information
    host_name = ""
    if hasattr(event, "host") and event.host:
        host_name = getattr(event.host, "name", "") or ""

    # Extract datacenter information
    dc_name = ""
    if hasattr(event, "datacenter") and event.datacenter:
        dc_name = getattr(event.datacenter, "name", "") or ""

    # Extract user
    user = getattr(event, "userName", "") or ""

    # Extract message
    message = getattr(event, "fullFormattedMessage", "") or ""

    # Timestamp handling
    timestamp = getattr(event, "createdTime", None)
    if timestamp:
        if isinstance(timestamp, datetime):
            timestamp_str = timestamp.isoformat()
        else:
            timestamp_str = str(timestamp)
    else:
        timestamp_str = datetime.now(timezone.utc).isoformat()

    # Build the raw event dict for full_event
    full_event: dict[str, Any] = {
        "key": getattr(event, "key", None),
        "chainId": getattr(event, "chainId", None),
        "createdTime": timestamp_str,
        "userName": user,
        "fullFormattedMessage": message,
        "eventType": event_type,
    }

    # Add change tag if present (vSphere 6.5+)
    if hasattr(event, "changeTag"):
        full_event["changeTag"] = getattr(event, "changeTag", "")

    severity = _SEVERITY_MAP.get(event_type, "info")

    return {
        "event_type": event_type,
        "timestamp": timestamp_str,
        "datacenter": dc_name,
        "host": host_name,
        "vm_name": vm_name,
        "vm_uuid": vm_uuid,
        "user": user,
        "message": message,
        "severity": severity,
        "full_event": full_event,
    }


def _validate_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Validate and apply defaults to plugin arguments.

    Returns the sanitized configuration dict.

    Raises
    ------
    ValueError
        If required arguments are missing.
    """
    required = ["vcenter_hostname", "vcenter_username", "vcenter_password"]
    missing = [k for k in required if not args.get(k)]
    if missing:
        raise ValueError(
            f"Missing required arguments: {', '.join(missing)}"
        )

    config: dict[str, Any] = {
        "vcenter_hostname": args["vcenter_hostname"],
        "vcenter_username": args["vcenter_username"],
        "vcenter_password": args["vcenter_password"],
        "validate_certs": args.get("validate_certs", True),
        "poll_interval": int(args.get("poll_interval", 10)),
        "event_types": args.get("event_types"),
        "exclude_event_types": args.get("exclude_event_types"),
        "datacenter": args.get("datacenter"),
        "max_events": int(args.get("max_events", 100)),
    }

    if config["poll_interval"] < 1:
        raise ValueError("poll_interval must be >= 1 second")

    if config["max_events"] < 1:
        raise ValueError("max_events must be >= 1")

    # Validate event type names if provided
    for list_key in ("event_types", "exclude_event_types"):
        type_list = config.get(list_key)
        if type_list:
            unknown = set(type_list) - set(SUPPORTED_EVENT_TYPES)
            if unknown:
                logger.warning(
                    "Unrecognized event types in %s (will still be "
                    "requested): %s",
                    list_key,
                    ", ".join(sorted(unknown)),
                )

    return config


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def main(queue: asyncio.Queue, args: dict[str, Any]) -> None:
    """
    EDA event source entry point.

    Connects to vCenter, polls EventManager on a configurable interval,
    normalizes events, and puts them onto the EDA queue.

    Parameters
    ----------
    queue : asyncio.Queue
        The EDA event queue to emit events into.
    args : dict
        Plugin arguments from the rulebook source configuration.
    """
    if not HAS_PYVMOMI:
        raise ImportError(
            "pyVmomi is required for the vcenter_events event source plugin. "
            "Install it with: pip install pyvmomi"
        )

    config = _validate_args(args)
    hostname = config["vcenter_hostname"]
    poll_interval = config["poll_interval"]
    event_types_filter = config["event_types"]
    exclude_types = set(config["exclude_event_types"] or [])
    max_events = config["max_events"]
    datacenter_name = config["datacenter"]

    logger.info(
        "vcenter_events plugin starting — host=%s poll_interval=%ds "
        "max_events=%d",
        hostname,
        poll_interval,
        max_events,
    )
    if event_types_filter:
        logger.info("Including event types: %s", ", ".join(event_types_filter))
    if exclude_types:
        logger.info("Excluding event types: %s", ", ".join(sorted(exclude_types)))
    if datacenter_name:
        logger.info("Filtering to datacenter: %s", datacenter_name)

    # Track connection state for reconnect logic
    si: vim.ServiceInstance | None = None
    last_event_time = datetime.now(timezone.utc)
    reconnect_delay = 5  # seconds, doubles on repeated failures up to 60s
    max_reconnect_delay = 60

    while True:
        # --- Connection management ---
        if si is None:
            try:
                si = await asyncio.get_event_loop().run_in_executor(
                    None,
                    _connect_vcenter,
                    hostname,
                    config["vcenter_username"],
                    config["vcenter_password"],
                    config["validate_certs"],
                )
                reconnect_delay = 5  # reset on success
            except ConnectionError as exc:
                logger.error("Connection failed: %s", exc)
                logger.info(
                    "Retrying connection in %d seconds", reconnect_delay
                )
                await asyncio.sleep(reconnect_delay)
                reconnect_delay = min(
                    reconnect_delay * 2, max_reconnect_delay
                )
                continue

        # --- Poll for events ---
        try:
            content = si.RetrieveContent()
            event_manager = content.eventManager

            filter_spec = _build_event_filter(
                si=si,
                event_types=event_types_filter,
                datacenter_name=datacenter_name,
                begin_time=last_event_time,
                max_events=max_events,
            )

            # Run the blocking vSphere API call in a thread executor
            event_collector = await asyncio.get_event_loop().run_in_executor(
                None,
                event_manager.CreateCollectorForEvents,
                filter_spec,
            )

            try:
                # Read the latest page of events (newest first)
                events = await asyncio.get_event_loop().run_in_executor(
                    None,
                    event_collector.ReadNextEvents,
                    max_events,
                )

                if events:
                    logger.debug(
                        "Retrieved %d events from vCenter", len(events)
                    )

                emitted = 0
                for event in events or []:
                    event_type_name = type(event).__name__

                    # Apply exclude filter
                    if exclude_types and event_type_name in exclude_types:
                        logger.debug(
                            "Excluding event type: %s", event_type_name
                        )
                        continue

                    normalized = _normalize_event(event)

                    # Update the high-water mark
                    event_created = getattr(event, "createdTime", None)
                    if event_created and isinstance(event_created, datetime):
                        if event_created > last_event_time:
                            last_event_time = event_created

                    await queue.put({"vcenter_events": normalized})
                    emitted += 1

                if emitted:
                    logger.info(
                        "Emitted %d events (latest timestamp: %s)",
                        emitted,
                        last_event_time.isoformat(),
                    )

            finally:
                # Always destroy the collector to free server resources
                try:
                    await asyncio.get_event_loop().run_in_executor(
                        None, event_collector.DestroyCollector
                    )
                except Exception:
                    logger.debug(
                        "Failed to destroy event collector (may already be "
                        "gone)"
                    )

        except vmodl.fault.NotAuthenticated:
            logger.warning(
                "Session expired or not authenticated; reconnecting"
            )
            si = None
            continue

        except (ConnectionError, OSError, vmodl.fault.HostCommunication) as exc:
            logger.warning("Connection lost to vCenter: %s", exc)
            si = None
            continue

        except vmodl.fault.ManagedObjectNotFound:
            logger.warning(
                "Managed object reference is stale; reconnecting"
            )
            si = None
            continue

        except asyncio.CancelledError:
            logger.info("vcenter_events plugin received cancellation signal")
            raise

        except Exception:
            logger.error(
                "Unexpected error during event poll:\n%s",
                traceback.format_exc(),
            )
            # On unexpected errors, invalidate the connection and retry
            si = None
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, max_reconnect_delay)
            continue

        # --- Wait for next poll cycle ---
        logger.debug("Sleeping %d seconds until next poll", poll_interval)
        await asyncio.sleep(poll_interval)


if __name__ == "__main__":
    """Allow standalone testing outside of EDA."""

    class _MockQueue:
        """Simple mock queue that prints events to stdout."""

        async def put(self, event: dict) -> None:
            import json

            print(json.dumps(event, indent=2, default=str))

    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Test vcenter_events EDA plugin standalone"
    )
    parser.add_argument("--hostname", required=True, help="vCenter hostname")
    parser.add_argument("--username", required=True, help="vCenter username")
    parser.add_argument("--password", required=True, help="vCenter password")
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL verification",
    )
    parser.add_argument(
        "--poll-interval", type=int, default=10, help="Poll interval seconds"
    )
    parsed = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    test_args = {
        "vcenter_hostname": parsed.hostname,
        "vcenter_username": parsed.username,
        "vcenter_password": parsed.password,
        "validate_certs": not parsed.no_verify_ssl,
        "poll_interval": parsed.poll_interval,
    }

    asyncio.run(main(_MockQueue(), test_args))
