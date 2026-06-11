"""
vcf_normalize.py - Event filter plugin for normalizing VCF event sources.

Normalizes events from vcenter_events, vcf_webhook, vcf_kafka, and vcf_mcp
into a unified schema for consistent rule evaluation.
"""

DOCUMENTATION = r"""
---
module: vcf_normalize
short_description: Normalize VCF events into a unified schema
description:
  - This event filter plugin normalizes events from all four VCF event
    sources (vcenter_events, vcf_webhook, vcf_kafka, vcf_mcp) into a
    unified schema.
  - It auto-detects the event source based on event keys and maps
    source-specific fields to a common structure.
  - The unified output allows rulebook conditions to be written
    consistently regardless of the originating event source.
version_added: "1.0.0"
author:
  - "VMware Ansible Team"
options: {}
notes:
  - The filter preserves all original event data in the metadata field.
  - Unknown event sources pass through with source set to "unknown".
unified_schema:
  source:
    type: str
    description: >
      Normalized source identifier (vcenter, vcf_automation,
      vcf_operations, vcf_mcp, kafka).
  event_type:
    type: str
    description: Normalized event name.
  category:
    type: str
    description: >
      Event category (vm_lifecycle, host_lifecycle, storage, network,
      security, compliance, alert, task).
  severity:
    type: str
    description: Severity level (critical, warning, info, unknown).
  timestamp:
    type: str
    description: ISO 8601 timestamp.
  object_name:
    type: str
    description: Name of the affected object.
  object_type:
    type: str
    description: >
      Type of the affected object (vm, host, cluster, datastore,
      network, alarm, etc.).
  datacenter:
    type: str
    description: Datacenter name if available.
  message:
    type: str
    description: Human-readable event summary.
  metadata:
    type: dict
    description: Source-specific extra fields.
"""

from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Category mappings
# ---------------------------------------------------------------------------

_VCENTER_EVENT_CATEGORY = {
    # VM lifecycle
    "VmPoweredOnEvent": "vm_lifecycle",
    "VmPoweredOffEvent": "vm_lifecycle",
    "VmSuspendedEvent": "vm_lifecycle",
    "VmCreatedEvent": "vm_lifecycle",
    "VmRemovedEvent": "vm_lifecycle",
    "VmClonedEvent": "vm_lifecycle",
    "VmMigratedEvent": "vm_lifecycle",
    "VmRelocatedEvent": "vm_lifecycle",
    "VmReconfiguredEvent": "vm_lifecycle",
    "DrsVmMigratedEvent": "vm_lifecycle",
    "VmGuestShutdownEvent": "vm_lifecycle",
    "VmResettingEvent": "vm_lifecycle",
    "VmStartingEvent": "vm_lifecycle",
    "VmStoppingEvent": "vm_lifecycle",
    # Snapshots
    "TaskEvent_CreateSnapshot_Task": "vm_lifecycle",
    "TaskEvent_RemoveSnapshot_Task": "vm_lifecycle",
    "TaskEvent_RevertToCurrentSnapshot_Task": "vm_lifecycle",
    # Host lifecycle
    "HostConnectedEvent": "host_lifecycle",
    "HostDisconnectedEvent": "host_lifecycle",
    "HostConnectionLostEvent": "host_lifecycle",
    "EnteredMaintenanceModeEvent": "host_lifecycle",
    "ExitMaintenanceModeEvent": "host_lifecycle",
    "HostAddedEvent": "host_lifecycle",
    "HostRemovedEvent": "host_lifecycle",
    # Storage
    "DatastoreCapacityIncreasedEvent": "storage",
    "DatastoreDestroyedEvent": "storage",
    "DatastoreDiscoveredEvent": "storage",
    "VmDiskFailedEvent": "storage",
    # Network
    "DvsPortConnectedEvent": "network",
    "DvsPortDisconnectedEvent": "network",
    "VmNetworkFailedEvent": "network",
    # Security
    "UserLoginSessionEvent": "security",
    "UserLogoutSessionEvent": "security",
    "BadUsernameSessionEvent": "security",
    "AccountCreatedEvent": "security",
    # Alarms
    "AlarmStatusChangedEvent": "alert",
    "AlarmCreatedEvent": "alert",
    "AlarmRemovedEvent": "alert",
    "AlarmReconfiguredEvent": "alert",
    # Tasks
    "TaskEvent": "task",
}

_VCENTER_SEVERITY_OVERRIDES = {
    "HostDisconnectedEvent": "critical",
    "HostConnectionLostEvent": "critical",
    "VmDiskFailedEvent": "critical",
    "VmNetworkFailedEvent": "warning",
    "BadUsernameSessionEvent": "warning",
}

_VCF_WEBHOOK_CATEGORY = {
    "alert": "alert",
    "alarm": "alert",
    "compliance": "compliance",
    "deployment": "task",
    "capacity": "alert",
    "network": "network",
    "security": "security",
    "storage": "storage",
}

_KAFKA_CATEGORY_MAP = {
    "vm": "vm_lifecycle",
    "host": "host_lifecycle",
    "storage": "storage",
    "network": "network",
    "security": "security",
    "compliance": "compliance",
    "alert": "alert",
    "task": "task",
}


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_ALIASES = {
    "critical": "critical",
    "crit": "critical",
    "error": "critical",
    "err": "critical",
    "high": "critical",
    "warning": "warning",
    "warn": "warning",
    "medium": "warning",
    "info": "info",
    "informational": "info",
    "low": "info",
    "normal": "info",
    "ok": "info",
    "clear": "info",
}


def _normalize_severity(raw: str) -> str:
    """Map a raw severity string to one of: critical, warning, info, unknown."""
    if not raw:
        return "unknown"
    return _SEVERITY_ALIASES.get(raw.lower().strip(), "unknown")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Source-specific normalizers
# ---------------------------------------------------------------------------

def _normalize_vcenter(event: dict) -> dict:
    """Normalize a vCenter event."""
    event_type = event.get("EventType") or event.get("event_type") or event.get("_event_type", "UnknownEvent")
    category = _VCENTER_EVENT_CATEGORY.get(event_type, "task")
    severity = _VCENTER_SEVERITY_OVERRIDES.get(event_type, "info")

    # Extract object info – vCenter events use nested dicts
    vm = event.get("Vm") or event.get("vm") or {}
    host = event.get("Host") or event.get("host") or {}
    ds = event.get("Ds") or event.get("ds") or {}

    if isinstance(vm, dict) and vm.get("Name", vm.get("name")):
        obj_name = vm.get("Name") or vm.get("name", "")
        obj_type = "vm"
    elif isinstance(host, dict) and host.get("Name", host.get("name")):
        obj_name = host.get("Name") or host.get("name", "")
        obj_type = "host"
    elif isinstance(ds, dict) and ds.get("Name", ds.get("name")):
        obj_name = ds.get("Name") or ds.get("name", "")
        obj_type = "datastore"
    else:
        obj_name = event.get("objectName", event.get("object_name", ""))
        obj_type = event.get("objectType", event.get("object_type", "unknown"))

    dc = event.get("Datacenter") or event.get("datacenter") or {}
    dc_name = dc.get("Name") or dc.get("name", "") if isinstance(dc, dict) else str(dc)

    message = event.get("FullFormattedMessage") or event.get("fullFormattedMessage") or event.get("message", f"{event_type} on {obj_name}")

    timestamp = event.get("CreatedTime") or event.get("createdTime") or event.get("timestamp", _now_iso())

    metadata = {k: v for k, v in event.items() if k not in (
        "EventType", "event_type", "_event_type", "Vm", "vm", "Host", "host",
        "Ds", "ds", "Datacenter", "datacenter", "FullFormattedMessage",
        "fullFormattedMessage", "message", "CreatedTime", "createdTime",
        "timestamp",
    )}

    return {
        "source": "vcenter",
        "event_type": event_type,
        "category": category,
        "severity": severity,
        "timestamp": str(timestamp),
        "object_name": str(obj_name),
        "object_type": obj_type,
        "datacenter": str(dc_name),
        "message": str(message),
        "metadata": metadata,
    }


def _normalize_vcf_webhook(event: dict) -> dict:
    """Normalize a VCF webhook event (Aria Operations / Automation)."""
    alert_type = (event.get("alertType") or event.get("type") or "").lower()
    category = _VCF_WEBHOOK_CATEGORY.get(alert_type, "alert")

    # Detect sub-source
    webhook_source = event.get("source", "")
    if "automation" in webhook_source.lower() or "vra" in webhook_source.lower():
        source = "vcf_automation"
    elif "operations" in webhook_source.lower() or "vrops" in webhook_source.lower():
        source = "vcf_operations"
    else:
        source = "vcf_operations"

    severity = _normalize_severity(
        event.get("severity") or event.get("criticality") or event.get("status", "")
    )

    event_type = event.get("alertName") or event.get("eventName") or event.get("name", "unknown_webhook_event")
    obj_name = event.get("resourceName") or event.get("resource", {}).get("name", "") if isinstance(event.get("resource"), dict) else event.get("resourceName", "")
    obj_type = event.get("resourceKind") or event.get("resourceType") or event.get("resource", {}).get("type", "unknown") if isinstance(event.get("resource"), dict) else event.get("resourceType", "unknown")

    dc_name = event.get("datacenter", "")
    message = event.get("message") or event.get("description") or event.get("alertName", "VCF webhook event")
    timestamp = event.get("timestamp") or event.get("startDate") or event.get("createTime", _now_iso())

    metadata = {k: v for k, v in event.items() if k not in (
        "alertType", "type", "source", "severity", "criticality", "status",
        "alertName", "eventName", "name", "resourceName", "resource",
        "resourceKind", "resourceType", "datacenter", "message",
        "description", "timestamp", "startDate", "createTime",
    )}

    return {
        "source": source,
        "event_type": str(event_type),
        "category": category,
        "severity": severity,
        "timestamp": str(timestamp),
        "object_name": str(obj_name),
        "object_type": str(obj_type),
        "datacenter": str(dc_name),
        "message": str(message),
        "metadata": metadata,
    }


def _normalize_vcf_kafka(event: dict) -> dict:
    """Normalize a VCF Kafka event."""
    topic = event.get("topic", "")
    key = event.get("key", "")

    payload = event.get("value") or event.get("payload") or event.get("data", {})
    if isinstance(payload, str):
        import json as _json
        try:
            payload = _json.loads(payload)
        except (ValueError, TypeError):
            payload = {"raw": payload}

    event_type = payload.get("eventType") or payload.get("event_type") or payload.get("type", topic or "unknown_kafka_event")

    # Derive category from topic or payload
    raw_category = payload.get("category", "")
    if not raw_category:
        for token in _KAFKA_CATEGORY_MAP:
            if token in topic.lower() or token in str(event_type).lower():
                raw_category = token
                break
    category = _KAFKA_CATEGORY_MAP.get(raw_category.lower(), "task") if raw_category else "task"

    severity = _normalize_severity(
        payload.get("severity") or payload.get("level") or payload.get("priority", "")
    )

    obj_name = payload.get("objectName") or payload.get("resourceName") or payload.get("name", "")
    obj_type = payload.get("objectType") or payload.get("resourceType") or payload.get("type", "unknown")
    dc_name = payload.get("datacenter", "")
    message = payload.get("message") or payload.get("description", f"Kafka event from {topic}")
    timestamp = payload.get("timestamp") or event.get("timestamp", _now_iso())

    metadata = {
        "topic": topic,
        "key": key,
        "partition": event.get("partition"),
        "offset": event.get("offset"),
    }
    metadata.update({
        k: v for k, v in payload.items() if k not in (
            "eventType", "event_type", "type", "category", "severity",
            "level", "priority", "objectName", "resourceName", "name",
            "objectType", "resourceType", "datacenter", "message",
            "description", "timestamp",
        )
    })

    return {
        "source": "kafka",
        "event_type": str(event_type),
        "category": category,
        "severity": severity,
        "timestamp": str(timestamp),
        "object_name": str(obj_name),
        "object_type": str(obj_type),
        "datacenter": str(dc_name),
        "message": str(message),
        "metadata": metadata,
    }


def _normalize_vcf_mcp(event: dict) -> dict:
    """Normalize a VCF MCP (Management Control Plane) event."""
    event_type = event.get("eventType") or event.get("type") or event.get("operationType", "unknown_mcp_event")

    raw_category = event.get("category", "").lower()
    category = raw_category if raw_category in (
        "vm_lifecycle", "host_lifecycle", "storage", "network",
        "security", "compliance", "alert", "task",
    ) else "task"

    severity = _normalize_severity(event.get("severity", ""))
    obj_name = event.get("entityName") or event.get("resourceName", "")
    obj_type = event.get("entityType") or event.get("resourceType", "unknown")
    dc_name = event.get("datacenter") or event.get("domainName", "")
    message = event.get("message") or event.get("description", f"MCP event: {event_type}")
    timestamp = event.get("timestamp") or event.get("occurredAt", _now_iso())

    metadata = {k: v for k, v in event.items() if k not in (
        "eventType", "type", "operationType", "category", "severity",
        "entityName", "resourceName", "entityType", "resourceType",
        "datacenter", "domainName", "message", "description",
        "timestamp", "occurredAt",
    )}

    return {
        "source": "vcf_mcp",
        "event_type": str(event_type),
        "category": category,
        "severity": severity,
        "timestamp": str(timestamp),
        "object_name": str(obj_name),
        "object_type": str(obj_type),
        "datacenter": str(dc_name),
        "message": str(message),
        "metadata": metadata,
    }


# ---------------------------------------------------------------------------
# Source detection
# ---------------------------------------------------------------------------

def _detect_source(event: dict) -> str:
    """Detect event source based on characteristic keys."""
    # vCenter events typically have EventType or vim-style keys
    if any(k in event for k in ("EventType", "FullFormattedMessage", "Vm", "CreatedTime")):
        return "vcenter_events"
    if event.get("_event_type") and event.get("vm"):
        return "vcenter_events"

    # Kafka events have topic/partition/offset
    if any(k in event for k in ("topic", "partition", "offset")):
        return "vcf_kafka"

    # MCP events have entityName/entityType or domainName
    if any(k in event for k in ("entityName", "entityType", "domainName", "operationType")):
        return "vcf_mcp"

    # VCF webhook events have alertType, alertName, resourceKind
    if any(k in event for k in ("alertType", "alertName", "resourceKind", "criticality")):
        return "vcf_webhook"

    # Fallback: check for nested source hint
    src = event.get("source", "").lower()
    if "vcenter" in src or "vsphere" in src:
        return "vcenter_events"
    if "kafka" in src:
        return "vcf_kafka"
    if "mcp" in src:
        return "vcf_mcp"
    if any(t in src for t in ("automation", "operations", "vra", "vrops", "webhook")):
        return "vcf_webhook"

    return "unknown"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

_NORMALIZERS = {
    "vcenter_events": _normalize_vcenter,
    "vcf_webhook": _normalize_vcf_webhook,
    "vcf_kafka": _normalize_vcf_kafka,
    "vcf_mcp": _normalize_vcf_mcp,
}


def main(event: dict, **kwargs) -> dict:
    """
    Normalize a VCF event into the unified schema.

    This is the EDA event filter entry point. It detects the originating
    source and transforms the event into a common structure so that
    rulebook conditions can be written once regardless of source.

    Args:
        event: The raw event dictionary from an EDA event source plugin.
        **kwargs: Additional keyword arguments (unused, reserved for
                  future filter options).

    Returns:
        A dictionary conforming to the unified VCF event schema.
    """
    source = _detect_source(event)
    normalizer = _NORMALIZERS.get(source)

    if normalizer:
        return normalizer(event)

    # Unknown source – pass through with minimal wrapping
    return {
        "source": "unknown",
        "event_type": event.get("event_type", event.get("type", "unknown")),
        "category": "task",
        "severity": "unknown",
        "timestamp": event.get("timestamp", _now_iso()),
        "object_name": event.get("name", event.get("object_name", "")),
        "object_type": event.get("object_type", "unknown"),
        "datacenter": event.get("datacenter", ""),
        "message": event.get("message", "Unrecognized event source"),
        "metadata": event,
    }
