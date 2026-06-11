"""
vcf_kafka.py - Ansible EDA event source plugin for VMware VCF Kafka events.

Consumes events from Kafka topics carrying VCF/vCenter lifecycle events and
normalises them into a common schema before placing them on the EDA rule queue.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from typing import Any

DOCUMENTATION = r"""
---
module: vcf_kafka
short_description: Consume VCF and vCenter events from Kafka topics.
description:
  - An Ansible Event-Driven Automation (EDA) event source plugin that
    consumes events from one or more Apache Kafka topics carrying VMware
    Cloud Foundation (VCF) and vCenter lifecycle events.
  - Events are automatically classified by source system (vCenter,
    VCF Automation, VCF Operations) and normalised into a common schema
    suitable for EDA rule matching.
  - Supports SASL authentication (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512),
    SSL/TLS encryption, consumer-group-based horizontal scaling, and
    automatic reconnection on broker failures.
version_added: "1.0.0"
author:
  - "Red Hat Ansible Team"
options:
  bootstrap_servers:
    description:
      - Comma-separated list of Kafka broker addresses
        (C(host1:port,host2:port)).
    type: str
    required: true
  topics:
    description:
      - List of Kafka topic names to subscribe to.
    type: list
    elements: str
    required: true
  group_id:
    description:
      - Kafka consumer group identifier.  Multiple EDA workers sharing
        the same group ID will partition the topic workload among
        themselves.
    type: str
    default: eda-vcf-consumer
  auto_offset_reset:
    description:
      - Where to begin consuming when no committed offset exists for the
        consumer group.
    type: str
    default: latest
    choices:
      - earliest
      - latest
  security_protocol:
    description:
      - Protocol used to communicate with brokers.
    type: str
    default: PLAINTEXT
    choices:
      - PLAINTEXT
      - SSL
      - SASL_PLAINTEXT
      - SASL_SSL
  sasl_mechanism:
    description:
      - SASL mechanism for authentication when I(security_protocol) is
        C(SASL_PLAINTEXT) or C(SASL_SSL).
    type: str
    choices:
      - PLAIN
      - SCRAM-SHA-256
      - SCRAM-SHA-512
  sasl_username:
    description:
      - Username for SASL authentication.
    type: str
  sasl_password:
    description:
      - Password for SASL authentication.
    type: str
  ssl_cafile:
    description:
      - Path to the CA certificate file for SSL/TLS verification.
    type: str
  ssl_certfile:
    description:
      - Path to the client certificate file for mutual TLS.
    type: str
  ssl_keyfile:
    description:
      - Path to the client private-key file for mutual TLS.
    type: str
  event_type_key:
    description:
      - JSON key inside the message payload that carries the event type.
    type: str
    default: event_type
  source_type_key:
    description:
      - JSON key inside the message payload that carries the source
        system identifier.
    type: str
    default: source
  batch_size:
    description:
      - Number of Kafka messages to accumulate before emitting a single
        batch event to the EDA rule engine.  Set to C(1) to emit every
        message individually.
    type: int
    default: 1
  poll_timeout_ms:
    description:
      - Maximum time in milliseconds the consumer will block waiting for
        messages per poll cycle.
    type: int
    default: 1000
"""

EXAMPLES = r"""
- name: Listen for VCF events via Kafka
  hosts: all
  sources:
    - vmware.vmware.vcf_kafka:
        bootstrap_servers: "kafka1.example.com:9092,kafka2.example.com:9092"
        topics:
          - vcenter-events
          - vcf-automation-events
          - vcf-operations-events
        group_id: eda-vcf-consumer
        security_protocol: SASL_SSL
        sasl_mechanism: SCRAM-SHA-512
        sasl_username: "{{ kafka_user }}"
        sasl_password: "{{ kafka_pass }}"
        ssl_cafile: /etc/pki/tls/certs/kafka-ca.pem
        batch_size: 5
  rules:
    - name: React to VM power-off
      condition: event.source_type == "vcenter" and event.event_type == "VmPoweredOffEvent"
      action:
        run_playbook:
          name: respond_to_vm_poweroff.yml
"""

logger = logging.getLogger("vcf_kafka")

# ---------------------------------------------------------------------------
# Source-type detection heuristics
# ---------------------------------------------------------------------------

# Patterns used to auto-detect which VMware subsystem produced the event.
_VCENTER_INDICATORS = frozenset(
    {
        "VmPoweredOnEvent",
        "VmPoweredOffEvent",
        "VmCreatedEvent",
        "VmRemovedEvent",
        "VmReconfiguredEvent",
        "VmMigratedEvent",
        "VmRelocatedEvent",
        "VmSuspendedEvent",
        "VmResumedEvent",
        "VmClonedEvent",
        "DrsVmMigratedEvent",
        "DrsVmPoweredOnEvent",
        "VmDiskFailedEvent",
        "VmGuestShutdownEvent",
        "VmGuestRebootEvent",
        "HostConnectionLostEvent",
        "HostConnectedEvent",
        "HostDisconnectedEvent",
        "DatastoreCapacityIncreasedEvent",
        "DatastoreRemovedOnHostEvent",
        "AlarmStatusChangedEvent",
        "TaskEvent",
        "EventEx",
        "UserLoginSessionEvent",
        "UserLogoutSessionEvent",
    }
)

_VCF_AUTOMATION_INDICATORS = frozenset(
    {
        "blueprint",
        "deployment",
        "catalog",
        "cloud_assembly",
        "service_broker",
        "vra",
        "aria_automation",
    }
)

_VCF_OPERATIONS_INDICATORS = frozenset(
    {
        "alert",
        "symptom",
        "recommendation",
        "vrops",
        "aria_operations",
        "operations_manager",
        "capacity",
        "compliance",
    }
)


def _detect_source_type(
    payload: dict[str, Any],
    source_type_key: str,
    event_type_key: str,
) -> str:
    """Return a normalised source-type string for the event payload."""

    # 1. Honour an explicit source field if present.
    explicit = str(payload.get(source_type_key, "")).lower()
    if explicit:
        for token in ("vcenter", "vsphere"):
            if token in explicit:
                return "vcenter"
        for token in ("automation", "vra", "cloud_assembly", "service_broker"):
            if token in explicit:
                return "vcf_automation"
        for token in ("operations", "vrops"):
            if token in explicit:
                return "vcf_operations"

    # 2. Inspect the event-type field.
    event_type = str(payload.get(event_type_key, ""))
    if event_type in _VCENTER_INDICATORS:
        return "vcenter"

    event_lower = event_type.lower()
    if any(ind in event_lower for ind in _VCF_AUTOMATION_INDICATORS):
        return "vcf_automation"
    if any(ind in event_lower for ind in _VCF_OPERATIONS_INDICATORS):
        return "vcf_operations"

    # 3. Deep-scan well-known keys in the payload body.
    payload_str = json.dumps(payload).lower()
    if "managed_object_reference" in payload_str or "vim.event" in payload_str:
        return "vcenter"
    if "blueprint_id" in payload_str or "deployment_id" in payload_str:
        return "vcf_automation"
    if "alert_id" in payload_str or "symptom_id" in payload_str:
        return "vcf_operations"

    return "unknown"


def _extract_severity(payload: dict[str, Any]) -> str:
    """Best-effort severity extraction from the raw event."""
    for key in ("severity", "Severity", "alert_level", "priority", "status"):
        val = payload.get(key)
        if val is not None:
            return str(val).upper()
    return "INFO"


def _extract_field(payload: dict[str, Any], *candidates: str) -> str | None:
    """Return the first non-empty value found for any candidate key."""
    for key in candidates:
        val = payload.get(key)
        if val not in (None, ""):
            return str(val)
    return None


def _normalise_event(
    payload: dict[str, Any],
    topic: str,
    partition: int,
    offset: int,
    event_type_key: str,
    source_type_key: str,
) -> dict[str, Any]:
    """Transform a raw Kafka message payload into the common EDA schema."""
    source_type = _detect_source_type(payload, source_type_key, event_type_key)
    return {
        "source_type": source_type,
        "event_type": payload.get(event_type_key, "unknown"),
        "timestamp": _extract_field(
            payload,
            "timestamp",
            "createdTime",
            "created_time",
            "eventTime",
            "event_time",
            "time",
        )
        or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "severity": _extract_severity(payload),
        "object_name": _extract_field(
            payload,
            "object_name",
            "objectName",
            "vm_name",
            "vmName",
            "host_name",
            "hostName",
            "entityName",
            "entity_name",
            "resourceName",
            "resource_name",
        ),
        "object_type": _extract_field(
            payload,
            "object_type",
            "objectType",
            "managedObjectType",
            "managed_object_type",
            "entityType",
            "entity_type",
            "resourceKind",
            "resource_kind",
        ),
        "message": _extract_field(
            payload,
            "message",
            "fullFormattedMessage",
            "full_formatted_message",
            "description",
            "text",
            "summary",
        ),
        "topic": topic,
        "partition": partition,
        "offset": offset,
        "raw_event": payload,
    }


# ---------------------------------------------------------------------------
# SSL context helper
# ---------------------------------------------------------------------------


def _build_ssl_context(args: dict[str, Any]) -> ssl.SSLContext | None:
    """Build an SSL context when the security protocol requires TLS."""
    protocol = args.get("security_protocol", "PLAINTEXT").upper()
    if protocol not in ("SSL", "SASL_SSL"):
        return None

    ctx = ssl.create_default_context(cafile=args.get("ssl_cafile"))
    certfile = args.get("ssl_certfile")
    keyfile = args.get("ssl_keyfile")
    if certfile:
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return ctx


# ---------------------------------------------------------------------------
# Consumer factory
# ---------------------------------------------------------------------------


async def _create_consumer(args: dict[str, Any]):  # noqa: ANN202
    """Instantiate and return a started AIOKafkaConsumer."""
    # Import here so the dependency is only required at runtime.
    from aiokafka import AIOKafkaConsumer  # type: ignore[import-untyped]

    bootstrap = args["bootstrap_servers"]
    topics = args["topics"]
    group_id = args.get("group_id", "eda-vcf-consumer")
    auto_offset_reset = args.get("auto_offset_reset", "latest")
    security_protocol = args.get("security_protocol", "PLAINTEXT").upper()

    kwargs: dict[str, Any] = {
        "bootstrap_servers": bootstrap,
        "group_id": group_id,
        "auto_offset_reset": auto_offset_reset,
        "security_protocol": security_protocol,
        "enable_auto_commit": True,
    }

    # SASL configuration
    sasl_mechanism = args.get("sasl_mechanism")
    if sasl_mechanism:
        kwargs["sasl_mechanism"] = sasl_mechanism
        kwargs["sasl_plain_username"] = args.get("sasl_username")
        kwargs["sasl_plain_password"] = args.get("sasl_password")

    # TLS configuration
    ssl_ctx = _build_ssl_context(args)
    if ssl_ctx is not None:
        kwargs["ssl_context"] = ssl_ctx

    consumer = AIOKafkaConsumer(*topics, **kwargs)
    await consumer.start()
    logger.info(
        "Kafka consumer started — brokers=%s topics=%s group=%s",
        bootstrap,
        topics,
        group_id,
    )
    return consumer


# ---------------------------------------------------------------------------
# Main entry point (EDA contract)
# ---------------------------------------------------------------------------

_RECONNECT_DELAY_INITIAL = 1.0  # seconds
_RECONNECT_DELAY_MAX = 60.0


async def main(queue: asyncio.Queue, args: dict[str, Any]) -> None:  # noqa: C901
    """EDA event source entry point.

    Connects to Kafka, continuously polls for messages, normalises them,
    and places them on *queue* for the EDA rule engine.  Reconnects
    automatically on transient broker failures.
    """
    # ---- validate required args ----
    if not args.get("bootstrap_servers"):
        msg = "bootstrap_servers is required"
        raise ValueError(msg)
    if not args.get("topics"):
        msg = "topics must be a non-empty list"
        raise ValueError(msg)

    event_type_key: str = args.get("event_type_key", "event_type")
    source_type_key: str = args.get("source_type_key", "source")
    batch_size: int = max(int(args.get("batch_size", 1)), 1)
    poll_timeout_ms: int = int(args.get("poll_timeout_ms", 1000))

    reconnect_delay = _RECONNECT_DELAY_INITIAL
    consumer = None

    try:
        while True:
            # ---- (re)connect ----
            if consumer is None:
                try:
                    consumer = await _create_consumer(args)
                    reconnect_delay = _RECONNECT_DELAY_INITIAL
                except Exception:
                    logger.exception(
                        "Failed to connect to Kafka — retrying in %.0fs",
                        reconnect_delay,
                    )
                    await asyncio.sleep(reconnect_delay)
                    reconnect_delay = min(
                        reconnect_delay * 2, _RECONNECT_DELAY_MAX
                    )
                    continue

            # ---- poll ----
            try:
                data = await consumer.getmany(
                    timeout_ms=poll_timeout_ms,
                    max_records=batch_size,
                )
            except Exception:
                logger.exception(
                    "Error polling Kafka — will reconnect in %.0fs",
                    reconnect_delay,
                )
                await _safe_close(consumer)
                consumer = None
                await asyncio.sleep(reconnect_delay)
                reconnect_delay = min(
                    reconnect_delay * 2, _RECONNECT_DELAY_MAX
                )
                continue

            if not data:
                continue

            # ---- process messages ----
            batch: list[dict[str, Any]] = []

            for tp, messages in data.items():
                for msg in messages:
                    payload = _deserialise(msg.value, msg.topic, msg.offset)
                    if payload is None:
                        continue

                    event = _normalise_event(
                        payload,
                        topic=msg.topic,
                        partition=msg.partition,
                        offset=msg.offset,
                        event_type_key=event_type_key,
                        source_type_key=source_type_key,
                    )

                    if batch_size <= 1:
                        await queue.put(event)
                        logger.debug(
                            "Enqueued event topic=%s partition=%d offset=%d type=%s",
                            msg.topic,
                            msg.partition,
                            msg.offset,
                            event.get("event_type"),
                        )
                    else:
                        batch.append(event)

            # Emit batch if we're in batching mode and have collected events.
            if batch_size > 1 and batch:
                await queue.put({"events": batch, "batch_size": len(batch)})
                logger.debug("Enqueued batch of %d events", len(batch))

    except asyncio.CancelledError:
        logger.info("Received cancellation — shutting down Kafka consumer")
    finally:
        await _safe_close(consumer)
        logger.info("Kafka consumer shut down")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _deserialise(
    value: bytes | None, topic: str, offset: int
) -> dict[str, Any] | None:
    """Attempt to decode a Kafka message value as JSON."""
    if value is None:
        return None
    try:
        return json.loads(value.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning(
            "Skipping non-JSON message on topic=%s offset=%d",
            topic,
            offset,
        )
        return None


async def _safe_close(consumer: Any) -> None:
    """Close the consumer, swallowing errors."""
    if consumer is None:
        return
    try:
        await consumer.stop()
        logger.info("Kafka consumer closed")
    except Exception:
        logger.exception("Error closing Kafka consumer")


if __name__ == "__main__":
    """Allow a quick smoke-test from the command line."""

    class _PrintQueue:
        """Tiny stand-in for an asyncio.Queue that prints events."""

        async def put(self, event: Any) -> None:  # noqa: ANN401
            print(json.dumps(event, indent=2, default=str))

    asyncio.run(
        main(
            queue=_PrintQueue(),  # type: ignore[arg-type]
            args={
                "bootstrap_servers": "localhost:9092",
                "topics": ["vcenter-events"],
            },
        )
    )
