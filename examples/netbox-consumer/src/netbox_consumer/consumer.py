"""Kafka poll loop: read a DeviceRecord, map it, upsert to NetBox, commit.

The loop is deliberately linear so a reader can follow the whole event
lifecycle top-to-bottom. Backoff/retry on NetBox 5xx is out of scope —
production consumers add a bounded retry loop with jitter here.
"""

from __future__ import annotations

import json
import logging
import signal

from confluent_kafka import Consumer, KafkaError, Message
from pydantic import ValidationError

from .config import Config
from .mapper import MappingError, map_device_record
from .models import DeviceRecord
from .netbox import NetBoxClient

logger = logging.getLogger(__name__)

_STOP = False


def run(config: Config) -> None:
    """Run the poll loop until SIGINT/SIGTERM."""
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    consumer = Consumer(
        {
            "bootstrap.servers": config.kafka_brokers,
            "group.id": config.kafka_group_id,
            "auto.offset.reset": config.kafka_auto_offset_reset,
            "enable.auto.commit": False,
        }
    )
    consumer.subscribe([config.kafka_topic])

    netbox = (
        None
        if config.dry_run
        else NetBoxClient(
            config.netbox_url,
            config.netbox_token,
            verify_tls=config.netbox_verify_tls,
            timeout_seconds=config.netbox_timeout_seconds,
        )
    )

    logger.info(
        "consumer starting",
        extra={
            "topic": config.kafka_topic,
            "group_id": config.kafka_group_id,
            "dry_run": config.dry_run,
        },
    )

    try:
        while not _STOP:
            message = consumer.poll(timeout=config.poll_timeout_ms / 1000.0)
            if message is None:
                continue
            err = message.error()
            if err is not None:
                if err.code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error("kafka poll error", extra={"error": str(err)})
                continue
            _process(message, netbox, dry_run=config.dry_run)
            consumer.commit(message=message, asynchronous=False)
    finally:
        consumer.close()
        logger.info("consumer stopped")


def _process(message: Message, netbox: NetBoxClient | None, *, dry_run: bool) -> None:
    raw = message.value()
    if raw is None:
        logger.warning("skipping message with empty value")
        return

    try:
        payload = json.loads(raw.decode("utf-8"))
        record = DeviceRecord.model_validate(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        logger.warning(
            "skipping poison message",
            extra={"error": str(exc), "offset": message.offset()},
        )
        return

    context = {"identity_key": record.identity_key, "offset": message.offset()}

    try:
        upsert_payload = map_device_record(record)
    except MappingError as exc:
        logger.warning("skipping record", extra={**context, "reason": str(exc)})
        return

    if dry_run or netbox is None:
        logger.info("dry-run upsert", extra={**context, "payload": upsert_payload})
        return

    try:
        netbox.upsert_device(upsert_payload)
    except Exception:
        logger.exception("NetBox upsert failed; skipping message", extra=context)
        return

    logger.info("upserted", extra=context)


def _stop(signum: int, _frame: object) -> None:
    global _STOP
    logger.info("received signal, stopping", extra={"signal": signum})
    _STOP = True
