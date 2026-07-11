"""Parsing tests for the DeviceRecord subset the consumer reads."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from nautobot_consumer.models import DeviceRecord


def test_minimal_record_parses(minimal_record_payload: dict[str, Any]) -> None:
    record = DeviceRecord.model_validate(minimal_record_payload)
    assert record.identity_key == "ip:10.50.0.10"
    assert record.mgmt_ip == "10.50.0.10"
    assert record.confidence == 0.2
    assert record.signals == [{"OpenPort": 80}]
    assert record.probe_kinds == ["TcpConnect"]
    assert record.platform is None
    assert record.role is None
    assert record.alt_ips == []
    assert record.scan_metadata.scan_id == "01J1ZQK6HVQ7YXP3D3W1Z9J4KM"


def test_full_record_parses(full_record_payload: dict[str, Any]) -> None:
    record = DeviceRecord.model_validate(full_record_payload)
    assert record.schema_version == "v1"
    assert record.schema_id == "https://davidban77.github.io/rastreo/schemas/device-record-v1.json"
    assert record.identity_key == "mac:aa:bb:cc:11:22:33"
    assert record.platform == "cisco_ios"
    assert record.os_version == "15.7"
    assert record.ssh_version == "Cisco-1.25"
    assert record.http_server is None
    assert record.http_version is None
    assert record.role == "router"
    assert record.manufacturer == "Cisco Systems, Inc"
    assert len(record.signals) == 6
    assert {"SshBanner": "SSH-2.0-Cisco-1.25"} in record.signals


def test_merged_record_parses_alt_ips(merged_record_payload: dict[str, Any]) -> None:
    record = DeviceRecord.model_validate(merged_record_payload)
    assert [alt.address for alt in record.alt_ips] == ["10.50.0.31", "10.50.0.32"]
    assert record.alt_ips[0].role == "secondary"
    assert record.alt_ips[0].responded_via == ["TcpConnect", "Ssh"]
    assert record.alt_ips[1].role == "vrrp"


def test_unknown_fields_are_ignored(minimal_record_payload: dict[str, Any]) -> None:
    """rastreo can add fields without breaking downstream consumers."""
    minimal_record_payload["future_field"] = {"foo": "bar"}
    minimal_record_payload["scan_metadata"]["another_new_field"] = 42
    record = DeviceRecord.model_validate(minimal_record_payload)
    assert record.identity_key == "ip:10.50.0.10"
    assert not hasattr(record, "future_field")


def test_missing_required_field_raises(minimal_record_payload: dict[str, Any]) -> None:
    del minimal_record_payload["identity_key"]
    with pytest.raises(ValidationError):
        DeviceRecord.model_validate(minimal_record_payload)


def test_last_seen_parsed_as_datetime(minimal_record_payload: dict[str, Any]) -> None:
    record = DeviceRecord.model_validate(minimal_record_payload)
    assert record.last_seen.year == 2026
    assert record.last_seen.tzinfo is not None
