"""Mapping tests: DeviceRecord -> Infrahub attribute payload."""

from __future__ import annotations

from typing import Any

import pytest

from infrahub_consumer.mapper import MappingError, map_device_record
from infrahub_consumer.models import DeviceRecord


def _map(payload: dict[str, Any]) -> dict[str, Any]:
    return map_device_record(DeviceRecord.model_validate(payload))


def test_minimal_record_maps_core_attributes(
    minimal_record_payload: dict[str, Any],
) -> None:
    result = _map(minimal_record_payload)
    assert result["identity_key"] == "ip:10.50.0.10"
    assert result["mgmt_ip"] == "10.50.0.10"
    assert result["last_seen"] == "2026-07-05T11:22:51.423959Z"
    assert result["confidence"] == "0.20"
    assert result["signals"] == [{"OpenPort": 80}]
    assert result["probe_kinds"] == ["TcpConnect"]
    assert result["alt_ips"] == []
    assert result["scan_metadata"]["scan_id"] == "01J1ZQK6HVQ7YXP3D3W1Z9J4KM"
    assert "platform" not in result
    assert "role" not in result
    assert "mac" not in result
    assert "os_version" not in result


def test_full_record_maps_platform_role_and_os_version(
    full_record_payload: dict[str, Any],
) -> None:
    result = _map(full_record_payload)
    assert result["platform"] == "cisco_ios"
    assert result["role"] == "router"
    assert result["os_version"] == "15.7"
    assert result["mac"] == "aa:bb:cc:11:22:33"
    assert result["confidence"] == "0.85"


def test_merged_record_carries_alt_ips_verbatim(
    merged_record_payload: dict[str, Any],
) -> None:
    result = _map(merged_record_payload)
    alt_ips = result["alt_ips"]
    assert len(alt_ips) == 2
    assert alt_ips[0] == {
        "address": "10.50.0.31",
        "role": "secondary",
        "responded_via": ["TcpConnect", "Ssh"],
    }
    assert alt_ips[1]["role"] == "vrrp"


def test_missing_mgmt_ip_raises_mapping_error(
    minimal_record_payload: dict[str, Any],
) -> None:
    minimal_record_payload["mgmt_ip"] = None
    with pytest.raises(MappingError, match="mgmt_ip"):
        _map(minimal_record_payload)


def test_invalid_mgmt_ip_raises_mapping_error(
    minimal_record_payload: dict[str, Any],
) -> None:
    minimal_record_payload["mgmt_ip"] = "not-an-ip"
    with pytest.raises(MappingError, match="not a valid IP"):
        _map(minimal_record_payload)


def test_ipv6_mgmt_ip_is_accepted(minimal_record_payload: dict[str, Any]) -> None:
    minimal_record_payload["mgmt_ip"] = "2001:db8::10"
    result = _map(minimal_record_payload)
    assert result["mgmt_ip"] == "2001:db8::10"


def test_platform_and_role_are_stripped_of_whitespace(
    minimal_record_payload: dict[str, Any],
) -> None:
    minimal_record_payload["platform"] = "  Cisco IOS-XR  "
    minimal_record_payload["role"] = "  edge-router  "
    result = _map(minimal_record_payload)
    assert result["platform"] == "Cisco IOS-XR"
    assert result["role"] == "edge-router"


def test_confidence_is_rounded_to_two_decimals(
    minimal_record_payload: dict[str, Any],
) -> None:
    minimal_record_payload["confidence"] = 0.847239
    result = _map(minimal_record_payload)
    assert result["confidence"] == "0.85"


def test_mapper_passes_through_ssh_and_http_fields(
    minimal_record_payload: dict[str, Any],
) -> None:
    """SSH and HTTP classifier outputs land as direct RastreoDevice attributes."""
    minimal_record_payload["ssh_version"] = "OpenSSH_8.9p1"
    minimal_record_payload["http_server"] = "nginx"
    minimal_record_payload["http_version"] = "1.24.0"
    result = _map(minimal_record_payload)
    assert result["ssh_version"] == "OpenSSH_8.9p1"
    assert result["http_server"] == "nginx"
    assert result["http_version"] == "1.24.0"


def test_ssh_and_http_fields_omitted_when_null(
    minimal_record_payload: dict[str, Any],
) -> None:
    """Records without SSH/HTTP classifier output do not emit the attributes."""
    result = _map(minimal_record_payload)
    assert "ssh_version" not in result
    assert "http_server" not in result
    assert "http_version" not in result
