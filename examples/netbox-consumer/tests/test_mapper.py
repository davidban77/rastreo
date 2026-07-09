"""Mapping tests: DeviceRecord -> NetBox payload dict."""

from __future__ import annotations

from typing import Any

import pytest

from netbox_consumer.mapper import MappingError, map_device_record
from netbox_consumer.models import DeviceRecord


def _map(payload: dict[str, Any]) -> dict[str, Any]:
    return map_device_record(DeviceRecord.model_validate(payload))


def test_minimal_record_maps_to_identity_and_last_seen(
    minimal_record_payload: dict[str, Any],
) -> None:
    result = _map(minimal_record_payload)
    cf = result["custom_fields"]
    assert cf["rastreo_identity_key"] == "ip:10.50.0.10"
    assert cf["rastreo_last_seen"] == "2026-07-05T11:22:51.423959Z"
    assert cf["rastreo_confidence"] == 0.2
    assert cf["rastreo_signals"] == [{"OpenPort": 80}]
    assert cf["rastreo_probe_kinds"] == ["TcpConnect"]
    assert cf["rastreo_alt_ips"] == []
    assert cf["rastreo_scan_metadata"]["scan_id"] == "01J1ZQK6HVQ7YXP3D3W1Z9J4KM"
    assert result["_mgmt_ip"] == "10.50.0.10"
    assert result["_mgmt_ip_family"] == 4
    assert "platform" not in result
    assert "role" not in result


def test_full_record_maps_platform_and_role_as_slugs(
    full_record_payload: dict[str, Any],
) -> None:
    result = _map(full_record_payload)
    assert result["platform"] == "cisco-ios"
    assert result["role"] == "router"
    cf = result["custom_fields"]
    assert cf["rastreo_os_version"] == "15.7"
    assert cf["rastreo_confidence"] == 0.85
    assert result["_mac"] == "aa:bb:cc:11:22:33"


def test_merged_record_carries_alt_ips_verbatim(
    merged_record_payload: dict[str, Any],
) -> None:
    result = _map(merged_record_payload)
    alt_ips = result["custom_fields"]["rastreo_alt_ips"]
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


def test_ipv6_mgmt_ip_marks_family_6(minimal_record_payload: dict[str, Any]) -> None:
    minimal_record_payload["mgmt_ip"] = "2001:db8::10"
    result = _map(minimal_record_payload)
    assert result["_mgmt_ip_family"] == 6


def test_platform_slug_stripped_of_junk(
    minimal_record_payload: dict[str, Any],
) -> None:
    minimal_record_payload["platform"] = "  Cisco IOS-XR  "
    result = _map(minimal_record_payload)
    assert result["platform"] == "cisco-ios-xr"


def test_os_version_omitted_when_null(minimal_record_payload: dict[str, Any]) -> None:
    result = _map(minimal_record_payload)
    assert "rastreo_os_version" not in result["custom_fields"]


def test_mapper_passes_through_ssh_and_http_fields(
    minimal_record_payload: dict[str, Any],
) -> None:
    """SSH and HTTP classifier outputs land in dedicated custom fields."""
    minimal_record_payload["ssh_version"] = "OpenSSH_8.9p1"
    minimal_record_payload["http_server"] = "nginx"
    minimal_record_payload["http_version"] = "1.24.0"
    result = _map(minimal_record_payload)
    cf = result["custom_fields"]
    assert cf["rastreo_ssh_version"] == "OpenSSH_8.9p1"
    assert cf["rastreo_http_server"] == "nginx"
    assert cf["rastreo_http_version"] == "1.24.0"


def test_ssh_and_http_fields_omitted_when_null(
    minimal_record_payload: dict[str, Any],
) -> None:
    """Records without SSH/HTTP classifier output do not emit the custom fields."""
    result = _map(minimal_record_payload)
    cf = result["custom_fields"]
    assert "rastreo_ssh_version" not in cf
    assert "rastreo_http_server" not in cf
    assert "rastreo_http_version" not in cf
