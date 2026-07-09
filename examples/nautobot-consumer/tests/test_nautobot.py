"""Nautobot client tests: mock pynautobot HTTP calls with ``responses``.

pynautobot uses ``requests`` under the hood, so ``responses`` is the correct
HTTP mocking layer here — it intercepts requests at the transport level and
lets us assert on the wire shape of what the reconciler sends to Nautobot.
Nautobot IDs are UUID strings, not integers.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import responses

from nautobot_consumer.mapper import map_device_record
from nautobot_consumer.models import DeviceRecord
from nautobot_consumer.nautobot import NautobotClient, NautobotLookupError

NAUTOBOT_URL = "https://nautobot.example.com"

DEVICE_TYPE_ID = "00000000-0000-0000-0000-000000000001"
LOCATION_ID = "00000000-0000-0000-0000-000000000002"
STATUS_ID = "00000000-0000-0000-0000-000000000003"
PLATFORM_ID = "00000000-0000-0000-0000-000000000010"
ROLE_ID = "00000000-0000-0000-0000-000000000020"
DEVICE_ID = "00000000-0000-0000-0000-000000000042"
IFACE_ID = "00000000-0000-0000-0000-000000000055"
PREFIX_ID = "00000000-0000-0000-0000-000000000077"
IP_ID = "00000000-0000-0000-0000-000000000099"


@pytest.fixture
def rsps() -> Iterator[responses.RequestsMock]:
    """Activate ``responses`` for a test and return the registry."""
    with responses.RequestsMock() as mock:
        yield mock


def _register_defaults(rsps: responses.RequestsMock) -> None:
    """Register the startup-lookup responses every client construction needs."""
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/device-types/",
        json=_paginated([{"id": DEVICE_TYPE_ID, "name": "generic-router"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/locations/",
        json=_paginated([{"id": LOCATION_ID, "name": "discovery"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/extras/statuses/",
        json=_paginated([{"id": STATUS_ID, "name": "Active"}]),
    )


@pytest.fixture
def client(rsps: responses.RequestsMock) -> NautobotClient:
    """A NautobotClient pointed at the mocked base URL, with defaults resolved."""
    _register_defaults(rsps)
    return NautobotClient(
        NAUTOBOT_URL,
        token="test-token",
        default_device_type="generic-router",
        default_location="discovery",
        default_device_status="Active",
    )


@pytest.fixture
def payload(full_record_payload: dict[str, Any]) -> dict[str, Any]:
    """A Nautobot payload derived from the canonical full-record fixture."""
    return map_device_record(DeviceRecord.model_validate(full_record_payload))


def _paginated(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {"count": len(results), "next": None, "previous": None, "results": results}


def _device_json(
    *,
    device_id: str = DEVICE_ID,
    name: str = "existing-device",
    identity_key: str = "mac:aa:bb:cc:11:22:33",
    custom_fields: dict[str, Any] | None = None,
    platform: dict[str, Any] | None = None,
    role: dict[str, Any] | None = None,
    primary_ip4: dict[str, Any] | None = None,
    primary_ip6: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cf = {"rastreo_identity_key": identity_key}
    if custom_fields:
        cf.update(custom_fields)
    return {
        "id": device_id,
        "name": name,
        "custom_fields": cf,
        "platform": platform,
        "role": role,
        "primary_ip4": primary_ip4,
        "primary_ip6": primary_ip6,
    }


def _find_call(rsps: responses.RequestsMock, method: str, path: str) -> Any:
    for call in rsps.calls:
        if call.request.method == method and urlparse(call.request.url).path == path:
            return call
    seen = [(c.request.method, c.request.url) for c in rsps.calls]
    raise AssertionError(f"expected {method} {path} in {seen}")


def _count_calls(rsps: responses.RequestsMock, method: str, path: str) -> int:
    return sum(
        1
        for call in rsps.calls
        if call.request.method == method and urlparse(call.request.url).path == path
    )


def test_device_type_missing_fails_startup(rsps: responses.RequestsMock) -> None:
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/device-types/", json=_paginated([]))
    with pytest.raises(NautobotLookupError, match="dcim.device_types"):
        NautobotClient(
            NAUTOBOT_URL,
            token="test-token",
            default_device_type="generic-router",
            default_location="discovery",
            default_device_status="Active",
        )


def test_location_missing_fails_startup(rsps: responses.RequestsMock) -> None:
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/device-types/",
        json=_paginated([{"id": DEVICE_TYPE_ID, "name": "generic-router"}]),
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/locations/", json=_paginated([]))
    with pytest.raises(NautobotLookupError, match="dcim.locations"):
        NautobotClient(
            NAUTOBOT_URL,
            token="test-token",
            default_device_type="generic-router",
            default_location="discovery",
            default_device_status="Active",
        )


def test_status_missing_fails_startup(rsps: responses.RequestsMock) -> None:
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/device-types/",
        json=_paginated([{"id": DEVICE_TYPE_ID, "name": "generic-router"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/locations/",
        json=_paginated([{"id": LOCATION_ID, "name": "discovery"}]),
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/extras/statuses/", json=_paginated([]))
    with pytest.raises(NautobotLookupError, match="extras.statuses"):
        NautobotClient(
            NAUTOBOT_URL,
            token="test-token",
            default_device_type="generic-router",
            default_location="discovery",
            default_device_status="Active",
        )


def test_create_path_posts_device_with_defaults_and_platform_role(
    rsps: responses.RequestsMock, client: NautobotClient, payload: dict[str, Any]
) -> None:
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/devices/", json=_paginated([]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/platforms/",
        json=_paginated([{"id": PLATFORM_ID, "name": "cisco_ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/extras/roles/",
        json=_paginated([{"id": ROLE_ID, "name": "router"}]),
    )
    created = _device_json(
        platform={"id": PLATFORM_ID, "name": "cisco_ios"},
        role={"id": ROLE_ID, "name": "router"},
    )
    rsps.add(responses.POST, f"{NAUTOBOT_URL}/api/dcim/devices/", json=created)
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/interfaces/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NAUTOBOT_URL}/api/dcim/interfaces/",
        json={
            "id": IFACE_ID,
            "name": "mgmt0",
            "device": {"id": DEVICE_ID},
            "mac_address": "aa:bb:cc:11:22:33",
        },
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/prefixes/",
        json=_paginated([{"id": PREFIX_ID, "prefix": "10.50.0.0/24"}]),
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/ipam/ip-addresses/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NAUTOBOT_URL}/api/ipam/ip-addresses/",
        json={"id": IP_ID, "address": "10.50.0.20/32"},
    )
    rsps.add(
        responses.PATCH,
        f"{NAUTOBOT_URL}/api/dcim/devices/{DEVICE_ID}/",
        json=_device_json(primary_ip4={"id": IP_ID, "address": "10.50.0.20/32"}),
    )

    client.upsert_device(payload)

    post = _find_call(rsps, "POST", "/api/dcim/devices/")
    body = json.loads(post.request.body)
    assert body["name"] == "mac:aa:bb:cc:11:22:33"
    assert body["device_type"] == DEVICE_TYPE_ID
    assert body["location"] == LOCATION_ID
    assert body["status"] == STATUS_ID
    assert body["platform"] == PLATFORM_ID
    assert body["role"] == ROLE_ID
    assert body["custom_fields"]["rastreo_identity_key"] == "mac:aa:bb:cc:11:22:33"
    assert body["custom_fields"]["rastreo_confidence"] == "0.85"


def test_update_is_noop_when_all_fields_match(
    rsps: responses.RequestsMock, client: NautobotClient, payload: dict[str, Any]
) -> None:
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": PLATFORM_ID, "name": "cisco_ios"},
        role={"id": ROLE_ID, "name": "router"},
        primary_ip4={"id": IP_ID, "address": "10.50.0.20/32"},
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/platforms/",
        json=_paginated([{"id": PLATFORM_ID, "name": "cisco_ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/extras/roles/",
        json=_paginated([{"id": ROLE_ID, "name": "router"}]),
    )
    iface = {
        "id": IFACE_ID,
        "name": "mgmt0",
        "device": {"id": DEVICE_ID},
        "mac_address": "aa:bb:cc:11:22:33",
    }
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/interfaces/", json=_paginated([iface]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/prefixes/",
        json=_paginated([{"id": PREFIX_ID, "prefix": "10.50.0.0/24"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/ip-addresses/",
        json=_paginated([{"id": IP_ID, "address": "10.50.0.20/32"}]),
    )

    client.upsert_device(payload)

    assert _count_calls(rsps, "PATCH", f"/api/dcim/devices/{DEVICE_ID}/") == 0
    assert _count_calls(rsps, "POST", "/api/dcim/devices/") == 0
    assert _count_calls(rsps, "POST", "/api/dcim/interfaces/") == 0
    assert _count_calls(rsps, "POST", "/api/ipam/ip-addresses/") == 0


def test_update_patches_only_changed_platform(
    rsps: responses.RequestsMock, client: NautobotClient, payload: dict[str, Any]
) -> None:
    other_platform_id = "00000000-0000-0000-0000-0000000000aa"
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": other_platform_id, "name": "cisco_nxos"},
        role={"id": ROLE_ID, "name": "router"},
        primary_ip4={"id": IP_ID, "address": "10.50.0.20/32"},
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/platforms/",
        json=_paginated([{"id": PLATFORM_ID, "name": "cisco_ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/extras/roles/",
        json=_paginated([{"id": ROLE_ID, "name": "router"}]),
    )
    rsps.add(responses.PATCH, f"{NAUTOBOT_URL}/api/dcim/devices/{DEVICE_ID}/", json=existing)
    iface = {
        "id": IFACE_ID,
        "name": "mgmt0",
        "device": {"id": DEVICE_ID},
        "mac_address": "aa:bb:cc:11:22:33",
    }
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/interfaces/", json=_paginated([iface]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/prefixes/",
        json=_paginated([{"id": PREFIX_ID, "prefix": "10.50.0.0/24"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/ip-addresses/",
        json=_paginated([{"id": IP_ID, "address": "10.50.0.20/32"}]),
    )

    client.upsert_device(payload)

    patch = _find_call(rsps, "PATCH", f"/api/dcim/devices/{DEVICE_ID}/")
    body = json.loads(patch.request.body)
    assert body == {"platform": PLATFORM_ID}


def test_missing_platform_name_omits_platform_from_create(
    rsps: responses.RequestsMock,
    client: NautobotClient,
    payload: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/devices/", json=_paginated([]))
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/platforms/", json=_paginated([]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/extras/roles/",
        json=_paginated([{"id": ROLE_ID, "name": "router"}]),
    )
    created = _device_json(role={"id": ROLE_ID, "name": "router"})
    rsps.add(responses.POST, f"{NAUTOBOT_URL}/api/dcim/devices/", json=created)
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/interfaces/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NAUTOBOT_URL}/api/dcim/interfaces/",
        json={
            "id": IFACE_ID,
            "name": "mgmt0",
            "device": {"id": DEVICE_ID},
            "mac_address": "aa:bb:cc:11:22:33",
        },
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/prefixes/",
        json=_paginated([{"id": PREFIX_ID, "prefix": "10.50.0.0/24"}]),
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/ipam/ip-addresses/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NAUTOBOT_URL}/api/ipam/ip-addresses/",
        json={"id": IP_ID, "address": "10.50.0.20/32"},
    )
    rsps.add(
        responses.PATCH,
        f"{NAUTOBOT_URL}/api/dcim/devices/{DEVICE_ID}/",
        json=_device_json(primary_ip4={"id": IP_ID, "address": "10.50.0.20/32"}),
    )

    with caplog.at_level("WARNING"):
        client.upsert_device(payload)

    post = _find_call(rsps, "POST", "/api/dcim/devices/")
    body = json.loads(post.request.body)
    assert "platform" not in body
    assert body["role"] == ROLE_ID
    assert any("dcim.platforms not found" in rec.message for rec in caplog.records)


def test_missing_role_name_omits_role_from_create(
    rsps: responses.RequestsMock,
    client: NautobotClient,
    payload: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/devices/", json=_paginated([]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/platforms/",
        json=_paginated([{"id": PLATFORM_ID, "name": "cisco_ios"}]),
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/extras/roles/", json=_paginated([]))
    created = _device_json(platform={"id": PLATFORM_ID, "name": "cisco_ios"})
    rsps.add(responses.POST, f"{NAUTOBOT_URL}/api/dcim/devices/", json=created)
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/interfaces/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NAUTOBOT_URL}/api/dcim/interfaces/",
        json={
            "id": IFACE_ID,
            "name": "mgmt0",
            "device": {"id": DEVICE_ID},
            "mac_address": "aa:bb:cc:11:22:33",
        },
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/prefixes/",
        json=_paginated([{"id": PREFIX_ID, "prefix": "10.50.0.0/24"}]),
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/ipam/ip-addresses/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NAUTOBOT_URL}/api/ipam/ip-addresses/",
        json={"id": IP_ID, "address": "10.50.0.20/32"},
    )
    rsps.add(
        responses.PATCH,
        f"{NAUTOBOT_URL}/api/dcim/devices/{DEVICE_ID}/",
        json=_device_json(primary_ip4={"id": IP_ID, "address": "10.50.0.20/32"}),
    )

    with caplog.at_level("WARNING"):
        client.upsert_device(payload)

    post = _find_call(rsps, "POST", "/api/dcim/devices/")
    body = json.loads(post.request.body)
    assert "role" not in body
    assert body["platform"] == PLATFORM_ID
    assert any("extras.roles not found" in rec.message for rec in caplog.records)


def test_mgmt0_interface_created_when_missing(
    rsps: responses.RequestsMock, client: NautobotClient, payload: dict[str, Any]
) -> None:
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": PLATFORM_ID, "name": "cisco_ios"},
        role={"id": ROLE_ID, "name": "router"},
        primary_ip4={"id": IP_ID, "address": "10.50.0.20/32"},
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/platforms/",
        json=_paginated([{"id": PLATFORM_ID, "name": "cisco_ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/extras/roles/",
        json=_paginated([{"id": ROLE_ID, "name": "router"}]),
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/interfaces/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NAUTOBOT_URL}/api/dcim/interfaces/",
        json={
            "id": IFACE_ID,
            "name": "mgmt0",
            "device": {"id": DEVICE_ID},
            "mac_address": "aa:bb:cc:11:22:33",
        },
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/prefixes/",
        json=_paginated([{"id": PREFIX_ID, "prefix": "10.50.0.0/24"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/ip-addresses/",
        json=_paginated([{"id": IP_ID, "address": "10.50.0.20/32"}]),
    )

    client.upsert_device(payload)

    post = _find_call(rsps, "POST", "/api/dcim/interfaces/")
    body = json.loads(post.request.body)
    assert body["name"] == "mgmt0"
    assert body["type"] == "virtual"
    assert body["device"] == DEVICE_ID
    assert body["mac_address"] == "aa:bb:cc:11:22:33"
    assert body["status"] == STATUS_ID


def test_mgmt0_interface_reused_when_present(
    rsps: responses.RequestsMock, client: NautobotClient, payload: dict[str, Any]
) -> None:
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": PLATFORM_ID, "name": "cisco_ios"},
        role={"id": ROLE_ID, "name": "router"},
        primary_ip4={"id": IP_ID, "address": "10.50.0.20/32"},
    )
    iface = {
        "id": IFACE_ID,
        "name": "mgmt0",
        "device": {"id": DEVICE_ID},
        "mac_address": "aa:bb:cc:11:22:33",
    }
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/platforms/",
        json=_paginated([{"id": PLATFORM_ID, "name": "cisco_ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/extras/roles/",
        json=_paginated([{"id": ROLE_ID, "name": "router"}]),
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/interfaces/", json=_paginated([iface]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/prefixes/",
        json=_paginated([{"id": PREFIX_ID, "prefix": "10.50.0.0/24"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/ip-addresses/",
        json=_paginated([{"id": IP_ID, "address": "10.50.0.20/32"}]),
    )

    client.upsert_device(payload)

    assert _count_calls(rsps, "POST", "/api/dcim/interfaces/") == 0


def test_primary_ip_created_inside_parent_prefix(
    rsps: responses.RequestsMock, client: NautobotClient, payload: dict[str, Any]
) -> None:
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/devices/", json=_paginated([]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/platforms/",
        json=_paginated([{"id": PLATFORM_ID, "name": "cisco_ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/extras/roles/",
        json=_paginated([{"id": ROLE_ID, "name": "router"}]),
    )
    created = _device_json(
        platform={"id": PLATFORM_ID, "name": "cisco_ios"},
        role={"id": ROLE_ID, "name": "router"},
    )
    rsps.add(responses.POST, f"{NAUTOBOT_URL}/api/dcim/devices/", json=created)
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/interfaces/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NAUTOBOT_URL}/api/dcim/interfaces/",
        json={
            "id": IFACE_ID,
            "name": "mgmt0",
            "device": {"id": DEVICE_ID},
            "mac_address": "aa:bb:cc:11:22:33",
        },
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/prefixes/",
        json=_paginated([{"id": PREFIX_ID, "prefix": "10.50.0.0/24"}]),
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/ipam/ip-addresses/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NAUTOBOT_URL}/api/ipam/ip-addresses/",
        json={"id": IP_ID, "address": "10.50.0.20/32"},
    )
    rsps.add(
        responses.PATCH,
        f"{NAUTOBOT_URL}/api/dcim/devices/{DEVICE_ID}/",
        json=_device_json(primary_ip4={"id": IP_ID, "address": "10.50.0.20/32"}),
    )

    client.upsert_device(payload)

    ip_post = _find_call(rsps, "POST", "/api/ipam/ip-addresses/")
    ip_body = json.loads(ip_post.request.body)
    assert ip_body["address"] == "10.50.0.20/32"
    assert ip_body["parent"] == PREFIX_ID
    assert ip_body["status"] == STATUS_ID
    assert ip_body["assigned_object_type"] == "dcim.interface"
    assert ip_body["assigned_object_id"] == IFACE_ID

    dev_patch = _find_call(rsps, "PATCH", f"/api/dcim/devices/{DEVICE_ID}/")
    dev_body = json.loads(dev_patch.request.body)
    assert dev_body == {"primary_ip4": IP_ID}


def test_primary_ip_skipped_with_warn_when_no_parent_prefix(
    rsps: responses.RequestsMock,
    client: NautobotClient,
    payload: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": PLATFORM_ID, "name": "cisco_ios"},
        role={"id": ROLE_ID, "name": "router"},
    )
    iface = {
        "id": IFACE_ID,
        "name": "mgmt0",
        "device": {"id": DEVICE_ID},
        "mac_address": "aa:bb:cc:11:22:33",
    }
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/platforms/",
        json=_paginated([{"id": PLATFORM_ID, "name": "cisco_ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/extras/roles/",
        json=_paginated([{"id": ROLE_ID, "name": "router"}]),
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/interfaces/", json=_paginated([iface]))
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/ipam/prefixes/", json=_paginated([]))

    with caplog.at_level("WARNING"):
        client.upsert_device(payload)

    assert _count_calls(rsps, "POST", "/api/ipam/ip-addresses/") == 0
    assert _count_calls(rsps, "PATCH", f"/api/dcim/devices/{DEVICE_ID}/") == 0
    assert any("no parent prefix" in rec.message for rec in caplog.records)


def test_primary_ip_idempotent_when_already_attached(
    rsps: responses.RequestsMock, client: NautobotClient, payload: dict[str, Any]
) -> None:
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": PLATFORM_ID, "name": "cisco_ios"},
        role={"id": ROLE_ID, "name": "router"},
        primary_ip4={"id": IP_ID, "address": "10.50.0.20/32"},
    )
    iface = {
        "id": IFACE_ID,
        "name": "mgmt0",
        "device": {"id": DEVICE_ID},
        "mac_address": "aa:bb:cc:11:22:33",
    }
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/platforms/",
        json=_paginated([{"id": PLATFORM_ID, "name": "cisco_ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/extras/roles/",
        json=_paginated([{"id": ROLE_ID, "name": "router"}]),
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/interfaces/", json=_paginated([iface]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/prefixes/",
        json=_paginated([{"id": PREFIX_ID, "prefix": "10.50.0.0/24"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/ip-addresses/",
        json=_paginated([{"id": IP_ID, "address": "10.50.0.20/32"}]),
    )

    client.upsert_device(payload)

    assert _count_calls(rsps, "POST", "/api/ipam/ip-addresses/") == 0
    assert _count_calls(rsps, "PATCH", f"/api/dcim/devices/{DEVICE_ID}/") == 0


def test_lookup_query_carries_identity_key(
    rsps: responses.RequestsMock, client: NautobotClient, payload: dict[str, Any]
) -> None:
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": PLATFORM_ID, "name": "cisco_ios"},
        role={"id": ROLE_ID, "name": "router"},
        primary_ip4={"id": IP_ID, "address": "10.50.0.20/32"},
    )
    iface = {
        "id": IFACE_ID,
        "name": "mgmt0",
        "device": {"id": DEVICE_ID},
        "mac_address": "aa:bb:cc:11:22:33",
    }
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/dcim/platforms/",
        json=_paginated([{"id": PLATFORM_ID, "name": "cisco_ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/extras/roles/",
        json=_paginated([{"id": ROLE_ID, "name": "router"}]),
    )
    rsps.add(responses.GET, f"{NAUTOBOT_URL}/api/dcim/interfaces/", json=_paginated([iface]))
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/prefixes/",
        json=_paginated([{"id": PREFIX_ID, "prefix": "10.50.0.0/24"}]),
    )
    rsps.add(
        responses.GET,
        f"{NAUTOBOT_URL}/api/ipam/ip-addresses/",
        json=_paginated([{"id": IP_ID, "address": "10.50.0.20/32"}]),
    )

    client.upsert_device(payload)

    lookup = next(c for c in rsps.calls if urlparse(c.request.url).path == "/api/dcim/devices/")
    qs = parse_qs(urlparse(lookup.request.url).query)
    assert qs["cf_rastreo_identity_key"] == ["mac:aa:bb:cc:11:22:33"]
