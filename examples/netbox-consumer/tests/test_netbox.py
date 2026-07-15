"""NetBox client tests: mock pynetbox HTTP calls with ``responses``.

pynetbox uses ``requests`` under the hood, so ``responses`` is the correct
HTTP mocking layer here — it intercepts requests at the transport level and
lets us assert on the wire shape of what the reconciler sends to NetBox.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import responses

from netbox_consumer.mapper import map_device_record
from netbox_consumer.models import DeviceRecord
from netbox_consumer.netbox import NetBoxClient

NETBOX_URL = "https://netbox.example.com"

DEVICE_TYPE_ID = 1
SITE_ID = 2
DEFAULT_ROLE_ID = 4


@pytest.fixture
def rsps() -> Iterator[responses.RequestsMock]:
    """Activate ``responses`` for a test and return the registry."""
    with responses.RequestsMock() as mock:
        yield mock


def _register_defaults(rsps: responses.RequestsMock) -> None:
    """Register the startup-lookup responses every client construction needs."""
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/device-types/",
        json=_paginated([{"id": DEVICE_TYPE_ID, "model": "generic-router"}]),
    )
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/sites/",
        json=_paginated([{"id": SITE_ID, "name": "discovery"}]),
    )
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/device-roles/",
        json=_paginated([{"id": DEFAULT_ROLE_ID, "slug": "discovered"}]),
    )


@pytest.fixture
def client(rsps: responses.RequestsMock) -> NetBoxClient:
    """A NetBoxClient pointed at the mocked base URL, with defaults resolved."""
    _register_defaults(rsps)
    return NetBoxClient(
        NETBOX_URL,
        token="test-token",
        default_device_type="generic-router",
        default_site="discovery",
        default_device_role="discovered",
    )


@pytest.fixture
def payload(full_record_payload: dict[str, Any]) -> dict[str, Any]:
    """A NetBox payload derived from the canonical full-record fixture."""
    return map_device_record(DeviceRecord.model_validate(full_record_payload))


def _paginated(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {"count": len(results), "next": None, "previous": None, "results": results}


def _device_json(
    *,
    device_id: int = 42,
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


def test_create_path_posts_device_with_platform_and_role(
    rsps: responses.RequestsMock, client: NetBoxClient, payload: dict[str, Any]
) -> None:
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/devices/", json=_paginated([]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/platforms/",
        json=_paginated([{"id": 7, "slug": "cisco-ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/device-roles/",
        json=_paginated([{"id": 3, "slug": "router"}]),
    )
    created = _device_json(
        device_id=42,
        platform={"id": 7, "slug": "cisco-ios"},
        role={"id": 3, "slug": "router"},
    )
    rsps.add(responses.POST, f"{NETBOX_URL}/api/dcim/devices/", json=created)
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/interfaces/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NETBOX_URL}/api/dcim/interfaces/",
        json={"id": 55, "name": "mgmt0", "device": {"id": 42}, "mac_address": "aa:bb:cc:11:22:33"},
    )
    rsps.add(responses.GET, f"{NETBOX_URL}/api/ipam/ip-addresses/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NETBOX_URL}/api/ipam/ip-addresses/",
        json={"id": 99, "address": "10.50.0.20/32"},
    )
    rsps.add(
        responses.PATCH,
        f"{NETBOX_URL}/api/dcim/devices/42/",
        json=_device_json(device_id=42, primary_ip4={"id": 99, "address": "10.50.0.20/32"}),
    )

    client.upsert_device(payload)

    post = _find_call(rsps, "POST", "/api/dcim/devices/")
    body = json.loads(post.request.body)
    assert body["name"] == "mac:aa:bb:cc:11:22:33"
    assert body["platform"] == 7
    assert body["role"] == 3
    assert body["custom_fields"]["rastreo_identity_key"] == "mac:aa:bb:cc:11:22:33"


def test_update_is_noop_when_all_fields_match(
    rsps: responses.RequestsMock, client: NetBoxClient, payload: dict[str, Any]
) -> None:
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": 7, "slug": "cisco-ios"},
        role={"id": 3, "slug": "router"},
        primary_ip4={"id": 99, "address": "10.50.0.20/32"},
    )
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/platforms/",
        json=_paginated([{"id": 7, "slug": "cisco-ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/device-roles/",
        json=_paginated([{"id": 3, "slug": "router"}]),
    )
    iface = {"id": 55, "name": "mgmt0", "device": {"id": 42}, "mac_address": "aa:bb:cc:11:22:33"}
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/interfaces/", json=_paginated([iface]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/ipam/ip-addresses/",
        json=_paginated([{"id": 99, "address": "10.50.0.20/32"}]),
    )

    client.upsert_device(payload)

    assert _count_calls(rsps, "PATCH", "/api/dcim/devices/42/") == 0
    assert _count_calls(rsps, "POST", "/api/dcim/devices/") == 0
    assert _count_calls(rsps, "POST", "/api/dcim/interfaces/") == 0
    assert _count_calls(rsps, "POST", "/api/ipam/ip-addresses/") == 0


def test_update_patches_only_changed_platform(
    rsps: responses.RequestsMock, client: NetBoxClient, payload: dict[str, Any]
) -> None:
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": 8, "slug": "cisco-nxos"},
        role={"id": 3, "slug": "router"},
        primary_ip4={"id": 99, "address": "10.50.0.20/32"},
    )
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/platforms/",
        json=_paginated([{"id": 7, "slug": "cisco-ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/device-roles/",
        json=_paginated([{"id": 3, "slug": "router"}]),
    )
    rsps.add(responses.PATCH, f"{NETBOX_URL}/api/dcim/devices/42/", json=existing)
    iface = {"id": 55, "name": "mgmt0", "device": {"id": 42}, "mac_address": "aa:bb:cc:11:22:33"}
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/interfaces/", json=_paginated([iface]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/ipam/ip-addresses/",
        json=_paginated([{"id": 99, "address": "10.50.0.20/32"}]),
    )

    client.upsert_device(payload)

    patch = _find_call(rsps, "PATCH", "/api/dcim/devices/42/")
    body = json.loads(patch.request.body)
    assert body == {"platform": 7}


def test_missing_platform_slug_omits_platform_from_create(
    rsps: responses.RequestsMock,
    client: NetBoxClient,
    payload: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/devices/", json=_paginated([]))
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/platforms/", json=_paginated([]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/device-roles/",
        json=_paginated([{"id": 3, "slug": "router"}]),
    )
    created = _device_json(device_id=42, role={"id": 3, "slug": "router"})
    rsps.add(responses.POST, f"{NETBOX_URL}/api/dcim/devices/", json=created)
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/interfaces/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NETBOX_URL}/api/dcim/interfaces/",
        json={"id": 55, "name": "mgmt0", "device": {"id": 42}, "mac_address": "aa:bb:cc:11:22:33"},
    )
    rsps.add(responses.GET, f"{NETBOX_URL}/api/ipam/ip-addresses/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NETBOX_URL}/api/ipam/ip-addresses/",
        json={"id": 99, "address": "10.50.0.20/32"},
    )
    rsps.add(
        responses.PATCH,
        f"{NETBOX_URL}/api/dcim/devices/42/",
        json=_device_json(device_id=42, primary_ip4={"id": 99, "address": "10.50.0.20/32"}),
    )

    with caplog.at_level("WARNING"):
        client.upsert_device(payload)

    post = _find_call(rsps, "POST", "/api/dcim/devices/")
    body = json.loads(post.request.body)
    assert "platform" not in body
    assert body["role"] == 3
    assert any("platforms not found" in rec.message for rec in caplog.records)


def test_missing_role_slug_uses_default_role(
    rsps: responses.RequestsMock,
    client: NetBoxClient,
    payload: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/devices/", json=_paginated([]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/platforms/",
        json=_paginated([{"id": 7, "slug": "cisco-ios"}]),
    )
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/device-roles/", json=_paginated([]))
    created = _device_json(device_id=42, platform={"id": 7, "slug": "cisco-ios"})
    rsps.add(responses.POST, f"{NETBOX_URL}/api/dcim/devices/", json=created)
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/interfaces/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NETBOX_URL}/api/dcim/interfaces/",
        json={"id": 55, "name": "mgmt0", "device": {"id": 42}, "mac_address": "aa:bb:cc:11:22:33"},
    )
    rsps.add(responses.GET, f"{NETBOX_URL}/api/ipam/ip-addresses/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NETBOX_URL}/api/ipam/ip-addresses/",
        json={"id": 99, "address": "10.50.0.20/32"},
    )
    rsps.add(
        responses.PATCH,
        f"{NETBOX_URL}/api/dcim/devices/42/",
        json=_device_json(device_id=42, primary_ip4={"id": 99, "address": "10.50.0.20/32"}),
    )

    with caplog.at_level("WARNING"):
        client.upsert_device(payload)

    post = _find_call(rsps, "POST", "/api/dcim/devices/")
    body = json.loads(post.request.body)
    assert body["role"] == DEFAULT_ROLE_ID
    assert body["platform"] == 7
    assert any("device_roles not found" in rec.message for rec in caplog.records)


def test_mgmt0_interface_created_when_missing(
    rsps: responses.RequestsMock, client: NetBoxClient, payload: dict[str, Any]
) -> None:
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": 7, "slug": "cisco-ios"},
        role={"id": 3, "slug": "router"},
        primary_ip4={"id": 99, "address": "10.50.0.20/32"},
    )
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/platforms/",
        json=_paginated([{"id": 7, "slug": "cisco-ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/device-roles/",
        json=_paginated([{"id": 3, "slug": "router"}]),
    )
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/interfaces/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NETBOX_URL}/api/dcim/interfaces/",
        json={"id": 55, "name": "mgmt0", "device": {"id": 42}, "mac_address": "aa:bb:cc:11:22:33"},
    )
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/ipam/ip-addresses/",
        json=_paginated([{"id": 99, "address": "10.50.0.20/32"}]),
    )

    client.upsert_device(payload)

    post = _find_call(rsps, "POST", "/api/dcim/interfaces/")
    body = json.loads(post.request.body)
    assert body["name"] == "mgmt0"
    assert body["type"] == "virtual"
    assert body["device"] == 42
    assert body["mac_address"] == "aa:bb:cc:11:22:33"


def test_mgmt0_interface_reused_when_present(
    rsps: responses.RequestsMock, client: NetBoxClient, payload: dict[str, Any]
) -> None:
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": 7, "slug": "cisco-ios"},
        role={"id": 3, "slug": "router"},
        primary_ip4={"id": 99, "address": "10.50.0.20/32"},
    )
    iface = {"id": 55, "name": "mgmt0", "device": {"id": 42}, "mac_address": "aa:bb:cc:11:22:33"}
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/platforms/",
        json=_paginated([{"id": 7, "slug": "cisco-ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/device-roles/",
        json=_paginated([{"id": 3, "slug": "router"}]),
    )
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/interfaces/", json=_paginated([iface]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/ipam/ip-addresses/",
        json=_paginated([{"id": 99, "address": "10.50.0.20/32"}]),
    )

    client.upsert_device(payload)

    assert _count_calls(rsps, "POST", "/api/dcim/interfaces/") == 0


def test_primary_ip_created_and_attached_on_create(
    rsps: responses.RequestsMock, client: NetBoxClient, payload: dict[str, Any]
) -> None:
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/devices/", json=_paginated([]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/platforms/",
        json=_paginated([{"id": 7, "slug": "cisco-ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/device-roles/",
        json=_paginated([{"id": 3, "slug": "router"}]),
    )
    created = _device_json(
        device_id=42,
        platform={"id": 7, "slug": "cisco-ios"},
        role={"id": 3, "slug": "router"},
    )
    rsps.add(responses.POST, f"{NETBOX_URL}/api/dcim/devices/", json=created)
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/interfaces/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NETBOX_URL}/api/dcim/interfaces/",
        json={"id": 55, "name": "mgmt0", "device": {"id": 42}, "mac_address": "aa:bb:cc:11:22:33"},
    )
    rsps.add(responses.GET, f"{NETBOX_URL}/api/ipam/ip-addresses/", json=_paginated([]))
    rsps.add(
        responses.POST,
        f"{NETBOX_URL}/api/ipam/ip-addresses/",
        json={"id": 99, "address": "10.50.0.20/32"},
    )
    rsps.add(
        responses.PATCH,
        f"{NETBOX_URL}/api/dcim/devices/42/",
        json=_device_json(device_id=42, primary_ip4={"id": 99, "address": "10.50.0.20/32"}),
    )

    client.upsert_device(payload)

    ip_post = _find_call(rsps, "POST", "/api/ipam/ip-addresses/")
    ip_body = json.loads(ip_post.request.body)
    assert ip_body["address"] == "10.50.0.20/32"
    assert ip_body["assigned_object_type"] == "dcim.interface"
    assert ip_body["assigned_object_id"] == 55

    dev_patch = _find_call(rsps, "PATCH", "/api/dcim/devices/42/")
    dev_body = json.loads(dev_patch.request.body)
    assert dev_body == {"primary_ip4": 99}


def test_primary_ip_idempotent_when_already_attached(
    rsps: responses.RequestsMock, client: NetBoxClient, payload: dict[str, Any]
) -> None:
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": 7, "slug": "cisco-ios"},
        role={"id": 3, "slug": "router"},
        primary_ip4={"id": 99, "address": "10.50.0.20/32"},
    )
    iface = {"id": 55, "name": "mgmt0", "device": {"id": 42}, "mac_address": "aa:bb:cc:11:22:33"}
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/platforms/",
        json=_paginated([{"id": 7, "slug": "cisco-ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/device-roles/",
        json=_paginated([{"id": 3, "slug": "router"}]),
    )
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/interfaces/", json=_paginated([iface]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/ipam/ip-addresses/",
        json=_paginated([{"id": 99, "address": "10.50.0.20/32"}]),
    )

    client.upsert_device(payload)

    assert _count_calls(rsps, "POST", "/api/ipam/ip-addresses/") == 0
    assert _count_calls(rsps, "PATCH", "/api/dcim/devices/42/") == 0


def test_lookup_query_carries_identity_key(
    rsps: responses.RequestsMock, client: NetBoxClient, payload: dict[str, Any]
) -> None:
    existing_cf = {k: v for k, v in payload["custom_fields"].items() if k != "rastreo_identity_key"}
    existing = _device_json(
        custom_fields=existing_cf,
        platform={"id": 7, "slug": "cisco-ios"},
        role={"id": 3, "slug": "router"},
        primary_ip4={"id": 99, "address": "10.50.0.20/32"},
    )
    iface = {"id": 55, "name": "mgmt0", "device": {"id": 42}, "mac_address": "aa:bb:cc:11:22:33"}
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/devices/", json=_paginated([existing]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/platforms/",
        json=_paginated([{"id": 7, "slug": "cisco-ios"}]),
    )
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/dcim/device-roles/",
        json=_paginated([{"id": 3, "slug": "router"}]),
    )
    rsps.add(responses.GET, f"{NETBOX_URL}/api/dcim/interfaces/", json=_paginated([iface]))
    rsps.add(
        responses.GET,
        f"{NETBOX_URL}/api/ipam/ip-addresses/",
        json=_paginated([{"id": 99, "address": "10.50.0.20/32"}]),
    )

    client.upsert_device(payload)

    lookup = next(c for c in rsps.calls if urlparse(c.request.url).path == "/api/dcim/devices/")
    qs = parse_qs(urlparse(lookup.request.url).query)
    assert qs["cf_rastreo_identity_key"] == ["mac:aa:bb:cc:11:22:33"]
