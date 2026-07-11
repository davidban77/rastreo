"""Thin pynetbox wrapper for the reference reconciler.

`upsert_device` is the only entry point. It looks up the device by the
`rastreo_identity_key` custom field, creates it (with mgmt interface + IP)
on first sight, and otherwise patches only fields that changed. Missing
platform/role FKs are logged and skipped rather than raising, so the
device is still upserted with its custom fields intact.
"""

from __future__ import annotations

import logging
from typing import Any

import pynetbox
from pynetbox.core.response import Record

from .mapper import NetBoxPayload

logger = logging.getLogger(__name__)


class NetBoxClient:
    """Reconciler-shaped view of the pynetbox API."""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        default_device_type: str,
        default_site: str,
        default_device_role: str,
        verify_tls: bool = True,
        timeout_seconds: int = 30,
    ) -> None:
        self._api = pynetbox.api(url, token=token)
        self._api.http_session.verify = verify_tls
        self._api.http_session.timeout = timeout_seconds
        self._default_device_type_id = self._require("device_types", "model", default_device_type)
        self._default_site_id = self._require("sites", "name", default_site)
        self._default_role_id = self._require("device_roles", "name", default_device_role)

    def _require(self, path: str, field: str, value: str) -> int:
        endpoint = getattr(self._api.dcim, path)
        record = endpoint.get(**{field: value})
        if record is None:
            raise RuntimeError(
                f"required NetBox dcim.{path} with {field}={value!r} not found; "
                "run the bootstrap first or set an existing value"
            )
        return record.id

    def upsert_device(self, payload: NetBoxPayload) -> Record:
        identity_key: str = payload["custom_fields"]["rastreo_identity_key"]
        existing = self._api.dcim.devices.get(cf_rastreo_identity_key=identity_key)

        if existing is None:
            logger.info("creating device", extra={"identity_key": identity_key})
            device = self._create(payload)
        else:
            device = self._patch(existing, payload, identity_key)

        self._attach_mgmt_ip(device, payload)
        return device

    def _create(self, payload: NetBoxPayload) -> Record:
        body: dict[str, Any] = {
            "name": payload["custom_fields"]["rastreo_identity_key"],
            "device_type": self._default_device_type_id,
            "site": self._default_site_id,
            "role": self._default_role_id,
            "custom_fields": payload["custom_fields"],
        }
        platform = self._lookup("platforms", payload.get("platform"))
        if platform is not None:
            body["platform"] = platform
        role = self._lookup("device_roles", payload.get("role"))
        if role is not None:
            body["role"] = role
        return self._api.dcim.devices.create(**body)

    def _patch(self, device: Record, payload: NetBoxPayload, identity_key: str) -> Record:
        update: dict[str, Any] = {}

        merged = dict(device.custom_fields or {})
        for key, value in payload["custom_fields"].items():
            if key == "rastreo_identity_key":
                continue
            if merged.get(key) != value:
                merged[key] = value
        if merged != (device.custom_fields or {}):
            update["custom_fields"] = merged

        platform = self._lookup("platforms", payload.get("platform"))
        if platform is not None and _fk_id(device.platform) != platform:
            update["platform"] = platform

        role = self._lookup("device_roles", payload.get("role"))
        if role is not None and _fk_id(device.role) != role:
            update["role"] = role

        if not update:
            logger.debug("no-op", extra={"identity_key": identity_key})
            return device

        device.update(update)
        return device

    def _attach_mgmt_ip(self, device: Record, payload: NetBoxPayload) -> None:
        mgmt_ip: str | None = payload.get("_mgmt_ip")
        if not mgmt_ip:
            return
        family: int = payload["_mgmt_ip_family"]
        mac: str | None = payload.get("_mac")

        iface = self._api.dcim.interfaces.get(device_id=device.id, name="mgmt0")
        if iface is None:
            iface = self._api.dcim.interfaces.create(
                device=device.id, name="mgmt0", type="virtual", mac_address=mac
            )
        elif mac and iface.mac_address != mac:
            iface.update({"mac_address": mac})

        address = f"{mgmt_ip}/{32 if family == 4 else 128}"
        ip = self._api.ipam.ip_addresses.get(address=address)
        if ip is None:
            ip = self._api.ipam.ip_addresses.create(
                address=address,
                assigned_object_type="dcim.interface",
                assigned_object_id=iface.id,
            )

        primary_field = "primary_ip4" if family == 4 else "primary_ip6"
        if _fk_id(getattr(device, primary_field, None)) != ip.id:
            device.update({primary_field: ip.id})

    def _lookup(self, endpoint: str, slug: str | None) -> int | None:
        if slug is None:
            return None
        record = getattr(self._api.dcim, endpoint).get(slug=slug)
        if record is None:
            logger.warning(f"{endpoint} not found in NetBox", extra={"slug": slug})
            return None
        return record.id


def _fk_id(fk: Any) -> int | None:
    return None if fk is None else getattr(fk, "id", None)
