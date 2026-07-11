"""Thin pynautobot wrapper for the reference reconciler.

`upsert_device` is the only per-record entry point. It looks up the device by
the `rastreo_identity_key` custom field, creates it (with mgmt interface + IP
if a parent prefix exists) on first sight, and otherwise patches only fields
that changed. Missing platform/role names are logged and skipped rather than
raising, so the device is still upserted with its custom fields intact.

Nautobot 2.x requires `device_type`, `location`, and `status` on every Device.
The client resolves these three defaults once at construction time from the
config and hard-fails if any is missing — a reference consumer should not
paper over misconfiguration.
"""

from __future__ import annotations

import logging
from typing import Any

import pynautobot
from pynautobot.core.response import Record

from .mapper import NautobotPayload

logger = logging.getLogger(__name__)


class NautobotLookupError(RuntimeError):
    """Raised when a required Nautobot default (device_type / location / status) is missing."""


class NautobotClient:
    """Reconciler-shaped view of the pynautobot API."""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        default_device_type: str,
        default_location: str,
        default_device_status: str,
        default_device_role: str,
        verify_tls: bool = True,
        timeout_seconds: int = 30,
    ) -> None:
        self._api = pynautobot.api(url, token=token)
        self._api.http_session.verify = verify_tls
        self._api.http_session.timeout = timeout_seconds

        self._default_device_type_id = self._require("dcim.device_types", default_device_type)
        self._default_location_id = self._require("dcim.locations", default_location)
        self._default_status_id = self._require("extras.statuses", default_device_status)
        self._default_role_id = self._require("extras.roles", default_device_role)

    def upsert_device(self, payload: NautobotPayload) -> Record:
        identity_key: str = payload["custom_fields"]["rastreo_identity_key"]
        existing = self._api.dcim.devices.get(cf_rastreo_identity_key=identity_key)

        if existing is None:
            logger.info("creating device", extra={"identity_key": identity_key})
            device = self._create(payload)
        else:
            device = self._patch(existing, payload, identity_key)

        self._attach_mgmt_ip(device, payload)
        return device

    def _create(self, payload: NautobotPayload) -> Record:
        body: dict[str, Any] = {
            "name": payload["custom_fields"]["rastreo_identity_key"],
            "device_type": self._default_device_type_id,
            "location": self._default_location_id,
            "status": self._default_status_id,
            "role": self._default_role_id,
            "custom_fields": payload["custom_fields"],
        }
        platform = self._lookup("dcim.platforms", payload.get("platform"))
        if platform is not None:
            body["platform"] = platform
        role = self._lookup("extras.roles", payload.get("role"))
        if role is not None:
            body["role"] = role
        return self._api.dcim.devices.create(**body)

    def _patch(self, device: Record, payload: NautobotPayload, identity_key: str) -> Record:
        update: dict[str, Any] = {}

        merged = dict(device.custom_fields or {})
        for key, value in payload["custom_fields"].items():
            if key == "rastreo_identity_key":
                continue
            if merged.get(key) != value:
                merged[key] = value
        if merged != (device.custom_fields or {}):
            update["custom_fields"] = merged

        platform = self._lookup("dcim.platforms", payload.get("platform"))
        if platform is not None and _fk_id(device.platform) != platform:
            update["platform"] = platform

        role = self._lookup("extras.roles", payload.get("role"))
        if role is not None and _fk_id(device.role) != role:
            update["role"] = role

        if not update:
            logger.debug("no-op", extra={"identity_key": identity_key})
            return device

        device.update(update)
        return device

    def _attach_mgmt_ip(self, device: Record, payload: NautobotPayload) -> None:
        mgmt_ip: str | None = payload.get("_mgmt_ip")
        if not mgmt_ip:
            return
        family: int = payload["_mgmt_ip_family"]
        mac: str | None = payload.get("_mac")

        iface = self._api.dcim.interfaces.get(device_id=device.id, name="mgmt0")
        if iface is None:
            iface = self._api.dcim.interfaces.create(
                device=device.id,
                name="mgmt0",
                type="virtual",
                status=self._default_status_id,
                mac_address=mac,
            )
        elif mac and iface.mac_address != mac:
            iface.update({"mac_address": mac})

        parent_prefix = self._api.ipam.prefixes.get(contains=mgmt_ip)
        if parent_prefix is None:
            logger.warning(
                "no parent prefix found; skipping primary IP attach",
                extra={
                    "identity_key": payload["custom_fields"]["rastreo_identity_key"],
                    "mgmt_ip": mgmt_ip,
                },
            )
            return

        address = f"{mgmt_ip}/{32 if family == 4 else 128}"
        ip = self._api.ipam.ip_addresses.get(address=address)
        if ip is None:
            ip = self._api.ipam.ip_addresses.create(
                address=address,
                parent=parent_prefix.id,
                status=self._default_status_id,
                assigned_object_type="dcim.interface",
                assigned_object_id=iface.id,
            )

        primary_field = "primary_ip4" if family == 4 else "primary_ip6"
        if _fk_id(getattr(device, primary_field, None)) != ip.id:
            device.update({primary_field: ip.id})

    # Nautobot 2.x endpoints that don't have a `name` field — key the lookup on
    # the display field the API actually filters by.
    _LOOKUP_FIELD = {
        "dcim.device_types": "model",
    }

    def _lookup(self, path: str, name: str | None) -> str | None:
        """Return the record ID for ``name`` on ``path``, or None with a WARN."""
        if name is None:
            return None
        endpoint = self._endpoint(path)
        record = endpoint.get(**{self._LOOKUP_FIELD.get(path, "name"): name})
        if record is None:
            logger.warning(f"{path} not found in Nautobot", extra={"lookup_name": name})
            return None
        return record.id

    def _require(self, path: str, name: str) -> str:
        """Return the record ID for ``name`` on ``path``, or raise NautobotLookupError."""
        endpoint = self._endpoint(path)
        record = endpoint.get(**{self._LOOKUP_FIELD.get(path, "name"): name})
        if record is None:
            raise NautobotLookupError(
                f"required Nautobot {path} named {name!r} was not found; "
                "create it in Nautobot or set a name that exists"
            )
        return record.id

    def _endpoint(self, path: str) -> Any:
        app, name = path.split(".", 1)
        return getattr(getattr(self._api, app), name)


def _fk_id(fk: Any) -> str | None:
    return None if fk is None else getattr(fk, "id", None)
