"""Translate a rastreo DeviceRecord into a NetBox upsert payload.

The output is a dict of NetBox `dcim.Device` field names to values, plus a
`custom_fields` sub-dict. Slug-shaped foreign keys (platform, role) are left
as strings; the NetBox client layer looks them up.

A `NetBoxPayload` is deliberately a plain dict, not a Pydantic model — every
field on it is either a NetBox schema attribute or a well-known rastreo
custom field. Modeling it as Pydantic would force us to invent Python names
for NetBox fields that a reader already knows.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .models import DeviceRecord

NetBoxPayload = dict[str, Any]


class MappingError(ValueError):
    """Raised when a record cannot be mapped to a valid NetBox payload."""


def map_device_record(record: DeviceRecord) -> NetBoxPayload:
    """Return the NetBox payload for one DeviceRecord.

    The caller decides whether the payload is used for `create` or `update`.
    Only the `identity_key` custom field is create-only; the NetBox client
    strips it out before update.
    """
    if not record.mgmt_ip:
        raise MappingError(
            f"record {record.identity_key!r} has no mgmt_ip; cannot map to NetBox device"
        )

    payload: NetBoxPayload = {
        "custom_fields": {
            "rastreo_identity_key": record.identity_key,
            "rastreo_last_seen": record.last_seen.isoformat().replace("+00:00", "Z"),
            "rastreo_confidence": record.confidence,
            "rastreo_signals": record.signals,
            "rastreo_probe_kinds": record.probe_kinds,
            "rastreo_alt_ips": [alt.model_dump(mode="json") for alt in record.alt_ips],
            "rastreo_scan_metadata": record.scan_metadata.model_dump(mode="json"),
        },
    }

    if record.os_version is not None:
        payload["custom_fields"]["rastreo_os_version"] = record.os_version

    if record.platform is not None:
        payload["platform"] = _slugify(record.platform)

    if record.role is not None:
        payload["role"] = _slugify(record.role)

    payload["_mgmt_ip"] = record.mgmt_ip
    payload["_mgmt_ip_family"] = _ip_family(record.mgmt_ip)
    payload["_mac"] = record.mac

    return payload


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(value: str) -> str:
    """NetBox slug: lowercase, alphanumerics + hyphen, no leading/trailing hyphen."""
    return _SLUG_RE.sub("-", value.lower()).strip("-")


def _ip_family(address: str) -> int:
    """Return 4 or 6 for a valid IPv4 or IPv6 mgmt_ip."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise MappingError(f"mgmt_ip {address!r} is not a valid IP address") from exc
    return parsed.version
