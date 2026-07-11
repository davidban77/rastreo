"""Translate a rastreo DeviceRecord into an Infrahub RastreoDevice payload.

The output is a dict of Infrahub attribute names to scalar values, matching
the shape `client.create(kind="RastreoDevice", data=<payload>, ...)` expects.
Infrahub accepts either `{attr: value}` or `{attr: {"value": value}}` — this
mapper produces the scalar form for readability.

A `InfrahubPayload` is deliberately a plain dict, not a Pydantic model — every
key on it is either a RastreoDevice attribute or a well-known passthrough for
the client layer.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from .models import DeviceRecord

InfrahubPayload = dict[str, Any]


class MappingError(ValueError):
    """Raised when a record cannot be mapped to a valid Infrahub payload."""


def map_device_record(record: DeviceRecord) -> InfrahubPayload:
    """Return the Infrahub attribute payload for one DeviceRecord.

    The caller decides whether the payload is used for `create` or `update`.
    `identity_key` is included in both — Infrahub rejects duplicates via the
    unique attribute constraint declared in the schema.
    """
    if not record.mgmt_ip:
        raise MappingError(
            f"record {record.identity_key!r} has no mgmt_ip; cannot map to Infrahub device"
        )

    _validate_ip(record.mgmt_ip)

    payload: InfrahubPayload = {
        "identity_key": record.identity_key,
        "mgmt_ip": record.mgmt_ip,
        "confidence": f"{record.confidence:.2f}",
        "last_seen": record.last_seen.isoformat().replace("+00:00", "Z"),
        "signals": record.signals,
        "probe_kinds": record.probe_kinds,
        "alt_ips": [alt.model_dump(mode="json") for alt in record.alt_ips],
        "scan_metadata": record.scan_metadata.model_dump(mode="json"),
    }

    if record.mac is not None:
        payload["mac"] = record.mac

    if record.platform is not None:
        payload["platform"] = record.platform.strip()

    if record.os_version is not None:
        payload["os_version"] = record.os_version

    if record.ssh_version is not None:
        payload["ssh_version"] = record.ssh_version

    if record.http_server is not None:
        payload["http_server"] = record.http_server

    if record.http_version is not None:
        payload["http_version"] = record.http_version

    if record.role is not None:
        payload["role"] = record.role.strip()

    return payload


def _validate_ip(address: str) -> None:
    try:
        ipaddress.ip_address(address)
    except ValueError as exc:
        raise MappingError(f"mgmt_ip {address!r} is not a valid IP address") from exc
