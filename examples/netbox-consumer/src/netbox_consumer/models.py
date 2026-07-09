"""Pydantic models for the subset of DeviceRecord this consumer uses.

The rastreo DeviceRecord schema is authoritative and lives at
`schemas/device-record-v1.json`. This module models only the fields the NetBox
mapper reads; unknown fields are ignored so rastreo can extend the record
without breaking the consumer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScanMetadata(BaseModel):
    """Per-scan provenance stamped by rastreo at scan entry."""

    model_config = ConfigDict(extra="ignore")

    scan_id: str
    initiated_at: datetime
    scenario_name: str | None = None
    source_config_hash: str | None = None


class AltIp(BaseModel):
    """Additional IP merged into the DeviceRecord by the identity fuser."""

    model_config = ConfigDict(extra="ignore")

    address: str
    role: str | None = None
    responded_via: list[str] = Field(default_factory=list)


class DeviceRecord(BaseModel):
    """The subset of `DeviceRecord` the NetBox reconciler reads.

    `signals` is kept as `list[dict]` because each signal is a rastreo-tagged
    single-key object (for example `{"OpenPort": 22}`). The mapper writes the
    raw list into the `rastreo_signals` custom field verbatim; nothing here
    needs to interpret the tag.
    """

    model_config = ConfigDict(extra="ignore")

    schema_version: str
    schema_id: str
    identity_key: str
    last_seen: datetime
    confidence: float
    signals: list[dict[str, Any]] = Field(default_factory=list)
    probe_kinds: list[str] = Field(default_factory=list)
    mgmt_ip: str | None = None
    mac: str | None = None
    manufacturer: str | None = None
    platform: str | None = None
    os_version: str | None = None
    role: str | None = None
    alt_ips: list[AltIp] = Field(default_factory=list)
    possible_alias_of: str | None = None
    scan_metadata: ScanMetadata
