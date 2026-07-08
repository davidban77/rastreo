"""Integration test skeleton against a live NetBox.

Runs only when explicitly opted-in via `-m integration`. Requires a
NetBox instance reachable at `NETBOX_URL` with an API token that has
`dcim.Device` read+write and the `rastreo_*` custom fields configured.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def integration_env() -> None:
    if not os.environ.get("NETBOX_URL") or not os.environ.get("NETBOX_TOKEN"):
        pytest.skip("NETBOX_URL and NETBOX_TOKEN must be set for integration tests")


def test_create_then_update_is_idempotent(integration_env: None, full_record_payload: dict) -> None:
    """Round-trip: create a device, run the same record again, assert no drift.

    Left as a skeleton — a real test would spin up a NetBox test instance
    or use a shared staging box, and clean up the device after the run.
    """
    pytest.skip("integration test skeleton; implement against your NetBox instance")
