"""Integration test skeleton against a live Nautobot.

Runs only when explicitly opted-in via `-m integration`. Requires a
Nautobot instance reachable at `NAUTOBOT_URL` with an API token that has
`dcim.Device` read+write and the `rastreo_*` custom fields configured.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def integration_env() -> None:
    if not os.environ.get("NAUTOBOT_URL") or not os.environ.get("NAUTOBOT_TOKEN"):
        pytest.skip("NAUTOBOT_URL and NAUTOBOT_TOKEN must be set for integration tests")


def test_create_then_update_is_idempotent(integration_env: None, full_record_payload: dict) -> None:
    """Round-trip: create a device, run the same record again, assert no drift.

    Left as a skeleton — a real test would spin up a Nautobot test instance
    or use a shared staging box, and clean up the device after the run.
    """
    pytest.skip("integration test skeleton; implement against your Nautobot instance")
