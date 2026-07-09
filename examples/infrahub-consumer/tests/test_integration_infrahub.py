"""Integration test skeleton against a live Infrahub.

Runs only when explicitly opted-in via `-m integration`. Requires an
Infrahub instance reachable at `INFRAHUB_URL` with an API token that has
`RastreoDevice` read+write and branch merge permission, and the reference
schema loaded on the target branch.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def integration_env() -> None:
    if not os.environ.get("INFRAHUB_URL") or not os.environ.get("INFRAHUB_TOKEN"):
        pytest.skip("INFRAHUB_URL and INFRAHUB_TOKEN must be set for integration tests")


def test_create_then_update_is_idempotent(integration_env: None, full_record_payload: dict) -> None:
    """Round-trip: create a device, run the same record again, assert no drift.

    Left as a skeleton — a real test would spin up an Infrahub test instance
    or use a shared staging box, load the schema, and clean up the device
    after the run.
    """
    pytest.skip("integration test skeleton; implement against your Infrahub instance")
