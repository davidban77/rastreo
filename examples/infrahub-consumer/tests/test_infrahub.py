"""Infrahub wrapper tests: mock the async infrahub-sdk client.

Every SDK call is mocked with `AsyncMock`. The mocks let us assert on
call arguments — the wrapper's job is to route arguments correctly,
not to talk to a live Infrahub. Tests marked ``asyncio_mode = "auto"``
in ``pyproject.toml`` so ``async def test_*`` functions run without
per-test decorators.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from infrahub_consumer.infrahub import (
    DEVICE_KIND,
    InfrahubClientWrapper,
    InfrahubSchemaMissingError,
)
from infrahub_consumer.mapper import map_device_record
from infrahub_consumer.models import DeviceRecord

BRANCH = "rastreo-updates"


def _make_wrapper(
    *,
    branch: str = BRANCH,
    auto_merge: bool = False,
    branches: dict[str, Any] | None = None,
    schemas: dict[str, Any] | None = None,
    existing_device: Any = None,
) -> tuple[InfrahubClientWrapper, MagicMock]:
    """Return a wrapper whose internal SDK client is a MagicMock with async stubs."""
    wrapper = InfrahubClientWrapper(
        url="https://infrahub.example.com",
        token="test-token",
        branch=branch,
        auto_merge=auto_merge,
    )
    client = MagicMock()
    client.branch = MagicMock()
    client.branch.all = AsyncMock(
        return_value=branches if branches is not None else {BRANCH: object()}
    )
    client.branch.create = AsyncMock()
    client.branch.merge = AsyncMock()
    client.schema = MagicMock()
    client.schema.all = AsyncMock(
        return_value=schemas if schemas is not None else {DEVICE_KIND: object()}
    )
    client.get = AsyncMock(return_value=existing_device)

    async def _create(*, kind: str, branch: str, data: dict[str, Any]) -> MagicMock:
        node = MagicMock()
        node.save = AsyncMock()
        node.update = AsyncMock()
        node._created_data = data
        node._created_kind = kind
        node._created_branch = branch
        return node

    client.create = AsyncMock(side_effect=_create)
    wrapper._client = client  # noqa: SLF001 - test-only stub injection
    return wrapper, client


def _payload(record_payload: dict[str, Any]) -> dict[str, Any]:
    return map_device_record(DeviceRecord.model_validate(record_payload))


def _stub_existing_node(payload: dict[str, Any]) -> MagicMock:
    """Return a MagicMock shaped like an InfrahubNode with attributes matching ``payload``."""
    node = MagicMock()
    node.save = AsyncMock()
    node.update = AsyncMock()
    for attr_name, value in payload.items():
        attr = MagicMock()
        attr.value = value
        setattr(node, attr_name, attr)
    return node


async def test_verify_schema_missing_raises_actionable_error(
    full_record_payload: dict[str, Any],
) -> None:
    wrapper, _ = _make_wrapper(schemas={})
    with pytest.raises(InfrahubSchemaMissingError) as excinfo:
        await wrapper.verify_schema()
    assert "infrahubctl schema load" in str(excinfo.value)
    assert BRANCH in str(excinfo.value)


async def test_verify_schema_present_returns_none() -> None:
    wrapper, client = _make_wrapper()
    await wrapper.verify_schema()
    client.schema.all.assert_awaited_once_with(branch=BRANCH)


async def test_ensure_branch_creates_when_missing() -> None:
    wrapper, client = _make_wrapper(branches={"main": object()})
    await wrapper.ensure_branch()
    client.branch.create.assert_awaited_once_with(branch_name=BRANCH)


async def test_ensure_branch_no_op_when_present() -> None:
    wrapper, client = _make_wrapper(branches={"main": object(), BRANCH: object()})
    await wrapper.ensure_branch()
    client.branch.create.assert_not_awaited()


async def test_ensure_branch_skips_when_writing_to_main() -> None:
    wrapper, client = _make_wrapper(branch="main", branches={"main": object()})
    await wrapper.ensure_branch()
    client.branch.all.assert_not_awaited()
    client.branch.create.assert_not_awaited()


async def test_create_path_calls_client_create_with_expected_args(
    full_record_payload: dict[str, Any],
) -> None:
    wrapper, client = _make_wrapper(existing_device=None)
    payload = _payload(full_record_payload)
    node = await wrapper.upsert_device(payload)

    client.create.assert_awaited_once()
    kwargs = client.create.await_args.kwargs
    assert kwargs["kind"] == DEVICE_KIND
    assert kwargs["branch"] == BRANCH
    assert kwargs["data"]["identity_key"] == "mac:aa:bb:cc:11:22:33"
    assert kwargs["data"]["platform"] == "cisco_ios"
    assert kwargs["data"]["role"] == "router"
    node.save.assert_awaited_once()


async def test_lookup_query_carries_identity_key(
    full_record_payload: dict[str, Any],
) -> None:
    wrapper, client = _make_wrapper(existing_device=None)
    payload = _payload(full_record_payload)
    await wrapper.upsert_device(payload)

    kwargs = client.get.await_args.kwargs
    assert kwargs["kind"] == DEVICE_KIND
    assert kwargs["branch"] == BRANCH
    assert kwargs["identity_key__value"] == "mac:aa:bb:cc:11:22:33"
    assert kwargs["raise_when_missing"] is False


async def test_update_is_noop_when_all_attributes_match(
    full_record_payload: dict[str, Any],
) -> None:
    payload = _payload(full_record_payload)
    existing = _stub_existing_node(payload)
    wrapper, client = _make_wrapper(existing_device=existing)

    await wrapper.upsert_device(payload)

    client.create.assert_not_awaited()
    existing.update.assert_not_awaited()


async def test_update_patches_only_changed_attribute(
    full_record_payload: dict[str, Any],
) -> None:
    payload = _payload(full_record_payload)
    existing = _stub_existing_node(payload)
    existing.platform.value = "cisco_nxos"
    wrapper, client = _make_wrapper(existing_device=existing)

    await wrapper.upsert_device(payload)

    client.create.assert_not_awaited()
    existing.update.assert_awaited_once()
    assert existing.platform.value == "cisco_ios"


async def test_auto_merge_false_does_not_merge_after_upsert(
    full_record_payload: dict[str, Any],
) -> None:
    wrapper, client = _make_wrapper(existing_device=None, auto_merge=False)
    await wrapper.upsert_device(_payload(full_record_payload))
    client.branch.merge.assert_not_awaited()


async def test_auto_merge_true_merges_branch_after_upsert(
    full_record_payload: dict[str, Any],
) -> None:
    wrapper, client = _make_wrapper(existing_device=None, auto_merge=True)
    await wrapper.upsert_device(_payload(full_record_payload))
    client.branch.merge.assert_awaited_once_with(branch_name=BRANCH)


async def test_auto_merge_skipped_when_branch_is_main(
    full_record_payload: dict[str, Any],
) -> None:
    wrapper, client = _make_wrapper(branch="main", auto_merge=True, existing_device=None)
    await wrapper.upsert_device(_payload(full_record_payload))
    client.branch.merge.assert_not_awaited()


async def test_signals_probe_kinds_and_alt_ips_pass_through_verbatim(
    merged_record_payload: dict[str, Any],
) -> None:
    wrapper, client = _make_wrapper(existing_device=None)
    payload = _payload(merged_record_payload)

    await wrapper.upsert_device(payload)

    data = client.create.await_args.kwargs["data"]
    assert data["signals"] == payload["signals"]
    assert data["probe_kinds"] == payload["probe_kinds"]
    assert data["alt_ips"] == payload["alt_ips"]


async def test_boot_sequence_verifies_schema(
    full_record_payload: dict[str, Any],
) -> None:
    """The consumer boot sequence must call verify_schema after ensure_branch."""
    wrapper, client = _make_wrapper()
    await wrapper.ensure_branch()
    await wrapper.verify_schema()
    client.schema.all.assert_awaited_once_with(branch=BRANCH)
