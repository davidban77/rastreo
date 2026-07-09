"""Thin async infrahub-sdk wrapper for the reference reconciler.

`upsert_device` is the only per-record entry point. It looks up the
`RastreoDevice` by the `identity_key` attribute on the configured branch,
creates it on first sight, and otherwise patches only attributes that changed.
If auto-merge is enabled the branch is merged back to `main` after each
successful upsert; otherwise changes pile up on the branch for review through
Infrahub's Proposed Changes workflow.

The wrapper hard-fails at boot when the `RastreoDevice` schema is not present
on the target branch — a reference consumer should not silently paper over a
missing schema. The error message tells the user the exact
`infrahubctl schema load` command they need.
"""

from __future__ import annotations

import logging
from typing import Any

from infrahub_sdk import Config as InfrahubSdkConfig
from infrahub_sdk import InfrahubClient
from infrahub_sdk.node import InfrahubNode

from .mapper import InfrahubPayload

logger = logging.getLogger(__name__)

DEVICE_KIND = "RastreoDevice"

_SOURCE_BRANCH = "main"


class InfrahubSchemaMissingError(RuntimeError):
    """Raised when the RastreoDevice schema is not loaded on the target branch."""


class InfrahubClientWrapper:
    """Reconciler-shaped async view of the infrahub-sdk API."""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        branch: str,
        auto_merge: bool,
        timeout_seconds: int = 30,
    ) -> None:
        self._branch = branch
        self._auto_merge = auto_merge
        self._client = InfrahubClient(
            address=url,
            config=InfrahubSdkConfig(api_token=token, timeout=timeout_seconds),
        )

    @property
    def branch(self) -> str:
        return self._branch

    async def ensure_branch(self) -> None:
        """Create the target branch from `main` if it does not already exist."""
        if self._branch == _SOURCE_BRANCH:
            return
        branches = await self._client.branch.all()
        if self._branch in branches:
            return
        logger.info(
            "creating branch",
            extra={"branch": self._branch, "source": _SOURCE_BRANCH},
        )
        await self._client.branch.create(branch_name=self._branch)

    async def verify_schema(self) -> None:
        """Confirm the RastreoDevice schema is loaded on the target branch.

        Raises InfrahubSchemaMissingError with an actionable command otherwise.
        """
        schemas = await self._client.schema.all(branch=self._branch)
        if DEVICE_KIND not in schemas:
            raise InfrahubSchemaMissingError(
                f"schema {DEVICE_KIND!r} not found on branch {self._branch!r}; "
                f"load it with: infrahubctl schema load infrahub-schema.yaml "
                f"--branch {self._branch}"
            )

    async def upsert_device(self, payload: InfrahubPayload) -> InfrahubNode:
        identity_key: str = payload["identity_key"]
        existing = await self._client.get(
            kind=DEVICE_KIND,
            branch=self._branch,
            raise_when_missing=False,
            identity_key__value=identity_key,
        )

        if existing is None:
            logger.info("creating device", extra={"identity_key": identity_key})
            node = await self._client.create(kind=DEVICE_KIND, branch=self._branch, data=payload)
            await node.save()
        else:
            node = await self._patch(existing, payload, identity_key)

        if self._auto_merge and self._branch != _SOURCE_BRANCH:
            logger.info(
                "merging branch to main",
                extra={"branch": self._branch, "identity_key": identity_key},
            )
            await self._client.branch.merge(branch_name=self._branch)

        return node

    async def _patch(
        self, node: InfrahubNode, payload: InfrahubPayload, identity_key: str
    ) -> InfrahubNode:
        changed: dict[str, Any] = {}
        for attr_name, new_value in payload.items():
            if attr_name == "identity_key":
                continue
            current = _current_value(node, attr_name)
            if current != new_value:
                changed[attr_name] = new_value

        if not changed:
            logger.debug("no-op", extra={"identity_key": identity_key})
            return node

        for attr_name, value in changed.items():
            getattr(node, attr_name).value = value
        await node.update()
        return node


def _current_value(node: InfrahubNode, attr_name: str) -> Any:
    """Return the current attribute value, or None if the attribute is unset."""
    attr = getattr(node, attr_name, None)
    if attr is None:
        return None
    return getattr(attr, "value", None)
