"""Shared fixtures for the reference-consumer tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / name).read_text())


@pytest.fixture
def minimal_record_payload() -> dict[str, Any]:
    return _load_fixture("minimal_record.json")


@pytest.fixture
def full_record_payload() -> dict[str, Any]:
    return _load_fixture("full_record.json")


@pytest.fixture
def merged_record_payload() -> dict[str, Any]:
    return _load_fixture("merged_record.json")
