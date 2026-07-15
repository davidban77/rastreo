"""Contract test: reference fixtures conform to the published DeviceRecord schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).parents[3] / "schemas" / "device-record-v1.json"
FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@pytest.mark.parametrize("fixture_name", ["minimal_record", "full_record", "merged_record"])
def test_fixture_conforms_to_device_record_schema(
    validator: Draft202012Validator, fixture_name: str
) -> None:
    instance = json.loads((FIXTURE_DIR / f"{fixture_name}.json").read_text())
    errors = list(validator.iter_errors(instance))
    assert not errors, "; ".join(f"{list(e.path)}: {e.message}" for e in errors)
