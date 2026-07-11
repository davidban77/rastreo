#!/usr/bin/env python3
"""Run every scenario under containerlab/lab-srlinux/scenarios and compare the
emitted DeviceRecords against golden snapshots in containerlab/lab-srlinux/golden.

The lab must already be up (`containerlab deploy -t lab.clab.yml`) and the
rastreo image tag under test must be pulled locally. Pass `--update` on the
first run (or after intentionally changing scenario semantics) to regenerate
the goldens.

Volatile fields (timestamps, scan_id) are masked before comparison so the
diff is meaningful.

stdlib-only; no third-party imports.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
LAB_ROOT = REPO_ROOT / "containerlab" / "lab-srlinux"
SCENARIOS_DIR = LAB_ROOT / "scenarios"
GOLDEN_DIR = LAB_ROOT / "golden"
DEFAULT_IMAGE = "ghcr.io/davidban77/rastreo:main"
DEFAULT_NETWORK = "rastreo-lab"

# Fields whose values are non-deterministic across runs. Set to a fixed
# placeholder before comparing to (or writing) the golden.
VOLATILE_FIELDS = ("last_seen", "scan_id", "initiated_at")


def mask_volatile(record: dict[str, Any]) -> dict[str, Any]:
    if "last_seen" in record:
        record["last_seen"] = "<masked>"
    meta = record.get("scan_metadata")
    if isinstance(meta, dict):
        if "scan_id" in meta:
            meta["scan_id"] = "<masked>"
        if "initiated_at" in meta:
            meta["initiated_at"] = "<masked>"
    return record


def run_scenario(scenario_path: pathlib.Path, image: str, network: str, orb_machine: str | None) -> list[dict[str, Any]]:
    scenario_name = scenario_path.name
    docker_cmd = [
        "sudo", "docker", "run", "--rm",
        "--entrypoint", "/rastreo",
        "--network", network,
        "-v", f"{SCENARIOS_DIR}:/scenarios",
        image,
        "discover",
        "--file", f"/scenarios/{scenario_name}",
        "--sink", "stdout",
    ]
    if orb_machine:
        cmd = ["orb", "-m", orb_machine, "bash", "-c", " ".join(docker_cmd)]
    else:
        cmd = docker_cmd
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"rastreo exited {proc.returncode} on {scenario_name}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    records: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise RuntimeError(f"invalid JSON on {scenario_name}: {line}\n{e}") from e
    records.sort(key=lambda r: r.get("identity_key", ""))
    return [mask_volatile(r) for r in records]


def write_golden(scenario_path: pathlib.Path, records: list[dict[str, Any]]) -> pathlib.Path:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    golden_path = GOLDEN_DIR / scenario_path.with_suffix(".ndjson").name
    with golden_path.open("w") as f:
        for r in records:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    return golden_path


def read_golden(scenario_path: pathlib.Path) -> list[dict[str, Any]] | None:
    golden_path = GOLDEN_DIR / scenario_path.with_suffix(".ndjson").name
    if not golden_path.exists():
        return None
    records = []
    for line in golden_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def diff_records(scenario: str, actual: list[dict[str, Any]], golden: list[dict[str, Any]]) -> list[str]:
    diffs: list[str] = []
    if len(actual) != len(golden):
        diffs.append(f"  record count: got {len(actual)}, expected {len(golden)}")
    for i, (a, g) in enumerate(zip(actual, golden)):
        a_norm = json.dumps(a, sort_keys=True)
        g_norm = json.dumps(g, sort_keys=True)
        if a_norm != g_norm:
            diffs.append(f"  record {i} differs:\n    actual:   {a_norm}\n    expected: {g_norm}")
    return diffs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=DEFAULT_IMAGE, help=f"rastreo image tag to run (default: {DEFAULT_IMAGE})")
    parser.add_argument("--network", default=DEFAULT_NETWORK, help=f"docker network the SR Linux nodes sit on (default: {DEFAULT_NETWORK})")
    parser.add_argument("--orb-machine", default="clab", help="OrbStack machine to run docker in (empty string to run against host docker directly)")
    parser.add_argument("--update", action="store_true", help="regenerate goldens instead of comparing")
    parser.add_argument("--scenario", help="run only a specific scenario file (basename)")
    args = parser.parse_args()

    orb_machine = args.orb_machine if args.orb_machine else None

    scenarios = sorted(SCENARIOS_DIR.glob("*.yml"))
    if args.scenario:
        scenarios = [s for s in scenarios if s.name == args.scenario]
        if not scenarios:
            print(f"scenario '{args.scenario}' not found under {SCENARIOS_DIR}", file=sys.stderr)
            return 2

    if not scenarios:
        print(f"no scenarios found under {SCENARIOS_DIR}", file=sys.stderr)
        return 2

    failed = 0
    for scenario in scenarios:
        print(f"running {scenario.name} ...", flush=True)
        try:
            actual = run_scenario(scenario, args.image, args.network, orb_machine)
        except RuntimeError as e:
            print(f"  ERROR: {e}", file=sys.stderr)
            failed += 1
            continue

        if args.update:
            path = write_golden(scenario, actual)
            print(f"  wrote {path.relative_to(REPO_ROOT)} ({len(actual)} records)")
            continue

        golden = read_golden(scenario)
        if golden is None:
            print(f"  MISS: no golden at {(GOLDEN_DIR / scenario.with_suffix('.ndjson').name).relative_to(REPO_ROOT)} (run with --update)", file=sys.stderr)
            failed += 1
            continue

        diffs = diff_records(scenario.name, actual, golden)
        if diffs:
            print(f"  FAIL: {scenario.name}", file=sys.stderr)
            for d in diffs:
                print(d, file=sys.stderr)
            failed += 1
        else:
            print(f"  pass ({len(actual)} records)")

    if args.update:
        return 0
    if failed:
        print(f"\n{failed} scenario(s) failed", file=sys.stderr)
        return 1
    print(f"\nall {len(scenarios)} scenario(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
