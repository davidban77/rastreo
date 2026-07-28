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

# Every lab node, keyed as rastreo emits it. Each scenario must observe all of them.
EXPECTED_IDENTITY_KEYS = ["ip:198.51.100.11", "ip:198.51.100.12"]

# The kafka-scan scenario sinks records to Kafka instead of stdout; it is
# NOT compared against goldens by the scenario-loop. The `--sot <name>` flow
# uses it end-to-end.
SOT_SCAN_SCENARIO = "kafka-scan.yml"

# Per-SoT reconciliation query. Each returns the count of devices whose
# identity key matches one of the expected values. Called via urllib inside
# the OrbStack VM (the OrbStack machine's Docker network is where the SoT
# containers live).
SOT_CONFIG: dict[str, dict[str, str]] = {
    "nautobot": {
        "url": "http://nautobot:8080/api/dcim/devices/?cf_rastreo_identity_key=ip:198.51.100.11",
        "url_alt": "http://nautobot:8080/api/dcim/devices/?cf_rastreo_identity_key=ip:198.51.100.12",
        "token": "0123456789abcdef0123456789abcdef01234567",
        "header": "Authorization: Token",
    },
    "netbox": {
        "url": "http://netbox:8080/api/dcim/devices/?cf_rastreo_identity_key=ip:198.51.100.11",
        "url_alt": "http://netbox:8080/api/dcim/devices/?cf_rastreo_identity_key=ip:198.51.100.12",
        "token": "abcdef0123456789abcdef0123456789abcdef01",
        "header": "Authorization: Token",
    },
    "infrahub": {
        "method": "POST",
        "checks": [
            {
                "url": "http://infrahub-server:8000/graphql/main",
                "body": '{"query":"{ RastreoDevice(identity_key__value: \\"ip:198.51.100.11\\") { count } }"}',
            },
            {
                "url": "http://infrahub-server:8000/graphql/main",
                "body": '{"query":"{ RastreoDevice(identity_key__value: \\"ip:198.51.100.12\\") { count } }"}',
            },
        ],
        "token": "06438eb2-8019-4776-878c-0941b1f1d1ec",
        "header": "X-INFRAHUB-KEY:",
    },
}

# Fields whose values are non-deterministic across runs. Set to a fixed
# placeholder before comparing to (or writing) the golden. `last_seen` is on
# device records, `observed_at` on collection-profile records.
VOLATILE_RECORD_FIELDS = ("last_seen", "observed_at")
VOLATILE_SCAN_METADATA_FIELDS = ("scan_id", "initiated_at")


def mask_volatile(record: dict[str, Any]) -> dict[str, Any]:
    for field in VOLATILE_RECORD_FIELDS:
        if field in record:
            record[field] = "<masked>"
    meta = record.get("scan_metadata")
    if isinstance(meta, dict):
        for field in VOLATILE_SCAN_METADATA_FIELDS:
            if field in meta:
                meta[field] = "<masked>"
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
        "--format", "json",
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
    if not records:
        raise RuntimeError(
            f"{scenario_name} emitted no records; an empty golden compares equal to anything\nstdout:\n{proc.stdout}"
        )
    observed = {r.get("identity_key") for r in records}
    missing = [key for key in EXPECTED_IDENTITY_KEYS if key not in observed]
    if missing:
        raise RuntimeError(
            f"{scenario_name} observed {sorted(k for k in observed if k)} but not {missing}; "
            f"a golden written from a partial scan compares equal on every later run\nstdout:\n{proc.stdout}"
        )
    records = [mask_volatile(r) for r in records]
    # identity_key is not unique: gnmi emits a device and a profile record per key.
    records.sort(key=lambda r: (r.get("identity_key", ""), json.dumps(r, sort_keys=True)))
    return records


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


def run_sot_scan(image: str, network: str, orb_machine: str | None) -> None:
    scenario_path = SCENARIOS_DIR / SOT_SCAN_SCENARIO
    docker_cmd = [
        "sudo", "docker", "run", "--rm",
        "--entrypoint", "/rastreo",
        "--network", network,
        "-v", f"{SCENARIOS_DIR}:/scenarios",
        image,
        "discover",
        "--file", f"/scenarios/{SOT_SCAN_SCENARIO}",
    ]
    if orb_machine:
        cmd = ["orb", "-m", orb_machine, "bash", "-c", " ".join(docker_cmd)]
    else:
        cmd = docker_cmd
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"kafka-scan failed:\n{proc.stderr}")


def reconciled_exactly_one(payload_text: str) -> bool:
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    if isinstance(payload.get("count"), int):
        return payload["count"] == 1
    data = payload.get("data")
    if isinstance(data, dict):
        return any(isinstance(v, dict) and v.get("count") == 1 for v in data.values())
    return False


def poll_sot(sot: str, network: str, orb_machine: str | None, timeout_s: int) -> int:
    import time
    config = SOT_CONFIG[sot]
    header_prefix = config["header"]
    token = config["token"]
    header = f"{header_prefix} {token}"
    deadline = time.monotonic() + timeout_s
    method = config.get("method", "GET")
    while time.monotonic() < deadline:
        found = 0
        entries = config.get("checks") or [{"url": config["url"]}, {"url": config["url_alt"]}]
        for entry in entries:
            url = entry["url"]
            body = entry.get("body")
            probe_cmd = [
                "sudo", "docker", "run", "--rm",
                "--network", network,
                "curlimages/curl:8.10.1",
                "-sf", "-X", method, "-H", header,
            ]
            if body is not None:
                probe_cmd += ["-H", "Content-Type: application/json", "-d", body]
            probe_cmd.append(url)
            if orb_machine:
                cmd = ["orb", "-m", orb_machine, "bash", "-c", " ".join(f"'{p}'" if any(c in p for c in " \"") else p for p in probe_cmd)]
            else:
                cmd = probe_cmd
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode == 0 and reconciled_exactly_one(proc.stdout):
                found += 1
        if found == len(entries):
            return found
        time.sleep(2)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=DEFAULT_IMAGE, help=f"rastreo image tag to run (default: {DEFAULT_IMAGE})")
    parser.add_argument("--network", default=DEFAULT_NETWORK, help=f"docker network the SR Linux nodes sit on (default: {DEFAULT_NETWORK})")
    parser.add_argument("--orb-machine", default="clab", help="OrbStack machine to run docker in (empty string to run against host docker directly)")
    parser.add_argument("--update", action="store_true", help="regenerate goldens instead of comparing")
    parser.add_argument("--scenario", help="run only a specific scenario file (basename)")
    parser.add_argument("--sot", choices=list(SOT_CONFIG), help="run kafka-scan and validate the target SoT reconciled the records (skips the stdout-scenario loop)")
    parser.add_argument("--sot-timeout", type=int, default=60, help="seconds to poll the SoT before giving up (default: 60)")
    args = parser.parse_args()

    orb_machine = args.orb_machine if args.orb_machine else None

    if args.sot:
        print(f"running {SOT_SCAN_SCENARIO} against kafka ...", flush=True)
        try:
            run_sot_scan(args.image, args.network, orb_machine)
        except RuntimeError as e:
            print(f"  ERROR: {e}", file=sys.stderr)
            return 1
        print(f"  kafka publish complete; polling {args.sot} for reconciled devices (timeout {args.sot_timeout}s) ...", flush=True)
        found = poll_sot(args.sot, args.network, orb_machine, args.sot_timeout)
        expected = len(EXPECTED_IDENTITY_KEYS)
        if found == expected:
            print(f"  pass ({found}/{expected} devices reconciled in {args.sot})")
            return 0
        print(f"  FAIL: {found}/{expected} devices reconciled in {args.sot}", file=sys.stderr)
        return 1

    scenarios = sorted(SCENARIOS_DIR.glob("*.yml"))
    # kafka-scan is the SoT-flow scenario; not comparable against a stdout golden.
    scenarios = [s for s in scenarios if s.name != SOT_SCAN_SCENARIO]
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
        if failed:
            print(f"\n{failed} scenario(s) failed to capture a complete record set", file=sys.stderr)
            return 1
        return 0
    if failed:
        print(f"\n{failed} scenario(s) failed", file=sys.stderr)
        return 1
    print(f"\nall {len(scenarios)} scenario(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
