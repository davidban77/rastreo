#!/usr/bin/env python3
"""Live-infra UAT harness for the rastreo e2e coverage matrix.

For each matrix row the harness:

1. Starts the compose stack ONCE (kafka + 3 nginx targets + rastreo-server).
2. Polls each backend's readiness endpoint until ready (no bare ``sleep``).
3. Runs the row (CLI subprocess or HTTP call) against the live stack.
4. Asserts the row's verification (NDJSON shape, HTTP response shape, Kafka
   topic content).
5. Tears down the stack ONCE, even on failure.

Stdlib-only. Run from the repo root via ``python3 scripts/live_infra_uat.py``
once Docker is available. The compose stack builds the rastreo image; the
harness invokes ``rastreo`` via ``docker run --entrypoint /rastreo`` and
``rastreo-server`` via HTTP. ``--self-test`` runs the inline unit tests with
no Docker dependency.

Exit code 0 on green, 1 on red. On failure, the failing container's
``docker logs`` tail is dumped to stderr so the GHA log is self-diagnosing.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import subprocess
import sys
import time
import unittest
import unittest.mock
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Sequence


# --- Configuration -----------------------------------------------------------

COMPOSE_FILE = Path("docker-compose.yml")

# Compose project name. Defaults to the parent directory. Used to derive the
# network name ("<project>_rastreo-net") and the built image name
# ("<project>-rastreo-server"). Overridable for CI / nested workspaces.
COMPOSE_PROJECT_NAME = os.environ.get("RASTREO_COMPOSE_PROJECT", "rastreo")
COMPOSE_NETWORK = f"{COMPOSE_PROJECT_NAME}_rastreo-net"
RASTREO_IMAGE = f"{COMPOSE_PROJECT_NAME}-rastreo-server"

# The 3 nginx targets defined in docker-compose.yml.
TARGET_IPS = ("10.50.0.10", "10.50.0.11", "10.50.0.12")
TARGET_PORT = 80

# Kafka in-network listener (used by CLI runs inside the compose network).
KAFKA_INTERNAL_BROKER = "kafka:29092"
# Randomised per harness invocation so concurrent CI runs (e.g. a push:main
# alongside an in-flight PR) don't share a topic and double-count records.
# Auto-create is enabled on the broker (KAFKA_AUTO_CREATE_TOPICS_ENABLE).
KAFKA_UAT_TOPIC = f"rastreo-uat-records-{os.urandom(4).hex()}"
KCAT_IMAGE = "edenhill/kcat:1.7.1"

# Server (host-reachable, published port).
SERVER_HEALTH_URL = "http://localhost:8080/health"
SERVER_SCANS_URL = "http://localhost:8080/scans"

# Per-step time budgets. Tuned for compose healthcheck `start_period` + flush.
READINESS_TIMEOUT_S = 60.0
READINESS_POLL_INTERVAL_S = 1.0
HTTP_REQUEST_TIMEOUT_S = 5.0
# Comfortable headroom over rastreo-server's 60s request timeout so a server-
# side timeout surfaces as a 5xx rather than racing the client-side urlopen.
SCENARIO_TIMEOUT_S = 90.0
KCAT_TIMEOUT_S = 20.0
COMPOSE_UP_TIMEOUT_S = 300.0
COMPOSE_DOWN_TIMEOUT_S = 120.0
DOCKER_LOG_TAIL_LINES = 100


# --- Data model --------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class MatrixRow:
    """One row of the e2e coverage matrix.

    ``run`` executes the row and returns ``(ok, message)``. ``failure_log_containers``
    is the list of compose services whose log tail to attach on failure.
    """

    name: str
    run: Callable[["HarnessCtx"], tuple[bool, str]]
    failure_log_containers: tuple[str, ...]


@dataclasses.dataclass
class RowResult:
    """Outcome of running one matrix row."""

    row: MatrixRow
    ok: bool
    message: str = ""
    duration_s: float = 0.0


@dataclasses.dataclass(frozen=True)
class HarnessCtx:
    """Runtime context handed to each row's ``run`` callable."""

    repo_root: Path
    verbose: bool


# --- Time + HTTP helpers -----------------------------------------------------


def _now_s() -> float:
    """Wall-clock seconds. Wrapped for self-test injection."""
    return time.monotonic()


def http_get(
    url: str, timeout_s: float = HTTP_REQUEST_TIMEOUT_S
) -> tuple[int, bytes]:
    """GET ``url`` and return ``(status, body)``.

    HTTP error statuses are returned rather than raised so the caller can decide
    whether to retry. Connection errors propagate via ``urllib.error.URLError``.
    """
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b""


def http_post_json(
    url: str, payload: dict, timeout_s: float = HTTP_REQUEST_TIMEOUT_S
) -> tuple[int, bytes]:
    """POST ``payload`` as JSON to ``url`` and return ``(status, body)``."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        method="POST",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b""


# --- Polling -----------------------------------------------------------------


def poll_until(
    predicate: Callable[[], bool],
    timeout_s: float,
    interval_s: float,
    *,
    now: Callable[[], float] = _now_s,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Call ``predicate`` until it returns True or ``timeout_s`` elapses.

    Returns True if the predicate succeeded, False on timeout. ``predicate``
    exceptions are swallowed (treated as transient) so connection-refused during
    startup doesn't crash the harness.
    """
    deadline = now() + timeout_s
    while True:
        try:
            if predicate():
                return True
        except Exception:  # noqa: BLE001 — transient backend failures
            pass
        if now() >= deadline:
            return False
        sleep(interval_s)


def wait_for_http_ok(
    url: str,
    *,
    timeout_s: float = READINESS_TIMEOUT_S,
    interval_s: float = READINESS_POLL_INTERVAL_S,
) -> bool:
    """Poll ``url`` until it returns 2xx, or timeout."""

    def _check() -> bool:
        status, _ = http_get(url, timeout_s=HTTP_REQUEST_TIMEOUT_S)
        return 200 <= status < 300

    return poll_until(_check, timeout_s=timeout_s, interval_s=interval_s)


def wait_for_kafka_ready(
    *,
    timeout_s: float = READINESS_TIMEOUT_S,
    interval_s: float = READINESS_POLL_INTERVAL_S,
) -> bool:
    """Poll Kafka broker metadata via kcat until the broker answers, or timeout.

    Uses kcat from inside the compose network so the internal listener
    (``kafka:29092``) is reachable.
    """

    def _check() -> bool:
        proc = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network", COMPOSE_NETWORK,
                KCAT_IMAGE,
                "-b", KAFKA_INTERNAL_BROKER,
                "-L",  # metadata mode
                "-J",  # JSON output
                "-m", "5",  # 5s metadata fetch timeout
            ],
            capture_output=True,
            text=True,
            timeout=15.0,
            check=False,
        )
        if proc.returncode != 0:
            return False
        try:
            meta = json.loads(proc.stdout)
        except (json.JSONDecodeError, ValueError):
            return False
        brokers = meta.get("brokers", [])
        return isinstance(brokers, list) and len(brokers) > 0

    return poll_until(_check, timeout_s=timeout_s, interval_s=interval_s)


# --- Compose lifecycle -------------------------------------------------------


def compose_command(repo_root: Path, *args: str) -> list[str]:
    """Build a ``docker compose`` argv anchored at the repo's compose file."""
    return ["docker", "compose", "-f", str(repo_root / COMPOSE_FILE), *args]


def compose_up(
    repo_root: Path, *, timeout_s: float = COMPOSE_UP_TIMEOUT_S
) -> subprocess.CompletedProcess[str]:
    """Bring the stack up (detached, build images as needed)."""
    return subprocess.run(
        compose_command(repo_root, "up", "-d", "--build"),
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )


def compose_down(
    repo_root: Path, *, timeout_s: float = COMPOSE_DOWN_TIMEOUT_S
) -> subprocess.CompletedProcess[str]:
    """Tear the stack down (with volumes)."""
    return subprocess.run(
        compose_command(repo_root, "down", "-v"),
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )


def compose_logs_tail(
    repo_root: Path,
    service: str,
    *,
    tail_lines: int = DOCKER_LOG_TAIL_LINES,
    timeout_s: float = 30.0,
) -> str:
    """Return the last ``tail_lines`` lines of the named service's logs.

    Best-effort: returns a diagnostic string on failure rather than raising.
    """
    try:
        proc = subprocess.run(
            compose_command(
                repo_root,
                "logs",
                "--no-color",
                "--tail",
                str(tail_lines),
                service,
            ),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return f"<logs unavailable for {service}: {e}>"
    return (proc.stdout or "") + (proc.stderr or "")


# --- Row implementations -----------------------------------------------------


def build_cli_stdout_argv(
    rastreo_image: str = RASTREO_IMAGE,
    network: str = COMPOSE_NETWORK,
    target_ips: Sequence[str] = TARGET_IPS,
    port: int = TARGET_PORT,
) -> list[str]:
    """Build the docker-run argv that invokes the rastreo CLI inside the compose
    network so it can reach the internal nginx targets.

    The nginx targets only ``expose`` port 80 to the compose network — they are
    not host-published — so the CLI must run on the same docker network.
    """
    return [
        "docker", "run", "--rm",
        "--network", network,
        "--entrypoint", "/rastreo",
        rastreo_image,
        "discover",
        *(arg for ip in target_ips for arg in ("--target", ip)),
        "--port", str(port),
        "--sink", "stdout",
    ]


def parse_ndjson_records(stdout: str) -> list[dict]:
    """Split ``stdout`` on newlines and return each non-empty line as a parsed
    JSON object. Raises ``ValueError`` if any line fails to parse."""
    records: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def record_has_open_port_signal(record: dict, port: int) -> bool:
    """Return True if ``record.signals`` contains ``{"OpenPort": <port>}``.

    Matches the externally-tagged serde shape of ``Signal::OpenPort(u16)``.
    """
    signals = record.get("signals", [])
    if not isinstance(signals, list):
        return False
    for sig in signals:
        if isinstance(sig, dict) and sig.get("OpenPort") == port:
            return True
    return False


def run_cli_stdout(ctx: HarnessCtx) -> tuple[bool, str]:
    """CLI -> stdout row: probe the 3 nginx targets on port 80 and verify a
    DeviceRecord per target with an ``OpenPort(80)`` signal."""
    argv = build_cli_stdout_argv()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=SCENARIO_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"rastreo CLI timed out after {SCENARIO_TIMEOUT_S:.0f}s"

    if proc.returncode != 0:
        stderr_tail = "\n    ".join(
            (proc.stderr or "").strip().splitlines()[-20:]
        )
        return False, f"rastreo exited {proc.returncode}\n    {stderr_tail}"

    try:
        records = parse_ndjson_records(proc.stdout)
    except json.JSONDecodeError as e:
        return False, f"stdout was not NDJSON: {e}\n    stdout: {proc.stdout!r}"

    if len(records) != len(TARGET_IPS):
        return False, (
            f"expected {len(TARGET_IPS)} records, got {len(records)}\n"
            f"    stdout: {proc.stdout!r}"
        )

    seen_keys: set[str] = set()
    for rec in records:
        key = rec.get("identity_key")
        if not isinstance(key, str):
            return False, f"record missing identity_key: {rec!r}"
        seen_keys.add(key)
        if not record_has_open_port_signal(rec, TARGET_PORT):
            return False, (
                f"record {key!r} missing OpenPort({TARGET_PORT}) signal: "
                f"{rec.get('signals')!r}"
            )

    expected_keys = {f"ip:{ip}" for ip in TARGET_IPS}
    if seen_keys != expected_keys:
        return False, (
            f"identity_key mismatch: expected {sorted(expected_keys)}, "
            f"got {sorted(seen_keys)}"
        )

    return True, f"{len(records)} records, all with OpenPort({TARGET_PORT})"


def build_server_scan_payload(
    target_ips: Sequence[str] = TARGET_IPS, port: int = TARGET_PORT
) -> dict:
    """Build the JSON body for POST /scans.

    ``DiscoverScenarioConfig.base`` is ``#[serde(flatten)]`` so the
    ``BaseProbeConfig`` fields sit at the top level alongside ``targets`` and
    ``probers``.
    """
    return {
        "targets": [{"Ip": ip} for ip in target_ips],
        "probers": [{"type": "tcp_connect", "ports": [port]}],
        "timeout_ms": 2000,
        "rate_limit": 16,
    }


def run_server_post_scans(ctx: HarnessCtx) -> tuple[bool, str]:
    """Server -> POST /scans row: submit a scenario, verify the response shape."""
    payload = build_server_scan_payload()
    try:
        status, body = http_post_json(
            SERVER_SCANS_URL, payload, timeout_s=SCENARIO_TIMEOUT_S
        )
    except urllib.error.URLError as e:
        return False, f"POST /scans connection error: {e}"

    if status != 200:
        return False, f"POST /scans returned {status}: {body[:500]!r}"

    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError) as e:
        return False, f"POST /scans body was not JSON: {e}"

    summary = parsed.get("summary")
    if not isinstance(summary, dict):
        return False, f"response missing summary: {parsed!r}"
    records = parsed.get("records")
    if not isinstance(records, list):
        return False, f"response missing records array: {parsed!r}"

    if summary.get("records_emitted") != len(TARGET_IPS):
        return False, (
            f"summary.records_emitted={summary.get('records_emitted')}, "
            f"expected {len(TARGET_IPS)}"
        )
    if len(records) != len(TARGET_IPS):
        return False, (
            f"records array length={len(records)}, expected {len(TARGET_IPS)}"
        )

    for rec in records:
        if not record_has_open_port_signal(rec, TARGET_PORT):
            return False, (
                f"record missing OpenPort({TARGET_PORT}) signal: "
                f"{rec.get('signals')!r}"
            )

    return True, (
        f"records_emitted={summary['records_emitted']}, "
        f"all with OpenPort({TARGET_PORT})"
    )


def build_cli_kafka_argv(
    rastreo_image: str = RASTREO_IMAGE,
    network: str = COMPOSE_NETWORK,
    target_ips: Sequence[str] = TARGET_IPS,
    port: int = TARGET_PORT,
    broker: str = KAFKA_INTERNAL_BROKER,
    topic: str = KAFKA_UAT_TOPIC,
) -> list[str]:
    """Build the docker-run argv for the CLI -> Kafka row."""
    return [
        "docker", "run", "--rm",
        "--network", network,
        "--entrypoint", "/rastreo",
        rastreo_image,
        "discover",
        *(arg for ip in target_ips for arg in ("--target", ip)),
        "--port", str(port),
        "--sink", "kafka",
        "--brokers", broker,
        "--topic", topic,
        "--kafka-flush-per-record",
    ]


def build_kcat_consume_argv(
    network: str = COMPOSE_NETWORK,
    broker: str = KAFKA_INTERNAL_BROKER,
    topic: str = KAFKA_UAT_TOPIC,
) -> list[str]:
    """Build the docker-run argv for the kcat sidecar consumer."""
    return [
        "docker", "run", "--rm",
        "--network", network,
        KCAT_IMAGE,
        "-b", broker,
        "-t", topic,
        "-C",          # consumer mode
        "-e",          # exit after EOF
        "-o", "beginning",
        "-q",          # quiet
        "-u",          # unbuffered
        "-X", "auto.offset.reset=earliest",
    ]


def run_cli_kafka(ctx: HarnessCtx) -> tuple[bool, str]:
    """CLI -> Kafka row: publish to the broker, then consume via kcat and
    verify the records arrived intact."""
    publish_argv = build_cli_kafka_argv()
    try:
        proc = subprocess.run(
            publish_argv,
            capture_output=True,
            text=True,
            timeout=SCENARIO_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"rastreo CLI (kafka) timed out after {SCENARIO_TIMEOUT_S:.0f}s"

    if proc.returncode != 0:
        stderr_tail = "\n    ".join(
            (proc.stderr or "").strip().splitlines()[-20:]
        )
        return False, f"rastreo exited {proc.returncode}\n    {stderr_tail}"

    consume_argv = build_kcat_consume_argv()
    try:
        kcat = subprocess.run(
            consume_argv,
            capture_output=True,
            text=True,
            timeout=KCAT_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"kcat consume timed out after {KCAT_TIMEOUT_S:.0f}s"

    if kcat.returncode != 0:
        stderr_tail = "\n    ".join(
            (kcat.stderr or "").strip().splitlines()[-20:]
        )
        return False, f"kcat exited {kcat.returncode}\n    {stderr_tail}"

    try:
        records = parse_ndjson_records(kcat.stdout)
    except json.JSONDecodeError as e:
        return False, f"kcat output was not NDJSON: {e}\n    stdout: {kcat.stdout!r}"

    if len(records) != len(TARGET_IPS):
        return False, (
            f"expected {len(TARGET_IPS)} records on topic, got {len(records)}\n"
            f"    kcat stdout: {kcat.stdout!r}"
        )

    for rec in records:
        if not record_has_open_port_signal(rec, TARGET_PORT):
            return False, (
                f"record missing OpenPort({TARGET_PORT}) signal: "
                f"{rec.get('signals')!r}"
            )

    return True, f"{len(records)} records consumed from {KAFKA_UAT_TOPIC}"


# --- Matrix ------------------------------------------------------------------

MATRIX: tuple[MatrixRow, ...] = (
    MatrixRow(
        name="cli_stdout",
        run=run_cli_stdout,
        failure_log_containers=("target-1", "target-2", "target-3"),
    ),
    MatrixRow(
        name="server_post_scans",
        run=run_server_post_scans,
        failure_log_containers=("rastreo-server", "target-1"),
    ),
    MatrixRow(
        name="cli_kafka",
        run=run_cli_kafka,
        failure_log_containers=("kafka", "target-1"),
    ),
)


# --- Failure attribution -----------------------------------------------------


def attribute_failure(result: RowResult, repo_root: Path) -> str:
    """Render a failure as a multi-line stderr block including container logs."""
    lines = [
        f"FAIL [{result.row.name}] ({result.duration_s:.1f}s)",
        f"    {result.message}",
    ]
    for container in result.row.failure_log_containers:
        logs = compose_logs_tail(repo_root, container)
        lines.append(f"--- docker logs (tail) for {container} ---")
        lines.append(logs.rstrip() or "(no output)")
        lines.append(f"--- end {container} ---")
    return "\n".join(lines)


# --- Orchestration -----------------------------------------------------------


def find_repo_root(start: Path) -> Path:
    """Walk up from ``start`` until a directory with a ``Cargo.toml`` is found."""
    current = start.resolve()
    while True:
        if (current / "Cargo.toml").is_file():
            return current
        if current.parent == current:
            raise RuntimeError(
                "could not locate repo root: no Cargo.toml in any parent of "
                f"{start}"
            )
        current = current.parent


def run_all(
    rows: Sequence[MatrixRow],
    ctx: HarnessCtx,
) -> list[RowResult]:
    """Spin the stack once, run every row in order, tear down once.

    Tear-down runs in a ``finally`` block so a panicking row, a Ctrl-C during
    ``compose_up`` (image build / container start), or a row exception still
    cleans up volumes. ``compose_down`` is safe to call even when ``compose_up``
    was interrupted mid-build.
    """
    results: list[RowResult] = []

    try:
        print("==> compose up", file=sys.stderr)
        up = compose_up(ctx.repo_root)
        if up.returncode != 0:
            print(up.stdout, file=sys.stderr)
            print(up.stderr, file=sys.stderr)
            raise RuntimeError(
                f"docker compose up failed (exit {up.returncode}); see stderr above"
            )

        print(f"==> waiting for kafka ({KAFKA_INTERNAL_BROKER})", file=sys.stderr)
        if not wait_for_kafka_ready():
            results.append(
                RowResult(
                    row=MatrixRow(
                        name="readiness:kafka",
                        run=lambda _c: (False, "n/a"),
                        failure_log_containers=("kafka",),
                    ),
                    ok=False,
                    message=(
                        f"kafka broker did not become ready within "
                        f"{READINESS_TIMEOUT_S:.0f}s"
                    ),
                )
            )
            return results

        print(f"==> waiting for rastreo-server ({SERVER_HEALTH_URL})", file=sys.stderr)
        if not wait_for_http_ok(SERVER_HEALTH_URL):
            results.append(
                RowResult(
                    row=MatrixRow(
                        name="readiness:rastreo-server",
                        run=lambda _c: (False, "n/a"),
                        failure_log_containers=("rastreo-server",),
                    ),
                    ok=False,
                    message=(
                        f"rastreo-server did not become ready within "
                        f"{READINESS_TIMEOUT_S:.0f}s"
                    ),
                )
            )
            return results

        for row in rows:
            print(f"==> running [{row.name}]", file=sys.stderr)
            start = _now_s()
            try:
                ok, message = row.run(ctx)
            except Exception as e:  # noqa: BLE001 — surface any row error as FAIL
                ok, message = False, f"unhandled exception: {e!r}"
            duration = _now_s() - start
            result = RowResult(row=row, ok=ok, message=message, duration_s=duration)
            status = "PASS" if ok else "FAIL"
            print(
                f"    [{row.name}] {status} ({duration:.1f}s) {message}",
                file=sys.stderr,
            )
            results.append(result)
    finally:
        print("==> compose down -v", file=sys.stderr)
        down = compose_down(ctx.repo_root)
        if down.returncode != 0:
            print(
                f"WARN: compose down exited {down.returncode}\n"
                f"    stdout: {down.stdout.strip()}\n"
                f"    stderr: {down.stderr.strip()}",
                file=sys.stderr,
            )

    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the rastreo e2e coverage matrix against live container backends."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run inline unit tests and exit. No Docker required.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print extra diagnostics to stderr.",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return _run_self_tests()

    repo_root = find_repo_root(Path(__file__).parent)

    ctx = HarnessCtx(repo_root=repo_root, verbose=args.verbose)

    try:
        results = run_all(MATRIX, ctx)
    except KeyboardInterrupt:
        print("\nInterrupted; tear-down already attempted.", file=sys.stderr)
        return 130

    failures = [r for r in results if not r.ok]
    for failure in failures:
        print(attribute_failure(failure, repo_root), file=sys.stderr)
    print(
        f"{len(results)} rows checked, {len(failures)} failed",
        file=sys.stderr,
    )
    return 0 if not failures else 1


# --- Self-tests --------------------------------------------------------------


class _ParseNdjsonRecordsTests(unittest.TestCase):
    def test_parses_three_lines(self) -> None:
        out = '{"a":1}\n{"b":2}\n{"c":3}\n'
        self.assertEqual(
            parse_ndjson_records(out),
            [{"a": 1}, {"b": 2}, {"c": 3}],
        )

    def test_skips_blank_lines(self) -> None:
        out = '{"a":1}\n\n  \n{"b":2}\n'
        self.assertEqual(parse_ndjson_records(out), [{"a": 1}, {"b": 2}])

    def test_empty_string_returns_empty_list(self) -> None:
        self.assertEqual(parse_ndjson_records(""), [])

    def test_invalid_json_raises(self) -> None:
        with self.assertRaises(json.JSONDecodeError):
            parse_ndjson_records("{not json}\n")


class _RecordHasOpenPortSignalTests(unittest.TestCase):
    def test_match(self) -> None:
        rec = {"signals": [{"OpenPort": 80}]}
        self.assertTrue(record_has_open_port_signal(rec, 80))

    def test_no_match_wrong_port(self) -> None:
        rec = {"signals": [{"OpenPort": 22}]}
        self.assertFalse(record_has_open_port_signal(rec, 80))

    def test_no_signals_key(self) -> None:
        self.assertFalse(record_has_open_port_signal({}, 80))

    def test_signals_not_list(self) -> None:
        self.assertFalse(record_has_open_port_signal({"signals": "x"}, 80))

    def test_match_among_multiple_signals(self) -> None:
        rec = {
            "signals": [
                {"HttpBanner": "nginx/1.25"},
                {"OpenPort": 80},
                {"Mac": "aa:bb:cc:dd:ee:ff"},
            ]
        }
        self.assertTrue(record_has_open_port_signal(rec, 80))


class _PollUntilTests(unittest.TestCase):
    def test_returns_true_on_first_success(self) -> None:
        calls = {"n": 0}

        def pred() -> bool:
            calls["n"] += 1
            return True

        self.assertTrue(
            poll_until(pred, timeout_s=1.0, interval_s=0.01, sleep=lambda _s: None)
        )
        self.assertEqual(calls["n"], 1)

    def test_eventually_succeeds(self) -> None:
        attempts = iter([False, False, True])

        def pred() -> bool:
            return next(attempts)

        self.assertTrue(
            poll_until(pred, timeout_s=1.0, interval_s=0.01, sleep=lambda _s: None)
        )

    def test_times_out_when_predicate_never_true(self) -> None:
        clock = [0.0]

        def now() -> float:
            return clock[0]

        def sleep(s: float) -> None:
            clock[0] += s

        self.assertFalse(
            poll_until(
                lambda: False,
                timeout_s=0.5,
                interval_s=0.1,
                now=now,
                sleep=sleep,
            )
        )
        self.assertGreaterEqual(clock[0], 0.5)

    def test_swallows_predicate_exceptions(self) -> None:
        attempts = iter([False, False, True])

        def pred() -> bool:
            v = next(attempts)
            if not v:
                raise ConnectionRefusedError("not yet")
            return True

        self.assertTrue(
            poll_until(pred, timeout_s=1.0, interval_s=0.01, sleep=lambda _s: None)
        )


class _ArgvBuildersTests(unittest.TestCase):
    def test_cli_stdout_argv_includes_each_target(self) -> None:
        argv = build_cli_stdout_argv(
            rastreo_image="img", network="net",
            target_ips=("10.0.0.1", "10.0.0.2"), port=80,
        )
        self.assertEqual(argv[:5], ["docker", "run", "--rm", "--network", "net"])
        self.assertIn("--entrypoint", argv)
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "/rastreo")
        self.assertEqual(argv.count("--target"), 2)
        self.assertIn("10.0.0.1", argv)
        self.assertIn("10.0.0.2", argv)
        self.assertEqual(argv[-4:], ["--port", "80", "--sink", "stdout"])

    def test_cli_kafka_argv_includes_brokers_topic_and_flush_flag(self) -> None:
        argv = build_cli_kafka_argv(
            rastreo_image="img", network="net",
            target_ips=("10.0.0.1",), port=80,
            broker="kafka:29092", topic="t",
        )
        self.assertIn("--sink", argv)
        self.assertEqual(argv[argv.index("--sink") + 1], "kafka")
        self.assertEqual(argv[argv.index("--brokers") + 1], "kafka:29092")
        self.assertEqual(argv[argv.index("--topic") + 1], "t")
        self.assertIn("--kafka-flush-per-record", argv)

    def test_kcat_consume_argv_uses_beginning_offset(self) -> None:
        argv = build_kcat_consume_argv(
            network="net", broker="kafka:29092", topic="t",
        )
        self.assertEqual(argv[:5], ["docker", "run", "--rm", "--network", "net"])
        self.assertIn("-C", argv)
        self.assertIn("-e", argv)
        self.assertEqual(argv[argv.index("-o") + 1], "beginning")
        self.assertEqual(argv[argv.index("-t") + 1], "t")
        self.assertEqual(argv[argv.index("-b") + 1], "kafka:29092")

    def test_server_scan_payload_shape(self) -> None:
        payload = build_server_scan_payload(
            target_ips=("10.0.0.1", "10.0.0.2"), port=80,
        )
        self.assertEqual(len(payload["targets"]), 2)
        self.assertEqual(payload["targets"][0], {"Ip": "10.0.0.1"})
        self.assertEqual(
            payload["probers"], [{"type": "tcp_connect", "ports": [80]}]
        )
        # Base fields are flattened (no nested "base" key).
        self.assertNotIn("base", payload)
        self.assertEqual(payload["timeout_ms"], 2000)


class _AttributeFailureTests(unittest.TestCase):
    def test_includes_row_name_and_message(self) -> None:
        row = MatrixRow(
            name="cli_stdout",
            run=lambda _c: (False, "boom"),
            failure_log_containers=(),
        )
        result = RowResult(row=row, ok=False, message="boom", duration_s=1.5)
        out = attribute_failure(result, repo_root=Path("/tmp"))
        self.assertIn("FAIL [cli_stdout]", out)
        self.assertIn("boom", out)
        self.assertIn("1.5s", out)


class _MatrixIntegrityTests(unittest.TestCase):
    """Static checks on the hardcoded MATRIX so drift is caught."""

    def test_row_names_unique(self) -> None:
        names = [r.name for r in MATRIX]
        self.assertEqual(len(names), len(set(names)))

    def test_expected_row_set(self) -> None:
        names = {r.name for r in MATRIX}
        self.assertEqual(
            names, {"cli_stdout", "server_post_scans", "cli_kafka"}
        )

    def test_failure_containers_non_empty(self) -> None:
        for row in MATRIX:
            self.assertTrue(row.failure_log_containers, row.name)


class _RowExecutionWithMocksTests(unittest.TestCase):
    """End-to-end row runs with subprocess + urllib mocked."""

    def _ctx(self) -> HarnessCtx:
        return HarnessCtx(repo_root=Path("/tmp"), verbose=False)

    def test_cli_stdout_passes_with_three_open_ports(self) -> None:
        stdout = "\n".join(
            json.dumps(
                {
                    "identity_key": f"ip:{ip}",
                    "signals": [{"OpenPort": 80}],
                }
            )
            for ip in TARGET_IPS
        ) + "\n"
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_stdout(self._ctx())
        self.assertTrue(ok, msg)
        self.assertIn("3 records", msg)

    def test_cli_stdout_fails_when_record_missing_signal(self) -> None:
        records = [
            {"identity_key": f"ip:{ip}", "signals": [{"OpenPort": 80}]}
            for ip in TARGET_IPS
        ]
        records[1]["signals"] = []  # second record has no open-port signal
        stdout = "\n".join(json.dumps(r) for r in records) + "\n"
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_stdout(self._ctx())
        self.assertFalse(ok)
        self.assertIn("OpenPort", msg)

    def test_cli_stdout_fails_when_cli_returns_nonzero(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="boom"
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_stdout(self._ctx())
        self.assertFalse(ok)
        self.assertIn("exited 1", msg)

    def test_server_post_scans_passes_on_full_match(self) -> None:
        body = json.dumps(
            {
                "summary": {"records_emitted": 3},
                "records": [
                    {"signals": [{"OpenPort": 80}]} for _ in TARGET_IPS
                ],
            }
        ).encode()
        with unittest.mock.patch(
            f"{__name__}.http_post_json", return_value=(200, body)
        ):
            ok, msg = run_server_post_scans(self._ctx())
        self.assertTrue(ok, msg)
        self.assertIn("records_emitted=3", msg)

    def test_server_post_scans_fails_on_non_200(self) -> None:
        with unittest.mock.patch(
            f"{__name__}.http_post_json", return_value=(500, b'{"error":"x"}')
        ):
            ok, msg = run_server_post_scans(self._ctx())
        self.assertFalse(ok)
        self.assertIn("500", msg)

    def test_server_post_scans_fails_on_wrong_count(self) -> None:
        body = json.dumps(
            {
                "summary": {"records_emitted": 2},
                "records": [
                    {"signals": [{"OpenPort": 80}]},
                    {"signals": [{"OpenPort": 80}]},
                ],
            }
        ).encode()
        with unittest.mock.patch(
            f"{__name__}.http_post_json", return_value=(200, body)
        ):
            ok, msg = run_server_post_scans(self._ctx())
        self.assertFalse(ok)
        self.assertIn("records_emitted=2", msg)

    def test_cli_kafka_passes_when_publish_and_consume_succeed(self) -> None:
        publish = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        kcat_stdout = "\n".join(
            json.dumps({"identity_key": f"ip:{ip}", "signals": [{"OpenPort": 80}]})
            for ip in TARGET_IPS
        ) + "\n"
        consume = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=kcat_stdout, stderr=""
        )
        with unittest.mock.patch.object(
            subprocess, "run", side_effect=[publish, consume]
        ):
            ok, msg = run_cli_kafka(self._ctx())
        self.assertTrue(ok, msg)
        self.assertIn("3 records consumed", msg)

    def test_cli_kafka_fails_when_publish_fails(self) -> None:
        publish = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="kafka down"
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=publish):
            ok, msg = run_cli_kafka(self._ctx())
        self.assertFalse(ok)
        self.assertIn("exited 1", msg)


def _run_self_tests() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in (
        _ParseNdjsonRecordsTests,
        _RecordHasOpenPortSignalTests,
        _PollUntilTests,
        _ArgvBuildersTests,
        _AttributeFailureTests,
        _MatrixIntegrityTests,
        _RowExecutionWithMocksTests,
    ):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
