#!/usr/bin/env python3
"""Live-infra UAT harness for the rastreo e2e coverage matrix.

The harness:

1. Refuses to run unless every service in ``docker-compose.yml`` either has a
   readiness gate in ``READINESS_GATES`` or a recorded reason in
   ``READINESS_EXEMPT_SERVICES`` — a new service cannot arrive ungated, and no
   service a matrix row names can be exempted.
2. Brings the stack up ONCE through separately bounded phases (build, pull,
   start), so a slow image build cannot be mistaken for a stuck container.
3. Polls every gate until its service is serving (no bare ``sleep``), and stops
   the run naming the service and the error its last probe attempt reported if
   one never comes up.
4. Runs each matrix row (CLI subprocess or HTTP call) against the live stack and
   asserts its verification (NDJSON shape, HTTP response shape, Kafka topic
   content).
5. Tears down the stack ONCE, even on failure.

Stdlib-only. Run from the repo root via ``python3 scripts/live_infra_uat.py``
once Docker is available. The compose stack builds the rastreo image; the
harness invokes ``rastreo`` via ``docker run --entrypoint /rastreo`` and
``rastreo-server`` via HTTP. ``--self-test`` runs the inline unit tests with
no Docker dependency.

Exit code 0 on green, 1 on red, 130 on Ctrl-C. Every failure snapshots the
container state and the relevant containers' ``docker logs`` tails while they
are still up, and dumps them to stderr so the GHA log is self-diagnosing. A
process that times out or exits non-zero carries its own output into the report
too: the sidecars run with ``--rm``, so ``compose logs`` cannot recover it.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import contextlib
import dataclasses
import functools
import inspect
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
import unittest.mock
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Mapping, Sequence


# --- Configuration -----------------------------------------------------------

COMPOSE_FILE = Path("docker-compose.yml")

# Compose project name. Defaults to the parent directory. Used to derive the
# network name ("<project>_rastreo-net") and the built image name
# ("<project>-rastreo-server"). Overridable for CI / nested workspaces.
COMPOSE_PROJECT_NAME = os.environ.get("RASTREO_COMPOSE_PROJECT", "rastreo")
COMPOSE_NETWORK = f"{COMPOSE_PROJECT_NAME}_rastreo-net"
RASTREO_IMAGE = f"{COMPOSE_PROJECT_NAME}-rastreo-server"

# The 3 nginx targets defined in docker-compose.yml, keyed by compose service
# name so each address stays tied to the service that must be proven ready.
TARGET_SERVICE_IPS: dict[str, str] = {
    "target-1": "10.50.0.10",
    "target-2": "10.50.0.11",
    "target-3": "10.50.0.12",
}
TARGET_IPS = tuple(TARGET_SERVICE_IPS.values())
TARGET_PORT = 80

# Kafka in-network listener (used by CLI runs inside the compose network).
KAFKA_INTERNAL_BROKER = "kafka:29092"
# Randomised per harness invocation so concurrent CI runs (e.g. a push:main
# alongside an in-flight PR) don't share a topic and double-count records.
# Auto-create is enabled on the broker (KAFKA_AUTO_CREATE_TOPICS_ENABLE).
KAFKA_UAT_TOPIC = f"rastreo-uat-records-{os.urandom(4).hex()}"
KCAT_IMAGE = "edenhill/kcat:1.7.1"

# NATS in-network listener (JetStream enabled on port 4222).
NATS_INTERNAL_URL = "nats://nats:4222"
# Randomised per harness invocation so concurrent CI runs don't collide on the
# shared server. Both stream and subject are randomised because both live in
# the server's global namespace.
NATS_UAT_STREAM = f"rastreo-uat-{os.urandom(4).hex()}"
NATS_UAT_SUBJECT = f"rastreo.uat.records.{os.urandom(4).hex()}"
NATS_BOX_IMAGE = "natsio/nats-box:0.18.0"

# target-ssh compose service. Fixed address; the SSH prober has no external
# broker so per-run randomisation is not needed.
TARGET_SSH_IP = "10.50.0.20"
TARGET_SSH_PORT = 2222
BUSYBOX_IMAGE = "busybox:1.36"

# target-tls compose service. Self-signed cert generated at container start
# with a known CN + DNS SAN + IP SAN so the TLS prober's fingerprints can be
# asserted exactly.
TARGET_TLS_IP = "10.50.0.30"
TARGET_TLS_PORT = 443
TARGET_TLS_EXPECTED_CN = "uat-tls.rastreo.local"
TARGET_TLS_EXPECTED_DNS_SAN = "uat-tls.rastreo.local"
TARGET_TLS_EXPECTED_IP_SAN = "ip:10.50.0.30"

# ReverseDns prober row queries a public resolver from inside the compose
# network. Cloudflare's second resolver (1.0.0.1) has a stable PTR for
# 1.1.1.1 -> one.one.one.one, so the assertion is deterministic.
RDNS_TARGET_IP = "1.1.1.1"
RDNS_RESOLVER_IP = "1.0.0.1"
RDNS_EXPECTED_NAME = "one.one.one.one"

# Server (host-reachable, published port).
SERVER_HEALTH_URL = "http://localhost:8080/health"
SERVER_SCANS_URL = "http://localhost:8080/scans"

# The compose server this harness starts runs with auth disabled
# (RASTREO_AUTH_DISABLED=true in docker-compose.yml), so CI needs no token. Set
# RASTREO_API_TOKEN in the harness environment to authenticate the POST /scans
# row when pointing the harness at an auth-enabled server.
SERVER_API_TOKEN = os.environ.get("RASTREO_API_TOKEN") or None

# Per-step time budgets. Tuned for compose healthcheck `start_period` + flush.
READINESS_TIMEOUT_S = 60.0
READINESS_POLL_INTERVAL_S = 1.0
HTTP_REQUEST_TIMEOUT_S = 5.0
# One sidecar `docker run` poll attempt (kcat, nats-box, busybox nc).
SIDECAR_PROBE_TIMEOUT_S = 15.0
# Comfortable headroom over rastreo-server's 60s request timeout so a server-
# side timeout surfaces as a 5xx rather than racing the client-side urlopen.
SCENARIO_TIMEOUT_S = 90.0
KCAT_TIMEOUT_S = 20.0
NATS_TIMEOUT_S = 20.0

# Startup is split into separately bounded phases: one `up -d --build` budget
# has to be loose enough for a cold Rust release build, which hides a stuck start.
COMPOSE_CONFIG_TIMEOUT_S = 30.0
COMPOSE_BUILD_TIMEOUT_S = 900.0
COMPOSE_PULL_TIMEOUT_S = 300.0
SIDECAR_PULL_TIMEOUT_S = 60.0
# `up` blocks on kafka turning healthy (20s start_period + 6x10s retries)
# because rastreo-server declares `depends_on: service_healthy`.
COMPOSE_START_TIMEOUT_S = 180.0
COMPOSE_DOWN_TIMEOUT_S = 120.0
DOCKER_LOG_TAIL_LINES = 100
TAIL_LINES_ON_FAILURE = 20
COMPOSE_PS_TIMEOUT_S = 10.0

# Whole-capture ceiling for one failure's diagnostics (container state plus
# every log tail it asks for), so a hung docker cannot spend a per-service
# budget once per service on the path where every row fails.
DIAGNOSTIC_BUDGET_S = 30.0

# The workflow whose `timeout-minutes` bounds every budget above. Read rather
# than mirrored, so lowering it in the workflow reddens the budget guard.
LIVE_UAT_WORKFLOW = Path(".github/workflows/live-infra-uat.yml")

# Sidecar images the harness runs directly (not compose services). Pulled up
# front so a cold image download cannot eat a readiness or row budget.
SIDECAR_IMAGES = (BUSYBOX_IMAGE, KCAT_IMAGE, NATS_BOX_IMAGE)


# --- Data model --------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class MatrixRow:
    """One row of the e2e coverage matrix.

    ``run`` executes the row and returns ``(ok, message)``. ``budget_s`` is the
    row's own ceiling — the sum of the timeouts ``run`` enforces — and is what
    the run budget charges for it. ``failure_log_containers`` is the list of
    compose services whose log tail to attach on failure.
    """

    name: str
    run: Callable[["HarnessCtx"], tuple[bool, str]]
    budget_s: float
    failure_log_containers: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class ServiceLog:
    """A container log tail, snapshotted while the container was still up."""

    service: str
    text: str


@dataclasses.dataclass(frozen=True)
class FailureSnapshot:
    """Container state and log tails, captured at failure time before tear-down."""

    container_state: str
    logs: tuple[ServiceLog, ...]


@dataclasses.dataclass
class RowResult:
    """Outcome of running one matrix row.

    ``snapshot`` is captured at failure time, before tear-down; rendering a
    failure after ``compose down`` would otherwise find every container gone.
    """

    row: MatrixRow
    ok: bool
    message: str = ""
    duration_s: float = 0.0
    snapshot: FailureSnapshot | None = None


@dataclasses.dataclass(frozen=True)
class HarnessCtx:
    """Runtime context handed to each row's ``run`` callable."""

    repo_root: Path
    verbose: bool


@dataclasses.dataclass(frozen=True)
class ReadinessGate:
    """Proof that one compose service is serving before any matrix row runs.

    ``service`` is the compose service name — it is reconciled against
    ``docker compose config --services`` so a service cannot arrive ungated.
    ``endpoint`` is the address reported to the operator and ``wait`` polls it;
    build gates through ``tcp_gate`` / ``http_gate`` so the two cannot disagree.
    """

    service: str
    endpoint: str
    wait: Wait

    @property
    def budget_s(self) -> float:
        """Wall-clock ceiling for this gate, derived from the poller behind ``wait``."""
        return (
            READINESS_TIMEOUT_S
            + READINESS_POLL_INTERVAL_S
            + poll_attempt_ceiling_s(self.wait)
        )


@dataclasses.dataclass(frozen=True)
class StartupPhase:
    """One separately bounded step of bringing the stack up."""

    name: str
    argv: tuple[str, ...]
    budget_s: float


# --- Time, subprocess and HTTP helpers ---------------------------------------


def _now_s() -> float:
    """Wall-clock seconds. Wrapped for self-test injection."""
    return time.monotonic()


def decoded_output(output: bytes | str | None) -> str:
    """Decode a captured stream. ``TimeoutExpired`` carries bytes even under
    ``text=True``, so callers cannot assume ``str``."""
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", "replace")
    return output


def output_tail(
    stdout: bytes | str | None,
    stderr: bytes | str | None,
    *,
    lines: int = TAIL_LINES_ON_FAILURE,
) -> str:
    """Render the tail of both captured streams as an indented block."""
    parts: list[str] = []
    for stream, captured in (("stdout", stdout), ("stderr", stderr)):
        text = decoded_output(captured).strip()
        if text:
            tail = "\n    ".join(text.splitlines()[-lines:])
            parts.append(f"    {stream}: {tail}")
    if not parts:
        return "\n    (no output)"
    return "\n" + "\n".join(parts)


def timeout_output_tail(
    e: subprocess.TimeoutExpired, *, lines: int = TAIL_LINES_ON_FAILURE
) -> str:
    """Render whatever a timed-out subprocess had written before it was killed."""
    return output_tail(e.stdout, e.stderr, lines=lines)


def exit_output_tail(
    proc: subprocess.CompletedProcess, *, lines: int = TAIL_LINES_ON_FAILURE
) -> str:
    """Render whatever a subprocess had written when it exited.

    A ``docker run`` sidecar is gone by the time the report renders, so its own
    output is the only evidence of why it exited; ``compose logs`` cannot
    recover it.
    """
    return output_tail(proc.stdout, proc.stderr, lines=lines)


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
    url: str,
    payload: dict,
    timeout_s: float = HTTP_REQUEST_TIMEOUT_S,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    """POST ``payload`` as JSON to ``url`` and return ``(status, body)``."""
    data = json.dumps(payload).encode("utf-8")
    merged = {"Content-Type": "application/json"}
    if headers:
        merged.update(headers)
    req = urllib.request.Request(
        url,
        method="POST",
        data=data,
        headers=merged,
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

    The deadline is only consulted between attempts, so the real ceiling is
    ``timeout_s + interval_s +`` one predicate call. Gate budgets charge for it.
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


@dataclasses.dataclass(frozen=True)
class ProbeResult:
    """Whether a service came up, and what the last failed attempt reported.

    ``last_failure`` is the line that says *why* a gate timed out — the probe's
    own ``Connection refused`` or ``context deadline exceeded``. Without it the
    gate-failure report can only say the service never answered.
    """

    ready: bool
    last_failure: str = ""


# A readiness poller takes the address it probes; the zero-argument callable a
# gate holds is that poller with its address already bound.
Poller = Callable[..., ProbeResult]
Wait = Callable[[], ProbeResult]


def poll_probe(
    check: Callable[[], str],
    *,
    timeout_s: float,
    interval_s: float,
) -> ProbeResult:
    """Poll ``check`` until the service is serving, carrying the last reason out.

    ``check`` returns the reason the attempt failed, or an empty string once the
    service answers. ``poll_until`` swallows predicate exceptions, so a raised
    error is recorded as the attempt's reason before it is swallowed.
    """
    reason = [""]

    def _attempt() -> bool:
        try:
            reason[0] = check()
        except Exception as e:  # noqa: BLE001 — recorded, then left to poll_until
            reason[0] = repr(e)
            raise
        return not reason[0]

    ready = poll_until(_attempt, timeout_s=timeout_s, interval_s=interval_s)
    return ProbeResult(ready=ready, last_failure="" if ready else reason[0])


def probe_failure_tail(result: ProbeResult) -> str:
    """Render why a probe never succeeded, for the gate-failure report."""
    if not result.last_failure:
        return "\n    (the probe reported no error)"
    return f"\n    last probe attempt: {result.last_failure}"


def wait_for_http_ok(
    url: str,
    *,
    timeout_s: float = READINESS_TIMEOUT_S,
    interval_s: float = READINESS_POLL_INTERVAL_S,
) -> ProbeResult:
    """Poll ``url`` until it returns 2xx, or timeout."""

    def _check() -> str:
        status, body = http_get(url, timeout_s=HTTP_REQUEST_TIMEOUT_S)
        if 200 <= status < 300:
            return ""
        return f"GET {url} returned {status}: {body[:200]!r}"

    return poll_probe(_check, timeout_s=timeout_s, interval_s=interval_s)


def build_kafka_metadata_argv(
    network: str = COMPOSE_NETWORK,
    broker: str = KAFKA_INTERNAL_BROKER,
) -> list[str]:
    """Build the kcat argv that fetches broker metadata as JSON."""
    return [
        "docker", "run", "--rm",
        "--network", network,
        KCAT_IMAGE,
        "-b", broker,
        "-L",  # metadata mode
        "-J",  # JSON output
        "-m", "5",  # 5s metadata fetch timeout
    ]


def wait_for_kafka_ready(
    *,
    timeout_s: float = READINESS_TIMEOUT_S,
    interval_s: float = READINESS_POLL_INTERVAL_S,
) -> ProbeResult:
    """Poll Kafka broker metadata via kcat until the broker answers, or timeout.

    Uses kcat from inside the compose network so the internal listener
    (``kafka:29092``) is reachable.
    """

    def _check() -> str:
        proc = subprocess.run(
            build_kafka_metadata_argv(),
            capture_output=True,
            text=True,
            timeout=SIDECAR_PROBE_TIMEOUT_S,
            check=False,
        )
        if proc.returncode != 0:
            return f"kcat exited {proc.returncode}{exit_output_tail(proc)}"
        try:
            meta = json.loads(proc.stdout)
        except (json.JSONDecodeError, ValueError) as e:
            return f"kcat metadata was not JSON: {e}{exit_output_tail(proc)}"
        brokers = meta.get("brokers", [])
        if not isinstance(brokers, list) or not brokers:
            return f"kcat metadata carries no brokers: {meta!r}"
        return ""

    return poll_probe(_check, timeout_s=timeout_s, interval_s=interval_s)


def build_nats_connection_check_argv(
    network: str = COMPOSE_NETWORK,
    server_url: str = NATS_INTERNAL_URL,
) -> list[str]:
    """Build the nats-box argv that checks the server accepts a connection."""
    return [
        "docker", "run", "--rm",
        "--network", network,
        NATS_BOX_IMAGE,
        "nats", "server", "check", "connection",
        "--server", server_url,
    ]


def wait_for_nats_ready(
    *,
    timeout_s: float = READINESS_TIMEOUT_S,
    interval_s: float = READINESS_POLL_INTERVAL_S,
) -> ProbeResult:
    """Poll NATS via nats-box until the server accepts a connection, or timeout.

    Uses ``nats server check connection`` from inside the compose network so
    the internal listener (``nats:4222``) is reachable.
    """

    def _check() -> str:
        proc = subprocess.run(
            build_nats_connection_check_argv(),
            capture_output=True,
            text=True,
            timeout=SIDECAR_PROBE_TIMEOUT_S,
            check=False,
        )
        if proc.returncode != 0:
            return f"nats server check exited {proc.returncode}{exit_output_tail(proc)}"
        return ""

    return poll_probe(_check, timeout_s=timeout_s, interval_s=interval_s)


def build_tcp_probe_argv(
    target_ip: str, port: int, network: str = COMPOSE_NETWORK
) -> list[str]:
    """Build the busybox ``nc -z`` argv that tests one in-network TCP port.

    Runs from inside the compose network so the target's private address is
    reachable — the compose targets are ``expose``-only, not host-published.
    """
    return [
        "docker", "run", "--rm",
        "--network", network,
        BUSYBOX_IMAGE,
        "nc", "-z", target_ip, str(port),
    ]


def wait_for_tcp_port_ready(
    target_ip: str,
    port: int,
    *,
    network: str = COMPOSE_NETWORK,
    timeout_s: float = READINESS_TIMEOUT_S,
    interval_s: float = READINESS_POLL_INTERVAL_S,
) -> ProbeResult:
    """Poll ``target_ip:port`` via a busybox ``nc -z`` sidecar until the port
    accepts connections, or timeout.

    This is the same layer the ``tcp_connect`` prober asserts on, so a target
    that passes this gate is serving by the definition the matrix uses.
    """

    def _check() -> str:
        proc = subprocess.run(
            build_tcp_probe_argv(target_ip, port, network),
            capture_output=True,
            text=True,
            timeout=SIDECAR_PROBE_TIMEOUT_S,
            check=False,
        )
        if proc.returncode != 0:
            return f"nc -z exited {proc.returncode}{exit_output_tail(proc)}"
        return ""

    return poll_probe(_check, timeout_s=timeout_s, interval_s=interval_s)


# --- Readiness gates ---------------------------------------------------------


# Pollers that carry their own address rather than taking one, mapped to the
# address they poll, so a gate's endpoint can be reconciled against its wait.
BARE_POLLER_ENDPOINTS: dict[Poller, str] = {
    wait_for_kafka_ready: KAFKA_INTERNAL_BROKER,
    wait_for_nats_ready: NATS_INTERNAL_URL,
}

# Pollers taking their address as leading positional arguments, mapped to the
# endpoint rendering of those arguments.
ADDRESSED_POLLER_ENDPOINTS: dict[Poller, Callable[..., str]] = {
    wait_for_tcp_port_ready: lambda ip, port: f"{ip}:{port}",
    wait_for_http_ok: lambda url: url,
}

# How long one attempt of each poller can take. Reconciled against the timeout
# the poller's own ``_check`` enforces, so the two cannot drift apart.
POLL_ATTEMPT_CEILING_S: dict[Poller, float] = {
    wait_for_kafka_ready: SIDECAR_PROBE_TIMEOUT_S,
    wait_for_nats_ready: SIDECAR_PROBE_TIMEOUT_S,
    wait_for_tcp_port_ready: SIDECAR_PROBE_TIMEOUT_S,
    # urlopen applies its timeout per socket operation, not to the whole call,
    # so this bounds one operation against localhost rather than the attempt.
    wait_for_http_ok: HTTP_REQUEST_TIMEOUT_S,
}


def poll_target(wait: Wait) -> Poller:
    """Return the poller function behind a gate's ``wait``, unwrapping partials."""
    return wait.func if isinstance(wait, functools.partial) else wait


def poll_attempt_ceiling_s(wait: Wait) -> float:
    """Return how long one attempt of ``wait`` can take, read off the poller."""
    poller = poll_target(wait)
    try:
        return POLL_ATTEMPT_CEILING_S[poller]
    except (KeyError, TypeError):
        raise ValueError(
            f"{wait!r} is not a registered readiness poller, so the time one "
            "attempt of it can take is unknown and the run budget cannot "
            "charge for it: build the gate with tcp_gate/http_gate/bare_gate, "
            "or register the poller in POLL_ATTEMPT_CEILING_S"
        ) from None


def tcp_gate(service: str, ip: str, port: int) -> ReadinessGate:
    """Gate ``service`` on a TCP connect to ``ip:port``."""
    return ReadinessGate(
        service,
        f"{ip}:{port}",
        functools.partial(wait_for_tcp_port_ready, ip, port),
    )


def http_gate(service: str, url: str) -> ReadinessGate:
    """Gate ``service`` on ``url`` returning 2xx."""
    return ReadinessGate(service, url, functools.partial(wait_for_http_ok, url))


def bare_gate(service: str, wait: Wait) -> ReadinessGate:
    """Gate ``service`` on a poller that carries its own address."""
    return ReadinessGate(service, BARE_POLLER_ENDPOINTS[wait], wait)


def polled_endpoint(wait: Wait) -> str:
    """Return the address ``wait`` actually contacts, read off the callable.

    Raises ``ValueError`` for a callable whose target cannot be read — an
    inline lambda or an unregistered poller can claim any endpoint it likes.
    """
    if wait in BARE_POLLER_ENDPOINTS:
        return BARE_POLLER_ENDPOINTS[wait]
    if isinstance(wait, functools.partial) and wait.func in ADDRESSED_POLLER_ENDPOINTS:
        if wait.keywords:
            raise ValueError(
                f"{wait.func.__name__} was bound with keyword arguments "
                f"{sorted(wait.keywords)}, which the endpoint rendering does "
                "not read: bind the address positionally (tcp_gate/http_gate do)"
            )
        try:
            return ADDRESSED_POLLER_ENDPOINTS[wait.func](*wait.args)
        except TypeError as e:
            raise ValueError(
                f"{wait.func.__name__} was bound with {len(wait.args)} "
                f"positional arguments, which do not render an endpoint: {e}"
            ) from None
    raise ValueError(
        f"{wait!r} is not a registered readiness poller, so the address it "
        "contacts cannot be reconciled against the gate's endpoint: build the "
        "gate with tcp_gate/http_gate, or register the poller in "
        "BARE_POLLER_ENDPOINTS / ADDRESSED_POLLER_ENDPOINTS"
    )


@dataclasses.dataclass(frozen=True)
class Address:
    host: str
    port: int | None


# Addresses that name the machine the harness runs on rather than a container.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

SCHEME_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


def parse_endpoint(endpoint: str) -> Address:
    """Split ``ip:port``, ``host:port``, ``[v6]:port`` or a URL into host and port."""
    scheme, separator, rest = endpoint.partition("://")
    if not separator:
        scheme, rest = "", endpoint
    authority = rest.split("/", 1)[0]
    if authority.startswith("["):
        host, _, tail = authority[1:].partition("]")
        port_text = tail[1:] if tail.startswith(":") else ""
    else:
        host, _, port_text = authority.partition(":")
    if not port_text:
        return Address(host=host, port=SCHEME_DEFAULT_PORTS.get(scheme))
    if not port_text.isdigit():
        raise ValueError(f"endpoint {endpoint!r} has a non-numeric port {port_text!r}")
    return Address(host=host, port=int(port_text))


def services_reachable_at(
    endpoint: str, services: Sequence[ComposeService]
) -> frozenset[str]:
    """Return every compose service that can answer at ``endpoint``.

    Host and port both have to match, on either side of the address space. An
    in-network address names the service compose gave that static address or
    DNS name, and only if the service declares the container port. A
    runner-local address names whichever service publishes that host port, and
    nothing else: ``localhost`` on its own binds a gate to no service at all.
    """
    address = parse_endpoint(endpoint)
    if address.port is None:
        return frozenset()
    if address.host in LOOPBACK_HOSTS:
        return frozenset(
            service.name
            for service in services
            if address.port in service.published_host_ports
        )
    return frozenset(
        service.name
        for service in services
        if address.host in (service.name, service.ipv4_address)
        and address.port in service.container_ports
    )


def endpoint_vantage_network(endpoint: str) -> str | None:
    """The docker network ``endpoint`` can be reached from.

    A container address only answers inside the compose network; a published
    host port only answers on the runner, where ``None`` is the vantage.
    """
    return None if parse_endpoint(endpoint).host in LOOPBACK_HOSTS else COMPOSE_NETWORK


READINESS_GATES: tuple[ReadinessGate, ...] = (
    bare_gate("kafka", wait_for_kafka_ready),
    bare_gate("nats", wait_for_nats_ready),
    *(
        tcp_gate(service, ip, TARGET_PORT)
        for service, ip in TARGET_SERVICE_IPS.items()
    ),
    tcp_gate("target-ssh", TARGET_SSH_IP, TARGET_SSH_PORT),
    tcp_gate("target-tls", TARGET_TLS_IP, TARGET_TLS_PORT),
    http_gate("rastreo-server", SERVER_HEALTH_URL),
)

# Compose services deliberately left without a readiness gate, mapped to the
# reason. An entry here is a claim that no matrix row depends on the service
# being served; it is not a way to silence a flaky gate.
READINESS_EXEMPT_SERVICES: dict[str, str] = {}


def matrix_service_dependencies(rows: Sequence[MatrixRow]) -> frozenset[str]:
    """Return every compose service some matrix row names."""
    return frozenset(
        service for row in rows for service in row.failure_log_containers
    )


def readiness_coverage_gaps(
    compose_services: Sequence[str],
    gated_services: Sequence[str],
    exempt_services: Mapping[str, str],
    depended_on_services: frozenset[str],
) -> list[str]:
    """Reconcile the readiness registry against the compose service list.

    Returns one message per gap; an empty list means every compose service is
    either gated or exempt, every gate and exemption names a real service, and
    no exemption covers a service the matrix depends on.
    """
    gaps: list[str] = []
    compose_set = set(compose_services)
    gated_set = set(gated_services)

    for service in sorted(compose_set - gated_set - set(exempt_services)):
        gaps.append(
            f"compose service {service!r} has no readiness gate: add a "
            "ReadinessGate to READINESS_GATES, or record why it needs none in "
            "READINESS_EXEMPT_SERVICES"
        )
    for service in sorted(gated_set - compose_set):
        gaps.append(
            f"READINESS_GATES has a gate for {service!r}, which is not a "
            f"service in {COMPOSE_FILE}"
        )
    for service in sorted(set(exempt_services) - compose_set):
        gaps.append(
            f"READINESS_EXEMPT_SERVICES exempts {service!r}, which is not a "
            f"service in {COMPOSE_FILE}"
        )
    for service in sorted(gated_set & set(exempt_services)):
        gaps.append(
            f"service {service!r} is both gated and exempt: drop one of the "
            "two entries"
        )
    for service in sorted(set(exempt_services) & depended_on_services):
        gaps.append(
            f"service {service!r} is exempt "
            f"({exempt_services[service]!r}) but a matrix row names it: an "
            "exemption claims no row depends on the service, so gate it instead"
        )
    for service in sorted({s for s in gated_services if gated_services.count(s) > 1}):
        gaps.append(f"READINESS_GATES has more than one gate for {service!r}")

    return gaps


# --- Compose lifecycle -------------------------------------------------------


def compose_command(repo_root: Path, *args: str) -> list[str]:
    """Build a ``docker compose`` argv anchored at the repo's compose file."""
    return ["docker", "compose", "-f", str(repo_root / COMPOSE_FILE), *args]


def compose_service_names(
    repo_root: Path, *, timeout_s: float = COMPOSE_CONFIG_TIMEOUT_S
) -> list[str]:
    """Return the compose file's service names, as compose itself resolves them."""
    proc = subprocess.run(
        compose_command(repo_root, "config", "--services"),
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"docker compose config --services failed (exit {proc.returncode})"
            f"{exit_output_tail(proc)}"
        )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


@dataclasses.dataclass(frozen=True)
class PublishedPort:
    """One ``ports:`` mapping. ``host_port`` is None when compose picks it."""

    host_port: int | None
    container_port: int


@dataclasses.dataclass(frozen=True)
class ComposeService:
    """A service declared in the compose file, with the addresses it answers on."""

    name: str
    ipv4_address: str | None
    published_ports: tuple[PublishedPort, ...] = ()
    exposed_ports: tuple[int, ...] = ()

    @property
    def container_ports(self) -> frozenset[int]:
        """Ports the service serves inside the compose network."""
        return frozenset(self.exposed_ports) | {
            published.container_port for published in self.published_ports
        }

    @property
    def published_host_ports(self) -> frozenset[int]:
        """Ports the service serves on the runner."""
        return frozenset(
            published.host_port
            for published in self.published_ports
            if published.host_port is not None
        )


def parse_published_port(entry: str) -> PublishedPort:
    """Parse one ``ports:`` entry (``8080``, ``8080:80``, ``127.0.0.1:8080:80/tcp``)."""
    text = entry.strip().strip("\"'").split("/", 1)[0]
    parts = text.split(":")
    if len(parts) > 3 or not all(part.isdigit() for part in parts[-2:]):
        raise ValueError(f"unsupported compose port mapping: {entry!r}")
    if len(parts) == 1:
        return PublishedPort(host_port=None, container_port=int(parts[0]))
    return PublishedPort(host_port=int(parts[-2]), container_port=int(parts[-1]))


def parse_exposed_port(entry: str) -> int:
    """Parse one ``expose:`` entry (``80``, ``"2222"``, ``443/tcp``)."""
    text = entry.strip().strip("\"'").split("/", 1)[0]
    if not text.isdigit():
        raise ValueError(f"unsupported compose expose entry: {entry!r}")
    return int(text)


# ``ports:`` and ``expose:`` are read the same way — a block of list entries
# under a service — and differ only in what one entry means.
COMPOSE_PORT_BLOCKS: dict[str, Callable[[str], PublishedPort | int]] = {
    "ports:": parse_published_port,
    "expose:": parse_exposed_port,
}


def parse_compose_services(text: str) -> tuple[ComposeService, ...]:
    """Read the service names, static addresses, published ports and exposed
    ports out of compose YAML source.

    A line scan, not a YAML parse, so the self-tests can reconcile against the
    committed compose file on a runner with neither Docker nor PyYAML.
    """
    names: list[str] = []
    addresses: dict[str, str] = {}
    entries: dict[tuple[str, str], list[PublishedPort | int]] = {}
    in_services = False
    block: str | None = None
    current: str | None = None

    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            in_services = stripped == "services:"
            current = None
            block = None
            continue
        if not in_services:
            continue
        if indent == 2 and stripped.endswith(":"):
            current = stripped[:-1].strip()
            names.append(current)
            block = None
            continue
        if current is None:
            continue
        if block is not None:
            if indent > 4 and stripped.startswith("- "):
                entries.setdefault((current, block), []).append(
                    COMPOSE_PORT_BLOCKS[block](stripped[2:])
                )
                continue
            block = None
        if indent == 4 and stripped in COMPOSE_PORT_BLOCKS:
            block = stripped
            continue
        if stripped.startswith("ipv4_address:"):
            addresses[current] = stripped.split(":", 1)[1].strip()

    return tuple(
        ComposeService(
            name=name,
            ipv4_address=addresses.get(name),
            published_ports=tuple(entries.get((name, "ports:"), ())),
            exposed_ports=tuple(entries.get((name, "expose:"), ())),
        )
        for name in names
    )


def read_compose_services(repo_root: Path) -> tuple[ComposeService, ...]:
    """Parse the repo's committed compose file without invoking Docker."""
    return parse_compose_services(
        (repo_root / COMPOSE_FILE).read_text(encoding="utf-8")
    )


def read_job_timeout_s(repo_root: Path) -> float:
    """Return the Live Infra UAT job's ``timeout-minutes``, in seconds."""
    text = (repo_root / LIVE_UAT_WORKFLOW).read_text(encoding="utf-8")
    minutes = re.findall(r"^\s*timeout-minutes:\s*(\d+)\s*$", text, re.MULTILINE)
    if len(minutes) != 1:
        raise RuntimeError(
            f"expected exactly one 'timeout-minutes:' in {LIVE_UAT_WORKFLOW}, "
            f"found {len(minutes)}: the budget guard cannot tell which job it bounds"
        )
    return float(minutes[0]) * 60.0


def diagnostic_snapshots(row_count: int) -> int:
    """How many failure snapshots one run can take.

    One per failing row — the row loop snapshots and carries on — plus the one
    an interrupt or a harness bug takes after the last row has already
    snapshotted its own failure.
    """
    return row_count + 1


def worst_case_run_budget_s(
    phases: Sequence[StartupPhase],
    gates: Sequence[ReadinessGate],
    rows: Sequence[MatrixRow],
) -> float:
    """Upper bound on the harness's wall clock: every step running to its budget.

    Each term is the budget of the operation it bounds — the coverage check's
    ``compose config``, each startup phase, each gate (including the poll
    overrun ``poll_until`` can add), each row, every diagnostic snapshot the run
    can take, and tear-down. The CI job timeout must clear this total for the
    harness to name the step that overran rather than being killed mid-step.
    """
    return (
        COMPOSE_CONFIG_TIMEOUT_S
        + sum(phase.budget_s for phase in phases)
        + sum(gate.budget_s for gate in gates)
        + sum(row.budget_s for row in rows)
        + diagnostic_snapshots(len(rows)) * DIAGNOSTIC_BUDGET_S
        + COMPOSE_DOWN_TIMEOUT_S
    )


def startup_phases(repo_root: Path) -> tuple[StartupPhase, ...]:
    """The separately bounded steps from a clean checkout to running containers.

    ``up`` runs with ``--no-build --pull never`` so a missing image fails it
    immediately instead of silently spending the start budget on a download.
    """
    return (
        StartupPhase(
            name="compose build",
            argv=tuple(compose_command(repo_root, "build")),
            budget_s=COMPOSE_BUILD_TIMEOUT_S,
        ),
        StartupPhase(
            name="compose pull",
            argv=tuple(compose_command(repo_root, "pull", "--ignore-buildable")),
            budget_s=COMPOSE_PULL_TIMEOUT_S,
        ),
        *(
            StartupPhase(
                name=f"pull sidecar {image}",
                argv=("docker", "pull", image),
                budget_s=SIDECAR_PULL_TIMEOUT_S,
            )
            for image in SIDECAR_IMAGES
        ),
        StartupPhase(
            name="compose up",
            argv=tuple(
                compose_command(repo_root, "up", "-d", "--no-build", "--pull", "never")
            ),
            budget_s=COMPOSE_START_TIMEOUT_S,
        ),
    )


def run_startup_phase(phase: StartupPhase) -> None:
    """Run one startup phase, raising ``RuntimeError`` on timeout or failure."""
    print(f"==> {phase.name} (budget {phase.budget_s:.0f}s)", file=sys.stderr)
    start = _now_s()
    try:
        proc = subprocess.run(
            list(phase.argv),
            capture_output=True,
            text=True,
            timeout=phase.budget_s,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(
            f"{phase.name} exceeded its {phase.budget_s:.0f}s budget"
            f"{timeout_output_tail(e)}"
        ) from None
    if proc.returncode != 0:
        raise RuntimeError(
            f"{phase.name} failed (exit {proc.returncode})"
            f"{exit_output_tail(proc)}"
        )
    print(f"    {phase.name} ok ({_now_s() - start:.1f}s)", file=sys.stderr)


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
    timeout_s: float = DIAGNOSTIC_BUDGET_S,
) -> str:
    """Return the last ``tail_lines`` lines of the named service's logs.

    Best-effort: returns a diagnostic string on failure rather than raising, so
    a broken docker cannot cost the caller the results it is reporting.
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
    except subprocess.TimeoutExpired as e:
        return (
            f"<logs for {service} timed out after {timeout_s:.0f}s>"
            f"{timeout_output_tail(e)}"
        )
    except Exception as e:  # noqa: BLE001 — diagnostics must not lose the report
        return f"<logs unavailable for {service}: {e!r}>"
    return (proc.stdout or "") + (proc.stderr or "")


def compose_ps(repo_root: Path, *, timeout_s: float = COMPOSE_PS_TIMEOUT_S) -> str:
    """Return the ``docker compose ps`` table, exited containers included.

    Best-effort, on the same contract as ``compose_logs_tail``.
    """
    try:
        proc = subprocess.run(
            compose_command(repo_root, "ps", "--all"),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return f"<compose ps timed out after {timeout_s:.0f}s>{timeout_output_tail(e)}"
    except Exception as e:  # noqa: BLE001 — diagnostics must not lose the report
        return f"<compose ps unavailable: {e!r}>"
    return (proc.stdout or "") + (proc.stderr or "")


def capture_or_report(label: str, capture: Callable[[], str]) -> str:
    """Run a diagnostic capture, reporting any failure of it as its own output."""
    try:
        return capture()
    except Exception as e:  # noqa: BLE001 — diagnostics must not lose the report
        return f"<{label} unavailable: {e!r}>"


def snapshot_failure_state(
    repo_root: Path,
    services: Sequence[str],
    *,
    budget_s: float = DIAGNOSTIC_BUDGET_S,
    now: Callable[[], float] = _now_s,
) -> FailureSnapshot:
    """Capture container state and log tails while the containers are alive.

    The whole capture shares ``budget_s``: each step gets what is left of it,
    and a service the budget no longer reaches records that instead of the
    tail. Nothing here raises — a failing snapshot must not cost the caller the
    results it is about to report.
    """
    deadline = now() + budget_s
    state = capture_or_report(
        "compose ps",
        lambda: compose_ps(
            repo_root, timeout_s=min(COMPOSE_PS_TIMEOUT_S, max(0.0, deadline - now()))
        ),
    )
    logs: list[ServiceLog] = []
    for service in services:
        remaining = deadline - now()
        if remaining <= 0.0:
            logs.append(
                ServiceLog(
                    service=service,
                    text=(
                        f"<not captured: the {budget_s:.0f}s diagnostic budget "
                        "was spent on the services above>"
                    ),
                )
            )
            continue
        logs.append(
            ServiceLog(
                service=service,
                text=capture_or_report(
                    f"logs for {service}",
                    lambda service=service, remaining=remaining: compose_logs_tail(
                        repo_root, service, timeout_s=remaining
                    ),
                ),
            )
        )
    return FailureSnapshot(container_state=state, logs=tuple(logs))


# --- Row implementations -----------------------------------------------------

# `docker run` options the harness passes with a separate value token.
DOCKER_RUN_VALUE_FLAGS = frozenset({"--network", "--entrypoint", "-v", "-e", "--name"})


def docker_run_image(argv: Sequence[str]) -> str:
    """Return the image a ``docker run`` argv launches."""
    if list(argv[:2]) != ["docker", "run"]:
        raise ValueError(f"not a docker run argv: {list(argv)!r}")
    index = 2
    while index < len(argv):
        token = argv[index]
        if not token.startswith("-"):
            return token
        index += 2 if token in DOCKER_RUN_VALUE_FLAGS else 1
    raise ValueError(f"docker run argv names no image: {list(argv)!r}")


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
        "--format", "json",
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


def record_has_signal_matching(
    record: dict, tag: str, predicate: Callable[[object], bool]
) -> bool:
    """Return True if ``record.signals`` contains ``{tag: <value>}`` whose
    value satisfies ``predicate``.

    Generic form of ``record_has_open_port_signal`` for externally-tagged
    variants with a single payload — string-valued (e.g. ``SshBanner``,
    ``SshHostKey``) or numeric (e.g. ``IcmpEchoRttMicros``). Missing tags are
    skipped so the predicate isn't handed ``None``; type-checking is the
    predicate's job.
    """
    signals = record.get("signals", [])
    if not isinstance(signals, list):
        return False
    for sig in signals:
        if not isinstance(sig, dict) or tag not in sig:
            continue
        if predicate(sig[tag]):
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
    except subprocess.TimeoutExpired as e:
        return False, (
            f"rastreo CLI timed out after {SCENARIO_TIMEOUT_S:.0f}s"
            f"{timeout_output_tail(e)}"
        )

    if proc.returncode != 0:
        return False, f"rastreo exited {proc.returncode}{exit_output_tail(proc)}"

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
        "max_concurrent": 16,
    }


def run_server_post_scans(ctx: HarnessCtx) -> tuple[bool, str]:
    """Server -> POST /scans row: submit a scenario, verify the response shape."""
    payload = build_server_scan_payload()
    headers = (
        {"Authorization": f"Bearer {SERVER_API_TOKEN}"} if SERVER_API_TOKEN else None
    )
    try:
        status, body = http_post_json(
            SERVER_SCANS_URL, payload, timeout_s=SCENARIO_TIMEOUT_S, headers=headers
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
    except subprocess.TimeoutExpired as e:
        return False, (
            f"rastreo CLI (kafka) timed out after {SCENARIO_TIMEOUT_S:.0f}s"
            f"{timeout_output_tail(e)}"
        )

    if proc.returncode != 0:
        return False, f"rastreo exited {proc.returncode}{exit_output_tail(proc)}"

    consume_argv = build_kcat_consume_argv()
    try:
        kcat = subprocess.run(
            consume_argv,
            capture_output=True,
            text=True,
            timeout=KCAT_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return False, (
            f"kcat consume timed out after {KCAT_TIMEOUT_S:.0f}s"
            f"{timeout_output_tail(e)}"
        )

    if kcat.returncode != 0:
        return False, f"kcat exited {kcat.returncode}{exit_output_tail(kcat)}"

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


def build_nats_stream_add_argv(
    stream: str = NATS_UAT_STREAM,
    subject: str = NATS_UAT_SUBJECT,
    server_url: str = NATS_INTERNAL_URL,
    network: str = COMPOSE_NETWORK,
) -> list[str]:
    """Build the nats-box argv that creates the JetStream stream.

    Memory storage keeps the stream cheap and self-cleaning; the ``--no-...``
    flags dodge nats-box's interactive prompt for the unspecified options.
    """
    return [
        "docker", "run", "--rm",
        "--network", network,
        NATS_BOX_IMAGE,
        "nats", "stream", "add", stream,
        "--subjects", subject,
        "--storage", "memory",
        "--retention", "limits",
        "--discard", "old",
        "--max-msgs", "1000",
        "--max-age", "5m",
        "--dupe-window", "2m",
        "--replicas", "1",
        "--no-allow-rollup",
        "--no-deny-delete",
        "--no-deny-purge",
        "--defaults",
        "--server", server_url,
    ]


def create_nats_stream(
    ctx: HarnessCtx,
    *,
    stream: str = NATS_UAT_STREAM,
    subject: str = NATS_UAT_SUBJECT,
    server_url: str = NATS_INTERNAL_URL,
    network: str = COMPOSE_NETWORK,
    timeout_s: float = NATS_TIMEOUT_S,
) -> subprocess.CompletedProcess[str]:
    """Create the JetStream stream the CLI publishes to.

    The rastreo NATS sink verifies the stream exists at construction time, so
    the harness must create it before running the row.
    """
    try:
        proc = subprocess.run(
            build_nats_stream_add_argv(stream, subject, server_url, network),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(
            f"nats stream add {stream} timed out after {timeout_s:.0f}s"
            f"{timeout_output_tail(e)}"
        ) from None
    if proc.returncode != 0:
        raise RuntimeError(
            f"nats stream add {stream} failed (exit {proc.returncode})"
            f"{exit_output_tail(proc)}"
        )
    return proc


def build_cli_nats_scenario_yaml(
    target_ips: Sequence[str] = TARGET_IPS,
    port: int = TARGET_PORT,
    server_url: str = NATS_INTERNAL_URL,
    subject: str = NATS_UAT_SUBJECT,
    stream: str = NATS_UAT_STREAM,
) -> str:
    """Render the scenario YAML for the CLI -> NATS row.

    The NATS sink has no CLI flag surface, so the CLI runs against a mounted
    scenario file. Field names match ``SinkConfig::Nats`` (``servers``,
    ``subject``, ``stream``); ``flush_mode`` is omitted so the Rust default
    ``PerRecord`` applies.
    """
    targets_yaml = "\n".join(f"      - Ip: {ip}" for ip in target_ips)
    return (
        "version: 1\n"
        "kind: discovery\n"
        "scenarios:\n"
        "  - signal_type: discover\n"
        "    name: uat-nats\n"
        "    timeout_ms: 2000\n"
        "    max_concurrent: 16\n"
        "    sink:\n"
        "      type: nats\n"
        f"      servers: [\"{server_url}\"]\n"
        f"      subject: {subject}\n"
        f"      stream: {stream}\n"
        "    targets:\n"
        f"{targets_yaml}\n"
        "    probers:\n"
        "      - type: tcp_connect\n"
        f"        ports: [{port}]\n"
    )


def build_cli_nats_argv(
    scenario_host_path: str,
    rastreo_image: str = RASTREO_IMAGE,
    network: str = COMPOSE_NETWORK,
) -> list[str]:
    """Build the docker-run argv for the CLI -> NATS row.

    The scenario file is bind-mounted at ``/scenario.yaml`` inside the
    container so the CLI can load it via ``--file``.
    """
    return [
        "docker", "run", "--rm",
        "--network", network,
        "-v", f"{scenario_host_path}:/scenario.yaml:ro",
        "--entrypoint", "/rastreo",
        rastreo_image,
        "discover",
        "--file", "/scenario.yaml",
    ]


def build_nats_consume_argv(
    network: str = COMPOSE_NETWORK,
    stream: str = NATS_UAT_STREAM,
    server_url: str = NATS_INTERNAL_URL,
) -> list[str]:
    """Build the docker-run argv that drains the JetStream stream.

    Uses ``nats stream get`` inside a shell loop: ``stream info --json``
    reports the message count, then each message is fetched by sequence and
    the base64-encoded payload decoded. This shape is the reliable one across
    nats-box versions; ``nats stream view --raw`` prints framing metadata
    interleaved with the payloads on nats-box 0.18.0 and is not usable as
    a clean NDJSON source.
    """
    script = (
        "set -e\n"
        f"N=$(nats stream info {stream} --server {server_url} --json | "
        "jq .state.messages)\n"
        "for i in $(seq 1 $N); do\n"
        f"  nats stream get {stream} $i --server {server_url} --json | "
        "jq -r .data | base64 -d\n"
        "  echo\n"
        "done\n"
    )
    return [
        "docker", "run", "--rm",
        "--network", network,
        "--entrypoint", "sh",
        NATS_BOX_IMAGE,
        "-c", script,
    ]


def run_cli_nats(ctx: HarnessCtx) -> tuple[bool, str]:
    """CLI -> NATS row: create the JetStream stream, publish via the CLI with
    a mounted scenario file, drain the stream, and verify record shape."""
    try:
        create_nats_stream(ctx)
    except RuntimeError as e:
        return False, str(e)

    scenario_yaml = build_cli_nats_scenario_yaml()
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    try:
        tmp.write(scenario_yaml)
        tmp.close()
        # rastreo runs as UID 65532 inside the container; NamedTemporaryFile
        # is 0600 by default, so widen so the container's non-root user can read.
        os.chmod(tmp.name, 0o644)

        publish_argv = build_cli_nats_argv(tmp.name)
        try:
            proc = subprocess.run(
                publish_argv,
                capture_output=True,
                text=True,
                timeout=SCENARIO_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            return False, (
                f"rastreo CLI (nats) timed out after {SCENARIO_TIMEOUT_S:.0f}s"
                f"{timeout_output_tail(e)}"
            )

        if proc.returncode != 0:
            return False, f"rastreo exited {proc.returncode}{exit_output_tail(proc)}"

        consume_argv = build_nats_consume_argv()
        try:
            consume = subprocess.run(
                consume_argv,
                capture_output=True,
                text=True,
                timeout=NATS_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            return False, (
                f"nats consume timed out after {NATS_TIMEOUT_S:.0f}s"
                f"{timeout_output_tail(e)}"
            )

        if consume.returncode != 0:
            return False, (
                f"nats consume exited {consume.returncode}"
                f"{exit_output_tail(consume)}"
            )

        try:
            records = parse_ndjson_records(consume.stdout)
        except json.JSONDecodeError as e:
            return False, (
                f"nats output was not NDJSON: {e}\n    stdout: {consume.stdout!r}"
            )

        if len(records) != len(TARGET_IPS):
            return False, (
                f"expected {len(TARGET_IPS)} records on stream, got {len(records)}\n"
                f"    nats stdout: {consume.stdout!r}"
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

        return True, f"{len(records)} records consumed from {NATS_UAT_STREAM}"
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def build_cli_ssh_scenario_yaml(
    target_ip: str = TARGET_SSH_IP,
    port: int = TARGET_SSH_PORT,
) -> str:
    """Render the scenario YAML for the CLI -> SSH row.

    The SSH prober has no CLI flag surface, so the CLI runs against a
    mounted scenario file. Field names match the ``ssh`` prober config.
    """
    return (
        "version: 1\n"
        "kind: discovery\n"
        "scenarios:\n"
        "  - signal_type: discover\n"
        "    name: uat-ssh\n"
        "    timeout_ms: 5000\n"
        "    targets:\n"
        f"      - Ip: {target_ip}\n"
        "    probers:\n"
        "      - type: ssh\n"
        f"        ports: [{port}]\n"
    )


def build_cli_ssh_argv(
    scenario_host_path: str,
    rastreo_image: str = RASTREO_IMAGE,
    network: str = COMPOSE_NETWORK,
) -> list[str]:
    """Build the docker-run argv for the CLI -> SSH row.

    The scenario file is bind-mounted at ``/scenario.yaml`` inside the
    container so the CLI can load it via ``--file``.
    """
    return [
        "docker", "run", "--rm",
        "--network", network,
        "-v", f"{scenario_host_path}:/scenario.yaml:ro",
        "--entrypoint", "/rastreo",
        rastreo_image,
        "discover",
        "--file", "/scenario.yaml",
        "--format", "json",
    ]


def run_cli_ssh(ctx: HarnessCtx) -> tuple[bool, str]:
    """CLI -> SSH row: probe target-ssh via a mounted scenario file and
    verify the emitted record carries both an ``SshBanner`` and an
    ``SshHostKey`` signal."""
    scenario_yaml = build_cli_ssh_scenario_yaml()
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    try:
        tmp.write(scenario_yaml)
        tmp.close()
        # rastreo runs as UID 65532 inside the container; widen so the
        # container's non-root user can read the mounted scenario.
        os.chmod(tmp.name, 0o644)

        argv = build_cli_ssh_argv(tmp.name)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=SCENARIO_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            return False, (
                f"rastreo CLI (ssh) timed out after {SCENARIO_TIMEOUT_S:.0f}s"
                f"{timeout_output_tail(e)}"
            )

        if proc.returncode != 0:
            return False, f"rastreo exited {proc.returncode}{exit_output_tail(proc)}"

        try:
            records = parse_ndjson_records(proc.stdout)
        except json.JSONDecodeError as e:
            return False, (
                f"stdout was not NDJSON: {e}\n    stdout: {proc.stdout!r}"
            )

        if len(records) != 1:
            return False, (
                f"expected 1 record, got {len(records)}\n"
                f"    stdout: {proc.stdout!r}"
            )

        rec = records[0]
        key = rec.get("identity_key")
        expected_key = f"ip:{TARGET_SSH_IP}"
        if key != expected_key:
            return False, (
                f"identity_key mismatch: expected {expected_key!r}, got {key!r}"
            )

        if not record_has_signal_matching(
            rec, "SshBanner", lambda s: s.startswith("SSH-")
        ):
            return False, (
                f"record missing SshBanner starting with 'SSH-': "
                f"{rec.get('signals')!r}"
            )

        if not record_has_signal_matching(
            rec, "SshHostKey", lambda s: " " in s
        ):
            return False, (
                f"record missing SshHostKey with '<algorithm> <base64>' shape: "
                f"{rec.get('signals')!r}"
            )

        return True, f"SshBanner + SshHostKey signals on {TARGET_SSH_IP}"
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def build_cli_icmp_scenario_yaml(
    target_ips: Sequence[str] = TARGET_IPS,
    count: int = 3,
    interval_ms: int = 100,
) -> str:
    """Render the scenario YAML for the CLI -> ICMP row.

    The ICMP prober has no CLI flag surface, so the CLI runs against a
    mounted scenario file. Field names match the ``icmp`` prober config.
    """
    targets_yaml = "\n".join(f"      - Ip: {ip}" for ip in target_ips)
    return (
        "version: 1\n"
        "kind: discovery\n"
        "scenarios:\n"
        "  - signal_type: discover\n"
        "    name: uat-icmp\n"
        "    timeout_ms: 5000\n"
        "    targets:\n"
        f"{targets_yaml}\n"
        "    probers:\n"
        "      - type: icmp\n"
        f"        count: {count}\n"
        f"        interval_ms: {interval_ms}\n"
    )


def build_cli_icmp_argv(
    scenario_host_path: str,
    rastreo_image: str = RASTREO_IMAGE,
    network: str = COMPOSE_NETWORK,
) -> list[str]:
    """Build the docker-run argv for the CLI -> ICMP row.

    Adds ``--cap-add=NET_RAW`` so the container has the raw-socket capability
    in its bounding set; the image ships with ``cap_net_raw+ep`` as a file
    capability but the runtime cap must be present for it to activate.
    """
    return [
        "docker", "run", "--rm",
        "--network", network,
        "--cap-add=NET_RAW",
        "-v", f"{scenario_host_path}:/scenario.yaml:ro",
        "--entrypoint", "/rastreo",
        rastreo_image,
        "discover",
        "--file", "/scenario.yaml",
        "--format", "json",
    ]


def run_cli_icmp(ctx: HarnessCtx) -> tuple[bool, str]:
    """CLI -> ICMP row: probe the 3 nginx targets and verify each emitted
    record carries an ``IcmpEchoRttMicros`` signal with a positive value."""
    scenario_yaml = build_cli_icmp_scenario_yaml()
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    try:
        tmp.write(scenario_yaml)
        tmp.close()
        # rastreo runs as UID 65532 inside the container; widen so the
        # container's non-root user can read the mounted scenario.
        os.chmod(tmp.name, 0o644)

        argv = build_cli_icmp_argv(tmp.name)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=SCENARIO_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            return False, (
                f"rastreo CLI (icmp) timed out after {SCENARIO_TIMEOUT_S:.0f}s"
                f"{timeout_output_tail(e)}"
            )

        if proc.returncode != 0:
            return False, f"rastreo exited {proc.returncode}{exit_output_tail(proc)}"

        try:
            records = parse_ndjson_records(proc.stdout)
        except json.JSONDecodeError as e:
            return False, (
                f"stdout was not NDJSON: {e}\n    stdout: {proc.stdout!r}"
            )

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
            if not record_has_signal_matching(
                rec,
                "IcmpEchoRttMicros",
                lambda v: isinstance(v, int) and v > 0,
            ):
                return False, (
                    f"record {key!r} missing positive IcmpEchoRttMicros signal: "
                    f"{rec.get('signals')!r}"
                )

        expected_keys = {f"ip:{ip}" for ip in TARGET_IPS}
        if seen_keys != expected_keys:
            return False, (
                f"identity_key mismatch: expected {sorted(expected_keys)}, "
                f"got {sorted(seen_keys)}"
            )

        return True, f"IcmpEchoRttMicros on {len(records)} targets"
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def build_cli_tls_scenario_yaml(
    target_ip: str = TARGET_TLS_IP,
    port: int = TARGET_TLS_PORT,
) -> str:
    """Render the scenario YAML for the CLI -> TLS row.

    The TLS prober has no CLI flag surface, so the CLI runs against a
    mounted scenario file. Field names match the ``tls`` prober config.
    """
    return (
        "version: 1\n"
        "kind: discovery\n"
        "scenarios:\n"
        "  - signal_type: discover\n"
        "    name: uat-tls\n"
        "    timeout_ms: 5000\n"
        "    targets:\n"
        f"      - Ip: {target_ip}\n"
        "    probers:\n"
        "      - type: tls\n"
        f"        ports: [{port}]\n"
    )


def build_cli_tls_argv(
    scenario_host_path: str,
    rastreo_image: str = RASTREO_IMAGE,
    network: str = COMPOSE_NETWORK,
) -> list[str]:
    """Build the docker-run argv for the CLI -> TLS row.

    The scenario file is bind-mounted at ``/scenario.yaml`` inside the
    container so the CLI can load it via ``--file``.
    """
    return [
        "docker", "run", "--rm",
        "--network", network,
        "-v", f"{scenario_host_path}:/scenario.yaml:ro",
        "--entrypoint", "/rastreo",
        rastreo_image,
        "discover",
        "--file", "/scenario.yaml",
        "--format", "json",
    ]


def run_cli_tls(ctx: HarnessCtx) -> tuple[bool, str]:
    """CLI -> TLS row: probe target-tls via a mounted scenario file and
    verify the emitted record carries the known ``TlsSubject`` and both
    the DNS and IP ``TlsSanName`` fingerprints."""
    scenario_yaml = build_cli_tls_scenario_yaml()
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    try:
        tmp.write(scenario_yaml)
        tmp.close()
        # rastreo runs as UID 65532 inside the container; widen so the
        # container's non-root user can read the mounted scenario.
        os.chmod(tmp.name, 0o644)

        argv = build_cli_tls_argv(tmp.name)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=SCENARIO_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            return False, (
                f"rastreo CLI (tls) timed out after {SCENARIO_TIMEOUT_S:.0f}s"
                f"{timeout_output_tail(e)}"
            )

        if proc.returncode != 0:
            return False, f"rastreo exited {proc.returncode}{exit_output_tail(proc)}"

        try:
            records = parse_ndjson_records(proc.stdout)
        except json.JSONDecodeError as e:
            return False, (
                f"stdout was not NDJSON: {e}\n    stdout: {proc.stdout!r}"
            )

        if len(records) != 1:
            return False, (
                f"expected 1 record, got {len(records)}\n"
                f"    stdout: {proc.stdout!r}"
            )

        rec = records[0]
        key = rec.get("identity_key")
        expected_key = f"ip:{TARGET_TLS_IP}"
        if key != expected_key:
            return False, (
                f"identity_key mismatch: expected {expected_key!r}, got {key!r}"
            )

        if not record_has_signal_matching(
            rec, "TlsSubject", lambda s: s == TARGET_TLS_EXPECTED_CN
        ):
            return False, (
                f"record missing TlsSubject == {TARGET_TLS_EXPECTED_CN!r}: "
                f"{rec.get('signals')!r}"
            )

        if not record_has_signal_matching(
            rec, "TlsSanName", lambda s: s == TARGET_TLS_EXPECTED_DNS_SAN
        ):
            return False, (
                f"record missing TlsSanName == {TARGET_TLS_EXPECTED_DNS_SAN!r}: "
                f"{rec.get('signals')!r}"
            )

        if not record_has_signal_matching(
            rec, "TlsSanName", lambda s: s == TARGET_TLS_EXPECTED_IP_SAN
        ):
            return False, (
                f"record missing TlsSanName == {TARGET_TLS_EXPECTED_IP_SAN!r}: "
                f"{rec.get('signals')!r}"
            )

        return True, f"TlsSubject + DNS/IP TlsSanName on {TARGET_TLS_IP}"
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def build_cli_reverse_dns_scenario_yaml(
    target_ip: str = RDNS_TARGET_IP,
    resolver_ip: str = RDNS_RESOLVER_IP,
) -> str:
    """Render the scenario YAML for the CLI -> ReverseDns row.

    The ReverseDns prober has no CLI flag surface, so the CLI runs against a
    mounted scenario file. Field names match the ``reverse_dns`` prober config.
    """
    return (
        "version: 1\n"
        "kind: discovery\n"
        "scenarios:\n"
        "  - signal_type: discover\n"
        "    name: uat-reverse-dns\n"
        "    timeout_ms: 8000\n"
        "    targets:\n"
        f"      - Ip: {target_ip}\n"
        "    probers:\n"
        "      - type: reverse_dns\n"
        f"        resolvers: [\"{resolver_ip}\"]\n"
    )


def build_cli_reverse_dns_argv(
    scenario_host_path: str,
    rastreo_image: str = RASTREO_IMAGE,
    network: str = COMPOSE_NETWORK,
) -> list[str]:
    """Build the docker-run argv for the CLI -> ReverseDns row.

    The scenario file is bind-mounted at ``/scenario.yaml`` inside the
    container so the CLI can load it via ``--file``. Reverse DNS is a plain
    UDP query, so no ``--cap-add`` is needed.
    """
    return [
        "docker", "run", "--rm",
        "--network", network,
        "-v", f"{scenario_host_path}:/scenario.yaml:ro",
        "--entrypoint", "/rastreo",
        rastreo_image,
        "discover",
        "--file", "/scenario.yaml",
        "--format", "json",
    ]


def run_cli_reverse_dns(ctx: HarnessCtx) -> tuple[bool, str]:
    """CLI -> ReverseDns row: probe RDNS_TARGET_IP via RDNS_RESOLVER_IP through
    a mounted scenario file and verify the emitted record carries a
    ``ReverseDnsName`` signal whose value is ``RDNS_EXPECTED_NAME``."""
    scenario_yaml = build_cli_reverse_dns_scenario_yaml()
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    try:
        tmp.write(scenario_yaml)
        tmp.close()
        # rastreo runs as UID 65532 inside the container; widen so the
        # container's non-root user can read the mounted scenario.
        os.chmod(tmp.name, 0o644)

        argv = build_cli_reverse_dns_argv(tmp.name)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=SCENARIO_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            return False, (
                f"rastreo CLI (reverse_dns) timed out after {SCENARIO_TIMEOUT_S:.0f}s"
                f"{timeout_output_tail(e)}"
            )

        if proc.returncode != 0:
            return False, f"rastreo exited {proc.returncode}{exit_output_tail(proc)}"

        try:
            records = parse_ndjson_records(proc.stdout)
        except json.JSONDecodeError as e:
            return False, (
                f"stdout was not NDJSON: {e}\n    stdout: {proc.stdout!r}"
            )

        if len(records) != 1:
            return False, (
                f"expected 1 record, got {len(records)}\n"
                f"    stdout: {proc.stdout!r}"
            )

        rec = records[0]
        key = rec.get("identity_key")
        expected_key = f"ip:{RDNS_TARGET_IP}"
        if key != expected_key:
            return False, (
                f"identity_key mismatch: expected {expected_key!r}, got {key!r}"
            )

        if not record_has_signal_matching(
            rec, "ReverseDnsName", lambda v: v == RDNS_EXPECTED_NAME
        ):
            return False, (
                f"record missing ReverseDnsName == {RDNS_EXPECTED_NAME!r}: "
                f"{rec.get('signals')!r}"
            )

        return True, f"ReverseDnsName={RDNS_EXPECTED_NAME} on {RDNS_TARGET_IP}"
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


# --- Matrix ------------------------------------------------------------------

MATRIX: tuple[MatrixRow, ...] = (
    MatrixRow(
        name="cli_stdout",
        run=run_cli_stdout,
        budget_s=SCENARIO_TIMEOUT_S,
        failure_log_containers=("target-1", "target-2", "target-3"),
    ),
    MatrixRow(
        name="server_post_scans",
        run=run_server_post_scans,
        budget_s=SCENARIO_TIMEOUT_S,
        failure_log_containers=("rastreo-server", "target-1"),
    ),
    MatrixRow(
        name="cli_kafka",
        run=run_cli_kafka,
        budget_s=SCENARIO_TIMEOUT_S + KCAT_TIMEOUT_S,
        failure_log_containers=("kafka", "target-1"),
    ),
    MatrixRow(
        name="cli_nats",
        run=run_cli_nats,
        budget_s=NATS_TIMEOUT_S + SCENARIO_TIMEOUT_S + NATS_TIMEOUT_S,
        failure_log_containers=("nats", "target-1"),
    ),
    MatrixRow(
        name="cli_ssh",
        run=run_cli_ssh,
        budget_s=SCENARIO_TIMEOUT_S,
        failure_log_containers=("target-ssh", "target-1"),
    ),
    MatrixRow(
        name="cli_icmp",
        run=run_cli_icmp,
        budget_s=SCENARIO_TIMEOUT_S,
        failure_log_containers=("target-1", "target-2"),
    ),
    MatrixRow(
        name="cli_tls",
        run=run_cli_tls,
        budget_s=SCENARIO_TIMEOUT_S,
        failure_log_containers=("target-tls", "target-1"),
    ),
    MatrixRow(
        name="cli_reverse_dns",
        run=run_cli_reverse_dns,
        budget_s=SCENARIO_TIMEOUT_S,
        # No in-network compose service participates (external resolver).
        # target-1 covers a network-reachability sanity dump on failure.
        failure_log_containers=("target-1",),
    ),
)


# --- Failure attribution -----------------------------------------------------


def preflight_failure(
    name: str,
    message: str,
    containers: tuple[str, ...] = (),
    snapshot: FailureSnapshot | None = None,
) -> RowResult:
    """Wrap a coverage, startup or readiness failure as a ``RowResult`` so it
    reports and exits through the same path as a failing matrix row."""
    row = MatrixRow(
        name=name,
        run=lambda _c: (False, message),
        budget_s=0.0,
        failure_log_containers=containers,
    )
    return RowResult(row=row, ok=False, message=message, snapshot=snapshot)


def attribute_failure(result: RowResult) -> str:
    """Render a failure as a multi-line stderr block.

    Pure formatting over the snapshot already taken on ``result``: the report is
    printed after tear-down, when no container is left to read state from.
    """
    lines = [
        f"FAIL [{result.row.name}] ({result.duration_s:.1f}s)",
        f"    {result.message}",
    ]
    if result.snapshot is None:
        return "\n".join(lines)
    lines.append("--- docker compose ps (at failure time) ---")
    lines.append(result.snapshot.container_state.rstrip() or "(no output)")
    lines.append("--- end compose ps ---")
    for log in result.snapshot.logs:
        lines.append(f"--- docker logs (tail) for {log.service} ---")
        lines.append(log.text.rstrip() or "(no output)")
        lines.append(f"--- end {log.service} ---")
    return "\n".join(lines)


# --- Orchestration -----------------------------------------------------------


class HarnessInterrupted(Exception):
    """Ctrl-C during a run, carrying the results gathered before it arrived."""

    def __init__(self, results: list[RowResult]) -> None:
        super().__init__("interrupted")
        self.results = results


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


def check_readiness_coverage(repo_root: Path, rows: Sequence[MatrixRow]) -> list[str]:
    """Return the readiness-coverage gaps for the repo's compose file."""
    try:
        services = compose_service_names(repo_root)
    except subprocess.TimeoutExpired as e:
        return [
            "could not read the compose service list: docker compose config "
            f"exceeded its {COMPOSE_CONFIG_TIMEOUT_S:.0f}s budget"
            f"{timeout_output_tail(e)}"
        ]
    except (RuntimeError, FileNotFoundError) as e:
        return [f"could not read the compose service list: {e}"]
    return readiness_coverage_gaps(
        services,
        [gate.service for gate in READINESS_GATES],
        READINESS_EXEMPT_SERVICES,
        matrix_service_dependencies(rows),
    )


def started_services() -> tuple[str, ...]:
    """Every compose service the run brings up.

    Gated plus exempt: the coverage check that runs first proves that union is
    exactly the compose file's service list, so a startup failure can dump the
    whole stack without re-reading it.
    """
    return tuple(gate.service for gate in READINESS_GATES) + tuple(
        READINESS_EXEMPT_SERVICES
    )


def tear_down(repo_root: Path) -> None:
    """Tear the stack down, reporting rather than raising on failure."""
    print("==> compose down -v", file=sys.stderr)
    try:
        down = compose_down(repo_root)
    except subprocess.TimeoutExpired as e:
        print(
            f"WARN: compose down timed out after {COMPOSE_DOWN_TIMEOUT_S:.0f}s"
            f"{timeout_output_tail(e)}",
            file=sys.stderr,
        )
        return
    except BaseException as e:  # noqa: BLE001 — tear-down must not lose the report
        print(f"WARN: compose down failed: {e!r}", file=sys.stderr)
        return
    if down.returncode != 0:
        print(
            f"WARN: compose down exited {down.returncode}{exit_output_tail(down)}",
            file=sys.stderr,
        )


def run_all(
    rows: Sequence[MatrixRow],
    ctx: HarnessCtx,
) -> list[RowResult]:
    """Prove every compose service ready, run every row in order, tear down once.

    The coverage check runs before anything is started, so an ungated service
    costs one ``docker compose config`` rather than a full build. Tear-down runs
    in a ``finally`` block so a panicking row, a Ctrl-C during a startup phase,
    or a row exception still cleans up volumes. ``compose_down`` is safe to call
    even when a startup phase was interrupted mid-build, and runs on the
    coverage-failure path too so an aborted earlier run leaves nothing up.

    Every failure raised once containers exist — a startup phase, a gate, a row,
    a Ctrl-C, or a bug in the harness itself — snapshots container state and
    logs before returning, because the ``finally`` removes the containers the
    diagnostics would be read from. The coverage failure is the one exception:
    it precedes every phase, so there is nothing up to snapshot.

    Raises ``HarnessInterrupted`` on Ctrl-C, carrying the results gathered so
    far so the report survives the interrupt.
    """
    results: list[RowResult] = []

    try:
        print("==> checking readiness coverage", file=sys.stderr)
        gaps = check_readiness_coverage(ctx.repo_root, rows)
        if gaps:
            return [
                preflight_failure(
                    "readiness:coverage",
                    "every compose service must be gated or exempt:\n    - "
                    + "\n    - ".join(gaps),
                )
            ]
        print(
            f"    {len(READINESS_GATES)} services gated, "
            f"{len(READINESS_EXEMPT_SERVICES)} exempt",
            file=sys.stderr,
        )

        for phase in startup_phases(ctx.repo_root):
            try:
                run_startup_phase(phase)
            except RuntimeError as e:
                services = started_services()
                results.append(
                    preflight_failure(
                        phase.name,
                        str(e),
                        services,
                        snapshot_failure_state(ctx.repo_root, services),
                    )
                )
                return results

        for gate in READINESS_GATES:
            print(f"==> waiting for {gate.service} ({gate.endpoint})", file=sys.stderr)
            start = _now_s()
            probe = gate.wait()
            elapsed = _now_s() - start
            if not probe.ready:
                results.append(
                    preflight_failure(
                        f"readiness:{gate.service}",
                        f"{gate.service} was not serving on {gate.endpoint} within "
                        f"{READINESS_TIMEOUT_S:.0f}s"
                        f"{probe_failure_tail(probe)}",
                        (gate.service,),
                        snapshot_failure_state(ctx.repo_root, (gate.service,)),
                    )
                )
                return results
            print(f"    {gate.service} ready ({elapsed:.1f}s)", file=sys.stderr)

        for row in rows:
            print(f"==> running [{row.name}]", file=sys.stderr)
            start = _now_s()
            try:
                ok, message = row.run(ctx)
            except KeyboardInterrupt:
                results.append(
                    RowResult(
                        row=row,
                        ok=False,
                        message="interrupted (Ctrl-C) while the row was running",
                        duration_s=_now_s() - start,
                        snapshot=snapshot_failure_state(
                            ctx.repo_root, row.failure_log_containers
                        ),
                    )
                )
                raise HarnessInterrupted(results) from None
            except Exception as e:  # noqa: BLE001 — surface any row error as FAIL
                ok, message = False, f"unhandled exception: {e!r}"
            duration = _now_s() - start
            snapshot = (
                None
                if ok
                else snapshot_failure_state(ctx.repo_root, row.failure_log_containers)
            )
            result = RowResult(
                row=row, ok=ok, message=message, duration_s=duration, snapshot=snapshot
            )
            status = "PASS" if ok else "FAIL"
            print(
                f"    [{row.name}] {status} ({duration:.1f}s) {message}",
                file=sys.stderr,
            )
            results.append(result)
    except HarnessInterrupted:
        raise
    except KeyboardInterrupt:
        services = started_services()
        results.append(
            preflight_failure(
                "interrupted",
                "interrupted (Ctrl-C) before the matrix finished",
                services,
                snapshot_failure_state(ctx.repo_root, services),
            )
        )
        raise HarnessInterrupted(results) from None
    except Exception:  # noqa: BLE001 — a harness bug still owes the evidence
        services = started_services()
        results.append(
            preflight_failure(
                "harness",
                f"the harness itself failed:\n{traceback.format_exc().rstrip()}",
                services,
                snapshot_failure_state(ctx.repo_root, services),
            )
        )
        return results
    finally:
        tear_down(ctx.repo_root)

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

    interrupted = False
    try:
        results = run_all(MATRIX, ctx)
    except HarnessInterrupted as e:
        interrupted = True
        results = e.results

    failures = [r for r in results if not r.ok]
    for failure in failures:
        print(attribute_failure(failure), file=sys.stderr)
    print(
        f"{len(results)} rows checked, {len(failures)} failed",
        file=sys.stderr,
    )
    if interrupted:
        print("Interrupted; tear-down already attempted.", file=sys.stderr)
        return 130
    return 0 if not failures else 1


# --- Self-tests --------------------------------------------------------------


def _repo_root_for_self_tests() -> Path:
    return find_repo_root(Path(__file__).parent)


def _this_module() -> object:
    return sys.modules[__name__]


def _function_defs(source: str) -> dict[str, ast.FunctionDef]:
    """Module-level function definitions, by name.

    An ``async def`` is refused rather than skipped: it is not an
    ``ast.FunctionDef``, so a coroutine helper would be invisible to the source
    analyses that read these bodies and they would silently undercount.
    """
    tree = ast.parse(source)
    coroutines = sorted(
        node.name for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
    )
    if coroutines:
        raise ValueError(
            f"{', '.join(coroutines)} are async, which the source analyses do "
            "not read: keep the harness synchronous, or teach _function_defs, "
            "_bounded_work_s and _poller_check_def to follow a coroutine"
        )
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


@functools.lru_cache(maxsize=None)
def _module_function_defs() -> dict[str, ast.FunctionDef]:
    return _function_defs(Path(__file__).read_text(encoding="utf-8"))


_TIMEOUT_KEYWORDS = frozenset({"timeout", "timeout_s"})

# Calls that block until their own timeout fires. One without a timeout keyword
# can hang forever, so the time analysis refuses rather than charging zero.
BLOCKING_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "urlopen",
        "urllib.request.urlopen",
        "socket.create_connection",
    }
)


def _parameter_default(fn: ast.FunctionDef, name: str) -> ast.expr | None:
    args = fn.args
    positional = list(getattr(args, "posonlyargs", [])) + list(args.args)
    bound = positional[len(positional) - len(args.defaults):]
    for arg, default in zip(bound, args.defaults):
        if arg.arg == name:
            return default
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if arg.arg == name and default is not None:
            return default
    return None


def _resolve_number(node: ast.expr, scope: ast.FunctionDef | None) -> float | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.Name):
        default = _parameter_default(scope, node.id) if scope is not None else None
        if default is not None:
            return _resolve_number(default, None)
        value = vars(_this_module()).get(node.id)
        return float(value) if isinstance(value, (int, float)) else None
    return None


def _dotted_name(node: ast.expr) -> str | None:
    """Render ``a.b.c`` or ``a`` from an expression, or None if it is neither."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _resolve_length(node: ast.expr, scope: ast.FunctionDef | None) -> int | None:
    """How many times iterating ``node`` runs the loop body, or None if unknown."""
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        if any(isinstance(elt, ast.Starred) for elt in node.elts):
            return None
        return len(node.elts)
    if isinstance(node, ast.Call) and _dotted_name(node.func) == "range":
        bounds = [_resolve_number(arg, scope) for arg in node.args]
        if not bounds or any(bound is None for bound in bounds):
            return None
        return len(range(*(int(bound) for bound in bounds)))
    if isinstance(node, ast.Name):
        default = _parameter_default(scope, node.id) if scope is not None else None
        if default is not None:
            return _resolve_length(default, None)
        value = vars(_this_module()).get(node.id)
        return len(value) if isinstance(value, (tuple, list, str, frozenset)) else None
    return None


def _call_work_s(node: ast.Call, fn: ast.FunctionDef, seen: frozenset[str]) -> float:
    """Ceiling on one call, charged from its timeout or from the body it enters."""
    bound = next(
        (kw.value for kw in node.keywords if kw.arg in _TIMEOUT_KEYWORDS), None
    )
    if bound is not None:
        resolved = _resolve_number(bound, fn)
        if resolved is None:
            raise ValueError(
                f"{fn.name} bounds the call at line {node.lineno} with a "
                "timeout that does not resolve to a number, so the ceiling "
                "of the operation it bounds cannot be derived"
            )
        return resolved
    callee = _dotted_name(node.func)
    if callee in BLOCKING_CALLS:
        raise ValueError(
            f"{fn.name} calls {callee} at line {node.lineno} with no timeout, "
            "so it can block for as long as the backend takes and no ceiling "
            "can be derived: pass a timeout"
        )
    if isinstance(node.func, ast.Name):
        called = _module_function_defs().get(callee)
        if called is not None:
            return 0.0 if callee in seen else _bounded_work_s(called, seen)
        if _is_resolvable_global(callee) or callee in _parameter_names(fn):
            # A supplied callable is refused unless it is free of bounded work.
            return 0.0
        raise ValueError(
            f"{fn.name} calls {callee} at line {node.lineno}, which is neither "
            "a function of this module, a builtin, nor one of its own "
            "parameters, so the time it can spend cannot be read off the source"
        )
    if isinstance(node.func, ast.Attribute):
        # Blocking methods are named in BLOCKING_CALLS and were refused above.
        return 0.0
    raise ValueError(
        f"{fn.name} calls an expression at line {node.lineno} rather than a "
        "named function, so the time it can spend cannot be read off the "
        "source: call the function by name"
    )


def _is_resolvable_global(name: str) -> bool:
    return name in vars(_this_module()) or name in vars(builtins)


def _parameter_names(fn: ast.FunctionDef) -> frozenset[str]:
    args = fn.args
    return frozenset(
        arg.arg
        for arg in list(getattr(args, "posonlyargs", []))
        + list(args.args)
        + list(args.kwonlyargs)
        + [args.vararg, args.kwarg]
        if arg is not None
    )


def _passed_callable_work_s(
    body: Sequence[ast.AST], fn: ast.FunctionDef, seen: frozenset[str], where: ast.AST
) -> float:
    """A callable defined to be handed to something else must cost nothing.

    Nothing in the source says how many times its holder runs it, so bounded
    work inside one cannot be charged and is refused instead.
    """
    work = sum(_node_work_s(node, fn, seen) for node in body)
    if work:
        raise ValueError(
            f"{fn.name} defines a callable at line {where.lineno} that spends "
            f"{work}s, and the source does not say how many times whoever holds "
            "it will run it: do the bounded work where it can be counted"
        )
    return 0.0


def _node_work_s(node: ast.AST, fn: ast.FunctionDef, seen: frozenset[str]) -> float:
    """Ceiling on the time evaluating ``node`` can spend, loops multiplied out."""
    if isinstance(node, ast.Lambda):
        return _passed_callable_work_s([node.body], fn, seen, node)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return _passed_callable_work_s(node.body, fn, seen, node)
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        referenced = _module_function_defs().get(node.id)
        work = (
            _bounded_work_s(referenced, seen)
            if referenced is not None and node.id not in seen
            else 0.0
        )
        if work:
            raise ValueError(
                f"{fn.name} hands {node.id} to another call at line "
                f"{node.lineno}, and {node.id} spends {work}s: the source does "
                "not say how many times its holder will run it"
            )
        return 0.0
    if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
        return _loop_work_s(node, fn, seen)
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        return _comprehension_work_s(node, fn, seen)
    work = _call_work_s(node, fn, seen) if isinstance(node, ast.Call) else 0.0
    if isinstance(node, ast.Call):
        # Arguments are evaluated before the call, so they are charged on top.
        children: list[ast.AST] = list(node.args) + [kw.value for kw in node.keywords]
    else:
        children = list(ast.iter_child_nodes(node))
    return work + sum(_node_work_s(child, fn, seen) for child in children)


def _trip_work_s(
    header: Sequence[ast.AST],
    body: Sequence[ast.AST],
    trips: int | None,
    fn: ast.FunctionDef,
    seen: frozenset[str],
    where: ast.AST,
) -> float:
    per_trip = sum(_node_work_s(node, fn, seen) for node in body)
    once = sum(_node_work_s(node, fn, seen) for node in header)
    if per_trip == 0.0:
        return once
    if trips is None:
        raise ValueError(
            f"{fn.name} does bounded work inside the loop at line {where.lineno} "
            "whose trip count does not resolve to a constant, so the ceiling of "
            "the loop cannot be derived: bound the iteration count"
        )
    return once + trips * per_trip


def _loop_work_s(node: ast.AST, fn: ast.FunctionDef, seen: frozenset[str]) -> float:
    iter_node = getattr(node, "iter", None)
    trips = None if iter_node is None else _resolve_length(iter_node, fn)
    header = [iter_node] if iter_node is not None else [node.test]
    return _trip_work_s(
        header, list(node.body) + list(node.orelse), trips, fn, seen, node
    )


def _comprehension_work_s(
    node: ast.AST, fn: ast.FunctionDef, seen: frozenset[str]
) -> float:
    trips: int | None = 1
    header: list[ast.AST] = []
    for generator in node.generators:
        header.append(generator.iter)
        length = _resolve_length(generator.iter, fn)
        trips = None if trips is None or length is None else trips * length
    body: list[ast.AST] = [
        part for generator in node.generators for part in generator.ifs
    ]
    body += [
        getattr(node, name) for name in ("elt", "key", "value") if hasattr(node, name)
    ]
    return _trip_work_s(header, body, trips, fn, seen, node)


def _bounded_work_s(fn: ast.FunctionDef, seen: frozenset[str] = frozenset()) -> float:
    """Ceiling on the time ``fn`` can spend, read off the source.

    A call passing an explicit timeout is charged that timeout and not followed
    — it already bounds whatever the callee does. A call into this module that
    passes none is followed, so the callee's own default is charged where it
    applies. Loop bodies that do bounded work are multiplied by their trip
    count. Branches are summed rather than maximised, so the result is an upper
    bound on any single path through ``fn``.

    Raises ``ValueError`` rather than guessing low: an unbounded blocking call,
    a callee that cannot be read off the source, or bounded work inside a loop
    whose trip count is not a constant all mean no ceiling can be derived.
    """
    return sum(
        _node_work_s(node, fn, seen | {fn.name})
        for node in ast.iter_child_nodes(fn)
        if not isinstance(node, ast.arguments)
    )


def _poller_check_def(poller: Poller) -> ast.FunctionDef:
    """The ``_check`` predicate a readiness poller polls, as an AST node."""
    fn = _module_function_defs().get(getattr(poller, "__name__", ""))
    if fn is None:
        raise ValueError(
            f"{poller!r} is not a function of this module, so the address it "
            "contacts and the time one attempt of it takes cannot be read off "
            "the source"
        )
    checks = [
        node
        for node in ast.walk(fn)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_check"
    ]
    if len(checks) != 1:
        raise ValueError(
            f"{poller.__name__} defines {len(checks)} '_check' predicates; a "
            "readiness poller needs exactly one for its per-attempt ceiling to "
            "be derivable"
        )
    return checks[0]


def _source_poll_attempt_ceiling_s(poller: Poller) -> float:
    return _bounded_work_s(_poller_check_def(poller))


# What a probe contacts, rendered from the arguments its ``_check`` passes.
# Every ``build_*_argv`` renders itself — the argv is the address it dials — so
# only a probe that reaches the network some other way registers here.
NON_ARGV_PROBE_DIALS: dict[str, Callable[..., Sequence[str]]] = {
    "http_get": lambda url, **_kwargs: (url,),
}


def _probe_dial_renderer(name: str) -> Callable[..., Sequence[str]] | None:
    if _is_argv_builder_name(name):
        builder = vars(_this_module()).get(name)
        return builder if callable(builder) else None
    return NON_ARGV_PROBE_DIALS.get(name)


def _bound_poller_arguments(wait: Wait) -> dict[str, object]:
    """The value every parameter of the poller behind ``wait`` holds when the
    gate calls it: what the gate bound, and the poller's own defaults for the
    rest."""
    poller = poll_target(wait)
    partial = wait if isinstance(wait, functools.partial) else None
    try:
        bound = inspect.signature(poller).bind_partial(
            *(partial.args if partial else ()),
            **(partial.keywords if partial else {}),
        )
    except TypeError as e:
        raise ValueError(
            f"{poller.__name__} was bound with arguments it does not take, so "
            f"what the probe contacts cannot be derived: {e}"
        ) from None
    bound.apply_defaults()
    return dict(bound.arguments)


def _dial_argument(
    node: ast.expr,
    *,
    poller: Poller,
    dial: str,
    keyword: str | None,
    bound: Mapping[str, object],
) -> object:
    if isinstance(node, ast.Name) and node.id in bound:
        return bound[node.id]
    if keyword in _TIMEOUT_KEYWORDS:
        resolved = _resolve_number(node, None)
        if resolved is not None:
            return resolved
    raise ValueError(
        f"{poller.__name__} passes {dial} an argument at line {node.lineno} "
        "that is neither one of its own parameters nor its attempt timeout, so "
        "the probe can contact an address the gate never bound: pass the "
        "poller's address parameters through"
    )


def probe_dial_tokens(wait: Wait) -> tuple[str, ...]:
    """The address tokens the probe behind ``wait`` contacts.

    Read off the single dial in the poller's ``_check`` and rendered with what
    the gate bound, so a gate's endpoint is reconciled against the address its
    probe really reaches rather than against the arguments it was built with.
    """
    poller = poll_target(wait)
    check = _poller_check_def(poller)
    dials = [
        node
        for node in ast.walk(check)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and _probe_dial_renderer(node.func.id) is not None
    ]
    if len(dials) != 1:
        raise ValueError(
            f"{poller.__name__} dials {len(dials)} addresses; a readiness probe "
            "needs exactly one for the address it contacts to be derivable"
        )
    dial = dials[0]
    bound = _bound_poller_arguments(wait)
    rendered = _probe_dial_renderer(dial.func.id)(
        *(
            _dial_argument(
                node, poller=poller, dial=dial.func.id, keyword=None, bound=bound
            )
            for node in dial.args
        ),
        **{
            kw.arg: _dial_argument(
                kw.value, poller=poller, dial=dial.func.id, keyword=kw.arg, bound=bound
            )
            for kw in dial.keywords
        },
    )
    return tuple(str(token) for token in rendered)


def argv_network(tokens: Sequence[str]) -> str | None:
    """The docker network ``tokens`` joins, or None when they run no container.

    Raises ``ValueError`` for a sidecar left on the default network, which
    reaches no compose address at all.
    """
    tokens = list(tokens)
    if tokens[:2] != ["docker", "run"]:
        return None
    if "--network" not in tokens:
        raise ValueError(
            f"the sidecar {tokens!r} runs on the default docker network, which "
            "reaches no compose address: pass --network"
        )
    return tokens[tokens.index("--network") + 1]


def probe_vantage_network(wait: Wait) -> str | None:
    """The docker network the probe behind ``wait`` runs on, or None when it
    runs on the harness's own machine."""
    return argv_network(probe_dial_tokens(wait))


def _poller_dialling_a_constant(url: str) -> ProbeResult:
    """Self-test fixture: a probe that ignores the address it was handed."""

    def _check() -> str:
        http_get("http://localhost:8222/varz", timeout_s=HTTP_REQUEST_TIMEOUT_S)
        return ""

    return poll_probe(_check, timeout_s=1.0, interval_s=1.0)


def _poller_dialling_nothing(url: str) -> ProbeResult:
    """Self-test fixture: a probe that contacts nothing the source can read."""

    def _check() -> str:
        return ""

    return poll_probe(_check, timeout_s=1.0, interval_s=1.0)


def _probe_ready() -> ProbeResult:
    """Self-test fixture: a gate whose service is already serving."""
    return ProbeResult(ready=True)


def _probe_never_ready() -> ProbeResult:
    """Self-test fixture: a gate whose service never came up."""
    return ProbeResult(ready=False, last_failure="nc -z exited 1")


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


class _PollProbeTests(unittest.TestCase):
    def _poll(self, check: Callable[[], str]) -> ProbeResult:
        return poll_probe(check, timeout_s=0.0, interval_s=0.0)

    def test_a_serving_backend_reports_ready_with_no_failure(self) -> None:
        self.assertEqual(self._poll(lambda: ""), ProbeResult(True, ""))

    def test_carries_the_reason_the_last_attempt_failed(self) -> None:
        result = self._poll(lambda: "kcat exited 1\n    stderr: Connection refused")
        self.assertFalse(result.ready)
        self.assertIn("Connection refused", result.last_failure)

    def test_carries_a_raised_error_the_poll_loop_swallowed(self) -> None:
        def _check() -> str:
            raise urllib.error.URLError("connection refused")

        result = self._poll(_check)
        self.assertFalse(result.ready)
        self.assertIn("connection refused", result.last_failure)

    def test_a_backend_that_comes_up_carries_no_earlier_failure(self) -> None:
        attempts = iter(["not yet", ""])
        result = poll_probe(
            lambda: next(attempts), timeout_s=1.0, interval_s=0.0
        )
        self.assertEqual(result, ProbeResult(True, ""))

    def test_a_gate_failure_renders_the_probes_own_error(self) -> None:
        rendered = probe_failure_tail(ProbeResult(False, "nats: context deadline"))
        self.assertIn("nats: context deadline", rendered)

    def test_a_gate_failure_says_so_when_the_probe_reported_nothing(self) -> None:
        self.assertIn("no error", probe_failure_tail(ProbeResult(False, "")))


class _ProbeDiagnosticsTests(unittest.TestCase):
    """A gate that times out must report why its probe never succeeded."""

    def _one_attempt(self, predicate: Callable[[], bool], **_kwargs: object) -> bool:
        try:
            return predicate()
        except Exception:  # noqa: BLE001 — poll_until swallows these too
            return False

    def test_every_gates_probe_carries_the_error_its_backend_reported(self) -> None:
        refused = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Connection refused by backend"
        )
        module = _this_module()
        for gate in READINESS_GATES:
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    unittest.mock.patch.object(
                        module, "poll_until", side_effect=self._one_attempt
                    )
                )
                stack.enter_context(
                    unittest.mock.patch.object(
                        subprocess, "run", return_value=refused
                    )
                )
                stack.enter_context(
                    unittest.mock.patch.object(
                        urllib.request,
                        "urlopen",
                        side_effect=urllib.error.URLError(
                            "Connection refused by backend"
                        ),
                    )
                )
                result = gate.wait()
            self.assertFalse(result.ready, gate.service)
            self.assertIn("Connection refused by backend", result.last_failure,
                          gate.service)

    def test_a_gate_failure_report_carries_the_probes_error(self) -> None:
        calls: list[str] = []
        gate = ReadinessGate(
            "target-3",
            "10.50.0.12:80",
            lambda: ProbeResult(False, "nc -z exited 1\n    stderr: bad address"),
        )
        row = MatrixRow(
            name="cli_stdout",
            run=lambda _c: (True, "ok"),
            budget_s=SCENARIO_TIMEOUT_S,
            failure_log_containers=("target-3",),
        )
        with _patched_lifecycle(calls, (gate,)):
            results = run_all((row,), HarnessCtx(repo_root=Path("/tmp"), verbose=False))
        rendered = attribute_failure(results[0])
        self.assertIn("was not serving", rendered)
        self.assertIn("bad address", rendered)


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
        self.assertEqual(
            argv[-6:],
            ["--port", "80", "--sink", "stdout", "--format", "json"],
        )

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

    def test_build_cli_nats_argv_shape(self) -> None:
        argv = build_cli_nats_argv(
            scenario_host_path="/tmp/scenario.yaml",
            rastreo_image="img",
            network="net",
        )
        self.assertEqual(argv[:5], ["docker", "run", "--rm", "--network", "net"])
        self.assertIn("-v", argv)
        self.assertEqual(argv[argv.index("-v") + 1], "/tmp/scenario.yaml:/scenario.yaml:ro")
        self.assertIn("--entrypoint", argv)
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "/rastreo")
        self.assertIn("img", argv)
        self.assertIn("discover", argv)
        self.assertIn("--file", argv)
        self.assertEqual(argv[argv.index("--file") + 1], "/scenario.yaml")

    def test_build_nats_consume_argv_shape(self) -> None:
        argv = build_nats_consume_argv(
            network="net", stream="uat-stream", server_url="nats://nats:4222",
        )
        self.assertEqual(argv[:5], ["docker", "run", "--rm", "--network", "net"])
        self.assertIn(NATS_BOX_IMAGE, argv)
        # The consume script is passed via `sh -c`.
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "sh")
        self.assertIn("-c", argv)
        script = argv[argv.index("-c") + 1]
        self.assertIn("uat-stream", script)
        self.assertIn("nats://nats:4222", script)
        self.assertIn("nats stream info", script)
        self.assertIn("nats stream get", script)

    def test_build_cli_nats_scenario_yaml_shape(self) -> None:
        yaml_text = build_cli_nats_scenario_yaml(
            target_ips=("10.0.0.1", "10.0.0.2"),
            port=80,
            server_url="nats://nats:4222",
            subject="rastreo.uat.records.abc",
            stream="rastreo-uat-abc",
        )
        # ScenarioFile wrapper present.
        self.assertIn("version: 1", yaml_text)
        self.assertIn("kind: discovery", yaml_text)
        self.assertIn("signal_type: discover", yaml_text)
        # Required scenario fields present.
        self.assertIn("name: uat-nats", yaml_text)
        self.assertIn("targets:", yaml_text)
        self.assertIn("- Ip: 10.0.0.1", yaml_text)
        self.assertIn("- Ip: 10.0.0.2", yaml_text)
        self.assertIn("probers:", yaml_text)
        self.assertIn("type: tcp_connect", yaml_text)
        self.assertIn("ports: [80]", yaml_text)
        self.assertIn("timeout_ms: 2000", yaml_text)
        self.assertIn("max_concurrent: 16", yaml_text)
        # Sink block uses the exact field names that SinkConfig::Nats expects.
        self.assertIn("sink:", yaml_text)
        self.assertIn("type: nats", yaml_text)
        self.assertIn('servers: ["nats://nats:4222"]', yaml_text)
        self.assertIn("subject: rastreo.uat.records.abc", yaml_text)
        self.assertIn("stream: rastreo-uat-abc", yaml_text)
        # Flush mode omitted so the Rust default (PerRecord) applies.
        self.assertNotIn("flush_mode:", yaml_text)

    def test_build_cli_ssh_argv_shape(self) -> None:
        argv = build_cli_ssh_argv(
            scenario_host_path="/tmp/scenario.yaml",
            rastreo_image="img",
            network="net",
        )
        self.assertEqual(argv[:5], ["docker", "run", "--rm", "--network", "net"])
        self.assertIn("-v", argv)
        self.assertEqual(
            argv[argv.index("-v") + 1], "/tmp/scenario.yaml:/scenario.yaml:ro"
        )
        self.assertIn("--entrypoint", argv)
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "/rastreo")
        self.assertIn("img", argv)
        self.assertIn("discover", argv)
        self.assertIn("--file", argv)
        self.assertEqual(argv[argv.index("--file") + 1], "/scenario.yaml")
        self.assertEqual(argv[argv.index("--format") + 1], "json")

    def test_build_cli_ssh_scenario_yaml_shape(self) -> None:
        yaml_text = build_cli_ssh_scenario_yaml(
            target_ip="10.50.0.20",
            port=2222,
        )
        self.assertIn("version: 1", yaml_text)
        self.assertIn("kind: discovery", yaml_text)
        self.assertIn("signal_type: discover", yaml_text)
        self.assertIn("name: uat-ssh", yaml_text)
        self.assertIn("- Ip: 10.50.0.20", yaml_text)
        self.assertIn("type: ssh", yaml_text)
        self.assertIn("ports: [2222]", yaml_text)

    def test_build_cli_icmp_argv_shape(self) -> None:
        argv = build_cli_icmp_argv(
            scenario_host_path="/tmp/scenario.yaml",
            rastreo_image="img",
            network="net",
        )
        self.assertEqual(argv[:5], ["docker", "run", "--rm", "--network", "net"])
        self.assertIn("--cap-add=NET_RAW", argv)
        self.assertIn("-v", argv)
        self.assertEqual(
            argv[argv.index("-v") + 1], "/tmp/scenario.yaml:/scenario.yaml:ro"
        )
        self.assertIn("--entrypoint", argv)
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "/rastreo")
        self.assertIn("img", argv)
        self.assertIn("discover", argv)
        self.assertIn("--file", argv)
        self.assertEqual(argv[argv.index("--file") + 1], "/scenario.yaml")
        self.assertEqual(argv[argv.index("--format") + 1], "json")

    def test_build_cli_icmp_scenario_yaml_shape(self) -> None:
        yaml_text = build_cli_icmp_scenario_yaml()
        self.assertIn("version: 1", yaml_text)
        self.assertIn("kind: discovery", yaml_text)
        self.assertIn("signal_type: discover", yaml_text)
        self.assertIn("name: uat-icmp", yaml_text)
        self.assertIn("- Ip: 10.50.0.10", yaml_text)
        self.assertIn("- Ip: 10.50.0.11", yaml_text)
        self.assertIn("- Ip: 10.50.0.12", yaml_text)
        self.assertIn("type: icmp", yaml_text)
        self.assertIn("count: 3", yaml_text)
        self.assertIn("interval_ms: 100", yaml_text)

    def test_build_cli_tls_argv_shape(self) -> None:
        argv = build_cli_tls_argv(
            scenario_host_path="/tmp/scenario.yaml",
            rastreo_image="img",
            network="net",
        )
        self.assertEqual(argv[:5], ["docker", "run", "--rm", "--network", "net"])
        self.assertIn("-v", argv)
        self.assertEqual(
            argv[argv.index("-v") + 1], "/tmp/scenario.yaml:/scenario.yaml:ro"
        )
        self.assertIn("--entrypoint", argv)
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "/rastreo")
        self.assertIn("img", argv)
        self.assertIn("discover", argv)
        self.assertIn("--file", argv)
        self.assertEqual(argv[argv.index("--file") + 1], "/scenario.yaml")
        self.assertEqual(argv[argv.index("--format") + 1], "json")

    def test_build_cli_tls_scenario_yaml_shape(self) -> None:
        yaml_text = build_cli_tls_scenario_yaml()
        self.assertIn("version: 1", yaml_text)
        self.assertIn("kind: discovery", yaml_text)
        self.assertIn("signal_type: discover", yaml_text)
        self.assertIn("name: uat-tls", yaml_text)
        self.assertIn("- Ip: 10.50.0.30", yaml_text)
        self.assertIn("type: tls", yaml_text)
        self.assertIn("ports: [443]", yaml_text)

    def test_build_cli_reverse_dns_argv_shape(self) -> None:
        argv = build_cli_reverse_dns_argv(
            scenario_host_path="/tmp/scenario.yaml",
            rastreo_image="img",
            network="net",
        )
        self.assertEqual(argv[:5], ["docker", "run", "--rm", "--network", "net"])
        # Reverse DNS is a plain UDP query — no raw-socket capability needed.
        self.assertNotIn("--cap-add=NET_RAW", argv)
        self.assertIn("-v", argv)
        self.assertEqual(
            argv[argv.index("-v") + 1], "/tmp/scenario.yaml:/scenario.yaml:ro"
        )
        self.assertIn("--entrypoint", argv)
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "/rastreo")
        self.assertIn("img", argv)
        self.assertIn("discover", argv)
        self.assertIn("--file", argv)
        self.assertEqual(argv[argv.index("--file") + 1], "/scenario.yaml")
        self.assertEqual(argv[argv.index("--format") + 1], "json")

    def test_build_cli_reverse_dns_scenario_yaml_shape(self) -> None:
        yaml_text = build_cli_reverse_dns_scenario_yaml()
        self.assertIn("version: 1", yaml_text)
        self.assertIn("kind: discovery", yaml_text)
        self.assertIn("signal_type: discover", yaml_text)
        self.assertIn("name: uat-reverse-dns", yaml_text)
        self.assertIn("- Ip: 1.1.1.1", yaml_text)
        self.assertIn("type: reverse_dns", yaml_text)
        self.assertIn('resolvers: ["1.0.0.1"]', yaml_text)

    def test_record_has_signal_matching_finds_prefix_match(self) -> None:
        rec = {
            "signals": [
                {"OpenPort": 2222},
                {"SshBanner": "SSH-2.0-Foo"},
            ]
        }
        self.assertTrue(
            record_has_signal_matching(
                rec, "SshBanner", lambda s: s.startswith("SSH-")
            )
        )

    def test_record_has_signal_matching_returns_false_when_no_match(self) -> None:
        rec = {"signals": [{"OpenPort": 2222}, {"SshBanner": "not-ssh"}]}
        self.assertFalse(
            record_has_signal_matching(
                rec, "SshBanner", lambda s: s.startswith("SSH-")
            )
        )
        # Missing tag entirely.
        self.assertFalse(
            record_has_signal_matching(
                {"signals": []}, "SshHostKey", lambda s: " " in s
            )
        )
        # signals not a list.
        self.assertFalse(
            record_has_signal_matching(
                {"signals": "nope"}, "SshBanner", lambda _s: True
            )
        )

    def test_record_has_signal_matching_finds_numeric_match(self) -> None:
        rec = {
            "signals": [
                {"OpenPort": 80},
                {"IcmpEchoRttMicros": 42},
            ]
        }
        self.assertTrue(
            record_has_signal_matching(
                rec,
                "IcmpEchoRttMicros",
                lambda v: isinstance(v, int) and v > 0,
            )
        )
        # Zero fails the positive-value predicate.
        rec_zero = {"signals": [{"IcmpEchoRttMicros": 0}]}
        self.assertFalse(
            record_has_signal_matching(
                rec_zero,
                "IcmpEchoRttMicros",
                lambda v: isinstance(v, int) and v > 0,
            )
        )


class _AttributeFailureTests(unittest.TestCase):
    def _result(self, snapshot: FailureSnapshot | None = None) -> RowResult:
        row = MatrixRow(
            name="cli_stdout",
            run=lambda _c: (False, "boom"),
            budget_s=SCENARIO_TIMEOUT_S,
            failure_log_containers=("target-1",),
        )
        return RowResult(
            row=row, ok=False, message="boom", duration_s=1.5, snapshot=snapshot
        )

    def _snapshot(
        self, *logs: ServiceLog, state: str = "rastreo-target-1 Up"
    ) -> FailureSnapshot:
        return FailureSnapshot(container_state=state, logs=logs)

    def test_includes_row_name_and_message(self) -> None:
        out = attribute_failure(self._result())
        self.assertIn("FAIL [cli_stdout]", out)
        self.assertIn("boom", out)
        self.assertIn("1.5s", out)

    def test_renders_the_snapshotted_log_text(self) -> None:
        snapshot = self._snapshot(
            ServiceLog(service="target-1", text="nginx: bind() failed\n")
        )
        out = attribute_failure(self._result(snapshot))
        self.assertIn("docker logs (tail) for target-1", out)
        self.assertIn("nginx: bind() failed", out)

    def test_renders_the_snapshotted_container_state(self) -> None:
        out = attribute_failure(
            self._result(self._snapshot(state="rastreo-kafka Exited (1)"))
        )
        self.assertIn("docker compose ps (at failure time)", out)
        self.assertIn("rastreo-kafka Exited (1)", out)

    def test_reads_no_containers_at_render_time(self) -> None:
        snapshot = self._snapshot(
            ServiceLog(service="target-1", text="captured earlier")
        )
        with unittest.mock.patch.object(
            subprocess, "run", side_effect=AssertionError("shelled out at render time")
        ):
            out = attribute_failure(self._result(snapshot))
        self.assertIn("captured earlier", out)

    def test_missing_snapshot_renders_no_output_marker(self) -> None:
        snapshot = self._snapshot(
            ServiceLog(service="target-1", text="   \n"), state=""
        )
        rendered = attribute_failure(self._result(snapshot))
        self.assertEqual(rendered.count("(no output)"), 2)

    def test_a_failure_with_no_snapshot_renders_message_only(self) -> None:
        out = attribute_failure(self._result())
        self.assertNotIn("docker compose ps", out)
        self.assertNotIn("docker logs", out)


class _MatrixIntegrityTests(unittest.TestCase):
    """Static checks on the hardcoded MATRIX so drift is caught."""

    def test_row_names_unique(self) -> None:
        names = [r.name for r in MATRIX]
        self.assertEqual(len(names), len(set(names)))

    def test_expected_row_set(self) -> None:
        names = {r.name for r in MATRIX}
        self.assertEqual(
            names,
            {
                "cli_stdout",
                "server_post_scans",
                "cli_kafka",
                "cli_nats",
                "cli_ssh",
                "cli_icmp",
                "cli_tls",
                "cli_reverse_dns",
            },
        )

    def test_failure_containers_non_empty(self) -> None:
        for row in MATRIX:
            self.assertTrue(row.failure_log_containers, row.name)

    def test_cli_nats_row_present(self) -> None:
        rows = [r for r in MATRIX if r.name == "cli_nats"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(callable(row.run))
        self.assertTrue(row.failure_log_containers)
        self.assertIn("nats", row.failure_log_containers)

    def test_cli_ssh_row_present(self) -> None:
        rows = [r for r in MATRIX if r.name == "cli_ssh"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(callable(row.run))
        self.assertTrue(row.failure_log_containers)
        self.assertIn("target-ssh", row.failure_log_containers)

    def test_cli_icmp_row_present(self) -> None:
        rows = [r for r in MATRIX if r.name == "cli_icmp"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(callable(row.run))
        self.assertTrue(row.failure_log_containers)
        self.assertIn("target-1", row.failure_log_containers)

    def test_cli_tls_row_present(self) -> None:
        rows = [r for r in MATRIX if r.name == "cli_tls"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(callable(row.run))
        self.assertTrue(row.failure_log_containers)
        self.assertIn("target-tls", row.failure_log_containers)

    def test_cli_reverse_dns_row_present(self) -> None:
        rows = [r for r in MATRIX if r.name == "cli_reverse_dns"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(callable(row.run))
        self.assertTrue(row.failure_log_containers)


class _ReadinessCoverageTests(unittest.TestCase):
    NONE: frozenset[str] = frozenset()

    def test_no_gaps_when_every_service_is_gated(self) -> None:
        self.assertEqual(
            readiness_coverage_gaps(["a", "b"], ["a", "b"], {}, self.NONE),
            [],
        )

    def test_no_gaps_when_service_is_exempt_with_a_reason(self) -> None:
        self.assertEqual(
            readiness_coverage_gaps(
                ["a", "b"], ["a"], {"b": "nothing probes it"}, frozenset({"a"})
            ),
            [],
        )

    def test_ungated_service_is_reported(self) -> None:
        gaps = readiness_coverage_gaps(["a", "b"], ["a"], {}, self.NONE)
        self.assertEqual(len(gaps), 1)
        self.assertIn("'b'", gaps[0])
        self.assertIn("READINESS_GATES", gaps[0])
        self.assertIn("READINESS_EXEMPT_SERVICES", gaps[0])

    def test_every_ungated_service_is_reported(self) -> None:
        gaps = readiness_coverage_gaps(["a", "b", "c"], [], {}, self.NONE)
        self.assertEqual(len(gaps), 3)

    def test_gate_for_unknown_service_is_reported(self) -> None:
        gaps = readiness_coverage_gaps(["a"], ["a", "ghost"], {}, self.NONE)
        self.assertEqual(len(gaps), 1)
        self.assertIn("'ghost'", gaps[0])

    def test_exemption_for_unknown_service_is_reported(self) -> None:
        gaps = readiness_coverage_gaps(["a"], ["a"], {"ghost": "stale"}, self.NONE)
        self.assertEqual(len(gaps), 1)
        self.assertIn("'ghost'", gaps[0])

    def test_service_both_gated_and_exempt_is_reported(self) -> None:
        gaps = readiness_coverage_gaps(["a"], ["a"], {"a": "contradiction"}, self.NONE)
        self.assertEqual(len(gaps), 1)
        self.assertIn("both gated and exempt", gaps[0])

    def test_duplicate_gate_is_reported(self) -> None:
        gaps = readiness_coverage_gaps(["a"], ["a", "a"], {}, self.NONE)
        self.assertEqual(len(gaps), 1)
        self.assertIn("more than one gate", gaps[0])

    def test_empty_compose_file_with_empty_registry_is_covered(self) -> None:
        self.assertEqual(readiness_coverage_gaps([], [], {}, self.NONE), [])

    def test_exempting_a_service_a_row_depends_on_is_reported(self) -> None:
        gaps = readiness_coverage_gaps(
            ["a", "b"], ["a"], {"b": "flaky, skipping"}, frozenset({"b"})
        )
        self.assertEqual(len(gaps), 1)
        self.assertIn("'b'", gaps[0])
        self.assertIn("a matrix row names it", gaps[0])

    def test_every_service_a_row_names_exists_in_the_compose_file(self) -> None:
        services = {
            svc.name for svc in read_compose_services(_repo_root_for_self_tests())
        }
        self.assertEqual(matrix_service_dependencies(MATRIX) - services, frozenset())

    def test_real_registry_covers_the_committed_compose_file(self) -> None:
        services = [
            svc.name for svc in read_compose_services(_repo_root_for_self_tests())
        ]
        self.assertEqual(
            readiness_coverage_gaps(
                services,
                [gate.service for gate in READINESS_GATES],
                READINESS_EXEMPT_SERVICES,
                matrix_service_dependencies(MATRIX),
            ),
            [],
        )

    def test_no_real_exemption_covers_a_service_the_matrix_depends_on(self) -> None:
        self.assertEqual(
            set(READINESS_EXEMPT_SERVICES) & matrix_service_dependencies(MATRIX),
            set(),
        )


class _GateContractTests(unittest.TestCase):
    """A gate's endpoint must be the address its wait callable contacts."""

    def test_every_gate_polls_the_endpoint_it_reports(self) -> None:
        for gate in READINESS_GATES:
            self.assertEqual(polled_endpoint(gate.wait), gate.endpoint, gate.service)

    def test_an_unregistered_wait_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            polled_endpoint(lambda: True)

    def test_a_partial_over_an_unregistered_poller_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            polled_endpoint(functools.partial(lambda _ip: True, "10.50.0.10"))

    def test_tcp_gate_binds_endpoint_and_poll_target(self) -> None:
        gate = tcp_gate("target-9", "10.50.0.99", 8080)
        self.assertEqual(gate.endpoint, "10.50.0.99:8080")
        self.assertEqual(polled_endpoint(gate.wait), "10.50.0.99:8080")

    def test_http_gate_binds_endpoint_and_poll_target(self) -> None:
        gate = http_gate("svc", "http://localhost:9/health")
        self.assertEqual(gate.endpoint, "http://localhost:9/health")
        self.assertEqual(polled_endpoint(gate.wait), "http://localhost:9/health")

    def test_bare_gate_takes_its_endpoint_from_the_poller(self) -> None:
        gate = bare_gate("kafka", wait_for_kafka_ready)
        self.assertEqual(gate.endpoint, KAFKA_INTERNAL_BROKER)
        self.assertEqual(polled_endpoint(gate.wait), KAFKA_INTERNAL_BROKER)

    def test_bare_gate_rejects_an_unregistered_poller(self) -> None:
        with self.assertRaises(KeyError):
            bare_gate("kafka", lambda: True)

    def test_a_gate_whose_wait_polls_elsewhere_is_rejected(self) -> None:
        gate = ReadinessGate(
            "target-ssh",
            f"{TARGET_SSH_IP}:{TARGET_SSH_PORT}",
            functools.partial(wait_for_tcp_port_ready, TARGET_TLS_IP, TARGET_TLS_PORT),
        )
        self.assertNotEqual(polled_endpoint(gate.wait), gate.endpoint)

    def test_an_address_bound_by_keyword_is_rejected(self) -> None:
        wait = functools.partial(
            wait_for_tcp_port_ready, target_ip="10.50.0.10", port=80
        )
        with self.assertRaises(ValueError) as cm:
            polled_endpoint(wait)
        self.assertIn("keyword", str(cm.exception))

    def test_an_address_bound_with_too_few_arguments_is_rejected(self) -> None:
        wait = functools.partial(wait_for_tcp_port_ready, "10.50.0.10")
        with self.assertRaises(ValueError) as cm:
            polled_endpoint(wait)
        self.assertIn("positional", str(cm.exception))

    def test_every_gates_probe_contacts_the_endpoint_it_reports(self) -> None:
        for gate in READINESS_GATES:
            tokens = probe_dial_tokens(gate.wait)
            address = parse_endpoint(gate.endpoint)
            self.assertTrue(
                any(address.host in token for token in tokens),
                f"the {gate.service} gate reports {gate.endpoint} but its probe "
                f"dials {tokens}",
            )
            self.assertTrue(
                any(
                    token == str(address.port) or f":{address.port}" in token
                    for token in tokens
                ),
                f"the {gate.service} gate reports port {address.port} but its "
                f"probe dials {tokens}",
            )

    def test_a_probe_dialling_an_address_the_gate_never_bound_is_rejected(self) -> None:
        with self.assertRaises(ValueError) as cm:
            probe_dial_tokens(
                functools.partial(_poller_dialling_a_constant, "http://svc/health")
            )
        self.assertIn("never bound", str(cm.exception))

    def test_a_probe_that_dials_nothing_derivable_is_rejected(self) -> None:
        with self.assertRaises(ValueError) as cm:
            probe_dial_tokens(functools.partial(_poller_dialling_nothing, "u"))
        self.assertIn("dials 0 addresses", str(cm.exception))

    def test_an_unregistered_wait_dials_nothing_derivable(self) -> None:
        with self.assertRaises(ValueError):
            probe_dial_tokens(lambda: ProbeResult(ready=True))

    def test_a_sidecar_is_read_as_the_network_it_joins(self) -> None:
        self.assertEqual(
            argv_network(build_tcp_probe_argv("10.50.0.10", 80, "other-net")),
            "other-net",
        )

    def test_a_probe_that_runs_no_container_is_read_as_the_runner(self) -> None:
        self.assertIsNone(argv_network(("http://localhost:8080/health",)))

    def test_a_sidecar_on_the_default_network_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            argv_network(("docker", "run", "--rm", BUSYBOX_IMAGE, "nc"))

    def test_every_gate_is_polled_from_the_space_its_endpoint_answers_in(self) -> None:
        for gate in READINESS_GATES:
            self.assertEqual(
                probe_vantage_network(gate.wait),
                endpoint_vantage_network(gate.endpoint),
                f"the {gate.service} gate polls {gate.endpoint}",
            )

    def test_a_compose_address_polled_from_the_runner_is_rejected(self) -> None:
        gate = http_gate("rastreo-server", "http://rastreo-server:8080/health")
        self.assertNotEqual(
            probe_vantage_network(gate.wait), endpoint_vantage_network(gate.endpoint)
        )

    def test_a_published_host_port_polled_in_network_is_rejected(self) -> None:
        gate = tcp_gate("rastreo-server", "127.0.0.1", 8080)
        self.assertNotEqual(
            probe_vantage_network(gate.wait), endpoint_vantage_network(gate.endpoint)
        )

    def test_every_gated_address_belongs_to_the_service_it_gates(self) -> None:
        services = read_compose_services(_repo_root_for_self_tests())
        for gate in READINESS_GATES:
            endpoint = polled_endpoint(gate.wait)
            self.assertIn(
                gate.service,
                services_reachable_at(endpoint, services),
                f"the {gate.service} gate polls {endpoint}",
            )

    def test_a_gate_on_a_port_its_service_does_not_serve_is_rejected(self) -> None:
        services = read_compose_services(_repo_root_for_self_tests())
        gate = tcp_gate("target-ssh", TARGET_SSH_IP, TARGET_PORT)
        self.assertNotIn(
            gate.service, services_reachable_at(gate.endpoint, services)
        )

    def test_gate_endpoints_are_distinct(self) -> None:
        endpoints = [gate.endpoint for gate in READINESS_GATES]
        self.assertEqual(len(endpoints), len(set(endpoints)))


class _EndpointBindingTests(unittest.TestCase):
    SERVICES = (
        ComposeService(
            "nats",
            "10.50.0.4",
            (PublishedPort(4222, 4222), PublishedPort(8222, 8222)),
        ),
        ComposeService("target-1", "10.50.0.10", exposed_ports=(80,)),
        ComposeService("rastreo-server", "10.50.0.3", (PublishedPort(8080, 8080),)),
    )

    def test_parses_host_and_port_forms(self) -> None:
        cases = {
            "10.50.0.10:80": Address("10.50.0.10", 80),
            "kafka:29092": Address("kafka", 29092),
            "nats://nats:4222": Address("nats", 4222),
            "http://localhost:8080/health": Address("localhost", 8080),
            "https://example.test/x": Address("example.test", 443),
            "http://example.test/x": Address("example.test", 80),
            "[::1]:80": Address("::1", 80),
            "http://[::1]:8080/health": Address("::1", 8080),
            "[::1]": Address("::1", None),
            "target-1": Address("target-1", None),
        }
        for endpoint, expected in cases.items():
            self.assertEqual(parse_endpoint(endpoint), expected, endpoint)

    def test_a_non_numeric_port_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_endpoint("target-1:http")

    def test_a_static_address_names_its_service(self) -> None:
        self.assertEqual(
            services_reachable_at("10.50.0.10:80", self.SERVICES),
            frozenset({"target-1"}),
        )

    def test_a_compose_dns_name_names_its_service(self) -> None:
        self.assertEqual(
            services_reachable_at("nats://nats:4222", self.SERVICES),
            frozenset({"nats"}),
        )

    def test_a_published_host_port_names_the_service_that_publishes_it(self) -> None:
        self.assertEqual(
            services_reachable_at("http://localhost:8080/health", self.SERVICES),
            frozenset({"rastreo-server"}),
        )

    def test_a_published_port_does_not_name_another_service(self) -> None:
        self.assertNotIn(
            "target-1",
            services_reachable_at("http://localhost:8222/varz", self.SERVICES),
        )

    def test_an_unpublished_runner_port_names_no_service(self) -> None:
        self.assertEqual(
            services_reachable_at("http://localhost:9999/health", self.SERVICES),
            frozenset(),
        )

    def test_loopback_without_a_port_names_no_service(self) -> None:
        self.assertEqual(services_reachable_at("localhost", self.SERVICES), frozenset())

    def test_an_unknown_address_names_no_service(self) -> None:
        self.assertEqual(
            services_reachable_at("10.99.99.99:80", self.SERVICES), frozenset()
        )

    def test_a_port_the_container_does_not_serve_names_no_service(self) -> None:
        self.assertEqual(
            services_reachable_at("10.50.0.10:2222", self.SERVICES), frozenset()
        )

    def test_a_container_port_is_read_from_a_published_mapping_too(self) -> None:
        self.assertEqual(
            services_reachable_at("nats://nats:4222", self.SERVICES),
            frozenset({"nats"}),
        )

    def test_an_in_network_address_without_a_port_names_no_service(self) -> None:
        self.assertEqual(services_reachable_at("target-1", self.SERVICES), frozenset())

    def test_loopback_ip_is_read_as_the_runner_not_a_container(self) -> None:
        self.assertEqual(
            services_reachable_at("127.0.0.1:8080", self.SERVICES),
            frozenset({"rastreo-server"}),
        )


class _StartupPhaseTests(unittest.TestCase):
    def test_phase_order_and_budgets(self) -> None:
        phases = startup_phases(Path("/repo"))
        names = [p.name for p in phases]
        self.assertEqual(names[0], "compose build")
        self.assertEqual(names[1], "compose pull")
        self.assertEqual(names[-1], "compose up")
        self.assertEqual(phases[0].budget_s, COMPOSE_BUILD_TIMEOUT_S)
        self.assertEqual(phases[-1].budget_s, COMPOSE_START_TIMEOUT_S)
        # The start budget must not be able to absorb an image build.
        self.assertLess(phases[-1].budget_s, phases[0].budget_s)

    def test_every_sidecar_image_is_pulled_before_up(self) -> None:
        phases = startup_phases(Path("/repo"))
        pulled = {p.argv[-1] for p in phases if p.argv[:2] == ("docker", "pull")}
        self.assertEqual(pulled, set(SIDECAR_IMAGES))
        up_index = [p.name for p in phases].index("compose up")
        for index, phase in enumerate(phases):
            if phase.argv[:2] == ("docker", "pull"):
                self.assertLess(index, up_index)

    def test_up_neither_builds_nor_pulls(self) -> None:
        phases = startup_phases(Path("/repo"))
        up = next(p for p in phases if p.name == "compose up")
        self.assertIn("--no-build", up.argv)
        self.assertEqual(up.argv[up.argv.index("--pull") + 1], "never")
        self.assertIn("-d", up.argv)

    def test_argv_is_anchored_at_the_repo_compose_file(self) -> None:
        build = startup_phases(Path("/repo"))[0]
        self.assertEqual(
            build.argv[:4],
            ("docker", "compose", "-f", "/repo/docker-compose.yml"),
        )

    def test_pull_phase_ignores_buildable_images(self) -> None:
        phases = startup_phases(Path("/repo"))
        pull = next(p for p in phases if p.name == "compose pull")
        self.assertIn("--ignore-buildable", pull.argv)


class _RunBudgetTests(unittest.TestCase):
    def _phases(self) -> tuple[StartupPhase, ...]:
        return startup_phases(Path("/repo"))

    def test_an_empty_run_still_charges_config_diagnostics_and_teardown(self) -> None:
        self.assertEqual(
            worst_case_run_budget_s((), (), ()),
            COMPOSE_CONFIG_TIMEOUT_S + DIAGNOSTIC_BUDGET_S + COMPOSE_DOWN_TIMEOUT_S,
        )

    def test_each_part_of_the_run_adds_exactly_its_own_budget(self) -> None:
        phases = self._phases()
        empty = worst_case_run_budget_s((), (), ())
        self.assertEqual(
            worst_case_run_budget_s(phases, (), ()) - empty,
            sum(p.budget_s for p in phases),
        )
        self.assertEqual(
            worst_case_run_budget_s((), READINESS_GATES, ()) - empty,
            sum(g.budget_s for g in READINESS_GATES),
        )
        self.assertEqual(
            worst_case_run_budget_s((), (), MATRIX) - empty,
            sum(r.budget_s for r in MATRIX) + len(MATRIX) * DIAGNOSTIC_BUDGET_S,
        )

    def test_worst_case_grows_with_each_gate_and_row(self) -> None:
        phases = self._phases()
        base = worst_case_run_budget_s(phases, READINESS_GATES, MATRIX)
        more_gates = worst_case_run_budget_s(
            phases, (*READINESS_GATES, READINESS_GATES[0]), MATRIX
        )
        more_rows = worst_case_run_budget_s(
            phases, READINESS_GATES, (*MATRIX, MATRIX[0])
        )
        self.assertEqual(more_gates - base, READINESS_GATES[0].budget_s)
        self.assertEqual(
            more_rows - base, MATRIX[0].budget_s + DIAGNOSTIC_BUDGET_S
        )

    def test_a_costlier_row_costs_the_budget_more(self) -> None:
        phases = self._phases()
        base = worst_case_run_budget_s(phases, READINESS_GATES, MATRIX)
        expensive = dataclasses.replace(MATRIX[0], name="slow", budget_s=690.0)
        self.assertEqual(
            worst_case_run_budget_s(phases, READINESS_GATES, (*MATRIX, expensive))
            - base,
            690.0 + DIAGNOSTIC_BUDGET_S,
        )

    def test_every_row_declares_the_ceiling_its_own_calls_enforce(self) -> None:
        for row in MATRIX:
            derived = _bounded_work_s(_module_function_defs()[row.run.__name__])
            self.assertGreaterEqual(
                row.budget_s,
                derived,
                f"row {row.name} declares {row.budget_s}s but {row.run.__name__} "
                f"can spend {derived}s",
            )

    def test_a_row_that_under_declares_its_ceiling_is_caught(self) -> None:
        derived = _bounded_work_s(_module_function_defs()["run_cli_nats"])
        self.assertGreater(derived, SCENARIO_TIMEOUT_S)

    def test_each_registered_poller_declares_the_ceiling_its_check_enforces(
        self,
    ) -> None:
        for poller, declared in POLL_ATTEMPT_CEILING_S.items():
            self.assertEqual(
                declared, _source_poll_attempt_ceiling_s(poller), poller.__name__
            )

    def test_every_gate_is_charged_its_pollers_attempt(self) -> None:
        for gate in READINESS_GATES:
            self.assertEqual(
                gate.budget_s,
                READINESS_TIMEOUT_S
                + READINESS_POLL_INTERVAL_S
                + POLL_ATTEMPT_CEILING_S[poll_target(gate.wait)],
                gate.service,
            )

    def test_a_gate_on_an_unregistered_poller_has_no_budget(self) -> None:
        gate = ReadinessGate("target-1", "10.50.0.10:80", _probe_ready)
        with self.assertRaises(ValueError):
            gate.budget_s  # noqa: B018 — the property is the assertion

    def test_no_gate_outlasts_the_budget_charged_for_it(self) -> None:
        for gate in READINESS_GATES:
            attempt = POLL_ATTEMPT_CEILING_S[poll_target(gate.wait)]
            clock = [0.0]

            def slow_attempt() -> bool:
                clock[0] += attempt
                return False

            poll_until(
                slow_attempt,
                timeout_s=READINESS_TIMEOUT_S,
                interval_s=READINESS_POLL_INTERVAL_S,
                now=lambda: clock[0],
                sleep=lambda s: clock.__setitem__(0, clock[0] + s),
            )
            self.assertGreater(clock[0], READINESS_TIMEOUT_S, gate.service)
            self.assertLessEqual(clock[0], gate.budget_s, gate.service)

    def test_every_declared_timeout_constant_is_used(self) -> None:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        declared = {
            target.id
            for node in tree.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
            and (target.id.endswith("_TIMEOUT_S") or target.id.endswith("_BUDGET_S"))
        }
        loaded = {
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }
        self.assertEqual(declared - loaded, set())

    def test_the_whole_run_fits_inside_the_ci_job_timeout(self) -> None:
        repo_root = _repo_root_for_self_tests()
        self.assertLess(
            worst_case_run_budget_s(
                startup_phases(repo_root), READINESS_GATES, MATRIX
            ),
            read_job_timeout_s(repo_root),
        )

    def test_job_timeout_is_read_from_the_workflow_not_mirrored(self) -> None:
        repo_root = _repo_root_for_self_tests()
        workflow = (repo_root / LIVE_UAT_WORKFLOW).read_text(encoding="utf-8")
        minutes = int(re.search(r"timeout-minutes:\s*(\d+)", workflow).group(1))
        self.assertEqual(read_job_timeout_s(repo_root), minutes * 60.0)

    def test_an_ambiguous_workflow_timeout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / LIVE_UAT_WORKFLOW).parent.mkdir(parents=True)
            (root / LIVE_UAT_WORKFLOW).write_text(
                "jobs:\n  a:\n    timeout-minutes: 10\n  b:\n    timeout-minutes: 20\n",
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError) as cm:
                read_job_timeout_s(root)
        self.assertIn("timeout-minutes", str(cm.exception))


class _SourceAnalysisTests(unittest.TestCase):
    """The time analysis refuses rather than charging less than the code spends."""

    def _fn(self, *lines: str) -> ast.FunctionDef:
        return ast.parse("\n".join(lines) + "\n").body[0]

    def test_a_retry_loop_costs_what_it_repeats(self) -> None:
        fn = self._fn(
            "def row():",
            "    for _attempt in range(3):",
            "        subprocess.run(['x'], timeout=SCENARIO_TIMEOUT_S, check=False)",
        )
        self.assertEqual(_bounded_work_s(fn), 3 * SCENARIO_TIMEOUT_S)

    def test_a_comprehension_costs_what_it_repeats(self) -> None:
        fn = self._fn(
            "def row(targets):",
            "    return [",
            "        subprocess.run(['x'], timeout=KCAT_TIMEOUT_S, check=False)",
            "        for _target in TARGET_IPS",
            "    ]",
        )
        self.assertEqual(_bounded_work_s(fn), len(TARGET_IPS) * KCAT_TIMEOUT_S)

    def test_bounded_work_in_a_loop_of_unknown_length_is_refused(self) -> None:
        fn = self._fn(
            "def row(targets):",
            "    for _target in targets:",
            "        subprocess.run(['x'], timeout=SCENARIO_TIMEOUT_S, check=False)",
        )
        with self.assertRaises(ValueError) as cm:
            _bounded_work_s(fn)
        self.assertIn("trip count", str(cm.exception))

    def test_a_while_loop_around_bounded_work_is_refused(self) -> None:
        fn = self._fn(
            "def row():",
            "    while True:",
            "        subprocess.run(['x'], timeout=SCENARIO_TIMEOUT_S, check=False)",
        )
        with self.assertRaises(ValueError):
            _bounded_work_s(fn)

    def test_a_loop_of_unknown_length_over_free_work_costs_nothing(self) -> None:
        fn = self._fn(
            "def row(lines):",
            "    for line in lines:",
            "        print(line)",
        )
        self.assertEqual(_bounded_work_s(fn), 0.0)

    def test_a_blocking_call_with_no_timeout_is_refused(self) -> None:
        fn = self._fn(
            "def row():",
            "    subprocess.run(['x'], capture_output=True, check=False)",
        )
        with self.assertRaises(ValueError) as cm:
            _bounded_work_s(fn)
        self.assertIn("no timeout", str(cm.exception))

    def test_every_blocking_call_the_harness_can_reach_is_refused_unbounded(
        self,
    ) -> None:
        for call in sorted(BLOCKING_CALLS):
            fn = self._fn("def row():", f"    {call}('x')")
            with self.assertRaises(ValueError, msg=call):
                _bounded_work_s(fn)

    def test_a_call_through_a_local_variable_is_refused(self) -> None:
        fn = self._fn(
            "def row(steps):",
            "    step = steps[0]",
            "    step()",
        )
        with self.assertRaises(ValueError) as cm:
            _bounded_work_s(fn)
        self.assertIn("step", str(cm.exception))

    def test_a_call_through_a_partial_is_refused(self) -> None:
        fn = self._fn(
            "def row():",
            "    functools.partial(run_cli_stdout)()",
        )
        with self.assertRaises(ValueError) as cm:
            _bounded_work_s(fn)
        self.assertIn("rather than a named function", str(cm.exception))

    def test_handing_off_a_callable_that_does_bounded_work_is_refused(self) -> None:
        fn = self._fn(
            "def row():",
            "    capture_or_report('cli', run_cli_stdout)",
        )
        with self.assertRaises(ValueError) as cm:
            _bounded_work_s(fn)
        self.assertIn("how many times", str(cm.exception))

    def test_a_lambda_that_does_bounded_work_is_refused(self) -> None:
        fn = self._fn(
            "def row():",
            "    capture_or_report('cli', lambda: http_get('u', timeout_s=5.0))",
        )
        with self.assertRaises(ValueError):
            _bounded_work_s(fn)

    def test_a_callee_that_calls_its_own_parameter_is_read(self) -> None:
        fn = self._fn(
            "def row(rec):",
            "    return record_has_signal_matching(rec, 'A', lambda v: v > 0)",
        )
        self.assertEqual(_bounded_work_s(fn), 0.0)

    def test_an_async_helper_is_refused_rather_than_skipped(self) -> None:
        with self.assertRaises(ValueError) as cm:
            _function_defs("async def wait_for_thing():\n    return True\n")
        self.assertIn("wait_for_thing", str(cm.exception))

    def test_a_synchronous_module_reads_every_function(self) -> None:
        defs = _function_defs("def a():\n    pass\ndef b():\n    pass\n")
        self.assertEqual(sorted(defs), ["a", "b"])

    def test_a_wait_that_is_not_a_module_function_is_refused(self) -> None:
        with self.assertRaises(ValueError) as cm:
            _poller_check_def(lambda: ProbeResult(ready=True))
        self.assertIn("not a function of this module", str(cm.exception))


class _RunStartupPhaseTests(unittest.TestCase):
    def _phase(self) -> StartupPhase:
        return StartupPhase(name="compose up", argv=("true",), budget_s=5.0)

    def test_returns_none_on_success(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            self.assertIsNone(run_startup_phase(self._phase()))

    def test_raises_naming_the_phase_on_nonzero_exit(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="no such image"
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            with self.assertRaises(RuntimeError) as cm:
                run_startup_phase(self._phase())
        self.assertIn("compose up", str(cm.exception))
        self.assertIn("no such image", str(cm.exception))

    def test_raises_naming_the_budget_on_timeout(self) -> None:
        with unittest.mock.patch.object(
            subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="x", timeout=5)
        ):
            with self.assertRaises(RuntimeError) as cm:
                run_startup_phase(self._phase())
        self.assertIn("compose up", str(cm.exception))
        self.assertIn("5s budget", str(cm.exception))


class _TcpProbeArgvTests(unittest.TestCase):
    def test_probes_the_given_address_inside_the_compose_network(self) -> None:
        argv = build_tcp_probe_argv("10.50.0.10", 80, network="net")
        self.assertEqual(argv[:5], ["docker", "run", "--rm", "--network", "net"])
        self.assertEqual(argv[-4:], ["nc", "-z", "10.50.0.10", "80"])


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

    def test_run_cli_nats_success_path(self) -> None:
        stream_add = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        publish = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        consume_stdout = "\n".join(
            json.dumps({"identity_key": f"ip:{ip}", "signals": [{"OpenPort": 80}]})
            for ip in TARGET_IPS
        ) + "\n"
        consume = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=consume_stdout, stderr=""
        )
        with unittest.mock.patch.object(
            subprocess, "run", side_effect=[stream_add, publish, consume]
        ):
            ok, msg = run_cli_nats(self._ctx())
        self.assertTrue(ok, msg)
        self.assertIn("3 records consumed", msg)

    def test_run_cli_nats_fails_when_stream_add_fails(self) -> None:
        stream_add = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="stream already exists"
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=stream_add):
            ok, msg = run_cli_nats(self._ctx())
        self.assertFalse(ok)
        self.assertIn("nats stream add", msg)

    def test_run_cli_ssh_success_path(self) -> None:
        stdout = json.dumps(
            {
                "identity_key": f"ip:{TARGET_SSH_IP}",
                "signals": [
                    {"OpenPort": TARGET_SSH_PORT},
                    {"SshBanner": "SSH-2.0-OpenSSH_9.6"},
                    {"SshHostKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"},
                ],
            }
        ) + "\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_ssh(self._ctx())
        self.assertTrue(ok, msg)
        self.assertIn("SshBanner", msg)
        self.assertIn("SshHostKey", msg)

    def test_run_cli_ssh_fails_when_cli_exits_nonzero(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="ssh probe crashed"
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_ssh(self._ctx())
        self.assertFalse(ok)
        self.assertIn("exited 1", msg)

    def test_run_cli_ssh_fails_when_banner_signal_missing(self) -> None:
        stdout = json.dumps(
            {
                "identity_key": f"ip:{TARGET_SSH_IP}",
                "signals": [
                    {"OpenPort": TARGET_SSH_PORT},
                    {"SshHostKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"},
                ],
            }
        ) + "\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_ssh(self._ctx())
        self.assertFalse(ok)
        self.assertIn("SshBanner", msg)

    def test_run_cli_icmp_success_path(self) -> None:
        stdout = "\n".join(
            json.dumps(
                {
                    "identity_key": f"ip:{ip}",
                    "signals": [{"IcmpEchoRttMicros": 1234}],
                }
            )
            for ip in TARGET_IPS
        ) + "\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_icmp(self._ctx())
        self.assertTrue(ok, msg)
        self.assertIn("IcmpEchoRttMicros", msg)
        self.assertIn("3 targets", msg)

    def test_run_cli_icmp_fails_when_signal_missing(self) -> None:
        # One record has no IcmpEchoRttMicros signal.
        records = [
            {"identity_key": f"ip:{ip}", "signals": [{"IcmpEchoRttMicros": 1000}]}
            for ip in TARGET_IPS
        ]
        records[1]["signals"] = [{"OpenPort": 80}]
        stdout = "\n".join(json.dumps(r) for r in records) + "\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_icmp(self._ctx())
        self.assertFalse(ok)
        self.assertIn("IcmpEchoRttMicros", msg)

    def test_run_cli_icmp_fails_when_record_count_wrong(self) -> None:
        stdout = "\n".join(
            json.dumps(
                {
                    "identity_key": f"ip:{ip}",
                    "signals": [{"IcmpEchoRttMicros": 1000}],
                }
            )
            for ip in TARGET_IPS[:2]  # emit only 2 records instead of 3
        ) + "\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_icmp(self._ctx())
        self.assertFalse(ok)
        self.assertIn("expected 3 records", msg)
        self.assertIn("got 2", msg)

    def test_run_cli_tls_success_path(self) -> None:
        stdout = json.dumps(
            {
                "identity_key": f"ip:{TARGET_TLS_IP}",
                "signals": [
                    {"OpenPort": TARGET_TLS_PORT},
                    {"TlsSubject": TARGET_TLS_EXPECTED_CN},
                    {"TlsSanName": TARGET_TLS_EXPECTED_DNS_SAN},
                    {"TlsSanName": TARGET_TLS_EXPECTED_IP_SAN},
                ],
            }
        ) + "\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_tls(self._ctx())
        self.assertTrue(ok, msg)
        self.assertIn("TlsSubject", msg)
        self.assertIn(TARGET_TLS_IP, msg)

    def test_run_cli_tls_fails_when_subject_missing(self) -> None:
        stdout = json.dumps(
            {
                "identity_key": f"ip:{TARGET_TLS_IP}",
                "signals": [
                    {"TlsSanName": TARGET_TLS_EXPECTED_DNS_SAN},
                    {"TlsSanName": TARGET_TLS_EXPECTED_IP_SAN},
                ],
            }
        ) + "\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_tls(self._ctx())
        self.assertFalse(ok)
        self.assertIn("TlsSubject", msg)

    def test_run_cli_tls_fails_when_dns_san_missing(self) -> None:
        stdout = json.dumps(
            {
                "identity_key": f"ip:{TARGET_TLS_IP}",
                "signals": [
                    {"TlsSubject": TARGET_TLS_EXPECTED_CN},
                    {"TlsSanName": TARGET_TLS_EXPECTED_IP_SAN},
                ],
            }
        ) + "\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_tls(self._ctx())
        self.assertFalse(ok)
        self.assertIn("TlsSanName", msg)
        self.assertIn(TARGET_TLS_EXPECTED_DNS_SAN, msg)

    def test_run_cli_tls_fails_when_ip_san_missing(self) -> None:
        stdout = json.dumps(
            {
                "identity_key": f"ip:{TARGET_TLS_IP}",
                "signals": [
                    {"TlsSubject": TARGET_TLS_EXPECTED_CN},
                    {"TlsSanName": TARGET_TLS_EXPECTED_DNS_SAN},
                ],
            }
        ) + "\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_tls(self._ctx())
        self.assertFalse(ok)
        self.assertIn("TlsSanName", msg)
        self.assertIn(TARGET_TLS_EXPECTED_IP_SAN, msg)

    def test_run_cli_reverse_dns_success_path(self) -> None:
        stdout = json.dumps(
            {
                "identity_key": f"ip:{RDNS_TARGET_IP}",
                "signals": [
                    {"ReverseDnsName": RDNS_EXPECTED_NAME},
                ],
            }
        ) + "\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_reverse_dns(self._ctx())
        self.assertTrue(ok, msg)
        self.assertIn("ReverseDnsName", msg)
        self.assertIn(RDNS_EXPECTED_NAME, msg)
        self.assertIn(RDNS_TARGET_IP, msg)

    def test_run_cli_reverse_dns_fails_when_signal_missing(self) -> None:
        stdout = json.dumps(
            {
                "identity_key": f"ip:{RDNS_TARGET_IP}",
                "signals": [{"OpenPort": 53}],
            }
        ) + "\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_reverse_dns(self._ctx())
        self.assertFalse(ok)
        self.assertIn("ReverseDnsName", msg)

    def test_run_cli_reverse_dns_fails_when_signal_value_wrong(self) -> None:
        stdout = json.dumps(
            {
                "identity_key": f"ip:{RDNS_TARGET_IP}",
                "signals": [{"ReverseDnsName": "wrong.host"}],
            }
        ) + "\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )
        with unittest.mock.patch.object(subprocess, "run", return_value=completed):
            ok, msg = run_cli_reverse_dns(self._ctx())
        self.assertFalse(ok)
        self.assertIn("ReverseDnsName", msg)
        self.assertIn(RDNS_EXPECTED_NAME, msg)


class _ComposeParsingTests(unittest.TestCase):
    SAMPLE = (
        "networks:\n"
        "  rastreo-net:\n"
        "    driver: bridge\n"
        "services:\n"
        "  # a comment\n"
        "  kafka:\n"
        "    image: apache/kafka:4.3.1\n"
        "    ports:\n"
        '      - "9092:9092"\n'
        "    networks:\n"
        "      rastreo-net:\n"
        "        ipv4_address: 10.50.0.2\n"
        "  target-1:\n"
        "    image: nginx\n"
        "    command:\n"
        '      - "-m"\n'
        '      - "8222"\n'
        "    expose:\n"
        '      - "80"\n'
        "    networks:\n"
        "      rastreo-net:\n"
        "        ipv4_address: 10.50.0.10\n"
        "volumes:\n"
        "  not-a-service:\n"
    )

    def test_reads_service_names_in_declaration_order(self) -> None:
        self.assertEqual(
            [svc.name for svc in parse_compose_services(self.SAMPLE)],
            ["kafka", "target-1"],
        )

    def test_reads_the_static_address_of_each_service(self) -> None:
        addresses = {
            svc.name: svc.ipv4_address for svc in parse_compose_services(self.SAMPLE)
        }
        self.assertEqual(addresses, {"kafka": "10.50.0.2", "target-1": "10.50.0.10"})

    def test_top_level_keys_other_than_services_are_not_services(self) -> None:
        names = {svc.name for svc in parse_compose_services(self.SAMPLE)}
        self.assertNotIn("not-a-service", names)
        self.assertNotIn("rastreo-net", names)

    def test_service_without_a_static_address_reports_none(self) -> None:
        text = "services:\n  plain:\n    image: nginx\n"
        self.assertEqual(
            parse_compose_services(text), (ComposeService("plain", None, ()),)
        )

    def test_empty_source_yields_no_services(self) -> None:
        self.assertEqual(parse_compose_services(""), ())

    def test_reads_the_ports_each_service_publishes(self) -> None:
        published = {
            svc.name: svc.published_ports for svc in parse_compose_services(self.SAMPLE)
        }
        self.assertEqual(published["kafka"], (PublishedPort(9092, 9092),))

    def test_list_items_outside_a_ports_block_are_not_published_ports(self) -> None:
        published = {
            svc.name: svc.published_ports for svc in parse_compose_services(self.SAMPLE)
        }
        self.assertEqual(published["target-1"], ())

    def test_reads_the_ports_each_service_exposes(self) -> None:
        exposed = {
            svc.name: svc.exposed_ports for svc in parse_compose_services(self.SAMPLE)
        }
        self.assertEqual(exposed, {"kafka": (), "target-1": (80,)})

    def test_a_service_serves_both_its_exposed_and_its_published_ports(self) -> None:
        services = {svc.name: svc for svc in parse_compose_services(self.SAMPLE)}
        self.assertEqual(services["kafka"].container_ports, frozenset({9092}))
        self.assertEqual(services["target-1"].container_ports, frozenset({80}))
        self.assertEqual(services["kafka"].published_host_ports, frozenset({9092}))
        self.assertEqual(services["target-1"].published_host_ports, frozenset())

    def test_a_port_compose_picks_is_no_host_port(self) -> None:
        service = ComposeService("svc", None, (PublishedPort(None, 80),))
        self.assertEqual(service.published_host_ports, frozenset())
        self.assertEqual(service.container_ports, frozenset({80}))

    def test_expose_entry_forms(self) -> None:
        for entry, expected in {'"80"': 80, "80": 80, '"443/tcp"': 443}.items():
            self.assertEqual(parse_exposed_port(entry), expected, entry)

    def test_an_unparseable_expose_entry_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_exposed_port('"${PORT}"')

    def test_port_mapping_forms(self) -> None:
        cases = {
            '"8080:80"': PublishedPort(8080, 80),
            "8080:80": PublishedPort(8080, 80),
            '"127.0.0.1:8080:80"': PublishedPort(8080, 80),
            '"8080:80/udp"': PublishedPort(8080, 80),
            '"80"': PublishedPort(None, 80),
        }
        for entry, expected in cases.items():
            self.assertEqual(parse_published_port(entry), expected, entry)

    def test_an_unparseable_port_mapping_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_published_port('"${HOST_PORT}:80"')

    def test_committed_compose_file_parses_to_the_running_stack(self) -> None:
        services = read_compose_services(_repo_root_for_self_tests())
        self.assertGreaterEqual(len(services), 8)
        addressed = {svc.name for svc in services if svc.ipv4_address}
        self.assertEqual(addressed, {svc.name for svc in services})

    def test_committed_compose_file_publishes_the_ports_the_gates_use(self) -> None:
        published = {
            (svc.name, host_port)
            for svc in read_compose_services(_repo_root_for_self_tests())
            for host_port in svc.published_host_ports
        }
        needed = {
            (gate.service, parse_endpoint(gate.endpoint).port)
            for gate in READINESS_GATES
            if endpoint_vantage_network(gate.endpoint) is None
        }
        self.assertTrue(needed, "no gate polls a published host port")
        self.assertLessEqual(needed, published)

    def test_committed_compose_file_declares_the_in_network_ports_gates_use(
        self,
    ) -> None:
        serving = {
            (svc.name, container_port)
            for svc in read_compose_services(_repo_root_for_self_tests())
            for container_port in svc.container_ports
        }
        needed = {
            (gate.service, parse_endpoint(gate.endpoint).port)
            for gate in READINESS_GATES
            if endpoint_vantage_network(gate.endpoint) is not None
        }
        self.assertTrue(needed, "no gate polls an in-network address")
        self.assertLessEqual(needed, serving)


def _is_argv_builder_name(name: str) -> bool:
    return name.startswith("build_") and name.endswith("_argv")


def _first_self_test_line(tree: ast.AST) -> int:
    """Where the self-tests start, so a guard scans only the harness itself."""
    return min(
        node.lineno
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name.endswith("Tests")
    )


def _nearest_statements(tree: ast.AST) -> dict[int, ast.stmt]:
    """Every node mapped to the statement it belongs to.

    An expression in an ``if`` test belongs to the ``if``, so a guard reading a
    branch condition sees the whole branch.
    """
    nearest: dict[int, ast.stmt] = {}

    def walk(node: ast.AST, enclosing: ast.stmt | None) -> None:
        for child in ast.iter_child_nodes(node):
            owner = child if isinstance(child, ast.stmt) else enclosing
            nearest[id(child)] = owner
            walk(child, owner)

    walk(tree, None)
    return nearest


def _docker_run_list_nodes(tree: ast.AST) -> list[ast.List]:
    """Every ``["docker", "run", ...]`` argv literal in ``tree``.

    Two-element lists are the guard's own comparison literals, not argvs.
    """
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.List)
        and len(node.elts) > 2
        and [elt.value for elt in node.elts[:2] if isinstance(elt, ast.Constant)]
        == ["docker", "run"]
    ]


def _docker_run_argv_builders() -> dict[str, list[str]]:
    """Every ``build_*_argv`` function that yields a ``docker run`` argv, called
    with placeholder arguments for its required parameters."""
    built: dict[str, list[str]] = {}
    for name, fn in sorted(vars(_this_module()).items()):
        if not (callable(fn) and _is_argv_builder_name(name)):
            continue
        required = [
            "/placeholder"
            for parameter in inspect.signature(fn).parameters.values()
            if parameter.default is inspect.Parameter.empty
            and parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        ]
        argv = fn(*required)
        if list(argv[:2]) == ["docker", "run"]:
            built[name] = list(argv)
    return built


class _DockerRunImageTests(unittest.TestCase):
    def test_reads_the_image_after_valued_flags(self) -> None:
        argv = ["docker", "run", "--rm", "--network", "net", "busybox:1.36", "nc"]
        self.assertEqual(docker_run_image(argv), "busybox:1.36")

    def test_reads_the_image_past_an_inline_valued_flag(self) -> None:
        argv = [
            "docker", "run", "--rm", "--network", "net", "--cap-add=NET_RAW",
            "-v", "/a:/b:ro", "--entrypoint", "/rastreo", "rastreo-server", "discover",
        ]
        self.assertEqual(docker_run_image(argv), "rastreo-server")

    def test_rejects_an_argv_that_is_not_docker_run(self) -> None:
        with self.assertRaises(ValueError):
            docker_run_image(["docker", "compose", "up"])

    def test_rejects_an_argv_with_no_image(self) -> None:
        with self.assertRaises(ValueError):
            docker_run_image(["docker", "run", "--rm"])

    def test_every_docker_run_argv_uses_a_prepulled_image(self) -> None:
        approved = set(SIDECAR_IMAGES) | {RASTREO_IMAGE}
        builders = _docker_run_argv_builders()
        self.assertGreaterEqual(len(builders), 8)
        for name, argv in builders.items():
            self.assertIn(docker_run_image(argv), approved, name)

    def test_no_docker_run_argv_escapes_the_builders(self) -> None:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        by_id = {id(node): node for node in _docker_run_list_nodes(tree)}
        in_builders: set[int] = set()
        in_self_tests: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and _is_argv_builder_name(node.name):
                in_builders |= {id(n) for n in _docker_run_list_nodes(node)}
            if isinstance(node, ast.ClassDef) and node.name.endswith("Tests"):
                in_self_tests |= {id(n) for n in _docker_run_list_nodes(node)}
        harness = set(by_id) - in_self_tests
        self.assertTrue(in_builders)
        self.assertEqual(
            sorted(by_id[node_id].lineno for node_id in harness - in_builders),
            [],
            "docker run argv built outside a build_*_argv function, at these lines",
        )


class _InterruptingStderr(io.StringIO):
    """A Ctrl-C landing while the harness writes the line carrying ``marker``."""

    def __init__(self, marker: str) -> None:
        super().__init__()
        self.marker = marker

    def write(self, text: str) -> int:
        if self.marker in text:
            raise KeyboardInterrupt
        return super().write(text)


def _patched_lifecycle(
    calls: list[str],
    gates: tuple[ReadinessGate, ...],
    phases: tuple[StartupPhase, ...] = (),
) -> contextlib.ExitStack:
    """Run ``run_all`` against a recorded stack instead of Docker."""
    stack = contextlib.ExitStack()
    module = _this_module()
    stack.enter_context(
        unittest.mock.patch.object(module, "READINESS_GATES", gates)
    )
    stack.enter_context(
        unittest.mock.patch.object(
            module, "check_readiness_coverage", return_value=[]
        )
    )
    stack.enter_context(
        unittest.mock.patch.object(module, "startup_phases", return_value=phases)
    )
    stack.enter_context(
        unittest.mock.patch.object(
            module,
            "compose_ps",
            side_effect=lambda _root, **_kw: (
                calls.append("ps") or "NAME STATUS\nrastreo-target-1 Up"
            ),
        )
    )
    stack.enter_context(
        unittest.mock.patch.object(
            module,
            "compose_logs_tail",
            side_effect=lambda _root, service, **_kw: (
                calls.append(f"logs:{service}") or f"tail of {service}"
            ),
        )
    )
    stack.enter_context(
        unittest.mock.patch.object(
            module,
            "compose_down",
            side_effect=lambda _root, **_kw: (
                calls.append("down")
                or subprocess.CompletedProcess([], 0, "", "")
            ),
        )
    )
    return stack


class _RunAllDiagnosticsTests(unittest.TestCase):
    """Every failure raised with containers up must snapshot them before tear-down."""


    def _ctx(self) -> HarnessCtx:
        return HarnessCtx(repo_root=Path("/tmp"), verbose=False)

    def _row(
        self,
        run: Callable[[HarnessCtx], tuple[bool, str]],
        containers: tuple[str, ...] = ("target-1",),
    ) -> MatrixRow:
        return MatrixRow(
            name="cli_stdout",
            run=run,
            budget_s=SCENARIO_TIMEOUT_S,
            failure_log_containers=containers,
        )

    def test_failing_row_logs_are_read_before_teardown(self) -> None:
        calls: list[str] = []
        gate = ReadinessGate("target-1", "10.50.0.10:80", _probe_ready)
        row = self._row(lambda _c: (False, "boom"), ("target-1", "target-2"))
        with _patched_lifecycle(calls, (gate,)):
            results = run_all((row,), self._ctx())
        self.assertEqual(calls, ["ps", "logs:target-1", "logs:target-2", "down"])
        rendered = attribute_failure(results[0])
        self.assertIn("tail of target-1", rendered)
        self.assertIn("tail of target-2", rendered)
        self.assertIn("rastreo-target-1 Up", rendered)

    def test_passing_row_reads_no_logs(self) -> None:
        calls: list[str] = []
        gate = ReadinessGate("target-1", "10.50.0.10:80", _probe_ready)
        row = self._row(lambda _c: (True, "ok"))
        with _patched_lifecycle(calls, (gate,)):
            results = run_all((row,), self._ctx())
        self.assertEqual(calls, ["down"])
        self.assertTrue(results[0].ok)

    def test_readiness_failure_logs_are_read_before_teardown(self) -> None:
        calls: list[str] = []
        gate = ReadinessGate("target-3", "10.50.0.12:80", _probe_never_ready)
        row = self._row(lambda _c: (True, "ok"), ("target-3",))
        with _patched_lifecycle(calls, (gate,)):
            results = run_all((row,), self._ctx())
        self.assertEqual(calls, ["ps", "logs:target-3", "down"])
        self.assertEqual(results[0].row.name, "readiness:target-3")
        self.assertIn("tail of target-3", attribute_failure(results[0]))

    def test_coverage_failure_still_tears_the_stack_down(self) -> None:
        calls: list[str] = []
        module = _this_module()
        with _patched_lifecycle(calls, ()):
            with unittest.mock.patch.object(
                module, "check_readiness_coverage", return_value=["target-9 ungated"]
            ):
                results = run_all((), self._ctx())
        self.assertEqual(calls, ["down"])
        self.assertEqual(results[0].row.name, "readiness:coverage")
        self.assertIn("target-9 ungated", results[0].message)

    def _failing_phase(self) -> tuple[StartupPhase, ...]:
        return (StartupPhase(name="compose up", argv=("false",), budget_s=1.0),)

    def test_startup_failure_snapshots_containers_before_teardown(self) -> None:
        calls: list[str] = []
        gate = ReadinessGate("target-1", "10.50.0.10:80", _probe_ready)
        module = _this_module()
        with _patched_lifecycle(calls, (gate,), self._failing_phase()):
            with unittest.mock.patch.object(
                module,
                "run_startup_phase",
                side_effect=RuntimeError("compose up exceeded its 180s budget"),
            ):
                results = run_all((self._row(lambda _c: (True, "ok")),), self._ctx())
        self.assertEqual(calls, ["ps", "logs:target-1", "down"])
        self.assertEqual(results[0].row.name, "compose up")
        rendered = attribute_failure(results[0])
        self.assertIn("exceeded its 180s budget", rendered)
        self.assertIn("rastreo-target-1 Up", rendered)
        self.assertIn("tail of target-1", rendered)
        self.assertNotIn("(no output)", rendered)

    def test_startup_failure_snapshots_every_service_the_run_starts(self) -> None:
        module = _this_module()
        with unittest.mock.patch.object(
            module,
            "READINESS_EXEMPT_SERVICES",
            {"sidecar": "nothing probes it"},
        ):
            services = started_services()
        self.assertIn("sidecar", services)
        self.assertEqual(
            set(services) - {"sidecar"},
            {gate.service for gate in READINESS_GATES},
        )

    def test_the_services_a_startup_failure_dumps_are_the_compose_services(
        self,
    ) -> None:
        compose = {
            svc.name for svc in read_compose_services(_repo_root_for_self_tests())
        }
        self.assertEqual(set(started_services()), compose)

    def test_a_snapshot_failure_does_not_lose_the_results_so_far(self) -> None:
        calls: list[str] = []
        gate = ReadinessGate("target-1", "10.50.0.10:80", _probe_ready)
        module = _this_module()
        rows = (
            dataclasses.replace(self._row(lambda _c: (True, "ok")), name="first"),
            dataclasses.replace(self._row(lambda _c: (False, "boom")), name="second"),
        )
        with _patched_lifecycle(calls, (gate,)):
            with unittest.mock.patch.object(
                module, "compose_logs_tail", side_effect=OSError("docker socket gone")
            ):
                results = run_all(rows, self._ctx())
        self.assertEqual([r.row.name for r in results], ["first", "second"])
        self.assertIn("down", calls)
        self.assertIn("docker socket gone", attribute_failure(results[1]))

    def test_a_teardown_timeout_does_not_lose_the_report(self) -> None:
        calls: list[str] = []
        gate = ReadinessGate("target-1", "10.50.0.10:80", _probe_ready)
        module = _this_module()
        row = self._row(lambda _c: (False, "boom"))
        with _patched_lifecycle(calls, (gate,)):
            with unittest.mock.patch.object(
                module,
                "compose_down",
                side_effect=subprocess.TimeoutExpired(cmd="down", timeout=120),
            ):
                results = run_all((row,), self._ctx())
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].ok)

    def test_interrupt_mid_row_snapshots_and_keeps_the_results_so_far(self) -> None:
        calls: list[str] = []
        gate = ReadinessGate("target-1", "10.50.0.10:80", _probe_ready)

        def interrupted(_ctx: HarnessCtx) -> tuple[bool, str]:
            raise KeyboardInterrupt

        rows = (
            dataclasses.replace(self._row(lambda _c: (True, "ok")), name="first"),
            dataclasses.replace(self._row(interrupted), name="second"),
        )
        with _patched_lifecycle(calls, (gate,)):
            with self.assertRaises(HarnessInterrupted) as cm:
                run_all(rows, self._ctx())
        results = cm.exception.results
        self.assertEqual([r.row.name for r in results], ["first", "second"])
        self.assertIn("interrupted", results[1].message)
        self.assertEqual(calls, ["ps", "logs:target-1", "down"])
        self.assertIn("tail of target-1", attribute_failure(results[1]))

    def test_interrupt_during_startup_snapshots_before_teardown(self) -> None:
        calls: list[str] = []
        gate = ReadinessGate("target-1", "10.50.0.10:80", _probe_ready)
        module = _this_module()
        with _patched_lifecycle(calls, (gate,), self._failing_phase()):
            with unittest.mock.patch.object(
                module, "run_startup_phase", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(HarnessInterrupted) as cm:
                    run_all((self._row(lambda _c: (True, "ok")),), self._ctx())
        self.assertEqual(calls, ["ps", "logs:target-1", "down"])
        self.assertIn("rastreo-target-1 Up", attribute_failure(cm.exception.results[0]))

    def test_a_harness_bug_still_reports_the_stack_it_ran_against(self) -> None:
        calls: list[str] = []
        gate = ReadinessGate("target-1", "10.50.0.10:80", _probe_ready)
        module = _this_module()
        with _patched_lifecycle(calls, (gate,), self._failing_phase()):
            with unittest.mock.patch.object(
                module,
                "run_startup_phase",
                side_effect=ZeroDivisionError("harness bug"),
            ):
                results = run_all((self._row(lambda _c: (True, "ok")),), self._ctx())
        self.assertEqual(calls, ["ps", "logs:target-1", "down"])
        self.assertEqual(results[0].row.name, "harness")
        rendered = attribute_failure(results[0])
        self.assertIn("ZeroDivisionError", rendered)
        self.assertIn("rastreo-target-1 Up", rendered)

    def test_a_second_interrupt_during_teardown_keeps_the_report(self) -> None:
        calls: list[str] = []
        gate = ReadinessGate("target-1", "10.50.0.10:80", _probe_ready)
        module = _this_module()

        def interrupted(_ctx: HarnessCtx) -> tuple[bool, str]:
            raise KeyboardInterrupt

        results: list[RowResult] = []
        with _patched_lifecycle(calls, (gate,)):
            with unittest.mock.patch.object(
                module, "compose_down", side_effect=KeyboardInterrupt
            ):
                try:
                    run_all((self._row(interrupted),), self._ctx())
                except HarnessInterrupted as e:
                    results = e.results
                except BaseException as e:  # noqa: BLE001 — the regression itself
                    self.fail(f"tear-down let {e!r} replace the report")
                else:
                    self.fail("run_all returned instead of reporting the interrupt")
        self.assertEqual(len(results), 1)
        self.assertIn("interrupted", results[0].message)

    def test_a_run_takes_no_more_snapshots_than_the_budget_charges(self) -> None:
        calls: list[str] = []
        gate = ReadinessGate("target-1", "10.50.0.10:80", _probe_ready)
        rows = tuple(
            dataclasses.replace(self._row(lambda _c: (False, "boom")), name=f"row-{n}")
            for n in range(3)
        )
        with _patched_lifecycle(calls, (gate,)):
            with contextlib.redirect_stderr(_InterruptingStderr("[row-2] FAIL")):
                with self.assertRaises(HarnessInterrupted):
                    run_all(rows, self._ctx())
        self.assertEqual(calls.count("ps"), diagnostic_snapshots(len(rows)))

    def test_main_prints_the_report_and_exits_130_when_interrupted(self) -> None:
        module = _this_module()
        row = self._row(lambda _c: (False, "boom"))
        result = RowResult(
            row=row,
            ok=False,
            message="interrupted (Ctrl-C) while the row was running",
            snapshot=FailureSnapshot(
                container_state="rastreo-target-1 Up",
                logs=(ServiceLog(service="target-1", text="nginx ready"),),
            ),
        )
        stderr = io.StringIO()
        with unittest.mock.patch.object(
            module, "run_all", side_effect=HarnessInterrupted([result])
        ):
            with contextlib.redirect_stderr(stderr):
                code = main([])
        self.assertEqual(code, 130)
        self.assertIn("nginx ready", stderr.getvalue())
        self.assertIn("rastreo-target-1 Up", stderr.getvalue())


class _SnapshotBudgetTests(unittest.TestCase):
    def _patch(
        self, calls: list[str], clock: list[float], cost_s: float
    ) -> contextlib.ExitStack:
        module = _this_module()
        stack = contextlib.ExitStack()
        stack.enter_context(
            unittest.mock.patch.object(
                module,
                "compose_ps",
                side_effect=lambda _root, **_kw: (
                    calls.append("ps")
                    or clock.__setitem__(0, clock[0] + cost_s)
                    or "state"
                ),
            )
        )
        stack.enter_context(
            unittest.mock.patch.object(
                module,
                "compose_logs_tail",
                side_effect=lambda _root, service, **_kw: (
                    calls.append(service)
                    or clock.__setitem__(0, clock[0] + cost_s)
                    or f"tail of {service}"
                ),
            )
        )
        return stack

    def test_a_hung_docker_cannot_outlast_the_diagnostic_budget(self) -> None:
        calls: list[str] = []
        clock = [0.0]
        services = tuple(f"svc-{n}" for n in range(16))
        with self._patch(calls, clock, cost_s=DIAGNOSTIC_BUDGET_S):
            snapshot = snapshot_failure_state(
                Path("/tmp"), services, now=lambda: clock[0]
            )
        self.assertLessEqual(clock[0], DIAGNOSTIC_BUDGET_S)
        self.assertEqual(len(snapshot.logs), len(services))
        self.assertIn("diagnostic budget", snapshot.logs[-1].text)

    def test_a_healthy_docker_captures_every_service(self) -> None:
        calls: list[str] = []
        clock = [0.0]
        services = ("kafka", "nats", "target-1")
        with self._patch(calls, clock, cost_s=0.1):
            snapshot = snapshot_failure_state(
                Path("/tmp"), services, now=lambda: clock[0]
            )
        self.assertEqual(calls, ["ps", "kafka", "nats", "target-1"])
        self.assertEqual(
            [log.text for log in snapshot.logs],
            ["tail of kafka", "tail of nats", "tail of target-1"],
        )

    def test_each_log_call_is_bounded_by_what_is_left_of_the_budget(self) -> None:
        clock = [0.0]
        seen: list[float] = []
        module = _this_module()
        with unittest.mock.patch.object(module, "compose_ps", return_value="state"):
            with unittest.mock.patch.object(
                module,
                "compose_logs_tail",
                side_effect=lambda _root, service, **kw: (
                    seen.append(kw["timeout_s"])
                    or clock.__setitem__(0, clock[0] + 10.0)
                    or "tail"
                ),
            ):
                snapshot_failure_state(
                    Path("/tmp"), ("a", "b", "c"), now=lambda: clock[0]
                )
        self.assertEqual(seen, [30.0, 20.0, 10.0])

    def test_a_raising_docker_still_returns_a_snapshot(self) -> None:
        with unittest.mock.patch.object(
            subprocess, "run", side_effect=OSError("docker socket gone")
        ):
            snapshot = snapshot_failure_state(Path("/tmp"), ("kafka",))
        self.assertIn("docker socket gone", snapshot.container_state)
        self.assertIn("docker socket gone", snapshot.logs[0].text)


class _ProcessOutputTests(unittest.TestCase):
    def test_renders_both_captured_streams(self) -> None:
        e = subprocess.TimeoutExpired(
            cmd="x", timeout=1, output=b"pulling image\n", stderr=b"no space left\n"
        )
        rendered = timeout_output_tail(e)
        self.assertIn("pulling image", rendered)
        self.assertIn("no space left", rendered)

    def test_renders_text_streams(self) -> None:
        e = subprocess.TimeoutExpired(cmd="x", timeout=1, output="waiting for kafka")
        self.assertIn("waiting for kafka", timeout_output_tail(e))

    def test_says_so_when_nothing_was_captured(self) -> None:
        e = subprocess.TimeoutExpired(cmd="x", timeout=1)
        self.assertIn("no output", timeout_output_tail(e))

    def test_keeps_only_the_tail(self) -> None:
        e = subprocess.TimeoutExpired(
            cmd="x",
            timeout=1,
            output="\n".join(f"line-{n}" for n in range(100)).encode(),
        )
        rendered = timeout_output_tail(e, lines=3)
        self.assertIn("line-99", rendered)
        self.assertNotIn("line-95", rendered)

    def test_a_startup_timeout_carries_what_the_phase_had_written(self) -> None:
        phase = StartupPhase(name="compose up", argv=("true",), budget_s=180.0)
        expired = subprocess.TimeoutExpired(
            cmd="x", timeout=180, output=b"", stderr=b"container kafka is unhealthy"
        )
        with unittest.mock.patch.object(subprocess, "run", side_effect=expired):
            with self.assertRaises(RuntimeError) as cm:
                run_startup_phase(phase)
        self.assertIn("180s budget", str(cm.exception))
        self.assertIn("container kafka is unhealthy", str(cm.exception))

    def test_a_row_timeout_carries_what_the_cli_had_written(self) -> None:
        expired = subprocess.TimeoutExpired(
            cmd="x", timeout=90, output=b"", stderr=b"connection refused"
        )
        with unittest.mock.patch.object(subprocess, "run", side_effect=expired):
            ctx = HarnessCtx(repo_root=Path("/tmp"), verbose=False)
            ok, message = run_cli_stdout(ctx)
        self.assertFalse(ok)
        self.assertIn("timed out", message)
        self.assertIn("connection refused", message)

    def test_a_log_tail_timeout_carries_what_docker_had_written(self) -> None:
        expired = subprocess.TimeoutExpired(
            cmd="x", timeout=30, output=b"partial log line", stderr=b""
        )
        with unittest.mock.patch.object(subprocess, "run", side_effect=expired):
            text = compose_logs_tail(Path("/tmp"), "kafka")
        self.assertIn("timed out", text)
        self.assertIn("partial log line", text)

    def test_renders_what_a_failed_process_wrote_on_both_streams(self) -> None:
        proc = subprocess.CompletedProcess(
            args=[], returncode=7, stdout="records so far", stderr="broker gone"
        )
        rendered = exit_output_tail(proc)
        self.assertIn("records so far", rendered)
        self.assertIn("broker gone", rendered)

    def test_says_so_when_a_failed_process_wrote_nothing(self) -> None:
        proc = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        self.assertIn("no output", exit_output_tail(proc))

    def test_a_row_keeps_the_stdout_of_a_sidecar_that_exited_nonzero(self) -> None:
        published = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        consumed = subprocess.CompletedProcess(
            args=[], returncode=3, stdout='{"identity_key":"ip:10.50.0.10"}', stderr=""
        )
        with unittest.mock.patch.object(
            subprocess, "run", side_effect=[published, consumed]
        ):
            ctx = HarnessCtx(repo_root=Path("/tmp"), verbose=False)
            ok, message = run_cli_kafka(ctx)
        self.assertFalse(ok)
        self.assertIn("kcat exited 3", message)
        self.assertIn("ip:10.50.0.10", message)

    def test_every_subprocess_timeout_handler_reads_the_captured_output(self) -> None:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        unnamed: list[int] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if "TimeoutExpired" not in ast.dump(node.type or ast.Constant(None)):
                continue
            if node.name is None or "timeout_output_tail" not in ast.dump(node):
                unnamed.append(node.lineno)
        harness_end = _first_self_test_line(tree)
        self.assertEqual([line for line in unnamed if line < harness_end], [])

    def test_every_nonzero_exit_path_reads_the_captured_output(self) -> None:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        statements = _nearest_statements(tree)
        harness_end = _first_self_test_line(tree)
        silent = sorted(
            {
                statements[id(node)].lineno
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute)
                and node.attr == "returncode"
                and statements.get(id(node)) is not None
                and statements[id(node)].lineno < harness_end
                and "exit_output_tail" not in ast.dump(statements[id(node)])
            }
        )
        self.assertEqual(
            silent,
            [],
            "a subprocess exit status is read without rendering what the "
            "process wrote, at these lines",
        )


class _SelfTestRegistryTests(unittest.TestCase):
    def test_the_suite_is_not_empty(self) -> None:
        self.assertGreater(len(self_test_classes()), 10)


def self_test_classes() -> list[type[unittest.TestCase]]:
    """Every ``TestCase`` this file defines, so a new one cannot go unregistered."""
    return [
        obj
        for _name, obj in sorted(vars(_this_module()).items())
        if isinstance(obj, type)
        and issubclass(obj, unittest.TestCase)
        and obj is not unittest.TestCase
    ]


def _run_self_tests() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in self_test_classes():
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
