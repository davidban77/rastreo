---
description: The rastreo-server HTTP control plane — routes, request and response shape for /scans, Prometheus metrics at /metrics, request-timeout configuration, and when to choose the server over the CLI.
---

# rastreo-server

`rastreo-server` is the HTTP control plane for rastreo. It is a long-running process that accepts discovery scenarios over a REST API, runs each scan synchronously, and returns the summary and records in the response body. Use it when another system needs to trigger scans (for example, a CMDB re-scan webhook, a scheduled job, or a UI). Use the CLI for one-shot scans from a laptop or CI.

## Run

The server binds to `0.0.0.0:8080` by default.

```bash
rastreo-server
```

```text
INFO rastreo_server: rastreo-server listening addr=0.0.0.0:8080
```

The bind address and port come from `--bind` (default `0.0.0.0`, env `RASTREO_SERVER_BIND`) and `--port` (default `8080`, env `RASTREO_SERVER_PORT`).

Logs go to stderr. Use `RUST_LOG` to raise or lower verbosity per module, for example `RUST_LOG=debug` for the whole crate or `RUST_LOG=rastreo_server=debug,rastreo_core=info` for finer control.

## Configuration

For every environment variable both binaries read at runtime, in one table, see the [Configuration reference](../reference/configuration.md).

| Flag                    | Env var                                | Default | Notes                                                  |
|-------------------------|----------------------------------------|---------|--------------------------------------------------------|
| `--port`                | `RASTREO_SERVER_PORT`                  | `8080`  | TCP port to bind.                                      |
| `--bind`                | `RASTREO_SERVER_BIND`                  | `0.0.0.0` | Bind address.                                        |
| `--request-timeout-ms`  | `RASTREO_SERVER_REQUEST_TIMEOUT_MS`    | `60000` | Per-request timeout in milliseconds. Minimum 1.        |
| —                       | `RASTREO_SHUTDOWN_TIMEOUT_SECS`        | `60`    | Hard cap in seconds on the graceful-drain window after a shutdown signal. When the drain runs longer, the server logs a warning and force-exits. Minimum 1. Keep it below the pod's `terminationGracePeriodSeconds`. See [Graceful shutdown](#graceful-shutdown). |
| —                       | `RASTREO_API_TOKEN`                    | unset   | Shared secret for `POST /scans` bearer auth. When set, every request to `POST /scans` must send `Authorization: Bearer <token>`. A trailing newline is tolerated. See [Authentication](#authentication). |
| —                       | `RASTREO_AUTH_DISABLED`                | unset   | Set to `true` to run `POST /scans` with no authentication. The server refuses to start unless this or `RASTREO_API_TOKEN` is set. See [Authentication](#authentication). |
| —                       | `RASTREO_SINK_CONFIG_PATH`             | unset   | Path to a YAML file with a `SinkConfig`. When set, the server builds the sink at startup and probes it every `RASTREO_SINK_PROBE_INTERVAL_SECS`. Sink construction failure is non-fatal — the pod stays up, `/readyz` reports `sink_unreachable`. |
| —                       | `RASTREO_SINK_PROBE_INTERVAL_SECS`     | `10`    | Sink reachability probe cadence in seconds. Minimum 1. |
| —                       | `RASTREO_SINK_PROBE_TIMEOUT_SECS`      | `5`     | Per-probe timeout in seconds. Probes exceeding this count as failures. Minimum 1. |
| —                       | `RASTREO_TARGET_ALLOWLIST`             | unset   | Comma-separated CIDRs (bare IPs accepted, treated as `/32` or `/128`) the server may probe. Unset or empty allows any target. See [Restricting scan targets](#restricting-scan-targets). |
| —                       | `RASTREO_MAX_TOTAL_HOSTS`              | `262144` | Aggregate cap on the total resolved hosts across all targets in one request. `0` disables. See [Restricting scan targets](#restricting-scan-targets). |
| —                       | `RASTREO_MAX_BODY_BYTES`               | `1048576` | `POST /scans` request body size limit in bytes (1 MiB by default). An over-limit body is rejected with `413`. See [Restricting scan targets](#restricting-scan-targets). |
| —                       | `RASTREO_MAX_RESULT_BYTES`             | `33554432` | `POST /scans` response record cap in bytes (32 MiB by default). A scan producing more still returns `200`, with `records` truncated to the subset that fit and `truncated: true`; a server-configured sink still receives every record. Peak memory at response time is roughly 3× this cap, so raise the pod's `limits.memory` before raising it. See [Bounded response size](#bounded-response-size). |

The request timeout is enforced by middleware in front of every route. A request that runs longer than the timeout is aborted and the client sees `503 Service Unavailable`. When the timeout drops a scan, its in-flight probes stop instead of continuing in the background. Wasted probing is bounded by the timeout. A dropped scan is counted under `rastreo_server_scans_total{outcome="cancelled"}` — see [GET /metrics](#get-metrics). Large scans against a populated subnet can easily exceed 60 seconds — size the scan to fit the timeout, or raise the timeout to match the workload.

## Authentication

`POST /scans` triggers active network probes, so it is authenticated by default with a bearer token. The health, readiness, and metrics endpoints are never authenticated, so Kubernetes probes and Prometheus scraping keep working with no credential.

Two environment variables control authentication:

- `RASTREO_API_TOKEN` — the shared secret. When set, every `POST /scans` request must carry `Authorization: Bearer <token>`.
- `RASTREO_AUTH_DISABLED` — set to `true` to run `POST /scans` with no authentication. Use this only on a trusted, isolated network.

!!! tip "A trailing newline in the token is tolerated"
    `RASTREO_API_TOKEN` is trimmed of surrounding whitespace, so a trailing newline does not break authentication. This often happens when the token comes from a Kubernetes Secret's `stringData`, or from a shell `echo` that adds a newline. The token still authenticates.

### Secure by default

The server refuses to start unless one of those two variables is set. This stops a scan endpoint from being exposed with no credential by accident. With neither set, startup fails with:

```text
RASTREO_API_TOKEN is not set: set it to a shared secret to authenticate POST /scans, or set RASTREO_AUTH_DISABLED=true to run the scan endpoint unauthenticated (not recommended)
```

!!! warning "Running without authentication"
    With `RASTREO_AUTH_DISABLED=true` the server starts and logs a prominent WARNING. Any caller that can reach `POST /scans` can trigger active network probes. Only disable authentication where every client is already trusted.

    ```text
    WARN rastreo_server::state: RASTREO_AUTH_DISABLED=true: the POST /scans endpoint is UNAUTHENTICATED — any caller that can reach it can trigger active network probes
    ```

### Send an authenticated request

Set the token, then send it in the `Authorization` header:

```bash
export RASTREO_API_TOKEN='a-long-random-secret'
rastreo-server &

curl -H "Authorization: Bearer $RASTREO_API_TOKEN" \
  -X POST http://localhost:8080/scans \
  -H 'content-type: application/json' \
  -d '{
    "targets": [{"Ip": "10.50.0.10"}],
    "probers": [{"type": "tcp_connect", "ports": [80]}]
  }'
```

You can also read the body from a file with `-d @scenario.json`.

### 401 response

A missing, malformed, or wrong token returns `401 Unauthorized` with a `WWW-Authenticate: Bearer` response header:

```text
HTTP/1.1 401 Unauthorized
content-type: application/json
www-authenticate: Bearer

{"error":"missing or invalid bearer token"}
```

The response is the same whether the token is missing or wrong. It never reveals which, and it never echoes the token you sent.

On Kubernetes the Helm chart supplies the token from a Secret. See [Authentication on Kubernetes](kubernetes.md#authentication) for the chart values.

Authentication controls who may call `POST /scans`. To also limit which targets a caller may probe, see [Restricting scan targets](#restricting-scan-targets).

## Restricting scan targets

[Authentication](#authentication) controls *who* may trigger a scan. The target guard controls *what* the server is allowed to probe. Use both together. Authentication keeps unknown callers out. The target guard stops an authenticated caller from probing addresses you never meant to expose.

Three server-only controls apply to `POST /scans`:

- `RASTREO_TARGET_ALLOWLIST` — the networks the server may probe. Opt-in.
- `RASTREO_MAX_TOTAL_HOSTS` — a cap on the total hosts one request may resolve to. Always on.
- `RASTREO_MAX_BODY_BYTES` — a cap on the request body size. Always on.

!!! note "Server-only — the CLI is not affected"
    These controls guard the HTTP server only. The `rastreo discover` CLI is operator-run and trusted, so it probes any target regardless of these variables.

### Allow-list

`RASTREO_TARGET_ALLOWLIST` is a comma-separated list of CIDRs the server may probe. A bare IP is accepted and treated as a single-host network (`/32` for IPv4, `/128` for IPv6). Leave it unset or empty to allow any target — the allow-list is opt-in.

```bash
export RASTREO_TARGET_ALLOWLIST='10.0.0.0/8,192.168.0.0/16'
```

When the allow-list is set, the server resolves every target in the request, then checks each resolved IP. If any resolved IP falls outside every listed network, the whole request is rejected with `403 Forbidden` and nothing is probed.

!!! note "The whole request is rejected, not part of it"
    One out-of-range address rejects the entire request. The server never runs a partial scan of the addresses that were in range.

The example below sends a target that is outside the allow-list above:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/scans \
  -H "Authorization: Bearer $RASTREO_API_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"targets":[{"Ip":"127.0.0.1"}],"probers":[{"type":"tcp_connect","ports":[80]}]}'
```

`127.0.0.1` is outside every listed network, so the response is `403`:

```text
HTTP/1.1 403 Forbidden
content-type: application/json

{"error":"target 127.0.0.1 is outside the configured allow-list"}
```

The error names only the caller's offending IP. It never echoes the allow-list.

!!! warning "A malformed entry stops startup"
    Each entry must be a valid CIDR or IP address. A bad value fails at startup and names the offending entry, so the server never runs with a half-parsed allow-list:

    ```text
    invalid entry in RASTREO_TARGET_ALLOWLIST: "not-a-cidr" is not a valid CIDR or IP address
    ```

### Aggregate host cap

`RASTREO_MAX_TOTAL_HOSTS` caps the total number of hosts one request may resolve to, summed across every target. The default is `262144`. Set it to `0` to disable the cap.

A request that resolves to more hosts than the cap is rejected with `400 Bad Request` before any probe runs:

```text
{"error":"scan resolves to 14 hosts; exceeds the configured aggregate limit of 4"}
```

This cap is separate from the per-target expansion limit. A single CIDR or range wider than 65536 hosts is rejected on its own with a different error (`CidrTooLarge` or `RangeTooLarge`). The aggregate cap adds a second limit on the sum across all targets. Many small targets then cannot add up to one very large scan.

### Request body size

`RASTREO_MAX_BODY_BYTES` limits the size of a `POST /scans` request body in bytes. The default is `1048576` (1 MiB). A body larger than the limit is rejected with `413 Payload Too Large` before the server parses the JSON or runs any scan.

On Kubernetes, set all three controls through the Helm chart. See [Restricting scan targets on Kubernetes](kubernetes.md#restricting-scan-targets) for the `targetGuard` values.

## Graceful shutdown

On `SIGTERM` (production) or `SIGINT` (`Ctrl+C` during local dev), the server stops accepting new connections, lets inflight requests drain against the per-request timeout above, and stops the background sink-reachability probe after its current iteration. Provided the deploy-side grace period is large enough, a scan in flight completes and its records reach the server-configured sink before shutdown; if the platform kills the process before drain completes (SIGKILL after the grace period elapses, or an unclean pod eviction), the in-flight scan is lost. The chart ships `terminationGracePeriodSeconds: 75` — see the [Kubernetes deploy page](kubernetes.md) for sizing guidance.

A hard cap bounds the drain so a stuck scan cannot block shutdown forever. `RASTREO_SHUTDOWN_TIMEOUT_SECS` (default 60 seconds) sets it. When the drain runs longer than this, the server logs a warning and force-exits. On Kubernetes, keep this value below the pod's `terminationGracePeriodSeconds` so the app exits on its own before the kubelet sends `SIGKILL`.

```text
WARN rastreo_server: graceful shutdown exceeded timeout; forcing exit timeout_secs=60
```

## GET /healthz and GET /readyz

`GET /healthz` is a liveness probe. It always returns `200 OK` with a static JSON body, and never runs any discovery work. Use it from Kubernetes liveness probes, from external uptime monitors, or from a quick `curl` to verify the server is up.

```bash
curl -sS http://localhost:8080/healthz
```

```json
{"status":"ok"}
```

`GET /readyz` is a readiness probe. It returns `200 OK` only when the server can accept new work; when an inflight-scan limit or a recent-error quarantine has fired it returns `503 SERVICE_UNAVAILABLE` with a `reason` string. Use it from Kubernetes readiness probes so the pod is temporarily removed from Service endpoints while it recovers, without triggering a restart.

```bash
curl -sS http://localhost:8080/readyz
```

```json
{
  "status": "ready",
  "inflight_scans": 0,
  "max_inflight_scans": 100,
  "seconds_since_sink_error": null,
  "seconds_since_scan_error": null,
  "sink_reachable": null,
  "sink_type": null,
  "seconds_since_last_probe": null,
  "last_probe_error": null
}
```

The gates and the `reason` values are documented in full in the [Health endpoints reference](../reference/health-endpoints.md), along with the three environment-variable knobs (`RASTREO_MAX_INFLIGHT_SCANS`, `RASTREO_SINK_ERROR_QUARANTINE_SECS`, `RASTREO_SCAN_ERROR_QUARANTINE_SECS`) and the sink-reachability trio (`RASTREO_SINK_CONFIG_PATH`, `RASTREO_SINK_PROBE_INTERVAL_SECS`, `RASTREO_SINK_PROBE_TIMEOUT_SECS`).

## Sink reachability probe

When `RASTREO_SINK_CONFIG_PATH` is unset the reachability axis reports null on `/readyz` and no series is emitted on `/metrics` — the server is a pure `POST /scans` control plane. When the env var points at a YAML file with a `SinkConfig`, the server builds the sink at startup and spawns a background probe task that fires every `RASTREO_SINK_PROBE_INTERVAL_SECS` (default 10s) with a per-probe timeout of `RASTREO_SINK_PROBE_TIMEOUT_SECS` (default 5s). The cached result feeds `/readyz` (`sink_reachable`, `sink_type`, `seconds_since_last_probe`, `last_probe_error`) and `/metrics` (`rastreo_server_sink_reachable{sink_type}`, `rastreo_server_sink_reachability_probe_total{outcome,sink_type}`).

The probe is proactive: a broker outage flips `sink_reachable` to `false` on the next tick, and `/readyz` returns 503 with `reason: "sink_unreachable"` before any scan-triggered sink write catches the fault. Sink construction failure at startup does not crash the pod — the server stays up with `sink_reachable: false` and a `last_probe_error` string, so an operator can debug through the same endpoints. Records from `POST /scans` land in both the response body and the server-configured sink on the same pipeline pass (see [POST /scans](#post-scans) below).

Kubernetes example (Helm values):

```yaml
sink:
  config:
    type: kafka
    brokers: ["kafka.observability.svc:9092"]
    topic: rastreo.discovery.records.v1
  probeIntervalSeconds: 10
  probeTimeoutSeconds: 5
```

The chart renders a ConfigMap with the sink YAML, mounts it at `/etc/rastreo/sink/sink.yaml`, and sets `RASTREO_SINK_CONFIG_PATH` on the container. Leave `sink.config` empty (default) to run the server without a probe.

`GET /health` is preserved as a backward-compat alias for `/healthz`. New deployments should point liveness at `/healthz` and readiness at `/readyz`.

## GET /metrics

`GET /metrics` returns operational signals in Prometheus text format (`text/plain; version=0.0.4`). Point a Prometheus Operator `ServiceMonitor` at it, scrape it directly with `prometheus.yml`, or pull it manually with `curl` for ad-hoc inspection. The endpoint is unauthenticated; gate access at the network or ingress layer if needed.

```bash
curl -sS http://localhost:8080/metrics | head
```

Metrics exposed:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `rastreo_server_scans_total` | counter | `outcome="success"\|"error"\|"cancelled"` | `POST /scans` requests served, partitioned by outcome. Validation rejections (`400`) count as `error`. A scan dropped by the request timeout counts as `cancelled` (see the note below). |
| `rastreo_server_probes_total` | counter | `outcome="success"\|"error"` | Probes executed across all scans. `success` is computed as `attempted - errored` and covers every probe that ran, including probes whose target stayed silent. `error` counts probe faults only. See [Observability · what `outcome` means](../reference/observability.md#what-outcome-means). |
| `rastreo_server_records_emitted_total` | counter | — | `DeviceRecord` events emitted across all scans. |
| `rastreo_server_sink_errors_total` | counter | — | Sink errors surfaced via `POST /scans` (the `RastreoError::Sink` variant). |
| `rastreo_server_scan_duration_seconds` | histogram | — | `POST /scans` request handling duration. Buckets: `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, +Inf`. |
| `rastreo_server_sink_reachability_probe_total` | counter | `outcome`, `sink_type` | Server-side sink reachability probes. Emitted only when `RASTREO_SINK_CONFIG_PATH` is set. |
| `rastreo_server_sink_reachable` | gauge | `sink_type` | `1` when the last sink probe succeeded, `0` otherwise. Emitted only when `RASTREO_SINK_CONFIG_PATH` is set. |
| `rastreo_server_uptime_seconds` | gauge | — | Seconds since the server process started. |
| `rastreo_server_build_info` | gauge | `version` | Static `1`; the `version` label carries the binary's `CARGO_PKG_VERSION`. |

All counters are monotonic across the server process's lifetime and reset only on restart. The histogram observes the same elapsed time the handler measures from the moment the request body is parsed to the moment the response is built.

!!! note "A rising `cancelled` count means scans are exceeding the request timeout"
    `rastreo_server_scans_total{outcome="cancelled"}` counts scans dropped by `--request-timeout-ms`, not a server fault. The dropped scan's in-flight probes are stopped, so an abandoned scan cannot keep probing in the background. A `cancelled` scan does not trigger the `/readyz` scan-error quarantine — a client-side timeout is not a server error. If this count climbs, size scans to fit the timeout or raise `--request-timeout-ms`.

## POST /scans

`POST /scans` submits a discovery scenario, runs it synchronously, and returns the summary and records in the response body. The request body is a `DiscoverScenarioConfig` JSON object. The required fields are `targets` (a non-empty list of targets) and `probers` (a non-empty list of prober configurations). Optional fields on the embedded `base` include `max_concurrent`, `probe_rate`, `timeout_ms`, `fuser`, and `name`. The `encoder` and `sink` fields are accepted but ignored — the server forces NDJSON encoding and captures records in memory so it can return them in the response.

To preview what a scan would do without probing anything, add the `?dry_run=true` query parameter. The server resolves the targets and returns a discovery plan instead of running the scan. See [Preview a scenario with a dry-run](#preview-a-scenario-with-a-dry-run).

When authentication is enabled (the default), the request must carry a bearer token or it returns `401`. See [Authentication](#authentication) for the header shape and the 401 response.

When `RASTREO_MAX_INFLIGHT_SCANS` real scans are already running, a new `POST /scans` is rejected with `429 Too Many Requests` instead of being queued. The same cap also makes `/readyz` return `503`, so it both marks the pod not-ready and refuses new scans. A dry-run does not count against the cap and is never rejected. Set `RASTREO_MAX_INFLIGHT_SCANS=0` to disable the cap. See [GET /readyz](#get-healthz-and-get-readyz) for the readiness gate.

When `RASTREO_SINK_CONFIG_PATH` is set, each record is fanned out to both the in-memory capture and the server-configured sink on the same pipeline pass. The response body remains identical to the unconfigured case; the server-configured sink additionally receives every record. A write error from the server-configured sink aborts the scan and returns 500 — the response body's `records` list is not returned even if the in-memory capture succeeded. When `RASTREO_SINK_CONFIG_PATH` is unset, the response body is the only destination and behavior is identical to earlier releases.

```bash
curl -sS -X POST http://localhost:8080/scans \
  -H "Authorization: Bearer $RASTREO_API_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "targets": [{"Ip": "10.50.0.10"}],
    "probers": [{"type": "tcp_connect", "ports": [80]}]
  }'
```

The response is `{summary, records, truncated}`, plus an optional `hint` when a probe faulted. `summary` carries the counters and the elapsed time. `records` is the list of `DeviceRecord` events the scan produced. `truncated` is a boolean and is always present. It is `true` when `RASTREO_MAX_RESULT_BYTES` capped the response, so `records` holds only a subset. A clean, uncapped scan returns `truncated: false` and omits `hint`. See [Bounded response size](#bounded-response-size) and [The hint field](#the-hint-field) below.

```json
{
  "summary": {
    "targets_resolved": 1,
    "probe_attempts": 1,
    "records_emitted": 1,
    "links_emitted": 0,
    "profiles_emitted": 0,
    "probes_by_kind": [
      { "kind": "TcpConnect", "attempted": 1, "errored": 0 }
    ],
    "dlq_records": 0,
    "sink_type": "tee",
    "cancelled": false,
    "elapsed_ms": 0
  },
  "records": [
    {
      "identity_key": "ip:10.50.0.10",
      "mgmt_ip": "10.50.0.10",
      "mac": null,
      "manufacturer": null,
      "platform": null,
      "role": null,
      "confidence": 0.2,
      "last_seen": "2026-07-05T13:47:22.678133082Z",
      "signals": [ { "OpenPort": 80 } ]
    }
  ],
  "truncated": false
}
```

The summary fields:

| Field | Meaning |
|---|---|
| `targets_resolved` | Addresses the scan probed after CIDR, range, and DNS expansion. |
| `probe_attempts` | Probes started: `targets_resolved` × number of probers. |
| `error_counts` | Faulted probes tallied by fault kind, as a JSON object — for example `{"decode_failed": 1}`. A kind appears only when it happened at least once, so a scan with no faults omits the field. A target that stays silent is a normal result, not a fault. See [Reachable, unreachable, and probe faults](../probe/index.md#reachable-unreachable-and-probe-faults). |
| `records_emitted` | `DeviceRecord` events produced. By default only targets that at least one prober reached produce a record. |
| `links_emitted` | Topology link records produced by the [LLDP prober](../probe/lldp.md). Always present; `0` when no LLDP neighbors were found. See [Topology](../discover/topology.md). |
| `profiles_emitted` | Collection profile records produced for gNMI endpoints that answered Capabilities. Always present; `0` when no gNMI capability data was collected. See [Collection profiles](../discover/collection-profile.md). |
| `probes_by_kind` | Per-prober `attempted` / `errored` breakdown. Omitted when no probes ran. |
| `first_probe_error` | The first probe fault, as an object with a `kind` field (the fault kind) and a `detail` field (a sample detail string). Omitted when no probe faulted. |
| `dlq_records` | Records the sink diverted to a dead-letter destination. |
| `sink_type` | Sink the scan wrote to. Always `tee` on `POST /scans`: the server writes every record to the in-memory buffer it returns in the response, and to the server-configured sink when `RASTREO_SINK_CONFIG_PATH` is set. |
| `cancelled` | `true` when the scan stopped early; the counters then reflect partial progress. |
| `elapsed_ms` | Wall-clock duration of the scan. |

When a probe faults, `error_counts` tallies it by kind and `first_probe_error` names the first one. The fault kinds you will see are `decode_failed`, `permission_denied`, `dns_failed`, and `other`; the [reachability reference](../probe/index.md#reachable-unreachable-and-probe-faults) explains each. A probe faults only when the probe itself broke — a silent target is not a fault. One case keeps the device anyway: a target that answers with a reply rastreo cannot decode. The classic case is an SNMP agent speaking a dialect rastreo does not parse. The device answered, so it is reachable. It still produces a record with no signals, and the fault is counted as `decode_failed`:

```json
{
  "summary": {
    "targets_resolved": 1,
    "probe_attempts": 1,
    "records_emitted": 1,
    "links_emitted": 0,
    "profiles_emitted": 0,
    "error_counts": { "decode_failed": 1 },
    "probes_by_kind": [
      { "kind": "Snmp", "attempted": 1, "errored": 1 }
    ],
    "dlq_records": 0,
    "sink_type": "tee",
    "cancelled": false,
    "first_probe_error": { "kind": "decode_failed", "detail": "snmp reply could not be decoded" },
    "elapsed_ms": 0
  },
  "records": [
    {
      "identity_key": "ip:10.50.0.10",
      "mgmt_ip": "10.50.0.10",
      "confidence": 0.1,
      "signals": [],
      "probe_kinds": ["Snmp"]
    }
  ],
  "truncated": false,
  "hint": "the target answered with a reply the prober could not parse — check the protocol, credentials, and the service on the port"
}
```

### The hint field

When a probe faults with a kind that has a specific remedy, the response adds a top-level `hint` field with one line of guidance. The server derives the hint from the fault kind in `first_probe_error`, so the same fault always gives the same advice. A clean scan omits the field. So does a fault kind with no specific action (`other`).

You will see a hint for the faults that carry a clear next step. A `decode_failed` fault suggests checking the protocol, credentials, and the service on the port. A `permission_denied` fault points at granting `CAP_NET_RAW` or checking local egress policy. A `dns_failed` fault points at the resolver configuration and DNS reachability. The exact wording is guidance text and may change between releases — read it, do not match on it.

The field-by-field meaning of a `DeviceRecord` is covered in [First scan](../get-started/first-scan.md#read-the-output).

### Progress in the logs

`POST /scans` runs to completion before it responds, so a long scan gives the caller nothing until the end. To follow a scan while it runs, read the server log. About every five seconds the server writes a `scan progress` line for each running scan:

```text
INFO rastreo_server::routes::scans: scan progress scenario=unnamed targets_completed=16 targets_total=30 records=0
```

The line carries these fields:

- `scenario` — the request's `name`, or `unnamed` when the request omits it.
- `targets_completed` — targets finished so far.
- `targets_total` — total targets to probe.
- `records` — `DeviceRecord` events emitted so far.

Logging stops when the scan finishes.

!!! note "Mid-scan progress is in the logs, not the response"
    Because `POST /scans` is synchronous, progress is not a response field and there is no progress endpoint. The response returns once, at the end, with the full summary and records. To follow a running scan, read the `scan progress` log lines above.

### Bounded response size

The server holds the whole response in memory before sending it. A very large scan could then exhaust the server's memory. To prevent this, the response is capped at `RASTREO_MAX_RESULT_BYTES` bytes of records. The default is `33554432` (32 MiB).

A scan that produces more records than the cap still completes and returns `200 OK`. The response then carries only the records that fit under the cap. Two fields tell the client it received a subset:

- `truncated` is `true`.
- `summary.records_emitted` stays the true total. The cap never changes it.

So the client always knows it received N of M records. `records` holds N. `records_emitted` is M.

The example below used a deliberately tiny cap, so the single record did not fit. The scan still completed and still reported the true total:

```json
{
  "summary": {
    "targets_resolved": 1,
    "probe_attempts": 1,
    "records_emitted": 1,
    "links_emitted": 0,
    "profiles_emitted": 0,
    "probes_by_kind": [
      { "kind": "TcpConnect", "attempted": 1, "errored": 0 }
    ],
    "dlq_records": 0,
    "sink_type": "tee",
    "cancelled": false,
    "elapsed_ms": 1
  },
  "records": [],
  "truncated": true
}
```

With the default 32 MiB cap, a truncated response still carries thousands of records — just fewer than `records_emitted`.

!!! note "A server-configured sink still receives every record"
    The cap applies only to the response body. When `RASTREO_SINK_CONFIG_PATH` is set, the server-configured sink receives every record, even when the response truncates. To get the full result of a large scan, configure a server-side sink and read the records there. Or narrow the scan's scope so the result fits under the cap.

!!! warning "Raise the memory limit before raising the cap"
    Peak memory at response time is roughly 3× the cap. The record buffer, the parsed records, and the serialized JSON body all exist at once. The 32 MiB default fits under the chart's `limits.memory` of `256Mi`. If you raise `RASTREO_MAX_RESULT_BYTES`, raise `limits.memory` by the same proportion.

Error surfaces:

| Status | When                                                                                                         |
|--------|--------------------------------------------------------------------------------------------------------------|
| `401`  | Authentication is enabled and the request carried a missing, malformed, or wrong bearer token. Checked before the scan runs. See [Authentication](#authentication). |
| `403`  | The target allow-list is set and a resolved target falls outside every allowed network. The whole request is rejected and nothing is probed. See [Restricting scan targets](#restricting-scan-targets). |
| `413`  | The request body exceeded `RASTREO_MAX_BODY_BYTES`. Rejected before the JSON body is parsed. See [Restricting scan targets](#restricting-scan-targets). |
| `429`  | `RASTREO_MAX_INFLIGHT_SCANS` real scans are already running. The body is `{"error":"inflight scan limit reached; retry once running scans complete"}`. A dry-run never counts against the cap and is never rejected. Setting the cap to `0` disables it. See [POST /scans](#post-scans). |
| `400`  | `scenario.targets` empty, `scenario.probers` empty, malformed JSON body, the request exceeded `RASTREO_MAX_TOTAL_HOSTS`, or a client-side resolver error (`CidrTooLarge`, `RangeTooLarge`, `InvalidRange`, `MixedFamilyRange`, `DnsNoRecords`). |
| `500`  | Internal probe / encoder / sink / runtime error. The response body carries `{"error":"internal server error"}` — full detail is logged for operators, not returned to the client. |
| `503`  | DNS infrastructure failure (`ResolverError::DnsLookupFailed`) or the request exceeded `--request-timeout-ms`. A timed-out scan has its in-flight probes stopped and is counted as `rastreo_server_scans_total{outcome="cancelled"}`. |

The response body is JSON in all cases: `{"error": "<message>"}` for 4xx and 5xx.

### Preview a scenario with a dry-run

Before a scan probes anything, you can preview exactly what it would do. Add `?dry_run=true` to the request. The server resolves every target and returns a discovery plan with HTTP 200. A dry-run runs no probers and writes to no sink.

Use a dry-run to validate a scenario before it probes the network:

- Confirm each target resolves to the addresses you expect.
- See how many probes the scan would start.
- Check the sink the scan would write to, with any inline credentials removed.

!!! note "A dry-run does not probe or write to a sink"
    A dry-run only resolves targets and builds the plan. It still requires a bearer token when authentication is enabled, and it still routes through the target allow-list.

```bash
curl -sS -X POST "http://localhost:8080/scans?dry_run=true" \
  -H "Authorization: Bearer $RASTREO_API_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name": "mgmt-sweep",
    "targets": [{"Ip": "10.50.0.10"}],
    "probers": [{"type": "tcp_connect", "ports": [22, 443]}]
  }'
```

The response is a `DiscoveryPlan`. Its fields are:

- `scenario` — the scenario name, or `unnamed` when the request omits `name`.
- `targets` — one entry per target you sent, each with the original `target` spec and a `resolution`.
- `resolution` — `resolved` with the list of IP addresses when the target resolves, or `error` with the reason when it fails to resolve or is blocked.
- `probers` — a readable summary of each prober the scan would run.
- `sink` — the destination the scan would write to.
- `max_concurrent` — the most probes the scan would run at once.
- `probe_rate` — the probes-per-second pace, or `null` for unlimited.
- `retries` — the retransmit count for connectionless probers.
- `timeout_ms` — the per-probe timeout in milliseconds.
- `total_probes` — unique resolved addresses across all targets, multiplied by the number of probers.

```json
{
  "scenario": "mgmt-sweep",
  "targets": [
    { "target": "10.50.0.10", "resolution": { "resolved": ["10.50.0.10"] } }
  ],
  "probers": ["tcp_connect (ports 22, 443)"],
  "sink": "stdout (default)",
  "max_concurrent": 64,
  "probe_rate": null,
  "retries": 0,
  "timeout_ms": 1000,
  "total_probes": 1
}
```

!!! tip "Safe to log or share"
    The plan strips inline credentials from a sink URL. A NATS server URL written as `nats://user:pass@host` renders as `nats://host` in the plan.

A real scan rejects an out-of-allow-list target with a hard `403` and probes nothing. A dry-run is more informative. It resolves what it can and reports the blocked target in the plan. The blocked target carries an `error` in its `resolution`, and it does not add to `total_probes`.

```json
{
  "scenario": "mgmt-sweep",
  "targets": [
    { "target": "192.168.1.1", "resolution": { "error": "target 192.168.1.1 is outside the configured allow-list" } }
  ],
  "probers": ["tcp_connect (ports 22, 443)"],
  "sink": "stdout (default)",
  "max_concurrent": 64,
  "probe_rate": null,
  "retries": 0,
  "timeout_ms": 1000,
  "total_probes": 0
}
```

The plan is described field by field in the [DiscoveryPlan schema reference](../reference/schema/discovery-plan.md).

## Server vs CLI

| Use the CLI when…                              | Use the server when…                                                |
|------------------------------------------------|---------------------------------------------------------------------|
| You want a one-shot scan from a laptop or CI. | A service needs to trigger scans on demand.                         |
| You want records on stdout, a file, or Kafka. | You want records returned in the response body to the caller.       |
| Output goes through shell pipelines (`jq`).    | Output is consumed by another system over HTTP.                     |
| Scans run from a developer machine.            | Scans run from a long-lived pod and need a liveness probe.          |

The two surfaces share `rastreo-core`, so the discovery behaviour is identical. The choice is operational, not functional.

## See also

- [Kubernetes](kubernetes.md) — install `rastreo-server` on a cluster via the Helm chart.
- [CLI](../discover/cli.md) — every flag the CLI accepts, for the one-shot scan path.
