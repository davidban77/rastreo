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

| Flag                    | Env var                                | Default | Notes                                                  |
|-------------------------|----------------------------------------|---------|--------------------------------------------------------|
| `--port`                | `RASTREO_SERVER_PORT`                  | `8080`  | TCP port to bind.                                      |
| `--bind`                | `RASTREO_SERVER_BIND`                  | `0.0.0.0` | Bind address.                                        |
| `--request-timeout-ms`  | `RASTREO_SERVER_REQUEST_TIMEOUT_MS`    | `60000` | Per-request timeout in milliseconds. Minimum 1.        |
| —                       | `RASTREO_SINK_CONFIG_PATH`             | unset   | Path to a YAML file with a `SinkConfig`. When set, the server builds the sink at startup and probes it every `RASTREO_SINK_PROBE_INTERVAL_SECS`. Sink construction failure is non-fatal — the pod stays up, `/readyz` reports `sink_unreachable`. |
| —                       | `RASTREO_SINK_PROBE_INTERVAL_SECS`     | `10`    | Sink reachability probe cadence in seconds. Minimum 1. |
| —                       | `RASTREO_SINK_PROBE_TIMEOUT_SECS`      | `5`     | Per-probe timeout in seconds. Probes exceeding this count as failures. Minimum 1. |

The request timeout is enforced by middleware in front of every route. A request that runs longer than the timeout is aborted and the client sees `503 Service Unavailable`. Large scans against a populated subnet can easily exceed 60 seconds — size the scan to fit the timeout, or raise the timeout to match the workload.

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

The probe is proactive: a broker outage flips `sink_reachable` to `false` on the next tick, and `/readyz` returns 503 with `reason: "sink_unreachable"` before any scan-triggered sink write catches the fault. Sink construction failure at startup does not crash the pod — the server stays up with `sink_reachable: false` and a `last_probe_error` string, so an operator can debug through the same endpoints. Records still return in the `POST /scans` response body; the server-configured sink does not currently receive record traffic.

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
| `rastreo_server_scans_total` | counter | `outcome="success"\|"error"\|"cancelled"` | `POST /scans` requests served, partitioned by outcome. Validation rejections (`400`) count as `error`. |
| `rastreo_server_probes_total` | counter | `outcome="success"\|"error"` | Probes executed across all scans. `success` is computed as `attempted - errored`. |
| `rastreo_server_records_emitted_total` | counter | — | `DeviceRecord` events emitted across all scans. |
| `rastreo_server_sink_errors_total` | counter | — | Sink errors surfaced via `POST /scans` (the `RastreoError::Sink` variant). |
| `rastreo_server_scan_duration_seconds` | histogram | — | `POST /scans` request handling duration. Buckets: `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, +Inf`. |
| `rastreo_server_sink_reachability_probe_total` | counter | `outcome`, `sink_type` | Server-side sink reachability probes. Emitted only when `RASTREO_SINK_CONFIG_PATH` is set. |
| `rastreo_server_sink_reachable` | gauge | `sink_type` | `1` when the last sink probe succeeded, `0` otherwise. Emitted only when `RASTREO_SINK_CONFIG_PATH` is set. |
| `rastreo_server_uptime_seconds` | gauge | — | Seconds since the server process started. |
| `rastreo_server_build_info` | gauge | `version` | Static `1`; the `version` label carries the binary's `CARGO_PKG_VERSION`. |

All counters are monotonic across the server process's lifetime and reset only on restart. The histogram observes the same elapsed time the handler measures from the moment the request body is parsed to the moment the response is built.

## POST /scans

`POST /scans` submits a discovery scenario, runs it synchronously, and returns the summary and records in the response body. The request body is a `DiscoverScenarioConfig` JSON object. The required fields are `targets` (a non-empty list of targets) and `probers` (a non-empty list of prober configurations). Optional fields on the embedded `base` include `rate_limit`, `timeout_ms`, `fuser`, and `name`. The `encoder` and `sink` fields are accepted but ignored — the server forces NDJSON encoding and captures records in memory so it can return them in the response.

```bash
curl -sS -X POST http://localhost:8080/scans \
  -H 'content-type: application/json' \
  -d '{
    "targets": [{"Ip": "10.50.0.10"}],
    "probers": [{"type": "tcp_connect", "ports": [80]}]
  }'
```

The response is `{summary, records}`. `summary` is a `DiscoverySummary` with counters and elapsed time; `records` is the list of `DeviceRecord` events produced by the scan.

```json
{
  "summary": {
    "targets_resolved": 1,
    "probe_attempts": 1,
    "probe_errors": 0,
    "records_emitted": 1,
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
  ]
}
```

The field-by-field meaning of a `DeviceRecord` is covered in [First scan](../get-started/first-scan.md#read-the-output).

Error surfaces:

| Status | When                                                                                                         |
|--------|--------------------------------------------------------------------------------------------------------------|
| `400`  | `scenario.targets` empty, `scenario.probers` empty, malformed JSON body, or a client-side resolver error (`CidrTooLarge`, `RangeTooLarge`, `InvalidRange`, `MixedFamilyRange`, `DnsNoRecords`). |
| `500`  | Internal probe / encoder / sink / runtime error. The response body carries `{"error":"internal server error"}` — full detail is logged for operators, not returned to the client. |
| `503`  | DNS infrastructure failure (`ResolverError::DnsLookupFailed`) or the request exceeded `--request-timeout-ms`. |

The response body is JSON in all cases: `{"error": "<message>"}` for 4xx and 5xx.

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
