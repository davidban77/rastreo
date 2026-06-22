---
description: The rastreo-server HTTP control plane — routes, request and response shape for /scans, request-timeout configuration, and when to choose the server over the CLI.
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

The request timeout is enforced by middleware in front of every route. A request that runs longer than the timeout is aborted and the client sees `503 Service Unavailable`. Large scans against a populated subnet can easily exceed 60 seconds — size the scan to fit the timeout, or raise the timeout to match the workload.

## GET /health

`GET /health` is a liveness probe. It always returns `200 OK` with a static JSON body, and never runs any discovery work. Use it from Kubernetes liveness and readiness probes, from external uptime monitors, or from a quick `curl` to verify the server is up.

```bash
curl -sS http://localhost:8080/health
```

```json
{"status":"ok"}
```

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
      "last_seen": { "secs_since_epoch": 1782167242, "nanos_since_epoch": 678133082 },
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
