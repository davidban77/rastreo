---
description: The rastreo-server health and readiness endpoints — /healthz for Kubernetes liveness, /readyz for readiness with inflight-scan and error-quarantine gating, plus the /health backward-compat alias.
---

# Health endpoints

`rastreo-server` exposes three health-related endpoints. `/healthz` is a liveness probe: it always returns `200 OK` unless the process is fundamentally broken. `/readyz` is a readiness probe: it returns `200 OK` only when the server can accept new work, and `503 SERVICE_UNAVAILABLE` when a gate has fired. `/health` is preserved as a backward-compat alias for `/healthz` so existing manifests and scripts keep working.

## `/healthz` — liveness

`GET /healthz` always returns `200 OK` with a static JSON body. If the handler runs at all, the process is alive; Kubernetes' liveness probe uses this signal to decide whether to restart the pod.

```bash
curl -sS http://localhost:8080/healthz
```

```json
{"status":"ok"}
```

Kubernetes liveness-probe snippet:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: http
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
```

## `/readyz` — readiness

`GET /readyz` reports whether the server can actually accept a new scan. Five gates can flip readiness to `not_ready`:

- **Inflight scan limit** — the number of in-flight `POST /scans` requests has reached `RASTREO_MAX_INFLIGHT_SCANS`. New scans would compete with running ones for CPU, sockets, and memory. Kubernetes removes the pod from Service endpoints until this drops.
- **Sink probe stalled** — the background probe task has not started a cycle recently enough for the server to stand behind the reachability verdict it is holding. Only active when `RASTREO_SINK_CONFIG_PATH` is set, and only once the task has run at least one cycle. See [When the probe task stops ticking](#when-the-probe-task-stops-ticking).
- **Sink unreachable** — the server-side reachability probe reported the sink as unreachable on its last tick, or the sink has not built yet. Proactive gate: fires before the sink-error quarantine, because a probe failure indicates downstream ingest is offline right now. Only active when `RASTREO_SINK_CONFIG_PATH` is set. A sink that failed to build is rebuilt on every tick, so this gate clears by itself once the sink builds and probes clean.
- **Recent sink error** — a scan failed in the last `RASTREO_SINK_ERROR_QUARANTINE_SECS` because the downstream sink (Kafka, NATS, file) errored. Reactive gate: catches transient errors between probe ticks; assumes the sink is still misbehaving until the window elapses.
- **Recent scan error** — a `POST /scans` request failed in the last `RASTREO_SCAN_ERROR_QUARANTINE_SECS` for any reason (not necessarily a sink failure). Coarser check that catches an invalid scenario body, a resolver failure, or a runtime failure.

If any gate has fired, the response is `503 SERVICE_UNAVAILABLE`. Otherwise it is `200 OK`.

!!! info "Probe results never gate readiness"
    A scan that reaches no device still succeeds — the server returns `200 OK` with an empty `records` list, and readiness is unaffected. A probe fault does not fail the scan either: the pipeline counts it in the summary (`error_counts`) and moves on. Watch `rastreo_server_probes_total{outcome="error"}` for probe faults, not `/readyz`. See [Observability · what `outcome` means](observability.md#what-outcome-means).

### Ready response

```bash
curl -sS http://localhost:8080/readyz | jq
```

```json
{
  "inflight_scans": 0,
  "last_probe_error": null,
  "max_inflight_scans": 100,
  "seconds_since_last_probe": null,
  "seconds_since_last_probe_tick": null,
  "seconds_since_scan_error": null,
  "seconds_since_sink_error": null,
  "sink_attached": null,
  "sink_reachable": null,
  "sink_type": null,
  "status": "ready"
}
```

`seconds_since_*_error` is `null` when no such error has been observed since the process started, and a fractional-seconds `f64` otherwise. `sink_reachable` is `null` when `RASTREO_SINK_CONFIG_PATH` is unset (no sink configured — this axis does not gate readiness); `true` after the last probe succeeded; `false` after the last probe failed or after the last sink build attempt failed. `sink_attached` is `null` on the same condition, and otherwise says whether the configured sink has been built and handed to the running server — see [Attached or not attached](#attached-or-not-attached) for why that is a different question from `sink_reachable`. `sink_type` carries the sink kind label (`kafka`, `nats`, `stdout`, `file`, `memory`) when a sink is configured. It reads `"unknown"` only while the config file cannot be read or parsed (missing file, malformed YAML, unknown `type:`); once the file parses, the label is the kind it names, whether or not the sink has built — a valid Kafka config whose broker is down reports `sink_type: "kafka"` with `sink_reachable: false`. `seconds_since_last_probe` reports the age of the cached probe result, and `seconds_since_last_probe_tick` the age of the last cycle the probe task started, whether or not that cycle produced a result — the two differ whenever a tick skipped its probe, and `seconds_since_last_probe_tick` is the one readiness gates on. Both are `null` until the corresponding event has happened for the first time. `last_probe_error` carries the last failure message verbatim (or `null` after a success). Every `seconds_since_*` value is elapsed time measured on the monotonic clock, so an NTP correction on the node never moves one — and never flips a quarantine or the staleness gate across a fleet at once.

The probe is a round-trip to the destination, so it only tells you something for a sink that has one. A `stdout`, `file` or `memory` sink reports `sink_reachable: true` for as long as the process runs — a full disk or a closed pipe does not move it. What catches a write that actually failed is `sink_error_within_quarantine`, which is set from the scan path rather than the probe.

### Not-ready response

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://localhost:8080/readyz
# 503
```

A scan in flight on a server with no sink configured and `RASTREO_MAX_INFLIGHT_SCANS=1`:

```json
{
  "inflight_scans": 1,
  "last_probe_error": null,
  "max_inflight_scans": 1,
  "reason": "inflight_scan_limit_exceeded",
  "seconds_since_last_probe": null,
  "seconds_since_last_probe_tick": null,
  "seconds_since_scan_error": null,
  "seconds_since_sink_error": null,
  "sink_attached": null,
  "sink_reachable": null,
  "sink_type": null,
  "status": "not_ready"
}
```

The not-ready body carries every field the ready body does, plus `reason`.

### `reason` values

| `reason` | Meaning |
|---|---|
| `inflight_scan_limit_exceeded` | `inflight_scans >= max_inflight_scans`. New scans are rejected upstream by the readiness probe pulling the pod out of the Service. |
| `sink_probe_stalled` | The sink reachability probe task has not started a cycle within the staleness window, so the cached `sink_reachable` value is no longer a verdict the server stands behind. The sink itself may be perfectly healthy. Only fires when `RASTREO_SINK_CONFIG_PATH` is set. See [When the probe task stops ticking](#when-the-probe-task-stops-ticking). |
| `sink_unreachable` | The server-side sink reachability probe reported the sink as unreachable on its last tick, or the sink has not built yet and the last build attempt failed. Only fires when `RASTREO_SINK_CONFIG_PATH` is set. |
| `sink_error_within_quarantine` | A sink error was observed less than `RASTREO_SINK_ERROR_QUARANTINE_SECS` ago. |
| `scan_error_within_quarantine` | A scan error was observed less than `RASTREO_SCAN_ERROR_QUARANTINE_SECS` ago (and no sink error is currently quarantining). |

When more than one gate fires simultaneously, the priority order is `inflight > sink_probe_stalled > sink_unreachable > sink_error_within_quarantine > scan_error_within_quarantine` — the most severe / most actionable reason is reported. `sink_probe_stalled` outranks `sink_unreachable` because a stalled task means the reachability value behind `sink_unreachable` is stale: reporting a broker outage from a verdict nobody refreshed would send you to the wrong system.

### Attached or not attached

`sink_reachable: false` covers two situations that need different responses, and `sink_attached` is what separates them.

| `sink_attached` | `sink_reachable` | What is happening | What to do |
|---|---|---|---|
| `false` | `false` | The configured sink never built. The server is up and scans run, but they write only to the `POST /scans` response body — nothing reaches the configured destination. | Read `last_probe_error`. It names the failure: an unreadable config file, a malformed document, an unset `${VAR}`, a broker that would not accept a connection during construction. The server retries the build every probe interval, so a corrected ConfigMap or a late-mounted `!file` secret clears it without a restart. An unset `${VAR}` is the exception: a process reads its environment as it was at start, so that one needs a restart once the Secret is in place. |
| `true` | `false` | The sink built and is held by the server, so scans do write to the configured destination. Its last probe failed, so the destination is not answering right now. | Look downstream: the broker is refusing connections, unreachable, or rejecting credentials. `last_probe_error` carries the message the client returned. |
| `true` | `true` | Normal operation. | — |

`sink_attached` is `null` exactly when `sink_reachable` is `null` — no sink is configured, so neither question applies.

A built sink is held for the process lifetime, so `sink_attached` only ever goes from `false` to `true`.

### When the probe task stops ticking

`/readyz` serves the cached result of the last sink probe. That cache is only worth serving while something keeps refreshing it, so the server also records when the probe task last *started* a cycle, and returns 503 with `reason: "sink_probe_stalled"` when that stamp gets too old. The pod leaves the Service rather than advertising a verdict nothing is standing behind.

The staleness window is derived from the two probe knobs you already set, not configured separately: `3 × (RASTREO_SINK_PROBE_INTERVAL_SECS + 3 × RASTREO_SINK_PROBE_TIMEOUT_SECS)`, which is **75 seconds** on the defaults of 10s and 5s. The inner term covers the work one cycle can legitimately do — a probe timeout each for rebuilding the sink, waiting for the sink lock, and running the probe, plus up to one interval before the next cycle starts — so the window leaves 3× headroom over a slow but healthy server. Two states are deliberately never gated: a server with no sink configured, and a server whose probe task has not recorded its first cycle.

```json
{
  "inflight_scans": 0,
  "last_probe_error": "sink construction failed: failed to read sink config at /tmp/rastreo/sink.yaml: No such file or directory (os error 2)",
  "max_inflight_scans": 100,
  "reason": "sink_probe_stalled",
  "seconds_since_last_probe": 18.061,
  "seconds_since_last_probe_tick": 17.062,
  "seconds_since_scan_error": null,
  "seconds_since_sink_error": null,
  "sink_attached": false,
  "sink_reachable": false,
  "sink_type": "unknown",
  "status": "not_ready"
}
```

Three things to check, in order:

- **`sink_attached`.** While it is `false` the sink has never built, so every cycle re-reads the config file and expands any `!file` path it names. Those reads are the one wait in a cycle that `RASTREO_SINK_PROBE_TIMEOUT_SECS` does not bound. A path on a filesystem that stops answering holds the cycle open for as long as the read hangs, so check that the path in `RASTREO_SINK_CONFIG_PATH` still reads.
- **`last_probe_error`.** It holds whatever the last *completed* probe left, and nothing refreshes it while the task is stalled. Read it as history, not as the current fault. It is `null` when the last completed probe succeeded.
- **`rastreo_server_sink_probe_ticks_total` on `/metrics`.** It stops rising on exactly the condition this reason reports, which is how the same state looks from the metrics side. The packaged `RastreoSinkProbeStalled` alert watches it — see [Observability · Sink reachability probe](observability.md#sink-reachability-probe).

Once `sink_attached` is `true` the config file is never read again, and every wait a cycle makes is bounded by the probe timeout. A stall from there points at the server process rather than at the sink or its config. Restart the pod, and keep the logs from the stalled window.

!!! important "A long scan does not make the pod unready"
    A scan does not hold the sink for its duration. Records reach a server-configured sink through a fan-out that takes the sink lock for one operation — one write, one flush, one close — and releases it on return, so probe ticks land between operations and keep refreshing however long the scan runs. On top of that the staleness gate reads `seconds_since_last_probe_tick`, which the task stamps on every cycle whether or not it probed, so a scan that keeps the sink continuously busy still keeps the pod ready.

    A tick skips its probe when it cannot take the lock within `RASTREO_SINK_PROBE_TIMEOUT_SECS`. That needs a **single** sink operation to run longer than one probe timeout: a slow broker round-trip, a large flush, a close against a stalled connection. So `seconds_since_last_probe` running ahead of a `seconds_since_last_probe_tick` that keeps resetting is a signal about the downstream, not about how busy the server is. It is also one `sink_unreachable` never raises, because the probe is being skipped rather than failing. Count the cycles that produced no result off `/metrics`: `rastreo_server_sink_probe_ticks_total` minus the two `rastreo_server_sink_reachability_probe_total` series. Then go look at the sink's own latency.

    Do not read either age as rising or falling. Both count up between ticks and reset when the next one lands, on a healthy server as much as on a broken one. Size is what tells them apart. A `seconds_since_last_probe_tick` approaching the staleness window is the task itself stopping, and once it crosses, `/readyz` says so with `sink_probe_stalled`.

Kubernetes readiness-probe snippet:

```yaml
readinessProbe:
  httpGet:
    path: /readyz
    port: http
  initialDelaySeconds: 2
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
```

## `/health` — backward-compat alias

`GET /health` returns the same body as `/healthz` and is preserved so pre-split manifests and monitoring scripts keep working. New deployments should point at `/healthz` (liveness) and `/readyz` (readiness) instead.

```bash
curl -sS http://localhost:8080/health
```

```json
{"status":"ok"}
```

## Configuration

The gates are tuned through environment variables read at server startup. The staleness window behind `sink_probe_stalled` has no variable of its own — it derives from the two probe knobs below. Invalid (non-numeric or non-UTF-8) values cause the server to fail fast at startup with a clear error naming the variable.

| Env var | Default | Behavior |
|---|---|---|
| `RASTREO_MAX_INFLIGHT_SCANS` | `100` | Inflight `POST /scans` counter above which `/readyz` returns `503`. Set to `0` to disable the check. |
| `RASTREO_SINK_ERROR_QUARANTINE_SECS` | `30` | Window after any sink error during which `/readyz` returns `503`. Set to `0` to disable the check. |
| `RASTREO_SCAN_ERROR_QUARANTINE_SECS` | `30` | Window after any scan error during which `/readyz` returns `503`. Set to `0` to disable the check. |
| `RASTREO_SINK_CONFIG_PATH` | unset | Path to a `SinkConfig` YAML file the server builds and probes. Leave unset to disable the reachability probe; `/readyz` reports `sink_reachable: null` and does not gate on this axis. |
| `RASTREO_SINK_PROBE_INTERVAL_SECS` | `10` | Sink reachability probe cadence in seconds, and the retry cadence for a sink that has not built yet. Only meaningful when `RASTREO_SINK_CONFIG_PATH` is set. Minimum 1. |
| `RASTREO_SINK_PROBE_TIMEOUT_SECS` | `5` | Per-probe timeout in seconds. Probes exceeding this count as failures. Minimum 1. |

## Kubernetes deployment fragment

A realistic Deployment stanza wiring both probes at the correct paths:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rastreo
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: rastreo-server
          image: ghcr.io/davidban77/rastreo:<TAG>
          env:
            - name: RASTREO_MAX_INFLIGHT_SCANS
              value: "100"
            - name: RASTREO_SINK_ERROR_QUARANTINE_SECS
              value: "30"
            - name: RASTREO_SCAN_ERROR_QUARANTINE_SECS
              value: "30"
          ports:
            - name: http
              containerPort: 8080
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /readyz
              port: http
            initialDelaySeconds: 2
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 3
```

The bundled Helm chart wires both probes at `/healthz` and `/readyz` out of the box — see [Kubernetes](../deploy/kubernetes.md).

## See also

- [rastreo-server](../deploy/server.md) — the full server surface: `/scans`, `/metrics`, request-timeout tuning.
- [Kubernetes](../deploy/kubernetes.md) — installing the Helm chart with the split probes.
