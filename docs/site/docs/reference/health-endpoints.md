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

`GET /readyz` reports whether the server can actually accept a new scan. Three gates can flip readiness to `not_ready`:

- **Inflight scan limit** — the number of in-flight `POST /scans` requests has reached `RASTREO_MAX_INFLIGHT_SCANS`. New scans would compete with running ones for CPU, sockets, and memory. Kubernetes removes the pod from Service endpoints until this drops.
- **Recent sink error** — a scan failed in the last `RASTREO_SINK_ERROR_QUARANTINE_SECS` because the downstream sink (Kafka, file, HTTP) errored. Assumes the sink is still misbehaving; quarantines the pod until the window elapses.
- **Recent scan error** — a scan failed in the last `RASTREO_SCAN_ERROR_QUARANTINE_SECS` for any reason (not necessarily a sink failure). Coarser check that catches persistent probe / runtime issues.

If any gate has fired, the response is `503 SERVICE_UNAVAILABLE`. Otherwise it is `200 OK`.

### Ready response

```bash
curl -sS http://localhost:8080/readyz
```

```json
{
  "status": "ready",
  "inflight_scans": 0,
  "max_inflight_scans": 100,
  "seconds_since_sink_error": null,
  "seconds_since_scan_error": null
}
```

`seconds_since_*_error` is `null` when no such error has been observed since the process started, and a fractional-seconds `f64` otherwise.

### Not-ready response

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://localhost:8080/readyz
# 503
```

```json
{
  "status": "not_ready",
  "reason": "inflight_scan_limit_exceeded",
  "inflight_scans": 100,
  "max_inflight_scans": 100,
  "seconds_since_sink_error": null,
  "seconds_since_scan_error": null
}
```

### `reason` values

| `reason` | Meaning |
|---|---|
| `inflight_scan_limit_exceeded` | `inflight_scans >= max_inflight_scans`. New scans are rejected upstream by the readiness probe pulling the pod out of the Service. |
| `sink_error_within_quarantine` | A sink error was observed less than `RASTREO_SINK_ERROR_QUARANTINE_SECS` ago. |
| `scan_error_within_quarantine` | A scan error was observed less than `RASTREO_SCAN_ERROR_QUARANTINE_SECS` ago (and no sink error is currently quarantining). |

When more than one gate fires simultaneously, the priority order is `inflight > sink > scan` — the most severe / most actionable reason is reported.

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

The three gates are tuned through environment variables read at server startup. Invalid (non-numeric or non-UTF-8) values cause the server to fail fast at startup with a clear error naming the variable.

| Env var | Default | Behavior |
|---|---|---|
| `RASTREO_MAX_INFLIGHT_SCANS` | `100` | Inflight `POST /scans` counter above which `/readyz` returns `503`. Set to `0` to disable the check. |
| `RASTREO_SINK_ERROR_QUARANTINE_SECS` | `30` | Window after any sink error during which `/readyz` returns `503`. Set to `0` to disable the check. |
| `RASTREO_SCAN_ERROR_QUARANTINE_SECS` | `30` | Window after any scan error during which `/readyz` returns `503`. Set to `0` to disable the check. |

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
