# rastreo-server — HTTP Control Plane

This is the binary crate for the HTTP REST API. It allows discovery scenarios to be started, inspected, and stopped over HTTP — enabling integration into CI pipelines, lab automation, and dashboards.

## Design Principle

The API mirrors the CLI. Every endpoint corresponds to an operation that is also doable from the command line. If a discovery can not be expressed in YAML, it can not be run via the API. This keeps the two surfaces in sync and prevents behavior drift.

No business logic lives in this crate. All scenario validation and launch logic is delegated to `rastreo-core`. The server crate is pure HTTP plumbing.

## Module Layout

```
src/
├── main.rs        ← entrypoint: clap arg parsing, tracing init, resolver
│                    construction, tokio runtime, axum serve loop
├── lib.rs         ← build_app(state) -> Router; reusable from tests
├── state.rs       ← AppState { resolver, metrics, readiness, sink, sink_reachability, auth, max_body_bytes, max_result_bytes }
│                    + HistogramShard + Metrics + ReadinessConfig + ReadinessState
│                    + SinkProbeConfig + SinkSlot + SinkReachability + AuthConfig + TargetGuardConfig
├── sink_probe.rs  ← spawn_sink_probe + periodic probe/retry task + run_probe helper
├── observability.rs ← OTLP exporters + instrument callbacks (feature: otlp)
├── error.rs       ← AppError + IntoResponse + RastreoError -> HTTP mapping
└── routes/
    ├── mod.rs     ← route module re-exports
    ├── auth.rs    ← require_bearer middleware (route_layer on /scans only) + ErrorDisclosure
    ├── health.rs  ← GET /health (alias), GET /healthz, GET /readyz
    ├── metrics.rs ← GET /metrics (Prometheus text format)
    └── scans.rs   ← POST /scans handler + ScanResponse + InflightGuard
```

## CLI Flags

| Flag                   | Env var                                | Default     | Description                                |
|------------------------|----------------------------------------|-------------|--------------------------------------------|
| `--port`               | `RASTREO_SERVER_PORT`                  | `8080`      | TCP port to bind                           |
| `--bind`               | `RASTREO_SERVER_BIND`                  | `0.0.0.0`   | Bind address                               |
| `--request-timeout-ms` | `RASTREO_SERVER_REQUEST_TIMEOUT_MS`    | `60000`     | Per-request timeout in ms; must be > 0     |
| `--log-format`         | `RASTREO_LOG_FORMAT`                   | `text`      | Log line format on stderr: `text` or `json` |
| —                      | `RASTREO_SHUTDOWN_TIMEOUT_SECS`        | `60`        | Hard cap on the graceful-drain window after the shutdown signal; on expiry the server logs a warning and force-exits. Clamped to ≥ 1s. Keep below the pod's `terminationGracePeriodSeconds`. |
| —                      | `RASTREO_API_TOKEN`                    | unset       | Shared secret gating `POST /scans` (bearer). Set & non-empty ⇒ auth enabled. |
| —                      | `RASTREO_AUTH_DISABLED`                | unset       | `true` runs `/scans` unauthenticated. Startup fails closed unless `RASTREO_API_TOKEN` or this is set. |
| —                      | `RASTREO_MAX_INFLIGHT_SCANS`           | `100`       | Inflight-scan cap: flips `/readyz` to 503 AND rejects a real `POST /scans` over the cap with 429; `0` disables. Dry-runs are never counted or rejected. |
| —                      | `RASTREO_SINK_ERROR_QUARANTINE_SECS`   | `30`        | `/readyz` sink-error quarantine window; `0` disables |
| —                      | `RASTREO_SCAN_ERROR_QUARANTINE_SECS`   | `30`        | `/readyz` scan-error quarantine window; `0` disables |
| —                      | `RASTREO_SINK_CONFIG_PATH`             | unset       | Path to a YAML `SinkConfig`. When set, the server builds the sink at startup and probes it periodically. A build that fails is retried on the probe interval and attaches to the running server (`SinkSlot`) when it succeeds — no restart. `sink_type` is `unknown` only while the file cannot be read or parsed; a parsed config labels its kind whether or not it built. Unset ⇒ no probe, `/readyz` reports `sink_reachable: null`. |
| —                      | `RASTREO_SINK_PROBE_INTERVAL_SECS`     | `10`        | Sink reachability probe cadence in seconds (min 1). |
| —                      | `RASTREO_SINK_PROBE_TIMEOUT_SECS`      | `5`         | Per-probe timeout in seconds (min 1). Elapsed probes count as failure. |
| —                      | `RASTREO_TARGET_ALLOWLIST`             | unset       | Comma-separated CIDRs (or bare IPs, parsed as `/32`/`/128` host nets). When set, a `POST /scans` is rejected with 403 if any resolved target falls outside every listed range. Unset ⇒ allow all. Wraps the server resolver in a `GuardedResolver`; the CLI is unaffected. |
| —                      | `RASTREO_MAX_TOTAL_HOSTS`              | `262144`    | Aggregate cap on total resolved hosts across all targets in one request; over-cap scans are rejected with 400. `0` disables. Independent of the per-target `CidrTooLarge` cap (65 536). |
| —                      | `RASTREO_MAX_BODY_BYTES`               | `1048576`   | `POST /scans` request-body size limit; a larger body is rejected with 413 before JSON parsing. |
| —                      | `RASTREO_MAX_RESULT_BYTES`             | `33554432`  | Byte cap on the `POST /scans` response capture (32 MiB). A scan producing more still completes; the response carries the records that fit plus `truncated: true` and the true `records_emitted`. A server-configured sink still receives EVERY record — the cap is response-only. Peak memory ≈ 3× the cap, so raising it requires raising `limits.memory`. |

## API Surface

| Method | Path     | Description                                                                                                                                                                  |
|--------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | /healthz | Liveness — always 200 OK with `{"status":"ok"}`. Backing endpoint for k8s liveness probes.                                                                                    |
| GET    | /readyz  | Readiness — 200 OK when the server can accept work; 503 with a `reason` string when the inflight-scan limit, a stalled sink probe task, the sink-unreachable probe, or a recent-error quarantine has fired. Response body carries `sink_reachable`, `sink_attached`, `sink_type`, `seconds_since_last_probe`, `seconds_since_last_probe_tick`, `last_probe_error` (all `null` when no sink is configured). `sink_attached` separates a sink that never built from one that is attached but failing its probe. `seconds_since_last_probe_tick` is the age of the last cycle the probe task *started* — the staleness gate reads it rather than `seconds_since_last_probe`, so a cycle that skips its probe never flips the pod to not-ready. The window is `3 × (probe_interval + 3 × probe_timeout)`, 75s on defaults, and is never applied before the first tick or when no sink is configured. A skip needs a *single* sink operation to outlast `probe_timeout` on the shared lock — `TeeSink` takes that lock per write/flush/close and releases it on return, so a running scan does not hold it and does not by itself cause skips. Skips are counted as `rastreo_server_sink_probe_ticks_total` minus the `rastreo_server_sink_reachability_probe_total` series, and `sink_unreachable` never covers them because a skipped probe produces no verdict at all. `last_probe_error` carries the whole cause chain and is reachable without a bearer token, so no credential may reach it on any failure path: a connect failure has its server-URL userinfo stripped (e.g. `nats://user:pass@host`), and a shape error in the sink config is reported against the file as written, never against the tree `${VAR}` / `!file` expansion produced.                                                                                                                                                                                                                                                             |
| GET    | /health  | Backward-compat alias for `/healthz`.                                                                                                                                        |
| GET    | /metrics | Prometheus text format with operational signals (scan / probe counters, records emitted, sink errors, request-duration histogram, uptime, build info). Namespace: `rastreo_server_`. |
| POST   | /scans   | Submit a discovery scenario; runs synchronously and returns summary + records. `?dry_run=true` resolves targets and returns a `DiscoveryPlan` (no probing, no sink, no records). Requires a valid bearer token when auth is enabled (401 otherwise); `/healthz`, `/readyz`, `/health`, `/metrics` are never authenticated. The client-specified `sink` field is ignored on the real-scan path; records land in the response body AND the server-configured sink (if any). |

## POST /scans

Authentication: when auth is enabled (`RASTREO_API_TOKEN` set, or the Helm `auth.enabled: true` default), the request must carry `Authorization: Bearer <token>`. A missing, malformed, or wrong credential returns `401 Unauthorized` with `{"error": "missing or invalid bearer token"}` and a `WWW-Authenticate: Bearer` header, and the scan never runs. The token is compared in constant time (`subtle::ConstantTimeEq`); the response never echoes the presented or expected token. The server refuses to start unauthenticated unless `RASTREO_AUTH_DISABLED=true`. Health, readiness, and metrics endpoints are never authenticated.

Request body: JSON-encoded `DiscoverScenarioConfig`. Required fields: `targets`, `probers`. The optional `sink` field is ignored — the server captures records via a server-side `MemorySink` (returned in the response) AND fans them out to the server-configured sink from `RASTREO_SINK_CONFIG_PATH` (when set). The fan-out is performed by a `TeeSink` in `rastreo-core`; each record hits both destinations on the same pipeline pass, in order.

Query parameters:
- `dry_run` (bool, default `false`) — `?dry_run=true` resolves every target through the (possibly guarded) server resolver and returns a `DiscoveryPlan` JSON with 200: the scenario label, per-target resolution (`resolved` IPs or a per-target `error`), the probers, the effective sink string, the scheduler/timeout knobs, and `total_probes`. No prober runs, no sink is opened, and no records are returned. The empty-`targets` / empty-`probers` 400 validation runs before the branch, so a dry-run of an invalid scenario is still 400, and auth still gates the route. An out-of-allow-list target surfaces as a per-target `error` in the plan rather than a 403. Sink credentials (e.g. `nats://user:pass@host`) are stripped from the rendered plan.

Response body:
- `summary`: `DiscoverySummary` — `targets_resolved`, `probe_attempts`, `error_counts` (by `ProbeErrorKind`), `first_probe_error`, `records_emitted`, `elapsed_ms`.
- `records`: array of `DeviceRecord` objects. Bounded by `RASTREO_MAX_RESULT_BYTES`: when the encoded records exceed the cap the array is truncated to the subset that fit.
- `truncated`: bool — `true` when the response capture hit `RASTREO_MAX_RESULT_BYTES`, so `records` is a subset while `summary.records_emitted` is the true total. A server-configured sink still received every record. Always present.

Errors:
- 401 — auth is enabled and the request carried a missing, malformed, or wrong bearer token. Returned by the `require_bearer` middleware before the handler runs.
- 403 — the target allow-list (`RASTREO_TARGET_ALLOWLIST`) is configured and at least one resolved target falls outside every listed range (`ResolverError::TargetNotAllowed`). The whole request is rejected and nothing is probed; the error body names the offending IP.
- 413 — the request body exceeded `RASTREO_MAX_BODY_BYTES`; rejected before JSON parsing.
- 429 — the inflight-scan cap (`RASTREO_MAX_INFLIGHT_SCANS`, when non-zero) is reached; a real scan submitted while the server is at capacity is rejected rather than queued. The gauge is rolled back atomically so a rejected request never inflates it. Dry-runs consume no slot and are never 429'd.
- 400 — bad scenario config (empty `targets` or `probers`, malformed JSON body) or unresolvable client input (`CidrTooLarge`, `RangeTooLarge`, `InvalidRange`, `MixedFamilyRange`, `DnsNoRecords`, `AggregateHostCapExceeded`).
- 500 — probe / encode / sink / runtime errors. A server-configured sink that returns an error mid-scan aborts the pipeline and surfaces as 500; the response body's `records` list is not returned even if the in-memory capture succeeded. The body carries the whole cause chain when auth was enforced on the request, and the fixed `internal server error` string when it was not.
- 503 — request exceeded the server-side timeout (`--request-timeout-ms`), or the server-side DNS infrastructure failed (`ResolverError::DnsLookupFailed`). A scan dropped by the request-timeout aborts its in-flight probes and records `rastreo_server_scans_total{outcome="cancelled"}` plus its duration in the scan-duration histogram; it does not trip the `/readyz` scan-error quarantine (a client timeout is not a server fault).

A request holds the HTTP connection open for the duration of the scan. The pipeline's own `BoundedScheduler` enforces per-scan concurrency via the scenario's `max_concurrent` and paces probe starts via `probe_rate`.

## Error Handling

- Use `anyhow` at the binary boundary.
- `AppError` maps `RastreoError` to HTTP status codes via `IntoResponse`: `Config` errors map to 400; `Resolver` errors map to 400 for structural / client-input variants (including `AggregateHostCapExceeded`), to 403 for `TargetNotAllowed`, and to 503 for `DnsLookupFailed` (server-side DNS infrastructure failure); `Probe`, `Encoder`, `Sink`, and `Runtime` errors map to 500.
- Error response body is `{"error": "<message>"}`.
- **A 5xx body carries the error detail exactly when the caller had to authenticate to reach it.** `impl From<RastreoError> for AppError` redacts every 5xx to `internal server error` and is what a bare `?` gives you — that is the default and it stays. `AppError::from_rastreo(err, disclosure)` discloses instead, but only for an `ErrorDisclosure` whose private `caller_authenticated` field is set, and the only code that can set it is `require_bearer` in `routes/auth.rs`, after a token compared equal. `ErrorDisclosure` extracts from request extensions and defaults to withholding, so a route the middleware does not cover cannot obtain a disclosing one — `AuthConfig::Enabled` in `AppState` is NOT proof, since it says nothing about this request. Disclosed bodies render the whole cause chain (`RastreoError::Sink` is `#[error(transparent)]` over `SinkError`, whose Display is the useless `output sink failed`); 4xx bodies stay at the top-level Display, unchanged. Every 5xx is logged either way, with a `disclosed` field.
- Do not panic. Recover from poisoned locks; return 500 with a JSON error body.

## Known Limitations

Pagination — `POST /scans` returns the record list in a single response body, bounded by `RASTREO_MAX_RESULT_BYTES` (32 MiB default). Large scans (a `/16` against a populated subnet, for example) that exceed the cap complete normally but return a truncated `records` array with `truncated: true`; the full set still reaches a server-configured sink. A streaming or paginated response shape (async `202 + GET /scans/{id}`) may be added later.

CORS — the server does not enable CORS today. Browser-based clients (a future dashboard) will need a `tower-http::cors::CorsLayer` added to `build_app`. Server-to-server callers are unaffected.

Resolver cache staleness — the system resolver is constructed once at server startup and cached for the server's lifetime. If `/etc/resolv.conf` changes after startup, restart the server to pick up the new configuration.

## Dependencies

| Crate                            | Purpose                                              |
|----------------------------------|------------------------------------------------------|
| `rastreo-core`                   | All discovery and lifecycle logic                    |
| `axum`                           | HTTP routing and handler infrastructure              |
| `subtle`                         | Constant-time bearer-token comparison (`ConstantTimeEq`) |
| `tower` + `tower-http`           | `TraceLayer` request/response logging, `TimeoutLayer` per-request timeout |
| `tokio`                          | Async runtime                                        |
| `serde` + `serde_json`           | Request and response serialization                   |
| `anyhow`                         | Error handling at the binary boundary                |
| `clap`                           | CLI argument parsing                                 |
| `tracing` + `tracing-subscriber` | Structured logging                                   |
