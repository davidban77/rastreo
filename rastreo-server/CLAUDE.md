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
├── state.rs       ← AppState { resolver: Arc<dyn Resolver> }
├── error.rs       ← AppError + IntoResponse + RastreoError -> HTTP mapping
└── routes/
    ├── mod.rs     ← route module re-exports
    ├── health.rs  ← GET /health
    └── scans.rs   ← POST /scans handler + ScanResponse
```

## CLI Flags

| Flag       | Env var                | Default     | Description              |
|------------|------------------------|-------------|--------------------------|
| `--port`   | `RASTREO_SERVER_PORT`  | `8080`      | TCP port to bind         |
| `--bind`   | `RASTREO_SERVER_BIND`  | `0.0.0.0`   | Bind address             |

## API Surface

| Method | Path     | Description                                                                                                                                                                  |
|--------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | /health  | Health check — always returns 200 OK                                                                                                                                         |
| POST   | /scans   | Submit a discovery scenario; runs synchronously and returns summary + records. The client-specified `sink` field is ignored; records are always returned in the response body. |

## POST /scans

Request body: JSON-encoded `DiscoverScenarioConfig`. Required fields: `targets`, `probers`. The optional `sink` field is ignored — the server captures records via a server-side `MemorySink` and returns them in the response.

Response body:
- `summary`: `DiscoverySummary` — `targets_resolved`, `probe_attempts`, `probe_errors`, `records_emitted`, `elapsed_ms`.
- `records`: array of `DeviceRecord` objects.

Errors:
- 400 — bad scenario config (empty `targets` or `probers`, malformed JSON body) or unresolvable targets.
- 500 — probe / encode / sink / runtime errors.
- 503 — request exceeded the 60-second server-side timeout.

A request holds the HTTP connection open for the duration of the scan. The pipeline's own `BoundedScheduler` enforces per-scan concurrency via the scenario's `rate_limit`.

## Error Handling

- Use `anyhow` at the binary boundary.
- `AppError` maps `RastreoError` to HTTP status codes via `IntoResponse`: `Config` and `Resolver` errors map to 400; `Probe`, `Encoder`, `Sink`, and `Runtime` errors map to 500.
- Error response body is `{"error": "<message>"}`.
- Do not panic. Recover from poisoned locks; return 500 with a JSON error body.

## Dependencies

| Crate                            | Purpose                                              |
|----------------------------------|------------------------------------------------------|
| `rastreo-core`                   | All discovery and lifecycle logic                    |
| `axum`                           | HTTP routing and handler infrastructure              |
| `tower` + `tower-http`           | `TraceLayer` request/response logging, `TimeoutLayer` per-request timeout |
| `tokio`                          | Async runtime                                        |
| `serde` + `serde_json`           | Request and response serialization                   |
| `anyhow`                         | Error handling at the binary boundary                |
| `clap`                           | CLI argument parsing                                 |
| `tracing` + `tracing-subscriber` | Structured logging                                   |
