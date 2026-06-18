# rastreo-server — HTTP Control Plane

This is the binary crate for the HTTP REST API. It allows discovery scenarios to be started, inspected, and stopped over HTTP — enabling integration into CI pipelines, lab automation, and dashboards.

## Design Principle

The API mirrors the CLI. Every endpoint corresponds to an operation that is also doable from the command line. If a discovery can not be expressed in YAML, it can not be run via the API. This keeps the two surfaces in sync and prevents behavior drift.

No business logic lives in this crate. All scenario validation and launch logic is delegated to `rastreo-core`. The server crate is pure HTTP plumbing.

## Module Layout

```
src/
└── main.rs   ← entrypoint: clap arg parsing, tracing init, axum router setup,
                 tokio runtime. The only route today is `GET /health`.
```

## CLI Flags

| Flag       | Env var                | Default     | Description              |
|------------|------------------------|-------------|--------------------------|
| `--port`   | `RASTREO_SERVER_PORT`  | `8080`      | TCP port to bind         |
| `--bind`   | `RASTREO_SERVER_BIND`  | `0.0.0.0`   | Bind address             |

## API Surface

| Method | Path     | Description                              |
|--------|----------|------------------------------------------|
| GET    | /health  | Health check — always returns 200 OK     |

## Error Handling

- Use `anyhow` at the binary boundary.
- Map `rastreo-core` `RastreoError` variants to HTTP status codes when handlers are added.
- Do not panic. Recover from poisoned locks; return 500 with a JSON error body.

## Dependencies

| Crate                            | Purpose                                              |
|----------------------------------|------------------------------------------------------|
| `rastreo-core`                   | All discovery and lifecycle logic                    |
| `axum`                           | HTTP routing and handler infrastructure              |
| `tokio`                          | Async runtime                                        |
| `serde` + `serde_json`           | Request and response serialization                   |
| `anyhow`                         | Error handling at the binary boundary                |
| `clap`                           | CLI argument parsing                                 |
| `tracing` + `tracing-subscriber` | Structured logging                                   |
