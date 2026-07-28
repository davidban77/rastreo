---
description: Every environment variable the rastreo CLI and rastreo-server read at runtime, in one table — server limits, auth, readiness, sink probe, OTLP export, logging, and the catalog search path, with defaults and scope.
---

# Configuration reference

This page lists every environment variable the `rastreo` CLI and `rastreo-server` read at runtime, with its default and scope. It is the single index. Each area links to the topic page that explains the behavior in depth.

The **Scope** column tells you which binary reads the variable:

- **server** — read by `rastreo-server` only.
- **CLI** — read by the `rastreo` CLI only.
- **both** — read by both binaries.

Several variables are also command-line flags — `RASTREO_SERVER_PORT`, `RASTREO_SERVER_BIND`, `RASTREO_SERVER_REQUEST_TIMEOUT_MS`, `RASTREO_LOG_FORMAT`, and `RASTREO_FORMAT`. Where a variable has a flag, the flag wins. See the [CLI reference](cli.md) for flag details.

## rastreo-server

These variables tune the HTTP control plane: bind address, authentication, request limits, readiness gates, and the sink reachability probe. For depth, see the [server deployment page](../deploy/server.md) and the [health endpoints reference](health-endpoints.md).

| Variable | Default | Scope | Description |
|---|---|---|---|
| `RASTREO_SERVER_PORT` | `8080` | server | TCP port the server binds. Also the `--port` flag. |
| `RASTREO_SERVER_BIND` | `0.0.0.0` | server | Bind address. Also the `--bind` flag. |
| `RASTREO_SERVER_REQUEST_TIMEOUT_MS` | `60000` | server | Per-request timeout in milliseconds (minimum 1). Also the `--request-timeout-ms` flag. |
| `RASTREO_SHUTDOWN_TIMEOUT_SECS` | `60` | server | Hard cap in seconds on the graceful-drain window after a shutdown signal. Clamped to a 1-second minimum. See [Graceful shutdown](../deploy/server.md#graceful-shutdown). |
| `RASTREO_API_TOKEN` | unset | server | Shared secret for `POST /scans` bearer auth. When set, every scan request must send `Authorization: Bearer <token>`. See [Authentication](../deploy/server.md#authentication). |
| `RASTREO_AUTH_DISABLED` | unset | server | Set to `true` to run `POST /scans` with no authentication. Startup fails unless this or `RASTREO_API_TOKEN` is set. See [Authentication](../deploy/server.md#authentication). |
| `RASTREO_MAX_INFLIGHT_SCANS` | `100` | server | Cap on concurrent real scans. Over the cap, `POST /scans` returns 429 and `/readyz` returns 503. `0` disables. Dry-runs never count. See [health endpoints](health-endpoints.md#configuration). |
| `RASTREO_SINK_ERROR_QUARANTINE_SECS` | `30` | server | Window in seconds that a recent sink error holds `/readyz` at 503. `0` disables. See [health endpoints](health-endpoints.md#configuration). |
| `RASTREO_SCAN_ERROR_QUARANTINE_SECS` | `30` | server | Window in seconds that a recent scan error holds `/readyz` at 503. `0` disables. See [health endpoints](health-endpoints.md#configuration). |
| `RASTREO_SINK_CONFIG_PATH` | unset | server | Path to a YAML `SinkConfig`. When set, the server builds the sink at startup and probes it. Unset means no probe and `/readyz` reports `sink_reachable: null`. See [sink reachability probe](../deploy/server.md#sink-reachability-probe). |
| `RASTREO_SINK_PROBE_INTERVAL_SECS` | `10` | server | Sink reachability probe cadence in seconds (minimum 1). |
| `RASTREO_SINK_PROBE_TIMEOUT_SECS` | `5` | server | Per-probe timeout in seconds (minimum 1). An elapsed probe counts as a failure. |
| `RASTREO_TARGET_ALLOWLIST` | unset | server | Comma-separated CIDRs (bare IPs treated as `/32` or `/128`) the server may probe. Unset means allow every target. See [restricting scan targets](../deploy/server.md#restricting-scan-targets). |
| `RASTREO_MAX_TOTAL_HOSTS` | `262144` | server | Aggregate cap on resolved hosts across all targets in one request. Over-cap scans return 400. `0` disables. See [restricting scan targets](../deploy/server.md#restricting-scan-targets). |
| `RASTREO_MAX_BODY_BYTES` | `1048576` | server | `POST /scans` request-body size limit in bytes (1 MiB). A larger body returns 413 before JSON parsing. See [restricting scan targets](../deploy/server.md#restricting-scan-targets). |
| `RASTREO_MAX_RESULT_BYTES` | `33554432` | server | Byte cap on the `POST /scans` response records (32 MiB). Over-cap scans still complete; the response is truncated with `truncated: true`, and a configured sink still receives every record. See [bounded response size](../deploy/server.md#bounded-response-size). |
| `RASTREO_SCENARIO_LABEL_ALLOWLIST` | unset | server | Comma-separated scenario names that get their own labeled `/metrics` histogram series. Every other scenario buckets to `scenario="other"`. See [observability](observability.md). |
| `RASTREO_SCENARIO_LABEL_MAX_LENGTH` | `64` | server | Truncation length for scenario names before allow-list matching. Bounds the metric label length. See [observability](observability.md). |

## rastreo CLI

These control the record format, the terminal output, the SNMP community, and where `@name` catalog references resolve. For the record format and the terminal surface in depth, see the [CLI reference](cli.md#colour-and-glyphs).

| Variable | Default | Scope | Description |
|---|---|---|---|
| `RASTREO_FORMAT` | unset | CLI | Record format: `table` (aliased `text`) or `json` (aliased `ndjson`). Also the `--format` flag, which wins. Unset, the destination decides — stdout gets the table, every other sink gets NDJSON. A value here also overrides a scenario's `encoder`, so `RASTREO_FORMAT=table` left exported refuses every Kafka or NATS scenario. See [Record format](../discover/cli.md#record-format). |
| `RASTREO_ASCII` | unset | CLI | Any non-empty value other than `0` renders the banners with the ASCII glyphs `>`, `#`, `!`, `*`, and `->` instead of `▶`, `■`, `⚠`, `•`, and `→`. Use it on a terminal that cannot render the Unicode set. |
| `RASTREO_SNMP_COMMUNITY` | `public` | CLI | SNMP read community for a flag-driven scan. Prefer it over `--snmp-community`, whose value is visible to anyone who can run `ps`. A `--file` run ignores it and reads the scenario's `community:` field. |
| `RASTREO_CATALOG_DIR` | unset | CLI | Colon-separated directories searched for `@name` catalog scenarios. When set, it is the only search path. Unset falls back to the two variables below, then `/etc/rastreo/catalog`. |
| `XDG_CONFIG_HOME` | unset | CLI | Standard base directory. When `RASTREO_CATALOG_DIR` is unset, the catalog search starts at `$XDG_CONFIG_HOME/rastreo/catalog`. |
| `HOME` | unset | CLI | Standard home directory. Used for the catalog fallback `$HOME/.config/rastreo/catalog` when `XDG_CONFIG_HOME` is unset. |

The CLI also honours `LC_ALL`, `LC_CTYPE`, and `LANG`: a non-UTF-8 locale selects the same ASCII glyphs `RASTREO_ASCII` forces. Colour follows the three standard variables — `NO_COLOR` turns it off, `CLICOLOR_FORCE` and `FORCE_COLOR` turn it on. See [Colour and glyphs](cli.md#colour-and-glyphs).

!!! info "Scenario files can read any environment variable"
    A `${VAR}` reference inside a scenario YAML file expands to the value of the named environment variable at load time. The variable name is chosen by the scenario author, not fixed by rastreo, so those names are not listed here. See [Secrets](secrets.md) for the `${VAR}` and `!file` syntaxes.

## Logging

Both binaries read this. See the [logging reference](logging.md).

| Variable | Default | Scope | Description |
|---|---|---|---|
| `RASTREO_LOG_FORMAT` | `text` | both | Log line format on stderr: `text` or `json`. Also the `--log-format` flag on both binaries. |

## OpenTelemetry OTLP export

Both binaries read the same `RASTREO_OTLP_*` variables at startup, and both fail fast on invalid or incomplete values. Export is off by default. The OTLP exporter is available only in builds compiled with the `otlp` feature. See the [OTLP reference](otlp.md).

| Variable | Default | Scope | Description |
|---|---|---|---|
| `RASTREO_OTLP_ENDPOINT` | unset (required when export is on) | both | OTLP collector URL. Required when metric, log, or trace export is enabled. The format depends on `RASTREO_OTLP_PROTOCOL`. |
| `RASTREO_OTLP_LOGS_ENABLED` | `false` | both | Enable log export via OTLP. |
| `RASTREO_OTLP_TRACES_ENABLED` | `false` | both | Enable trace export via OTLP. Emits a fixed set of per-scan pipeline-stage spans. Valid on its own, without metrics or logs. |
| `RASTREO_OTLP_METRICS_ENABLED` | `false` | server | Enable metric export via OTLP. Server-only — setting `true` on the CLI is rejected at startup. |
| `RASTREO_OTLP_PROTOCOL` | `grpc` | both | OTLP transport: `grpc`, `http-protobuf`, or the alias `http`. Case-insensitive. |
| `RASTREO_OTLP_SERVICE_NAME` | `rastreo-server` (server) / `rastreo` (CLI) | both | Value of the `service.name` resource attribute on every exported signal. |
| `RASTREO_OTLP_METRICS_INTERVAL_SECS` | `30` | server | Metric export interval in seconds. The CLI ignores it, because the CLI does not export metrics. |
| `RASTREO_OTLP_HEADERS` | unset | both | Custom headers on every OTLP request, as comma-separated `key=value` pairs (for example an `authorization` bearer token for a hosted collector). Values are secrets — redacted from logs. See [Custom headers](otlp.md#custom-headers). |

!!! tip "Boolean values"
    The boolean variables (`RASTREO_AUTH_DISABLED`, `RASTREO_OTLP_LOGS_ENABLED`, `RASTREO_OTLP_TRACES_ENABLED`, `RASTREO_OTLP_METRICS_ENABLED`) accept `true`/`false`, `1`/`0`, `yes`/`no`, and `on`/`off`. Any other value fails startup with a clear error.

## See also

- [Server deployment](../deploy/server.md) — auth, target guards, and request limits in context.
- [Health endpoints](health-endpoints.md) — the readiness gates and quarantine windows.
- [OTLP](otlp.md) — OpenTelemetry export setup and transport choice.
- [Logging](logging.md) — text and JSON log formats.
- [CLI reference](cli.md) — every flag for `rastreo` and `rastreo-server`.
