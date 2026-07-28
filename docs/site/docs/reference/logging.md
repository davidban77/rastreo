---
description: rastreo's structured logging — text (default) and JSON output formats, log-level control, and drop-in Loki, ELK, and Splunk ingestion examples.
---

# Logging

Both `rastreo` and `rastreo-server` emit tracing logs to stderr. The default format is a human-readable text renderer, chosen so the tools stay pleasant to use interactively. A second format — JSON — is available for log aggregators that expect one JSON object per line (Loki, ELK, Splunk, and any pipeline built on Grafana Alloy, Vector, or Fluent Bit). Select the format with `--log-format` on either binary or with the `RASTREO_LOG_FORMAT` environment variable.

## `--log-format` flag

| Value  | Effect                                                          |
|--------|-----------------------------------------------------------------|
| `text` | Human-readable text output on stderr. Default.                  |
| `json` | One JSON object per line on stderr, ready for aggregator ingest. |

The flag is available on both binaries. On the `rastreo` CLI it is a global flag — set it before or after the subcommand:

```bash
rastreo --log-format json discover --target 10.0.0.0/24 --probe tcp_connect -p 22,80
rastreo discover --log-format json --target 10.0.0.0/24 --probe tcp_connect -p 22,80
```

On `rastreo-server` it is a top-level flag:

```bash
rastreo-server --log-format json --port 8080
```

## `RASTREO_LOG_FORMAT` environment variable

Set `RASTREO_LOG_FORMAT=json` (or `text`) as an alternative to the flag. This is the natural way to configure the format inside a container image, a systemd unit, or a Kubernetes Deployment. Both binaries accept the same variable name.

```bash
RASTREO_LOG_FORMAT=json rastreo-server --port 8080
```

Precedence, from lowest to highest: built-in default (`text`), then `RASTREO_LOG_FORMAT`, then the `--log-format` flag. An explicit `--log-format text` overrides `RASTREO_LOG_FORMAT=json`. Unknown values (e.g. `RASTREO_LOG_FORMAT=yaml`) are rejected at startup with a clap validation error listing the accepted values.

## Text format

The default. Each log line contains a timestamp, level, target module, message, and any structured fields, formatted for humans:

```text
2026-07-09T14:23:45.123456Z  INFO rastreo_server: rastreo-server listening addr=0.0.0.0:8080
```

Use this when running the tools interactively, in CI logs read by humans, or piped into `less` / `grep`.

## JSON format

One JSON object per line. Each line contains a timestamp, level, target module, and a `fields` object that carries the message and any additional structured fields attached to the tracing event. When a tracing span is active, its fields appear under a `spans` array.

Sample line from `rastreo-server --log-format json`:

```json
{"timestamp":"2026-07-09T14:23:45.123456Z","level":"INFO","fields":{"message":"rastreo-server listening","addr":"0.0.0.0:8080"},"target":"rastreo_server"}
```

Field shape:

| Field       | Type   | Description                                                             |
|-------------|--------|-------------------------------------------------------------------------|
| `timestamp` | string | RFC 3339 / ISO 8601 UTC timestamp with microsecond precision.           |
| `level`     | string | One of `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`.                       |
| `target`    | string | Module path that produced the event (`rastreo_server`, `rastreo_core::pipeline`, ...). |
| `fields`    | object | The event's `message` and any `key=value` structured fields.            |
| `spans`     | array  | Present only when the event was emitted inside a tracing span. Each entry carries the span name and its fields. |

The JSON serializer is the one provided by `tracing-subscriber`; no custom fields are added. Field order across lines is not guaranteed to be stable — parse the JSON, do not match on line prefixes.

## Log levels

Log format and log level are controlled independently. Format selects how each line is rendered; level selects which lines are emitted at all.

On the `rastreo` CLI:

- No flag: `info` (the default).
- `-v` / `--verbose`: `debug`.
- `-vv` (or more): `trace`.
- `-q` / `--quiet`: `error` (overrides `-v`).

On `rastreo-server`:

- The default level is `info`.
- The `-v` / `-q` flags are CLI-only and do not apply to the server.

For both binaries, the `RUST_LOG` environment variable — parsed by `tracing-subscriber`'s `EnvFilter` — takes precedence over the built-in default when set. `RUST_LOG` supports full per-target filtering:

```bash
RUST_LOG=info,rastreo_core::pipeline=debug rastreo-server --log-format json
```

## stderr vs stdout

Logs always go to **stderr**, in both text and JSON formats. Stdout is reserved for the `rastreo` CLI's record stream — the triage table by default, or NDJSON `DeviceRecord` lines under `--format json`. This split lets you pipe stdout straight into `jq`, a Kafka producer, or any NDJSON consumer without log noise. See [Discover · Sinks](../discover/sinks.md) for the sink options.

`--log-format` governs log lines only. The `rastreo` CLI writes status lines of its own to stderr as well:

- the `▶` start banner and the `■` completion banner,
- the live progress line,
- `⚠ hint:` notices.

Those stay human-readable even under `--log-format json`. Two flags keep them out of a log pipeline. `--format json` drops all of them except the hints. `-q` drops every one. `rastreo-server` writes only log lines, so its stderr is uniformly JSON when the flag is set.

## Aggregator ingestion

The JSON format is one JSON object per line, which every mainstream log aggregator reads with no setup. The snippets below are the smallest working fragments. Merge them into the collector config you already run.

### Loki via Promtail

Attach a `json` stage to the scrape target so `level`, `target`, and the fields inside `fields` become labels or extracted keys:

```yaml
scrape_configs:
  - job_name: rastreo
    static_configs:
      - targets: [rastreo-server]
        labels:
          job: rastreo-server
    pipeline_stages:
      - json:
          expressions:
            level: level
            target: target
            message: fields.message
      - labels:
          level:
          target:
```

### ELK via Filebeat

Enable the JSON decoder on the input so each line becomes a structured document indexed in Elasticsearch:

```yaml
filebeat.inputs:
  - type: container
    paths:
      - /var/log/containers/rastreo-server-*.log
    json.keys_under_root: true
    json.add_error_key: true
    json.overwrite_keys: true
```

### Splunk

The line format is standard NDJSON. Point a Universal Forwarder at the stderr stream (or scrape it with the Kubernetes / Docker log-collection input) and set `sourcetype = _json` — the default JSON sourcetype handles the shape.

### Grafana Alloy / Vector / Fluent Bit

Any modern log shipper with a "parse JSON per line" transform will pick the format up unchanged. In Alloy use `loki.process` with a `stage.json {}` block; in Vector use the `remap` transform with `parse_json!(.message)`; in Fluent Bit use the `parser json` filter.

## See also

- [CLI reference](cli.md) — every flag for both binaries.
- [Discover · Sinks](../discover/sinks.md) — where `DeviceRecord` events go (stdout vs file vs Kafka).
- [Deploy · Kubernetes](../deploy/kubernetes.md) — recommended production configuration.
