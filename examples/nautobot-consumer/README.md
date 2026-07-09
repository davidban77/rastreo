# Nautobot reference consumer

## What this is

rastreo emits `DeviceRecord` NDJSON events to a Kafka topic. This reference consumer reads that topic, maps each record onto a Nautobot 2.x `dcim.Device`, and upserts it — creating the device on first sight and patching only changed fields on subsequent scans. The upsert is idempotent: replaying the same scan produces no drift.

It is intentionally a **reference implementation**, not a production consumer. Read it as executable documentation for how to write your own reconciler against Nautobot.

## Prerequisites

- Python 3.12+ and [uv](https://docs.astral.sh/uv/).
- A Kafka broker reachable from where you run the consumer.
- A Nautobot 2.x instance and an API token with `dcim.Device`, `dcim.Interface`, `ipam.IPAddress`, and `ipam.Prefix` read+write.
- The `rastreo_*` custom fields configured on `dcim.device` (see *Set up Nautobot custom fields*).
- A default `dcim.DeviceType`, a default `dcim.Location`, and a device `Status` present in Nautobot — Nautobot 2.x requires all three on every device. The consumer resolves these three defaults once at startup and hard-fails if any name is missing.

## Set up Nautobot custom fields

The consumer expects the following custom fields on `dcim.device`. The shape each field must have is documented in [`nautobot-custom-fields.yaml`](nautobot-custom-fields.yaml); Nautobot does not ship a single one-shot importer for custom-field YAML in core, so apply the definitions via the admin UI or via the `nautobot-app-bootstrap-ssot` plugin if you use one.

| Field | Type | Notes |
|---|---|---|
| `rastreo_identity_key` | Text | Canonical device identity from rastreo. The consumer looks devices up by this field. Mark as **unique**. |
| `rastreo_last_seen` | Date & Time | Timestamp of the latest probe with signals. |
| `rastreo_confidence` | Text | Fuser confidence in `[0.0, 1.0]`, formatted as a two-decimal string (Nautobot 2.x has no decimal custom-field type). |
| `rastreo_os_version` | Text | OS version captured alongside the platform. |
| `rastreo_ssh_version` | Text | SSH software identifier from the classifier (e.g. `OpenSSH_8.9p1`). |
| `rastreo_http_server` | Text | Web-server product name from the classifier (e.g. `nginx`). |
| `rastreo_http_version` | Text | Web-server version from the classifier (e.g. `1.24.0`). |
| `rastreo_signals` | JSON | Raw signals for audit. |
| `rastreo_probe_kinds` | JSON | Which probers contributed to this record. |
| `rastreo_alt_ips` | JSON | Extra IPs merged in by the identity fuser. |
| `rastreo_scan_metadata` | JSON | Scan provenance (scan_id, initiated_at, scenario_name). |

Admin UI walkthrough: **Extensibility → Custom Fields → Add**. Set *Content Type(s)* to `dcim | device` and pick the type from the table above. Mark `rastreo_identity_key` as **Unique** so Nautobot rejects duplicate identity keys at the database layer.

## Configuration

All configuration is env-driven. Copy `.env.example` to `.env` and adjust:

| Variable | Default | Notes |
|---|---|---|
| `KAFKA_BROKERS` | *(required)* | Comma-separated broker list, e.g. `localhost:9092`. |
| `KAFKA_TOPIC` | `rastreo.devices` | Topic rastreo publishes to. |
| `KAFKA_GROUP_ID` | `rastreo-nautobot-consumer` | Kafka consumer group. Use distinct names per deployment. |
| `KAFKA_AUTO_OFFSET_RESET` | `earliest` | Where to start when no committed offset exists. |
| `POLL_TIMEOUT_MS` | `1000` | Kafka poll timeout in ms. |
| `NAUTOBOT_URL` | *(required)* | Base URL, no trailing `/api`. |
| `NAUTOBOT_TOKEN` | *(required)* | API token. |
| `NAUTOBOT_VERIFY_TLS` | `true` | Set to `false` for dev with self-signed certs. |
| `NAUTOBOT_TIMEOUT_SECONDS` | `30` | Nautobot HTTP timeout. |
| `NAUTOBOT_DEFAULT_DEVICE_TYPE` | *(required)* | Name of the `dcim.DeviceType` used on device creates. Nautobot 2.x requires `device_type` on every device. |
| `NAUTOBOT_DEFAULT_LOCATION` | *(required)* | Name of the `dcim.Location` used on device creates. Nautobot 2.x requires `location` on every device. |
| `NAUTOBOT_DEFAULT_DEVICE_STATUS` | `Active` | Name of the `extras.Status` used on device and IP creates. Nautobot ships `Active` by default; override if your instance renamed it. |
| `LOG_LEVEL` | `INFO` | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `DRY_RUN` | `false` | Log the intended Nautobot operation without calling Nautobot. |

Missing required vars cause a hard failure at startup with a clear enumeration. If the default DeviceType, Location, or Status name does not exist in Nautobot, the consumer aborts with a `NautobotLookupError` at startup — a reference consumer should not silently paper over misconfiguration.

Note on **names, not slugs**: Nautobot 2.x removed the `slug` field from `Role`, `Status`, `Platform`, `DeviceType`, `Location`, and `Manufacturer`. All lookups happen by `name`. The env vars above accept names as displayed in the Nautobot UI (case-sensitive).

## Run locally

```bash
uv sync
cp .env.example .env
# edit .env with your NAUTOBOT_URL, NAUTOBOT_TOKEN, and the three default names
uv run python -m nautobot_consumer
```

The consumer runs in the foreground, logs one JSON line per event, and shuts down cleanly on SIGINT/SIGTERM.

## Run with docker-compose

The included `docker-compose.yml` brings up Kafka and the consumer:

```bash
cp .env.example .env
# edit NAUTOBOT_URL, NAUTOBOT_TOKEN, and the three default names
docker compose up --build
```

To also bring up rastreo-server + an nginx target for a full-stack demo:

```bash
docker compose --profile demo up --build
```

Nautobot is not part of this compose stack because a real Nautobot install brings PostgreSQL, Redis, Celery workers, a housekeeping service, and (optionally) selenium test runners — a seven-service stack that would swamp a reference implementation. Point the consumer at an existing Nautobot instance via `NAUTOBOT_URL`. If you don't have one, use the [official nautobot-docker-compose](https://github.com/nautobot/nautobot-docker-compose) stack alongside this one.

## Idempotency

Re-running the consumer against the same Nautobot produces no drift because every write path first checks the current Nautobot state and only patches fields that changed. Concretely, on a repeated scan of the same device:

- `custom_fields` are compared; unchanged values are not written.
- `platform` and `role` foreign keys are compared by ID; unchanged FKs are not written.
- The management interface (`mgmt0`) and its IP address are found-or-created, not recreated.
- `primary_ip4` / `primary_ip6` is only set when it differs from the current value.

The Kafka offset commit happens **after** the Nautobot upsert returns, so a crash mid-upsert replays the message on next start.

## Device naming and interface conventions

On first sight the device is created with `name = identity_key`, so a record with `identity_key = "mac:aa:bb:cc:11:22:33"` produces a Nautobot device literally named `mac:aa:bb:cc:11:22:33`. Operators are expected to rename the device via the Nautobot UI or API afterwards; subsequent scans do not overwrite `name`, so the manual rename sticks.

The management interface is created as `mgmt0` with `type=virtual` and `status` set to the same default status as the device. Real switches and routers have specific management port names (`Management1` on Arista, `mgmt0` on Nexus, `me0` on Juniper) — an ops team that wants those preserved should override `_attach_mgmt_ip` in `nautobot.py`, which is the single extension point that chooses the interface name.

The `primary_ip4` / `primary_ip6` is attached only when an enclosing `ipam.Prefix` already exists in Nautobot. Nautobot 2.x requires `IPAddress.parent` (a Prefix FK) at create time, so a reference consumer with no way to synthesise prefixes on the fly must skip primary-IP attachment when no prefix contains `mgmt_ip`. In that case the consumer logs a `WARN` and continues — the device is still upserted with its custom fields intact.

## What this reference does NOT do

Kept out on purpose — production consumers should add these:

- **Dead-letter queue.** Poison messages (bad JSON, validation failures) are logged at `WARN` and committed. A production consumer routes them to a DLQ topic for inspection.
- **Retry with backoff on transient Nautobot 5xx.** Right now, any Nautobot exception logs at `ERROR`, skips the message, and commits. Production consumers wrap the upsert in a bounded exponential-backoff retry.
- **Metrics endpoint.** No `/metrics` here. A production consumer exposes Prometheus counters for `messages_consumed`, `upserts_created`, `upserts_updated`, `upserts_skipped`, `upsert_errors_total`.
- **Multi-instance sharding coordination.** Runs single-instance. Kafka partition assignment already handles horizontal scale for identical instances, but there is no leader election or work-stealing beyond what Kafka provides.
- **Nautobot SSoT framework integration.** This reference calls the REST API directly. In production, wrapping the reconciliation logic inside a Nautobot Job or an [`nautobot-app-ssot`](https://docs.nautobot.com/projects/ssot/en/latest/) DataSource is the canonical Nautobot pattern — you get diff UIs, dry-run previews, sync history, and RBAC without hand-rolling any of it. This reference stays REST-only so the reader can follow the wire calls.
- **Auto-creating Prefixes for `primary_ip4`/`primary_ip6`.** When no enclosing prefix exists, primary-IP attachment is skipped with a WARN rather than synthesising a `/24` (or whatever) from thin air. Prefix policy is out of scope for a reference reconciler.

## Not currently mapped

`manufacturer` is present on the `DeviceRecord` (populated from the OUI database) but is not linked to `dcim.Manufacturer` in Nautobot. Nautobot 2.x derives `Device.manufacturer` from `Device.device_type.manufacturer`, so a reference implementation would need to look up or synthesize a matching `dcim.DeviceType` per (manufacturer, model) pair. That round-trip is out of scope here — an ops team that wants it can extend `nautobot.py`'s create/patch paths to resolve a `device_type` name from `record.manufacturer` (and a model attribute of their choosing) before calling `dcim.devices.create` / `update`.

## Extending this reference

Two other reference consumers ship in the same repo:

- **[NetBox](../netbox-consumer/)** — same reconciliation shape, NetBox 4.x API + custom fields.
- **Infrahub** — GraphQL mutations against the device kind (follow-up PR).

All follow the same layout: `models.py` for the record shape, `mapper.py` for the SoT payload, `<sot>.py` for the client wrapper, `consumer.py` for the poll loop.

## Layout

```
nautobot-consumer/
├── src/nautobot_consumer/
│   ├── config.py     env -> Config
│   ├── models.py     DeviceRecord subset (pydantic v2)
│   ├── mapper.py     DeviceRecord -> Nautobot payload dict
│   ├── nautobot.py   pynautobot find_or_create + update
│   └── consumer.py   Kafka poll loop
├── tests/            pytest suite (unit only by default)
├── docker-compose.yml
├── Dockerfile
└── nautobot-custom-fields.yaml
```
