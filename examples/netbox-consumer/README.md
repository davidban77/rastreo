# NetBox reference consumer

## What this is

rastreo emits `DeviceRecord` NDJSON events to a Kafka topic. This reference consumer reads that topic, maps each record onto a NetBox `dcim.Device`, and upserts it — creating the device on first sight and patching only changed fields on subsequent scans. The upsert is idempotent: replaying the same scan produces no drift.

It is intentionally a **reference implementation**, not a production consumer. Read it as executable documentation for how to write your own reconciler.

## Prerequisites

- Python 3.12+ and [uv](https://docs.astral.sh/uv/).
- A Kafka broker reachable from where you run the consumer.
- A NetBox instance and an API token with `dcim.Device`, `dcim.Interface`, and `ipam.IPAddress` read+write. NetBox 4.x.
- The `dcim.Device` custom fields listed below already configured (see *Set up NetBox custom fields*).

## Set up NetBox custom fields

The consumer expects the following custom fields on `dcim.Device`. Ship the definitions via the shipped [`netbox-custom-fields.yaml`](netbox-custom-fields.yaml) file if you manage NetBox via GitOps, or add them through the NetBox admin UI.

| Field | Type | Notes |
|---|---|---|
| `rastreo_identity_key` | Text (unique) | Canonical device identity from rastreo. The consumer looks devices up by this field. |
| `rastreo_last_seen` | Date & Time | Timestamp of the latest probe with signals. |
| `rastreo_confidence` | Decimal | Fuser confidence in `[0.0, 1.0]`. |
| `rastreo_os_version` | Text | OS version captured alongside the platform. |
| `rastreo_signals` | JSON | Raw signals for audit. |
| `rastreo_probe_kinds` | JSON | Which probers contributed to this record. |
| `rastreo_alt_ips` | JSON | Extra IPs merged in by the identity fuser. |
| `rastreo_scan_metadata` | JSON | Scan provenance (scan_id, initiated_at, scenario_name). |

Admin UI walkthrough: **Customization → Custom Fields → Add**. Set *Content types* to `DCIM > device` and pick the type from the table above. Mark `rastreo_identity_key` as **Unique** so NetBox rejects duplicate identity keys at the database layer.

## Configuration

All configuration is env-driven. Copy `.env.example` to `.env` and adjust:

| Variable | Default | Notes |
|---|---|---|
| `KAFKA_BROKERS` | *(required)* | Comma-separated broker list, e.g. `localhost:9092`. |
| `KAFKA_TOPIC` | `rastreo.devices` | Topic rastreo publishes to. |
| `KAFKA_GROUP_ID` | `rastreo-netbox-consumer` | Kafka consumer group. Use distinct names per deployment. |
| `KAFKA_AUTO_OFFSET_RESET` | `earliest` | Where to start when no committed offset exists. |
| `POLL_TIMEOUT_MS` | `1000` | Kafka poll timeout in ms. |
| `NETBOX_URL` | *(required)* | Base URL, no trailing `/api`. |
| `NETBOX_TOKEN` | *(required)* | API token. |
| `NETBOX_VERIFY_TLS` | `true` | Set to `false` for dev with self-signed certs. |
| `NETBOX_TIMEOUT_SECONDS` | `30` | NetBox HTTP timeout. |
| `LOG_LEVEL` | `INFO` | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `DRY_RUN` | `false` | Log the intended NetBox operation without calling NetBox. |

Missing required vars cause a hard failure at startup with a clear enumeration.

## Run locally

```bash
uv sync
cp .env.example .env
# edit .env with your NETBOX_URL and NETBOX_TOKEN
uv run python -m netbox_consumer
```

The consumer runs in the foreground, logs one JSON line per event, and shuts down cleanly on SIGINT/SIGTERM.

## Run with docker-compose

The included `docker-compose.yml` brings up Kafka and the consumer:

```bash
cp .env.example .env
# edit NETBOX_URL and NETBOX_TOKEN
docker compose up --build
```

To also bring up rastreo-server + an nginx target for a full-stack demo:

```bash
docker compose --profile demo up --build
```

NetBox is not part of this compose stack because a real NetBox install brings PostgreSQL, Redis, and worker processes — an unnecessary detour for a reference implementation. Point the consumer at an existing NetBox instance via `NETBOX_URL`. If you don't have one, use NetBox's [official docker-compose setup](https://github.com/netbox-community/netbox-docker) alongside this stack.

## Idempotency

Re-running the consumer against the same NetBox produces no drift because every write path first checks the current NetBox state and only patches fields that changed. Concretely, on a repeated scan of the same device:

- `custom_fields` are compared; unchanged values are not written.
- `platform` and `role` foreign keys are compared by ID; unchanged FKs are not written.
- The management interface (`mgmt0`) and its IP address are found-or-created, not recreated.
- `primary_ip4` / `primary_ip6` is only set when it differs from the current value.

The Kafka offset commit happens **after** the NetBox upsert returns, so a crash mid-upsert replays the message on next start.

## Device naming and interface conventions

On first sight the device is created with `name = identity_key`, so a record with `identity_key = "mac:aa:bb:cc:11:22:33"` produces a NetBox device literally named `mac:aa:bb:cc:11:22:33`. Operators are expected to rename the device via the NetBox UI or API afterwards; subsequent scans do not overwrite `name`, so the manual rename sticks.

The management interface is created as `mgmt0` with `type=virtual`. Real switches and routers have specific management port names (`Management1` on Arista, `mgmt0` on Nexus, `me0` on Juniper) — an ops team that wants those preserved should override `_attach_mgmt_ip` in `netbox.py`, which is the single extension point that chooses the interface name.

## What this reference does NOT do

Kept out on purpose — production consumers should add these:

- **Dead-letter queue.** Poison messages (bad JSON, validation failures) are logged at `WARN` and committed. A production consumer routes them to a DLQ topic for inspection.
- **Retry with backoff on transient NetBox 5xx.** Right now, any NetBox exception logs at `ERROR`, skips the message, and commits. Production consumers wrap the upsert in a bounded exponential-backoff retry.
- **Metrics endpoint.** No `/metrics` here. A production consumer exposes Prometheus counters for `messages_consumed`, `upserts_created`, `upserts_updated`, `upserts_skipped`, `upsert_errors_total`.
- **Multi-instance sharding coordination.** Runs single-instance. Kafka partition assignment already handles horizontal scale for identical instances, but there is no leader election or work-stealing beyond what Kafka provides.
- **NetBox schema-version model integration.** `os_version` lands in a text custom field, not the versioned software-version model NetBox 4.x introduced — the versioned model shape varies across NetBox versions and a schema-agnostic reference should not pin one.

## Not currently mapped

`manufacturer` is present on the `DeviceRecord` (populated from the OUI database) but is not linked to `dcim.Manufacturer` in NetBox. NetBox 4.x derives `Device.manufacturer` from `Device.device_type.manufacturer`, so a reference implementation would need to look up or synthesize a matching `dcim.DeviceType` per (manufacturer, model) pair. That round-trip is out of scope here — an ops team that wants it can extend `netbox.py`'s create/patch paths to resolve a `device_type` FK from `record.manufacturer` (and a model attribute of their choosing) before calling `dcim.devices.create` / `update`.

## Extending this reference

Two more reference consumers ship separately for other sources of truth:

- **Nautobot** — same reconciliation shape, Nautobot API + custom fields.
- **Infrahub** — GraphQL mutations against the device kind.

Both follow the same layout: `models.py` for the record shape, `mapper.py` for the SoT payload, `<sot>.py` for the client wrapper, `consumer.py` for the poll loop.

## Layout

```
netbox-consumer/
├── src/netbox_consumer/
│   ├── config.py     env -> Config
│   ├── models.py     DeviceRecord subset (pydantic v2)
│   ├── mapper.py     DeviceRecord -> NetBox payload dict
│   ├── netbox.py     pynetbox find_or_create + update
│   └── consumer.py   Kafka poll loop
├── tests/            pytest suite (unit only by default)
├── docker-compose.yml
├── Dockerfile
└── netbox-custom-fields.yaml
```
