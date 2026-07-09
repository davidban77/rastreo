# Infrahub reference consumer

## What this is

rastreo emits `DeviceRecord` NDJSON events to a Kafka topic. This reference consumer reads that topic, maps each record onto an Infrahub `RastreoDevice` node, and upserts it into a dedicated branch — creating the device on first sight and patching only changed attributes on subsequent scans. The upsert is idempotent: replaying the same scan produces no drift.

It is intentionally a **reference implementation**, not a production consumer. Read it as executable documentation for how to write your own Infrahub reconciler.

Infrahub is the third reference in the rastreo series. Two properties make it genuinely different from NetBox and Nautobot, and both are shown by this consumer:

- **Schema-flexible.** Infrahub has no fixed device model. This reference ships an `infrahub-schema.yaml` declaring a `RastreoDevice` kind that the consumer writes against. Extend it to your own operational model without asking the consumer to change.
- **Branch-based mutations.** Every write lands on a branch, not on `main`. The default is a persistent `rastreo-updates` branch that accumulates changes for human review through Infrahub's Proposed Changes UI. Auto-merge is opt-in.

## Prerequisites

- Python 3.12+ and [uv](https://docs.astral.sh/uv/).
- A Kafka broker reachable from where you run the consumer.
- An Infrahub instance and an API token with read+write on `RastreoDevice` and branch merge permission.
- The `RastreoDevice` schema (see [`infrahub-schema.yaml`](infrahub-schema.yaml)) loaded on the branch the consumer will write to. The consumer verifies this at boot and hard-fails with an actionable message if the schema is missing.

## Load the RastreoDevice schema

The reference schema is [`infrahub-schema.yaml`](infrahub-schema.yaml) — a flat `RastreoDevice` node in the `Rastreo` namespace with the attributes the mapper writes. Load it against the branch the consumer will use:

```bash
infrahubctl schema load infrahub-schema.yaml --branch rastreo-updates
```

If the branch does not exist yet, the consumer creates it from `main` at boot; you can therefore load the schema on the branch immediately after the first consumer start, or pre-create the branch yourself and load the schema before starting the consumer. Either order works — the consumer verifies both at boot and hard-fails with the exact `infrahubctl` command if the schema is missing.

Extend the schema with relationships to your own `Site`, `Manufacturer`, `Prefix`, or `IPAddress` nodes as needed. The consumer only reads the attributes it writes, so richer schemas are backwards-compatible.

## Configuration

All configuration is env-driven. Copy `.env.example` to `.env` and adjust:

| Variable | Default | Notes |
|---|---|---|
| `KAFKA_BROKERS` | *(required)* | Comma-separated broker list, e.g. `localhost:9092`. |
| `KAFKA_TOPIC` | `rastreo.devices` | Topic rastreo publishes to. |
| `KAFKA_GROUP_ID` | `rastreo-infrahub-consumer` | Kafka consumer group. Use distinct names per deployment. |
| `KAFKA_AUTO_OFFSET_RESET` | `earliest` | Where to start when no committed offset exists. |
| `POLL_TIMEOUT_MS` | `1000` | Kafka poll timeout in ms. |
| `INFRAHUB_URL` | *(required)* | Base URL. |
| `INFRAHUB_TOKEN` | *(required)* | API token. |
| `INFRAHUB_BRANCH` | `rastreo-updates` | Branch the consumer writes to. Set to `main` to skip branch review. |
| `INFRAHUB_AUTO_MERGE` | `false` | Merge the branch to `main` after each successful upsert. |
| `INFRAHUB_TIMEOUT_SECONDS` | `30` | Infrahub HTTP timeout. |
| `LOG_LEVEL` | `INFO` | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `DRY_RUN` | `false` | Log the intended Infrahub operation without calling Infrahub. |

Missing required vars cause a hard failure at startup with a clear enumeration. If the `RastreoDevice` schema is not present on the target branch, the consumer aborts at boot with the exact `infrahubctl schema load` command needed — a reference consumer should not silently paper over misconfiguration.

### Why a persistent branch by default?

Infrahub's differentiating feature is that mutations happen on branches you can review before merging. The default `rastreo-updates` branch turns the consumer into a change-proposal generator: rastreo streams discovery events, the consumer applies them to a durable branch, and an operator reviews the accumulated diff through Infrahub's Proposed Changes workflow before merging to `main`. This is the pattern you would build in a production SoT — the reference ships it out of the box.

Two other modes are supported by configuration alone:

- **Direct writes to `main`**: set `INFRAHUB_BRANCH=main` and `INFRAHUB_AUTO_MERGE=true`. The consumer writes each upsert straight to `main` — the fastest path, no review step.
- **Persistent branch with auto-merge**: keep `INFRAHUB_BRANCH=rastreo-updates` and set `INFRAHUB_AUTO_MERGE=true`. Every upsert lands on the branch and is merged to `main` immediately — useful when you want branch attribution on `main` but no review gate.

**Per-scan branches** (one branch per rastreo scan) are intentionally not shipped. They pile up branches in Infrahub's UI and hide the drift signal that a durable branch surfaces. Users who want per-scan branches need to fork the code — the extension point is `InfrahubClientWrapper.upsert_device`.

## Run locally

```bash
uv sync
cp .env.example .env
# edit .env with your INFRAHUB_URL and INFRAHUB_TOKEN
uv run python -m infrahub_consumer
```

The consumer runs in the foreground, logs one JSON line per event, and shuts down cleanly on SIGINT/SIGTERM.

## Run with docker-compose

The included `docker-compose.yml` brings up Kafka and the consumer:

```bash
cp .env.example .env
# edit INFRAHUB_URL and INFRAHUB_TOKEN
docker compose up --build
```

To also bring up rastreo-server + an nginx target for a full-stack demo:

```bash
docker compose --profile demo up --build
```

Infrahub is intentionally not part of this compose stack. A real Infrahub install brings PostgreSQL, Neo4j, the backend and frontend services, and background workers — a multi-service stack that would swamp a reference implementation. Point the consumer at an existing Infrahub instance via `INFRAHUB_URL`. If you don't have one, use the [official Infrahub docker-compose stack](https://docs.infrahub.app/guides/installation/) alongside this one.

## Idempotency

Re-running the consumer against the same Infrahub branch produces no drift because every write path first reads the current attribute values and only writes attributes that changed. Concretely, on a repeated scan of the same device:

- The wrapper reads the `RastreoDevice` node by `identity_key__value`.
- Each mapped attribute is compared to the current node value.
- If nothing changed, `node.update()` is not called.
- If auto-merge is off, the branch's diff surface stays clean between re-runs.

The Kafka offset commit happens **after** the Infrahub upsert returns, so a crash mid-upsert replays the message on next start.

## Branch review workflow

With `INFRAHUB_AUTO_MERGE=false` (the default), the branch `rastreo-updates` accumulates every rastreo-driven change. Ops teams review the diff before merging:

1. Open Infrahub's UI, navigate to **Branches** and select `rastreo-updates`.
2. Inspect the diff view — every attribute the consumer wrote is annotated with its source branch and the account that made the change.
3. Open a **Proposed Change** targeting `main` when the diff looks correct. Infrahub's checks (schema validation, custom checks, referential integrity) run against the proposed merge.
4. Merge the proposed change from the UI, or reject specific fields and let the next scan re-apply them.

This is Infrahub's differentiator over an SoT that mutates `main` directly: the human sits between discovery and truth without slowing the discovery pipeline down.

## Sync-outer, async-inner runtime

The consumer's outer loop is sync `confluent-kafka` and the inner per-message upsert is async `infrahub-sdk`. Every polled message triggers `asyncio.run(...)` for its Infrahub work. This trades throughput for readability — the sync/async boundary is at exactly one line, `asyncio.run(infrahub.upsert_device(payload))`.

High-throughput deployments should switch to an all-async setup with `aiokafka` and a single long-lived event loop. That is a larger structural change than this reference is trying to teach, so it stays sync-outer.

## What this reference does NOT do

Kept out on purpose — production consumers should add these:

- **Per-scan branches.** Every upsert lands on the persistent `INFRAHUB_BRANCH`. Per-scan branches would need lifecycle tracking that is out of scope for a reference.
- **Related-node creation.** The consumer does not create `Site`, `Manufacturer`, `Prefix`, or `IPAddress` nodes and does not attach `RastreoDevice` to any of them. The reference schema is flat on purpose.
- **Infrahub Groups / Tags integration.** No group membership, no tag application.
- **Git-sync schema synchronization.** The schema is applied out-of-band via `infrahubctl`, not through Infrahub's git-sync module. Production deployments typically manage schemas via git-sync.
- **Dead-letter queue.** Poison messages (bad JSON, validation failures) are logged at `WARN` and committed. A production consumer routes them to a DLQ topic for inspection.
- **Retry with backoff on transient Infrahub 5xx.** Right now, any Infrahub exception logs at `ERROR`, skips the message, and commits. Production consumers wrap the upsert in a bounded exponential-backoff retry.
- **Metrics endpoint.** No `/metrics` here. A production consumer exposes Prometheus counters for `messages_consumed`, `upserts_created`, `upserts_updated`, `upserts_skipped`, `upsert_errors_total`.
- **Multi-instance sharding coordination.** Runs single-instance. Kafka partition assignment already handles horizontal scale for identical instances.

## Not currently mapped

`manufacturer` is present on the `DeviceRecord` (populated from the OUI database) but is not written to Infrahub. The reference schema does not model a `Manufacturer` relationship, and modeling one would require a per-deployment decision about how the ops team already models manufacturers in Infrahub. An extension that resolves `record.manufacturer` to a `Manufacturer` node and attaches it as a relationship on `RastreoDevice` fits inside `InfrahubClientWrapper.upsert_device`.

## Extending this reference

Two other reference consumers ship in the same repo:

- **[NetBox](../netbox-consumer/)** — NetBox 4.x, REST API + custom fields.
- **[Nautobot](../nautobot-consumer/)** — Nautobot 2.x, REST API + custom fields.

All three follow the same layout: `models.py` for the record shape, `mapper.py` for the SoT payload, `<sot>.py` for the client wrapper, `consumer.py` for the poll loop.

## Layout

```
infrahub-consumer/
├── src/infrahub_consumer/
│   ├── config.py      env -> Config
│   ├── models.py      DeviceRecord subset (pydantic v2)
│   ├── mapper.py      DeviceRecord -> Infrahub attribute payload
│   ├── infrahub.py    async infrahub-sdk find_or_create + update + branch merge
│   └── consumer.py    Kafka poll loop; asyncio.run per message
├── tests/             pytest suite (unit only by default)
├── docker-compose.yml
├── Dockerfile
└── infrahub-schema.yaml
```
