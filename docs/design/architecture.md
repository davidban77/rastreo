# rastreo — Architecture

## 1. Engine overview

rastreo probes a network across TCP, UDP, HTTP, DNS, SNMP, and ARP, fuses OUI vendor data with active fingerprints into a deduplicated, classified `DeviceRecord`, and emits each record as a Kafka event (or NDJSON / CSV file, or stdout). The core library (`rastreo-core`) is the product. The CLI (`rastreo`) and HTTP control plane (`rastreo-server`) are delivery mechanisms built on top of it; they own argument parsing, scenario loading, and process lifetime — never discovery logic.

The discovery pipeline is a single linear flow. Each stage consumes the previous stage's output and produces the input for the next:

```
+--------+    +----------+    +-----------+    +--------+    +--------------+    +-------+    +--------------+    +---------+    +-------+
| Target | -> | Resolver | -> | Scheduler | -> | Prober | -> | ProbeOutcome | -> | Fuser | -> | DeviceRecord | -> | Encoder | -> | Sink  |
+--------+    +----------+    +-----------+    +--------+    +--------------+    +-------+    +--------------+    +---------+    +-------+
```

Stages `Target` through `ProbeOutcome` are wired today. `Fuser`, `DeviceRecord`, `Encoder`, and `Sink` are defined as types and traits with no concrete implementations registered yet. Each stage is an extension point — new probers, encoders, and sinks slot in by implementing the matching trait and registering with the matching factory.

## 2. Workspace structure

rastreo is organised as a Cargo workspace with three crates:

| Crate | Responsibility |
|-------|----------------|
| **rastreo-core** | Library crate. Owns the data model, the four pipeline traits, factory dispatch, the error hierarchy, and the scheduler. No `main` function. This crate is the product. |
| **rastreo** | Binary crate. CLI. A thin layer over `rastreo-core`: argument parsing with `clap`, YAML scenario loading, config merge, and runner invocation. Contains no discovery logic. |
| **rastreo-server** | Binary crate. HTTP control plane built on `axum`. Exposes the same conceptual operations as the CLI via REST endpoints. Delegates all scenario validation and lifecycle to `rastreo-core`. |

The split lets `rastreo-core` be published to crates.io independently of the binaries, isolates server-only runtime concerns (axum, hyper) inside `rastreo-server`, and allows the three crates to compile in parallel. Each crate has its own `CLAUDE.md` documenting the module layout, allowed dependencies, and contribution conventions.

## 3. Data model

The data model is defined in `rastreo-core::model`. Types are deliberately format-agnostic — wire serialization is the encoder's concern, not the model's.

### `Target`

A `Target` is what the user asked rastreo to scan. Four variants cover the common discovery inputs:

```rust
pub enum Target {
    Ip(IpAddr),
    Cidr(IpNet),
    Range { start: IpAddr, end: IpAddr },
    DnsName(String),
}
```

### `ResolvedTarget`

A `ResolvedTarget` is the output of the resolver — a concrete IP, the original target it was derived from (for reverse mapping), and the resolution timestamp.

```rust
pub struct ResolvedTarget {
    pub ip: IpAddr,
    pub original: Target,
    pub resolved_at: SystemTime,
}
```

### `ProbeKind`

A discriminator naming the protocol family of a probe. Used both at runtime (the prober declares its kind) and on the wire (encoders may include it in their output).

```rust
pub enum ProbeKind {
    TcpConnect,
    Udp,
    Http,
    Dns,
    Snmp,
    Arp,
}
```

### `Signal`

A `Signal` is a single observable fact discovered during a probe. The variant set is small and protocol-family-agnostic — encoders interpret signals into protocol-specific wire content.

```rust
pub enum Signal {
    OpenPort(u16),
    HttpBanner(String),
    SnmpSysObjectId(String),
    SnmpSysDescr(String),
    Mac(String),
    DnsHost(String),
}
```

### `ProbeCtx`

Per-probe execution context — supplied by the scheduler when invoking a prober.

```rust
pub struct ProbeCtx {
    pub timeout: Duration,
    pub retries: u32,
}
```

### `ProbeOutcome`

The structured result of one probe against one resolved target. Reachability is a derived boolean: `true` iff the probe collected at least one signal.

```rust
pub struct ProbeOutcome {
    pub kind: ProbeKind,
    pub target_ip: IpAddr,
    pub timestamp: SystemTime,
    pub reachable: bool,
    pub signals: Vec<Signal>,
}
```

### `IdentityKey`, `Confidence`, `DeviceRecord`

The fused, deduplicated representation of a discovered device. `IdentityKey` wraps a normalised string (trimmed, lowercased) used to merge probe outcomes across protocols and time. `Confidence` is a validated `f64` in `[0.0, 1.0]`. `DeviceRecord` carries the union of fields — management IP, MAC, manufacturer, platform, role — with a confidence score and the underlying signals that produced the record.

```rust
pub struct DeviceRecord {
    pub identity_key: IdentityKey,
    pub mgmt_ip: Option<IpAddr>,
    pub mac: Option<String>,
    pub manufacturer: Option<String>,
    pub platform: Option<String>,
    pub role: Option<String>,
    pub confidence: Confidence,
    pub last_seen: SystemTime,
    pub signals: Vec<Signal>,
}
```

## 4. Traits and factories

Every extension point in `rastreo-core` is a trait. Concrete implementations are constructed via a factory function that dispatches on a serde-deserializable config enum. Adding a new variant means: implement the trait, add an enum variant, add a match arm to the factory, add tests.

### `Resolver`

`Resolver` expands a `Target` into a list of `ResolvedTarget`. The default `HickoryResolver` handles IPs, CIDRs, IP ranges, and DNS names; it caps expansion at `DEFAULT_HOST_LIMIT` (65,536) to prevent accidental `/8` scans.

```rust
#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, target: &Target) -> Result<Vec<ResolvedTarget>, RastreoError>;
    async fn resolve_many(&self, targets: &[Target]) -> Result<Vec<ResolvedTarget>, RastreoError>;
}
```

The default implementation of `resolve_many` deduplicates across targets by IP. There is no factory for resolvers today — the library exposes `HickoryResolver` directly.

### `Prober`

`Prober` performs an active probe against a single resolved target and returns a structured outcome. Closed ports, refused connections, and timeouts are discovery results, not errors — `Err` is reserved for system-level failures the prober cannot classify.

```rust
#[async_trait::async_trait]
pub trait Prober: Send + Sync {
    fn kind(&self) -> ProbeKind;
    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError>;
}
```

Factory: `create_prober(&ProberConfig) -> Result<Box<dyn Prober>, RastreoError>`. The current `ProberConfig` carries one variant, `TcpConnect { ports: Vec<u16> }`, dispatched to `TcpConnectProber::new(ports)`.

### `Encoder`

`Encoder` serializes a `DeviceRecord` into a caller-provided byte buffer. The synchronous signature reflects encoding being a pure CPU step — the buffer is the output, allocations are the caller's choice.

```rust
pub trait Encoder: Send + Sync {
    fn encode_record(
        &self,
        record: &DeviceRecord,
        buf: &mut Vec<u8>,
    ) -> Result<(), RastreoError>;
}
```

Factory: `create_encoder(&EncoderConfig) -> Result<Box<dyn Encoder>, RastreoError>`. `EncoderConfig` is currently empty — no concrete encoder variants are registered yet.

### `Sink`

`Sink` writes encoded bytes to a destination. The interface is async to accommodate Kafka, HTTP, and other I/O-bound destinations. `last_write_delivered` lets batching sinks signal partial state to the runner.

```rust
#[async_trait::async_trait]
pub trait Sink: Send + Sync {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError>;
    async fn flush(&mut self) -> Result<(), RastreoError>;
    fn last_write_delivered(&self) -> bool { true }
}
```

Factory: `create_sink(&SinkConfig) -> Result<Box<dyn Sink>, RastreoError>` (async, because some sinks open network connections at construction time). `SinkConfig` is currently empty.

### `Scheduler`

`Scheduler` drives a shared `Arc<dyn Prober>` across a vector of resolved targets, returning per-target results in input order. The default `BoundedScheduler` caps concurrency with a `tokio::sync::Semaphore`.

```rust
#[async_trait::async_trait]
pub trait Scheduler: Send + Sync {
    async fn run(
        &self,
        prober: Arc<dyn Prober>,
        targets: Vec<ResolvedTarget>,
        ctx: ProbeCtx,
    ) -> Vec<Result<ProbeOutcome, RastreoError>>;
}
```

There is no factory for schedulers — `BoundedScheduler::new(max_concurrent)` and `BoundedScheduler::with_default_concurrency()` are the construction points.

## 5. Error hierarchy

All fallible APIs in `rastreo-core` return `Result<T, RastreoError>`. `RastreoError` is an umbrella enum over five sub-enums, each scoped to a failure domain:

```rust
pub enum RastreoError {
    Config(ConfigError),
    Probe(ProbeError),
    Resolver(ResolverError),
    Encoder(EncoderError),
    Sink(std::io::Error),
    Runtime(RuntimeError),
}
```

| Sub-enum | Scope |
|----------|-------|
| `ConfigError` | Invalid user configuration — bad YAML values, out-of-range fields, empty required collections. |
| `ProbeError` | Probe-level failures the prober chose to classify as errors: unreachable target, timeout, opaque protocol error. Closed/filtered ports are not in this enum — they are discovery results. |
| `ResolverError` | DNS lookup failures, CIDR/range expansions exceeding the configured host limit, inverted or mixed-family ranges. |
| `EncoderError` | Serialization failures, unsupported record shapes for a given wire format. |
| `RuntimeError` | Task panics and aborts surfaced from the scheduler. |

`RastreoError::Sink` wraps `std::io::Error` directly rather than via a `From` impl. There is no blanket `From<std::io::Error> for RastreoError` — every call site that touches I/O must classify the failure explicitly. This keeps `?` propagation honest: a sink I/O error never silently becomes a probe error.

## 6. Concurrency model

The default scheduler, `BoundedScheduler`, runs probes concurrently across targets with a configurable cap (default 64 in-flight). Each target spawns a `tokio::task`, which acquires a permit from a shared `tokio::sync::Semaphore` before invoking the prober. The prober is shared as `Arc<dyn Prober>` so the same instance services every spawned task.

Result order matches input order. The scheduler collects `JoinHandle`s in target order and awaits them sequentially; the underlying tasks still execute in parallel on the multi-thread runtime — only the await order constrains the result vector. A target whose probe returns `Err`, or whose task panics, does not abort the run: errors and `RuntimeError::TaskPanicked` are placed in the per-target slot and the rest of the targets finish.

The scheduler does not wrap probe invocations in `tokio::time::timeout`. Timeouts are the prober's concern (see §7).

## 7. Timeout ownership

Each prober owns its own timeout semantics. `ProbeCtx::timeout` is the soft budget the scheduler hands to every probe; how the prober uses it is up to the implementation. The scheduler does not wrap probes in a `tokio::time::timeout` wrapper, because a uniform deadline would amputate protocol-specific behavior:

- **TCP** needs to differentiate connect-timeout from read-timeout, and may want SYN-retransmit time inside a single budget.
- **SNMP** has per-PDU retry semantics that consume the budget incrementally.
- **HTTP** must split the budget between connect and read.

The `TcpConnectProber` applies `tokio::time::timeout(ctx.timeout, connect)` per port. Future probers may interpret the same `ProbeCtx::timeout` differently — as a total budget across retries, as a per-operation budget, or as a connect-only budget paired with a separate read timeout from the prober's own configuration.

## 8. Feature flag matrix

`rastreo-core` uses Cargo features to keep the default dependency footprint small. Library consumers who construct configs in code can disable `config` and avoid the YAML stack entirely; consumers who do not need a given protocol family do not pay for its transitive dependencies.

| Feature | Default | Enables | Transitive deps pulled in |
|---------|---------|---------|---------------------------|
| `config` | yes | YAML scenario file parsing via `serde::Deserialize` on the config types. | `serde_yaml_ng` |
| `http` | no | HTTP prober and HTTP-based sinks. | (none yet) |
| `kafka` | no | Kafka sink for streaming discovered records. | (none yet) |
| `snmp` | no | SNMP prober for vendor and interface fingerprinting. | (none yet) |
| `arp` | no | ARP prober (requires raw-socket capability on the host). | (none yet) |

The CLI and HTTP server enable the features they need in their own `Cargo.toml`. Pre-built binaries and the Docker image enable every feature.

## 9. Scenario YAML schema

A scenario file is a top-level `ScenarioFile` value. It declares its version, kind, defaults applied to all entries, and a list of per-entry scenarios. The currently supported entry kind is `discover`.

```yaml
version: 1
kind: discovery

defaults:
  rate_limit: 50
  timeout_ms: 1000

scenarios:
  - signal_type: discover
    targets:
      - Ip: "192.168.1.1"
      - Cidr: "10.0.0.0/24"
      - DnsName: "router-1.lab.local"
    probers:
      - type: tcp_connect
        ports: [22, 80, 443]
```

`defaults` carries the `BaseProbeConfig` applied across all entries: optional name, rate limit, per-probe timeout, encoder, and sink. Each `ScenarioEntry::Discover` flattens its own `BaseProbeConfig` over the defaults and adds the list of `Target`s and `ProberConfig`s to run against them.

## 10. Extension points

Adding a new prober, encoder, or sink follows the same pattern in every case:

1. **Implement the trait** in a new file under the matching module (`rastreo-core/src/prober/`, `encoder/`, or `sink/`). Validate inputs in the constructor; reject invalid configurations with `ConfigError`.
2. **Add a config variant** to the matching enum (`ProberConfig`, `EncoderConfig`, `SinkConfig`). Use `#[serde(tag = "type", rename_all = "snake_case")]` so YAML stays consistent.
3. **Wire the factory** — add a match arm in `create_prober` / `create_encoder` / `create_sink`.
4. **Re-export** from the module's `mod.rs` and from `lib.rs`.
5. **Test** the construction path (empty / invalid config), the trait-impl behaviour (happy path, edge cases, error cases), the YAML round-trip (`serde_yaml_ng::from_str`), and the `Send + Sync` contract.
6. **Update** `rastreo-core/CLAUDE.md` to reflect the new file in the module layout.

Skill guides under `.claude/skills/` (when present) document the exact mechanical steps and the test scaffolding to mirror.
