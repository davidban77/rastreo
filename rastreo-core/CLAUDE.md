# rastreo-core — The Engine

This is the library crate. It owns **all** domain logic. If it probes a network, fuses enrichment data, classifies a device, encodes a record, or delivers output — it lives here.

## Module Layout

```
src/
├── lib.rs       ← crate-root re-exports + version()
├── error.rs     ← RastreoError umbrella + sub-enums
├── model/
│   ├── target.rs    ← Target, ResolvedTarget
│   ├── outcome.rs   ← ProbeKind, ProbeOutcome, Signal, ProbeCtx
│   └── device.rs    ← DeviceRecord, IdentityKey, Confidence
├── resolver/mod.rs  ← Resolver trait + HickoryResolver default impl
├── prober/
│   ├── mod.rs       ← Prober trait + ProberConfig + create_prober factory
│   └── tcp_connect.rs ← TcpConnectProber
├── encoder/
│   ├── mod.rs       ← Encoder trait + EncoderConfig + create_encoder factory
│   └── ndjson.rs    ← NdjsonEncoder
├── sink/
│   ├── mod.rs       ← Sink trait + SinkConfig + create_sink factory
│   ├── stdout.rs    ← StdoutSink
│   ├── file.rs      ← FileSink
│   ├── memory.rs    ← MemorySink + MemorySinkHandle
│   └── kafka.rs     ← KafkaSink (feature: kafka)
├── scheduler/mod.rs ← Scheduler trait + BoundedScheduler default impl
├── fuser/mod.rs     ← Fuser trait + DirectFuser default impl
├── pipeline.rs     ← run_discovery + DiscoverySummary
└── config/mod.rs    ← ScenarioFile + ScenarioEntry + BaseProbeConfig
```

## Cargo Features

| Feature  | Default | Description |
|----------|---------|-------------|
| `config` | yes     | Pulls in `serde_yaml_ng` for YAML scenario-file parsing. Disable for library consumers who construct configs in code and do not need YAML deserialization. |
| `http`   | no      | Enables the HTTP prober (`reqwest` + rustls-webpki-roots). |
| `kafka`  | no      | Enables `KafkaSink` (rskafka producer with rustls TLS support and embedded webpki-roots). |
| `snmp`   | no      | Enables the SNMP prober for vendor / interface fingerprinting. |
| `arp`    | no      | Enables the ARP prober for IPv4 link-layer MAC discovery (requires `CAP_NET_RAW` at runtime). |
| `ndp`    | no      | Enables the NDP prober for IPv6 link-layer MAC discovery (requires `CAP_NET_RAW` at runtime). |

The `config`, `http`, `kafka`, `snmp`, `arp`, and `ndp` features each pull in their own dependency chain when enabled. `arp` and `ndp` share the `pnet_datalink` + `pnet_packet` + `ipnetwork` dep chain — enabling either pulls the full set in.

## Prober Config Conventions

Every prober (`TcpConnect`, `Http`, and any future `Udp` / `Dns` / `Snmp` / `Arp` addition) is a variant on `ProberConfig` — a `#[serde(tag = "type", rename_all = "snake_case")] #[non_exhaustive]` tagged enum. New probers slot in without breaking existing scenarios because `#[non_exhaustive]` prevents downstream exhaustive matching.

**Field naming.** snake_case. Prefer descriptive nouns over abbreviations (`user_agent` over `ua`, `path` over `endpoint`, `query_names` over `queries`). If the protocol has a well-known term, use it verbatim (`community` for SNMP, `interface` for ARP).

**Field ordering inside a variant.** `ports: Vec<u16>` first for any network-layer prober (omit for link-layer probers like ARP). Then protocol-specific mandatory fields. Then protocol-specific optional fields with defaults. Example:

```rust
Http {
    ports: Vec<u16>,                                             // mandatory, no default
    #[serde(default)]
    scheme: HttpScheme,                                          // optional, enum default via #[derive(Default)]
    #[serde(default = "http::default_path")]
    path: String,                                                // optional, typed default from free fn
    #[serde(default = "http::default_tls_verify")]
    tls_verify: bool,
    #[serde(default = "http::default_user_agent")]
    user_agent: String,
},
```

**Optional field shape.** Use `#[serde(default = "prober_module::default_<field>")]` returning the concrete type. Never `Option<T>`. A YAML author who omits the field gets the typed default — no `path: null` in scenarios, no `Option::unwrap_or_else` inside the prober constructor.

- Each default is a free `pub fn default_<field>()` in the prober's module. `pub` so tests and consumers can reference it. Doc-commented with the returned value and, where non-obvious, the rationale.
- Rationale for the pattern: YAML users write scenarios by hand. `path: /` is idiomatic; `path: null` is not. Typed defaults keep the wire format ergonomic and move the "what if it's missing?" decision to a single greppable location.

**Sub-enums for enumerable choices.** Nested enums like `HttpScheme::{Auto, Http, Https}` derive `Default` with the sensible variant (`Auto` in the HTTP case). `#[serde(rename_all = "snake_case")]` keeps YAML lowercase.

**Where knobs live.** Cross-prober knobs (`rate_limit`, `timeout_ms`, `retries`) stay on `BaseProbeConfig` at the scenario level and propagate to every prober via `ProbeCtx`. Individual probers do NOT re-declare these fields. If a future protocol genuinely needs a per-probe deviation, that's a case for a scoped override field on the specific variant, not a hoist of the shared knobs.

**Security-toggle default polarity.** Discovery-oriented toggles like `tls_verify` default to the permissive value (`false`), because rastreo is aimed at unknown / lab / internal networks where self-signed and expired certificates are the norm. Users on trusted networks opt into strict mode with an explicit `tls_verify: true`. This is a deliberate departure from the Rust HTTP-client ecosystem's strict-by-default convention; document the default and the rationale on the prober's docs page.

**Constructor signature.** `<Prober>::new(fields...)` takes concrete types (never `Option<T>`) and returns `Result<Self, RastreoError>`. Validation errors surface as `ConfigError::InvalidValue`. Empty required collections (like `ports` for network-layer probers) are validated at construction time. The factory arm in `prober::create_prober` clones the fields out of the config variant and hands them to the constructor.

**Documentation page.** Every prober gets a page under `docs/site/docs/probe/<name>.md` with these sections in order: intro paragraph, `## Configuration` (field table matching the struct), any protocol-specific resolution table (e.g. HTTP's scheme resolution), TLS or security notes, `## Signals emitted`, `## Build feature`, `## Example scenario`, `## See also`. Update `docs/site/docs/probe/index.md` and `docs/site/docs/reference/scenario.md` when adding a new prober.

## Error Handling

- Define errors using `thiserror`. Every public function returns `Result<T, RastreoError>`.
- Never `unwrap()` in this crate. Use `?` propagation or explicit error mapping.
- The structured error hierarchy uses sub-enums per failure domain (`ConfigError`, `ProbeError`, `ResolverError`, `EncoderError`, `RuntimeError`) accessed via the umbrella `RastreoError`. No blanket `From<std::io::Error>` — sink call sites map I/O failures to `RastreoError::Sink` explicitly.

## Performance Guidelines

- No per-record allocations on the hot path. The probe → fuse → classify → encode → write pipeline must write into pre-allocated or caller-provided memory in steady state.
- Pre-build invariant content (label prefixes, validated names) at construction time.
- Use `BufWriter` for any file or socket sink.
- Benchmark before optimizing. Do not optimize speculatively.

## Testing

- Unit tests live in `#[cfg(test)] mod tests` at the bottom of each file.
- Integration tests live under `rastreo-core/tests/`.
- Use `rstest` for parametrized test families.
- Use `insta` for golden-file snapshots of structured outputs.
- Seed every randomized component for deterministic tests.

## Extension Points

To add a prober, encoder, or sink: implement the matching trait, register the implementation in its factory, and add unit tests covering happy path, edge cases, and error cases.
