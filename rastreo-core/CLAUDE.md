# rastreo-core — The Engine

This is the library crate. It owns **all** domain logic. If it probes a network, fuses enrichment data, classifies a device, encodes a record, or delivers output — it lives here.

## Module Layout

```
src/
├── lib.rs           ← crate-root re-exports + version()
├── error.rs         ← RastreoError umbrella + sub-enums + ProbeErrorKind taxonomy
├── model/
│   ├── target.rs        ← Target, ResolvedTarget
│   ├── outcome.rs       ← ProbeKind, ProbeOutcome, ProbeFault, Signal, ProbeCtx
│   ├── device.rs        ← DeviceRecord, IdentityKey, AltIp, AltIpRole
│   ├── scan.rs          ← ScanMetadata, source_config_hash
│   └── serde_iso8601.rs ← RFC 3339 serde helpers for SystemTime
├── resolver/
│   ├── mod.rs       ← Resolver trait + HickoryResolver default impl
│   └── guarded.rs   ← GuardedResolver decorator (allow-list + aggregate host cap)
├── prober/
│   ├── mod.rs           ← Prober trait + ProberConfig + create_prober factory
│   ├── classify.rs      ← shared absence-vs-fault classifier (io / hickory errors) + chain walkers
│   ├── tcp_connect.rs   ← TcpConnectProber
│   ├── http.rs          ← HttpProber (feature: http)
│   ├── dns.rs           ← DnsProber
│   ├── reverse_dns.rs   ← ReverseDnsProber (PTR lookup; no feature — reuses hickory-resolver)
│   ├── udp/             ← UdpProber (NTP / SIP / memcached / STUN)
│   ├── snmp/            ← SnmpProber v1/v2c/v3-USM (feature: snmp)
│   ├── arp.rs           ← ArpProber (feature: arp)
│   ├── ndp.rs           ← NdpProber (feature: ndp)
│   ├── link_layer.rs    ← LinkLayerProtocol trait + shared ARP/NDP resolution engine (feature: arp or ndp)
│   ├── ssh.rs           ← SshProber (feature: ssh)
│   ├── icmp.rs          ← IcmpProber (feature: icmp)
│   ├── tls.rs           ← TlsProber (feature: tls)
│   └── redacted.rs      ← Password, Community — Debug + Serialize redact plaintext
├── encoder/
│   ├── mod.rs       ← Encoder trait + EncoderConfig + create_encoder factory
│   └── ndjson.rs    ← NdjsonEncoder
├── sink/
│   ├── mod.rs       ← Sink trait + SinkConfig + create_sink factory
│   ├── stdout.rs    ← StdoutSink
│   ├── file.rs      ← FileSink
│   ├── memory.rs    ← MemorySink + MemorySinkHandle
│   ├── kafka.rs     ← KafkaSink (feature: kafka)
│   └── nats.rs      ← NatsSink (feature: nats)
├── scheduler/mod.rs ← Scheduler trait + BoundedScheduler default impl
├── fuser/
│   ├── mod.rs       ← Fuser trait + DirectFuser default impl
│   ├── oui.rs       ← OuiEnrichmentFuser (feature: oui)
│   └── identity.rs  ← IdentityFuser (MAC + SnmpSysName + SshHostKey + TlsSubject + TlsSanName + ReverseDnsName correlation)
├── classifier/
│   ├── mod.rs           ← Classifier trait + ClassifierConfig + create_classifier factory + NoopClassifier / RulesClassifier
│   ├── platform_rules.rs ← Baked-in default PlatformRule table
│   └── role_rules.rs    ← Baked-in default RoleRule table
├── observability/
│   ├── mod.rs           ← module root
│   └── otlp_config.rs   ← OtlpProtocol enum + shared env-var parsers (parse_env_bool / parse_env_u64 / parse_env_protocol) + http_endpoint_for_signal; consumed by rastreo and rastreo-server. No OpenTelemetry deps — pure types + string parsing.
├── pipeline.rs     ← run_discovery + DiscoverySummary
├── plan.rs         ← DiscoveryPlan + PlanKnobs (exhaustive dry-run plan render + Display)
└── config/mod.rs    ← ScenarioFile + ScenarioEntry + BaseProbeConfig
```

## Cargo Features

| Feature  | Default | Description |
|----------|---------|-------------|
| `config` | yes     | Pulls in `serde_yaml_ng` for YAML scenario-file parsing. Disable for library consumers who construct configs in code and do not need YAML deserialization. |
| `http`   | no      | Enables the HTTP prober (`reqwest` + rustls-webpki-roots). Also pulls `rustls` directly, so a `rustls::Error` in reqwest's source chain can be recognized as proof the TCP connect completed — the port is open even when the TLS handshake fails. |
| `kafka`  | no      | Enables `KafkaSink` (rskafka producer). Optional TLS (rustls with embedded webpki-roots plus an optional custom CA; permissive `verify: false` default) and optional SASL auth (PLAIN / SCRAM-SHA-256 / SCRAM-SHA-512) each opt in independently, so PLAINTEXT, SSL, SASL_PLAINTEXT, and SASL_SSL all compose. |
| `snmp`   | no      | Enables the SNMP prober for vendor / interface fingerprinting. |
| `arp`    | no      | Enables the ARP prober for IPv4 link-layer MAC discovery (requires `CAP_NET_RAW` at runtime). |
| `ndp`    | no      | Enables the NDP prober for IPv6 link-layer MAC discovery (requires `CAP_NET_RAW` at runtime). |
| `ssh`    | no      | Enables the SSH prober. Reads the pre-negotiation banner and captures the server's host key via `russh` (client mode, `ring` crypto backend). No authentication is attempted. |
| `icmp`   | no      | Enables the ICMP echo prober. Hand-rolled `pnet_packet::icmp` + `socket2` with SOCK_DGRAM → SOCK_RAW fallback (requires `CAP_NET_RAW` on Linux for the raw path). Emits per-target minimum RTT in microseconds. |
| `tls`    | no      | Enables the TLS handshake prober. `tokio-rustls` (`ring` backend) + `x509-parser` extract the leaf certificate's Subject CN and SANs. Accept-any-cert verifier — fingerprinting, not authenticating. |
| `nats`   | no      | Enables `NatsSink` (`async-nats` JetStream client with `ring` crypto backend). |
| `oui`    | no      | Enables the `oui_enrichment` fuser and bundles a compressed Wireshark manuf snapshot (`data/manuf.gz`, ~800 KB in-binary). Populates `DeviceRecord::manufacturer` from a MAC-address OUI lookup. |

The `config`, `http`, `kafka`, `snmp`, `arp`, `ndp`, `ssh`, `icmp`, `tls`, `nats`, and `oui` features each pull in their own dependency chain when enabled. `arp`, `ndp`, and `icmp` share the `pnet_packet` chain — enabling any of them pulls it in (`arp` and `ndp` additionally pull `pnet_datalink` + `ipnetwork` + `socket2`). `ssh`, `tls`, and `nats` all use `ring` as the crypto backend, so enabling any of them brings the `ring` chain in.

The reverse DNS prober (`ReverseDnsProber`) is unconditional — it reuses `hickory-resolver` which is already required for the forward-resolver machinery. No Cargo feature guards it.

## Prober Config Conventions

Every prober (`TcpConnect`, `Http`, `Dns`, `ReverseDns`, `Udp`, `Snmp`, `Arp`, `Ndp`, `Ssh`, `Icmp`, `Tls`) is a variant on `ProberConfig` — a `#[serde(tag = "type", rename_all = "snake_case")] #[non_exhaustive]` tagged enum. New probers slot in without breaking existing scenarios because `#[non_exhaustive]` prevents downstream exhaustive matching.

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

**Where knobs live.** Scenario-level knobs stay on `BaseProbeConfig`: `timeout_ms` propagates to every prober via `ProbeCtx`, while `max_concurrent` and `probe_rate` configure the `BoundedScheduler` (in-flight cap and probe-start pace). Individual probers do NOT re-declare these fields. If a future protocol genuinely needs a per-probe deviation, that's a case for a scoped override field on the specific variant, not a hoist of the shared knobs.

**Retries.** `BaseProbeConfig.retries` (threaded via `ProbeCtx.retries`, default 0) is an opt-in retransmit count honored only by connectionless probers that lack native retransmission — UDP service probers, SNMP v1/v2c/v3 (v3 retransmits the engine discovery exchange), DNS/reverse_dns (re-issue the hickory lookup; hickory's own `attempts` is inert behind the 3600s inner timeout), and ARP/NDP (re-send the request frame on no-reply). Each re-sends on no-response within a per-attempt slice of `timeout_ms / (retries + 1)`, so the total per-probe deadline is unchanged; a *received* answer — records, `NoRecords`, or `NXDOMAIN` — is the server responding and stops the retries, while exhausted retries with no reply is absence (`reachable=false`), never a fault. TCP-based probers (transport retransmits) and ICMP (already sends `count` echoes) ignore it.

**Security-toggle default polarity.** Discovery-oriented toggles like `tls_verify` default to the permissive value (`false`), because rastreo is aimed at unknown / lab / internal networks where self-signed and expired certificates are the norm. Users on trusted networks opt into strict mode with an explicit `tls_verify: true`. This is a deliberate departure from the Rust HTTP-client ecosystem's strict-by-default convention; document the default and the rationale on the prober's docs page.

The SSH prober follows the same permissive posture without a toggle: it offers legacy KEX/cipher/MAC algorithms (`diffie-hellman-group14-sha1`/`-group1-sha1`/`-group-exchange-sha1`, AES-CBC, `hmac-sha1`) appended after russh's modern defaults, so a legacy-only IOS/NX-OS/JunOS server completes negotiation and its host key is captured. Fingerprinting reads the host key over a read-only handshake and never authenticates, so offering weak crypto to finish the handshake carries no credential exposure.

**Constructor signature.** `<Prober>::new(fields...)` takes concrete types (never `Option<T>`) and returns `Result<Self, RastreoError>`. Validation errors surface as `ConfigError::InvalidValue`. Empty required collections (like `ports` for network-layer probers) are validated at construction time. The factory arm in `prober::create_prober` clones the fields out of the config variant and hands them to the constructor.

**Documentation page.** Every prober gets a page under `docs/site/docs/probe/<name>.md` with these sections in order: intro paragraph, `## Configuration` (field table matching the struct), any protocol-specific resolution table (e.g. HTTP's scheme resolution), TLS or security notes, `## Signals emitted`, `## Build feature`, `## Example scenario`, `## See also`. Update `docs/site/docs/probe/index.md` and `docs/site/docs/reference/scenario.md` when adding a new prober.

## Error Handling

- Define errors using `thiserror`. Every public function returns `Result<T, RastreoError>`.
- Never `unwrap()` in this crate. Use `?` propagation or explicit error mapping.
- The structured error hierarchy uses sub-enums per failure domain (`ConfigError`, `ProbeError`, `ResolverError`, `EncoderError`, `RuntimeError`) accessed via the umbrella `RastreoError`. No blanket `From<std::io::Error>` — sink call sites map I/O failures to `RastreoError::Sink` explicitly.

**The reachability contract.** A probe result is a complete, typed record of what the probe learned. `probe()` returns `Ok(ProbeOutcome)` whenever it attempted a target; the outcome carries `reachable`, `signals`, and a typed `fault: Option<ProbeFault>`. A target that does not answer is `Ok(ProbeOutcome { reachable: false, signals: [], fault: None })`. A probe that broke is `Ok(ProbeOutcome { fault: Some(ProbeFault { kind, detail }) })` — the fault is data, never discarded. `Err` from `probe()` is vestigial: reserved for "could not attempt at all" (e.g. a panicked blocking thread → `RuntimeError`); the pipeline still handles a stray `Err` by counting it as `ProbeErrorKind::Other`.

- Faults are named by `ProbeErrorKind`, never by string-matching. `ProbeFault { kind, detail }` carries the kind plus a sample detail string for the summary.
- Decide by *reason*, not by counting. `prober::classify` is the single seam: `io_error` and `net_error` (hickory) each return `Absence` or `Fault(ProbeErrorKind)`. `rustls_error_in_chain` is a chain *walker*, not a classifier — a rustls error proves the TCP connect completed, so HTTP credits the port as open. Probers build a `ProbeFault` from the classifier's kind.
- An unclassified failure is a **fault**, never absence. A visible fault is recoverable; a fault hidden as a dark host is not.
- Multi-port probers latch the fault and surface it on the outcome only when nothing answered: silence on one port is not evidence against a fault on another, but an answer is. The exception is a reply the probe cannot decode (SNMP): the agent answered, so the device is kept (`reachable: true`) with the `DecodeFailed` fault recorded and no signals.
- The pipeline derives `DiscoverySummary.error_counts` (by `ProbeErrorKind`) and `first_probe_error` from `outcome.fault`, not from `Err`. A faulted-but-reachable outcome still fuses into a record.
- Every `ProbeKind` must be able to report both. `tests/reachability_contract.rs` walks `ProbeKind::all()` and fails until a new kind declares both halves — an absent target as `Ok`-without-fault, a broken probe as `Ok`-with-`fault` — as a live probe case, or as the named unit-test seam covering it.

## Performance Guidelines

- No per-record allocations on the hot path. The probe → fuse → classify → encode → write pipeline must write into pre-allocated or caller-provided memory in steady state.
- Pre-build invariant content (label prefixes, validated names) at construction time.
- Use `BufWriter` for any file or socket sink.
- Benchmark before optimizing. Do not optimize speculatively.
- `IdentityFuser` correlation is bucketed, not a full pair scan: records are indexed by their correlation values (MAC, sysName, SSH host key, TLS subject, TLS SAN, reverse DNS) and only intra-bucket pairs are weighed. Any new correlation contribution must add a matching bucket key derived from the *same* helper and normalization the contribution's equality test uses, or the bucketed candidate set silently drops a merge. The differential test in `fuser/identity.rs` pins bucketed output against a `#[cfg(test)]` brute-force reference and must stay green.

## Trait Shape

The `Fuser` trait is streaming-native: `ingest(Vec<ProbeOutcome>) -> Result<Vec<DeviceRecord>>` takes one target's outcomes at a time and returns records ready to emit, while `finish() -> Result<Vec<DeviceRecord>>` flushes records held back for cross-target correlation. `IdentityFuser` buffers its inner records across `ingest` calls and emits the correlated set on `finish`; `DirectFuser`/`OuiEnrichmentFuser` emit per `ingest` and return nothing from `finish`. The pipeline drives this as a stream: it ingests each target the moment its scan completes (in input-target order via a reorder buffer) and emits the returned records straight to the sink, so a `DirectFuser` record reaches the sink before the scan finishes. `Identity` still emits its correlated set at `finish` because correlation needs the whole record set. Because `resolve_many` deduplicates by IP, each `target_index` is a distinct IP, so per-target ingest is equivalent to the batch `fuser::group_outcomes_by_ip` grouping. A `#[cfg(test)]` batch reference (`group_outcomes_by_ip` + `drive_fuser` in `fuser`, `finish_discovery_ref` in `pipeline.rs`) is retained and differential-tested against the streaming path; the `fuser/identity.rs` reference against the old `fuse_many` semantics must also stay green. `Identity` is enforced as the outermost fuser — `FuserConfig::validate` rejects nesting it inside `OuiEnrichment` or another `Identity` — so this equivalence holds for every representable config (the one shape that diverged under streaming is now invalid).

`Scheduler::run_scan` is the target-outer contract: it runs every prober against every target, bounds in-flight probes to the concurrency cap, paces probe starts, and sends each fully-scanned target's outcomes — each tagged with its prober pass index — on a bounded `mpsc` channel the moment its last prober completes (completion order). The bounded channel backpressures the scan to the consumer's pace: when the sink paces the scan, a slow sink blocks the producer and in-flight state (the pipeline's reorder buffer plus the channel) stays bounded by the concurrency window rather than the target count. This is a steady-state expectation, not an enforced cap: a fast sink draining ahead of a pathologically-slow earliest target lets the consumer empty the channel while `next_expected` waits, so the reorder buffer can grow to O(N) — the same bound the batch path always held. The pipeline reorders completions by `target_index` and reconstructs the batch's order-sensitive results: records in input-target order, and `first_probe_error` at the smallest `(prober_pass_index, target_index)` key (the fault a prober-outer scan would have latched first). Order-insensitive metrics (`probe_attempts`, `error_counts`, per-kind tallies, DLQ) are sums and do not depend on scan order. On an emit error mid-scan the pipeline stops emitting but keeps draining the scan, so every target still probes and `probe_attempts`/`error_counts`/`first_probe_error`/`probes_by_kind` stay complete (only `records_emitted` is partial) — identical to the batch pipeline, which accumulates the whole scan before emitting. A cancelled scan stops priming new probes, lets in-flight probes drain, and emits only the fully-scanned targets (a contiguous input-order prefix), so the pipeline emits complete records for the targets that finished.

## Testing

- Unit tests live in `#[cfg(test)] mod tests` at the bottom of each file.
- Integration tests live under `rastreo-core/tests/`.
- Use `rstest` for parametrized test families.
- Use `insta` for golden-file snapshots of structured outputs.
- Seed every randomized component for deterministic tests.
- `tests/kafka_integration.rs` and `tests/nats_integration.rs` stand up a real broker with `testcontainers`, so they need a running Docker daemon and are `#[ignore]`d to stay out of the default suite. Run them with `cargo test -p rastreo-core --features kafka,nats --test kafka_integration --test nats_integration -- --ignored`.
- `KafkaSink::new` bounds the whole broker connect (`build` + `partition_client`) with `CONNECT_TIMEOUT` (10s) so a black-hole broker fails fast instead of hanging; the in-module black-hole test exercises the seam with a 1s timeout. `NatsSink` relies on `async-nats`' own bounded initial connect (default 5s `connection_timeout`, no retry-on-initial-connect).

## Extension Points

To add a prober, encoder, or sink: implement the matching trait, register the implementation in its factory, and add unit tests covering happy path, edge cases, and error cases.
