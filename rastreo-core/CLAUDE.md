# rastreo-core — The Engine

This is the library crate. It owns **all** domain logic. If it probes a network, fuses enrichment data, classifies a device, encodes a record, or delivers output — it lives here.

## Module Layout

```
src/
├── lib.rs           ← crate-root re-exports + version()
├── error.rs         ← RastreoError umbrella + sub-enums + ProbeErrorKind taxonomy
├── checkpoint/mod.rs ← Checkpoint (atomic write/load) + resume eligibility predicates + two-tier resume fingerprint
├── model/
│   ├── target.rs        ← Target, ResolvedTarget
│   ├── outcome.rs       ← ProbeKind, ProbeOutcome, ProbeFault, Signal, ProbeCtx, GnmiEndpoint, Transport
│   ├── device.rs        ← DeviceRecord, IdentityKey, AltIp, AltIpRole
│   ├── collection_profile.rs ← CollectionProfileRecord, Collection (protocol-tagged), ProfileEndpoint, ProfileConfidence, Subscription
│   ├── scan.rs          ← ScanMetadata, source_config_hash
│   └── serde_iso8601.rs ← RFC 3339 serde helpers for SystemTime
├── resolver/
│   ├── mod.rs       ← Resolver trait (plan → ResolvedPlan → lazy resolve_stream/resolve_many) + HickoryResolver default impl
│   └── guarded.rs   ← GuardedResolver decorator (spec-level allow-list + arithmetic aggregate host cap, both pre-flight)
├── prober/
│   ├── mod.rs           ← Prober trait + ProberConfig + create_prober factory
│   ├── selection.rs     ← probe-kind name parsing, default set, and expansion into ProberConfig
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
│   ├── mod.rs       ← Encoder trait + EncoderConfig + create_encoder factory + ensure_encoder_output_fits_sink
│   ├── ndjson.rs    ← NdjsonEncoder
│   └── table.rs     ← TableEncoder (fixed-width ADDRESS/NAME/PLATFORM/PORTS triage view; device records only)
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
│   ├── mib.rs       ← MibEnrichmentFuser + MibTable (feature: mib_enrichment)
│   └── identity.rs  ← IdentityFuser (MAC + SnmpSysName + SshHostKey + TlsSubject + TlsSanName + ReverseDnsName correlation)
├── classifier/
│   ├── mod.rs           ← Classifier trait + ClassifierConfig + create_classifier factory + NoopClassifier / RulesClassifier (Rules over the baked tables is the pipeline default) + SignalKind, the rule vocabulary shared by PlatformRule and RoleRule::SignalMatch
│   ├── platform_rules.rs ← Baked-in default PlatformRule table
│   └── role_rules.rs    ← Baked-in default RoleRule table (multi-port evidence only) + the opt-in single-port heuristics
├── oid.rs           ← crate-private dotted-decimal validation + arc-boundary subtree containment, shared by the classifier and the MIB table parser
├── observability/
│   ├── mod.rs           ← module root
│   └── otlp_config.rs   ← OtlpProtocol enum + shared env-var parsers (parse_env_bool / parse_env_u64 / parse_env_protocol / parse_env_headers) + http_endpoint_for_signal; consumed by rastreo and rastreo-server. No OpenTelemetry deps — pure types + string parsing.
├── collection_profile/
│   ├── mod.rs           ← CollectionProfileAssembler (per-gNMI-endpoint profiles, built from per-IP outcomes)
│   └── openconfig_paths.rs ← curated OpenConfig telemetry path table + advertised-model matcher (populates suggested_subscriptions)
├── pipeline.rs     ← run_discovery + DiscoverySummary + DiscoveryProgress (opt-in watch progress hook)
├── plan.rs         ← DiscoveryPlan + PlanKnobs (exhaustive dry-run plan render + Display)
├── redact.rs       ← crate-private server-URL userinfo stripping, shared by the plan render and the NATS sink's error text (feature: nats)
└── config/
    ├── mod.rs       ← ScenarioFile + ScenarioEntry + BaseProbeConfig + the parse entry points every config ingestion surface goes through
    └── secrets.rs   ← `${VAR}` / `!file` expansion + the non-disclosing shape-error seam (feature: config)
```

## Config Ingestion

`parse_scenario_file` and `parse_sink_config` expand `${VAR}` references and `!file` tags before deserializing; `parse_discover_scenario_json` does not, because the body is client-supplied and expanding it would read the server's environment back to the caller. Both file-backed entry points go through `deserialize_expanded`, which runs the retired-`type:`-tag walk over the *expanded* tree (a tag delivered through a reference must still be rejected) but reports a shape error from `secrets::shape_failure_detail`. Formatting the serde error raised over the expanded tree would disclose the secret, because serde quotes the offending scalar verbatim and `rastreo-server` publishes `last_probe_error` on the unauthenticated `/readyz`. `shape_failure_detail` instead re-deserializes a *reference-form* tree — raw, with `!file` tags flattened to the literal text `!file <path>`, because a raw re-parse of an internally-tagged enum fails on the tag itself and names nothing. The reported text can therefore only ever contain a `${VAR}` reference or an `!file` path. Anything that formats an error out of expanded data breaks the invariant; `config::tests::no_expanding_parse_entry_point_quotes_an_expanded_secret_in_a_shape_error` and `rastreo-server`'s `readyz_never_publishes_a_secret_expanded_into_a_malformed_sink_config` pin both halves.

The note `shape_failure_detail` appends states only what holds at every reference position, because the function has no schema knowledge and must not grow any: the references resolved (expansion errors on an unset variable long before shape validation), the text quotes them as written rather than the values they produced, and expansion substitutes a `Value::String`, so a reference can only fill a field that accepts a string. That last clause is the feature's ceiling, not a fixable mistake: a reference fills a string-valued position and nothing else — not `timeout_ms`, `max_concurrent`, `probe_rate`, or `retry.max_attempts`, not a boolean, not a sequence like `servers:`, and not an internally tagged enum like `flush_mode:`, whose wire form is a mapping (the `type:` string inside such a mapping does accept one). No referenced variable's contents change that. The note must not claim a value was withheld for secrecy: most reference positions hold no secret, and an operator who checks the field name against what it holds would rightly stop trusting the note where it *is* protecting a credential. `secrets::tests::the_note_claims_no_secrecy_for_a_reference_in_a_field_that_holds_none`, `secrets::tests::the_note_is_the_same_for_a_reference_in_a_numeric_field_and_in_a_stringly_typed_one`, and `config::tests::parse_scenario_file_rejects_a_reference_in_a_numeric_field_holding_a_valid_number` pin the wording and the ceiling.

## Second Streams

Beyond the primary `DeviceRecord` stream, the pipeline emits two additive record streams, each keyed by `RecordKind` at the sink boundary and versioned independently of the device record:

- **Links** (`RecordKind::Link`, `rastreo.discovery.links.v1`) — deduplicated topology edges from `TopologyAssembler`.
- **Collection profiles** (`RecordKind::CollectionProfile`, `rastreo.discovery.profiles.v1`) — one `CollectionProfileRecord` per gNMI endpoint that returned capability data, from `CollectionProfileAssembler`. The assembler builds from per-IP `ProbeOutcome`s (via the surfaced `ProbeOutcome::gnmi_endpoint`), not the merged `DeviceRecord`, because the identity fuser dedups signals across a device's IPs and would lose per-endpoint model attribution. It draws only from capability signals (`GnmiVersion` / `GnmiSupportedModel` / `GnmiSupportedEncoding`) and the endpoint — never `GnmiState`, whose values can be sensitive — and emits only when capability data is present (not on mere reachability).

Both assemblers run in `stream_discovery` and the `finish_discovery_ref` batch reference; the streaming-vs-batch differential test pins them field-identical. Sinks route each kind via `write_kind`; the Kafka/NATS sinks fan the second streams to their own topic/subject (`profiles_topic` / `profiles_subject`), and `Encoder::encode_profile` is a required trait method like `encode_link`.

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
| `mib_enrichment` | no | Enables the `mib_enrichment` fuser and bundles a small compressed sysObjectID seed (`data/mib_identity.gz`). Populates `DeviceRecord::model` / `product_family` (and `manufacturer` when unset) from an exact SNMP `sysObjectID` lookup. The bundled table is a stub; the `data_path` overlay merges a user fleet table on top (user keys win). |

The `config`, `http`, `kafka`, `snmp`, `arp`, `ndp`, `ssh`, `icmp`, `tls`, and `nats` features each pull in their own dependency chain when enabled. `arp`, `ndp`, and `icmp` share the `pnet_packet` chain — enabling any of them pulls it in (`arp` and `ndp` additionally pull `pnet_datalink` + `ipnetwork` + `socket2`). `ssh`, `tls`, and `nats` all use `ring` as the crypto backend, so enabling any of them brings the `ring` chain in.

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

## Encoders and Sinks

`Encoder` renders into a caller-provided `Vec<u8>`. An encoder with nothing to render for a record kind leaves the buffer untouched; `pipeline::write_encoded` — the single guard every emit site in `stream_discovery` and the batch reference goes through — skips the write and does not count the record. Never publish an empty message. `TableEncoder` is the case that exercises it: it renders device rows and returns `Ok(())` without writing for links and collection profiles.

All three of `encode_record`, `encode_link`, and `encode_profile` are required. The NDJSON one-object-per-line bodies live on `NdjsonEncoder`, not in the trait, so a new format states its own rendering for every stream rather than inheriting NDJSON semantics it never chose. Rendering nothing is a legitimate answer — but it has to be written down, because a silently dropped link stream reaches the operator as `banner.rs`'s links segment disappearing entirely, indistinguishable from a network with no LLDP.

**Trait defaults.** A default body may only encode a fact the trait can derive from its required methods, or a fact that is true of every implementor. When the honest answer depends on something only the implementor knows, there is no default — the method is required. This separates *behaviour* defaults (composition of required methods, always legal: `write_kind`, `close`, `Resolver::plan`) from *observation* defaults (reporting a fact about the implementor). To keep an observation default legal, add a required method it can derive from: `Sink::kind` is required precisely so `Sink::requires_structured_records` can stay defaulted.

`Sink::probe` is the deliberate exception, and stays defaulted to `Ok(())`. No fail-closed value exists — `Err` would make every local sink report unhealthy and break `/readyz` for stdout, file, and memory, which is the majority case — and the blast radius is an operator-visible health endpoint that self-corrects the moment a write fails, not silent data loss.

`Sink::dlq_records_delivered` and `Sink::dlq_records_by_class` are observation defaults that stay defaulted, because a dead-letter destination is a discrete opt-in: it arrives as one `dead_letter: Some(..)` block, so the override is necessarily co-located with the code that writes to it. That co-location is the discriminator, not the "nothing to report" phrasing — the same phrasing would have justified `last_write_delivered`'s removed default, and it must not. Delivery has no opt-in block to hang an override on: `MemorySink` and `FileSink` disagree with no capability edit between them, and `KafkaSink`'s answer varies at runtime with flush mode and buffer occupancy.

`Sink::last_write_delivered` is required, and reports `true` only once the bytes of the most recent `write` / `write_kind` have been accepted by the destination. It is `false` while they sit in a local buffer, which for `FileSink` and `StdoutSink` means every write revokes the claim and only a successful `flush` restores it — `BufWriter` may drain to the fd mid-write, but never observably. `MemorySink` is the one sink that publishes inside `write`, since its buffer *is* the destination; a write dropped by its byte cap clears the flag. Derivation from `SinkType` is not available: `KafkaSink` answers differently for the same kind depending on `KafkaFlushMode`, so synchronicity is `(kind × flush-mode × buffer occupancy)`, not a property of the kind. The rule holds on every stream: `KafkaSink` and `NatsSink` revoke the claim on a `Link` or `CollectionProfile` write too and restore it when that stream's own publish completes, while `flush` restores it only after all three buffers have published, and `TeeSink` recomputes the conjunction over its children on `flush` and `close` as well as on write — without that, a tee over a `FileSink` child reports `false` forever, which is the shape `rastreo-server` builds. `sink::tests::every_constructible_sink_claims_delivery_only_once_the_bytes_left_its_buffer` pins the family: expected answers come from an exhaustive match on `SinkConfig`, so a new variant fails to compile until it declares one; it walks two write/flush cycles, because on the first `false` is indistinguishable from "nothing has happened yet"; and it carries `TeeSink`, which no `SinkConfig` variant reaches. The `#[ignore]`d broker suites pin the Kafka and NATS second streams against a live broker.

`SinkType::requires_structured_records` is the single source of truth for destinations whose consumers parse each write as one structured record (`Kafka`, `Nats`). `Sink::kind` carries no default — every implementation must name its `SinkType`, because `Sink::requires_structured_records` defaults to `self.kind().requires_structured_records()` and an inherited kind would fail that guard open, silently admitting aligned-text output onto a broker topic. `KafkaSink` and `NatsSink` therefore need no structuredness override; `TeeSink` overrides with the disjunction over its children. The trait method is `async` for the same reason `probe` is — a fan-out sink answers by locking children held behind a `tokio::sync::Mutex`. `SinkConfig::requires_structured_records` reads the same table through `SinkConfig::sink_type`, so `rastreo validate` can check a config without constructing (and, for a broker, dialling) the sink. A new sink discharges four obligations — `Sink::kind` and `Sink::last_write_delivered`, plus the exhaustive matches in `SinkType::requires_structured_records` and `SinkConfig::sink_type`, neither of which an empty arm satisfies. `sink::tests::every_constructible_sink_config_agrees_with_the_sink_it_builds` pins kind and structuredness parity for the locally-constructible variants and `sink::tests::the_trait_default_reads_structuredness_off_the_sink_kind` pins both halves of the default body; the `#[ignore]`d broker integration tests pin Kafka and NATS against a live sink.

`encoder::ensure_encoder_output_fits_sink` owns the comparison. `run_discovery` calls it twice: once against `SinkConfig` before the sink is built, so a broker is rejected before the connect, and once against the resolved `Box<dyn Sink>`, which is the only guard a sink injected through `RunOptions::sink` passes.

## Error Handling

- Define errors using `thiserror`. Every public function returns `Result<T, RastreoError>`.
- Never `unwrap()` in this crate. Use `?` propagation or explicit error mapping.
- The structured error hierarchy uses sub-enums per failure domain (`ConfigError`, `ProbeError`, `ResolverError`, `EncoderError`, `RuntimeError`, `ResumeError`) accessed via the umbrella `RastreoError`. No blanket `From<std::io::Error>` — sink call sites map I/O failures to `RastreoError::Sink` explicitly.

**The reachability contract.** A probe result is a complete, typed record of what the probe learned. `probe()` returns `Ok(ProbeOutcome)` whenever it attempted a target; the outcome carries `reachable`, `signals`, and a typed `fault: Option<ProbeFault>`. A target that does not answer is `Ok(ProbeOutcome { reachable: false, signals: [], fault: None })`. A probe that broke is `Ok(ProbeOutcome { fault: Some(ProbeFault { kind, detail }) })` — the fault is data, never discarded. `Err` from `probe()` is vestigial: reserved for "could not attempt at all" (e.g. a panicked blocking thread → `RuntimeError`); the pipeline still handles a stray `Err` by counting it as `ProbeErrorKind::Other`.

- Faults are named by `ProbeErrorKind`, never by string-matching. `ProbeFault { kind, detail }` carries the kind plus a sample detail string for the summary.
- Decide by *reason*, not by counting. `prober::classify` is the single seam: `io_error` and `net_error` (hickory) each return `Absence` or `Fault(ProbeErrorKind)`. `rustls_error_in_chain` is a chain *walker*, not a classifier — a rustls error proves the TCP connect completed, so HTTP credits the port as open. Probers build a `ProbeFault` from the classifier's kind.
- An unclassified failure is a **fault**, never absence. A visible fault is recoverable; a fault hidden as a dark host is not.
- Multi-port probers latch the fault and surface it on the outcome only when nothing answered: silence on one port is not evidence against a fault on another, but an answer is. The exception is a reply the probe cannot decode (SNMP): the agent answered, so the device is kept (`reachable: true`) with the `DecodeFailed` fault recorded and no signals.
- The pipeline derives `DiscoverySummary.error_counts` (by `ProbeErrorKind`) and `first_probe_error` from `outcome.fault`, not from `Err`. A faulted-but-reachable outcome still fuses into a record.
- Every `ProbeKind` must be able to report both. `tests/reachability_contract.rs` walks `ProbeKind::all()` and fails until a new kind declares both halves — an absent target as `Ok`-without-fault, a broken probe as `Ok`-with-`fault` — as a live probe case, or as the named unit-test seam covering it.

## Performance Guidelines

- No per-record allocations on the hot path. The probe → fuse → classify → encode → write pipeline must write into pre-allocated or caller-provided memory in steady state. Encoding meets this; the emit path does not — see the allocation guards below for what it actually costs.
- Pre-build invariant content (label prefixes, validated names) at construction time.
- Use `BufWriter` for any file or socket sink.
- `tests/emit_path_guards.rs` counts heap allocations per record under `cargo test`, so an emit-path change is caught on every PR without a benchmark run. It pins the counts: `write` through a `Box<dyn Sink>` costs one boxed future; `write_kind` on a sink that does not override it costs two, because the trait default falls through to `write`; `pipeline::write_encoded` costs the same two, and zero when the encoder rendered nothing; a `TeeSink` with C children costs 1+C on `write` and 1+2C on `write_kind`; and NDJSON encoding into a buffer that already has capacity allocates nothing, because `model::serde_iso8601` renders `last_seen` and `scan_metadata.initiated_at` into a stack buffer rather than through chrono's `to_rfc3339_opts`, which returns a `String`. Future sizes are layout-dependent and not asserted — 32 B and 80 B on a debug build. The same file pins the benchmark's record fixture, which `DeviceRecord`'s `#[serde(default)]` fields would otherwise let rot silently.
- Benchmark before optimizing. Do not optimize speculatively. `cargo bench -p rastreo-core` runs the criterion suite in `benches/emit_path.rs` — sink dispatch (`write`, `write_kind`, the emit guard, and a sink that overrides `write_kind`) and encoder cost (`ndjson` vs `table`), each at 65 / 650 / 6500 records. Three sizes make size-independence visible and expose the fixed harness cost the smallest one carries (~1 ns/record), so quote the 6500 figures. Every comparison is between arms of a single run: the arms are hard-coded side by side, and cross-run `--save-baseline` / `--baseline` comparison is not the intended use — arms within one run resolve down to ~0.4%, while the same arm across two runs drifts by up to ~6%. Report deltas in ns/record, never as a bare percentage: the emit guard's +17 ns/record over a plain `write` is +2.2% of an NDJSON encode-and-write record (784 + 17 ns) and +14% of a table one (109 + 17 ns). The table encoder is ~7× cheaper per record only because it emits 100 bytes to NDJSON's 1156 — per output byte it is ~1.6× more expensive, not a fast path. A full run takes ~3 min and reports land in `target/criterion/`; `cargo bench -p rastreo-core -- --test` runs one iteration of each in ~2 s as a compile-and-run check.
- `IdentityFuser` correlation is bucketed, not a full pair scan: records are indexed by their correlation values (MAC, sysName, SSH host key, TLS subject, TLS SAN, reverse DNS) and only intra-bucket pairs are weighed. Any new correlation contribution must add a matching bucket key derived from the *same* helper and normalization the contribution's equality test uses, or the bucketed candidate set silently drops a merge. The differential test in `fuser/identity.rs` pins bucketed output against a `#[cfg(test)]` brute-force reference and must stay green.

## Trait Shape

The `Fuser` trait is streaming-native: `ingest(Vec<ProbeOutcome>) -> Result<Vec<DeviceRecord>>` takes one target's outcomes at a time and returns records ready to emit, while `finish() -> Result<Vec<DeviceRecord>>` flushes records held back for cross-target correlation. `IdentityFuser` buffers its inner records across `ingest` calls and emits the correlated set on `finish`; `DirectFuser`/`MibEnrichmentFuser` emit per `ingest` and return nothing from `finish`. The pipeline drives this as a stream: it ingests each target the moment its scan completes (in input-target order via a reorder buffer) and emits the returned records straight to the sink, so a `DirectFuser` record reaches the sink before the scan finishes. `Identity` still emits its correlated set at `finish` because correlation needs the whole record set. Resolution yields the concatenation of each target spec's expansion in input order with no cross-target dedup, so for non-overlapping specs (the normal case and every differential-test corpus) each `target_index` is still a distinct IP and per-target ingest is equivalent to the batch `fuser::group_outcomes_by_ip` grouping — the differential holds. Overlapping user specs are the one exception: they yield the shared addresses more than once, so a duplicate IP is probed and emitted per occurrence (`DirectFuser` emits one record each). That is detected and `tracing::warn!`ed pre-flight (naming the overlapping specs) and is the documented, accepted cost of dropping the dedup `HashSet` for lazy streaming — not a silent behavior change. A `#[cfg(test)]` batch reference (`group_outcomes_by_ip` + `drive_fuser` in `fuser`, `finish_discovery_ref` in `pipeline.rs`) is retained and differential-tested against the streaming path; the `fuser/identity.rs` reference against the old `fuse_many` semantics must also stay green. `Identity` is enforced as the outermost fuser — `FuserConfig::validate` rejects nesting it inside `MibEnrichment` or another `Identity` — so this equivalence holds for every representable config (the one shape that diverged under streaming is now invalid).

`Scheduler::run_scan` takes a lazy `Box<dyn Iterator<Item = ResolvedTarget> + Send>` (not a materialized `Vec`) so a huge scan never expands the address space up front. It is the target-outer contract: it pulls one target at a time — assigning a monotonic `target_index` on pull — runs every prober against it before advancing, bounds in-flight probes to the concurrency cap, paces probe starts, and sends each fully-scanned target's outcomes — each tagged with its prober pass index — on a bounded `mpsc` channel the moment its last prober completes (completion order). Each pulled target lives in an in-window `HashMap<usize, Arc<ResolvedTarget>>` from its first spawned probe until its last completes, so the scheduler's own target storage stays bounded by the concurrency window, not the target count. The bounded channel backpressures the scan to the consumer's pace: when the sink paces the scan, a slow sink blocks the producer and in-flight state (the scheduler's target map, the pipeline's reorder buffer, plus the channel) stays bounded by the concurrency window rather than the target count. This is a steady-state expectation, not an enforced cap: a fast sink draining ahead of a pathologically-slow earliest target lets the consumer empty the channel while `next_expected` waits, so the reorder buffer can grow to O(N) — the same bound the batch path always held. The pipeline reorders completions by `target_index` and reconstructs the batch's order-sensitive results: records in input-target order, and `first_probe_error` at the smallest `(prober_pass_index, target_index)` key (the fault a prober-outer scan would have latched first). Order-insensitive metrics (`probe_attempts`, `error_counts`, per-kind tallies, DLQ) are sums and do not depend on scan order. On an emit error mid-scan the pipeline stops emitting but keeps draining the scan, so every target still probes and `probe_attempts`/`error_counts`/`first_probe_error`/`probes_by_kind` stay complete (only `records_emitted` is partial) — identical to the batch pipeline, which accumulates the whole scan before emitting. A cancelled scan stops priming new probes, lets in-flight probes drain, and emits only the fully-scanned targets (a contiguous input-order prefix), so the pipeline emits complete records for the targets that finished.

## Testing

- Unit tests live in `#[cfg(test)] mod tests` at the bottom of each file.
- Integration tests live under `rastreo-core/tests/`.
- Use `rstest` for parametrized test families.
- Use `insta` for golden-file snapshots of structured outputs.
- Seed every randomized component for deterministic tests.
- `tests/kafka_integration.rs` and `tests/nats_integration.rs` stand up a real broker with `testcontainers`, so they need a running Docker daemon and are `#[ignore]`d to stay out of the default suite. Run them with `cargo test -p rastreo-core --features kafka,nats --test kafka_integration --test nats_integration -- --ignored`.
- The `#[ignore]`d tests in `sink/nats.rs`'s own test module stand up their own container too, for the cases that need a private field the integration crate cannot reach. `--test <name>` does not select the lib target, so they run under `cargo test -p rastreo-core --features nats --lib -- --ignored`; CI runs both selectors. The `#[ignore]`d tests in `sink/kafka.rs` still require a hand-run broker and are excluded by leaving the `kafka` feature off that selector.
- `KafkaSink::new` bounds the whole broker connect (`build` + `partition_client`) with `CONNECT_TIMEOUT` (10s) so a black-hole broker fails fast instead of hanging; the in-module black-hole test exercises the seam with a 1s timeout. `NatsSink` relies on `async-nats`' own bounded initial connect (default 5s `connection_timeout`, no retry-on-initial-connect).

## Extension Points

To add a prober, encoder, or sink: implement the matching trait, register the implementation in its factory, and add unit tests covering happy path, edge cases, and error cases.
