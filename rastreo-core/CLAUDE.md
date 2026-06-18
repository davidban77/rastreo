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
├── prober/mod.rs    ← Prober trait + ProberConfig + create_prober factory
├── encoder/mod.rs   ← Encoder trait + EncoderConfig + create_encoder factory
├── sink/mod.rs      ← Sink trait + SinkConfig + create_sink factory
└── config/mod.rs    ← ScenarioFile + ScenarioEntry + BaseProbeConfig
```

## Cargo Features

| Feature  | Default | Description |
|----------|---------|-------------|
| `config` | yes     | Pulls in `serde_yaml_ng` for YAML scenario-file parsing. Disable for library consumers who construct configs in code and do not need YAML deserialization. |
| `http`   | no      | Enables the HTTP prober and HTTP-based sinks. |
| `kafka`  | no      | Enables the Kafka sink for streaming discovered records. |
| `snmp`   | no      | Enables the SNMP prober for vendor / interface fingerprinting. |
| `arp`    | no      | Enables the ARP prober (requires raw-socket capability on the host). |

Features beyond `config` currently have no associated code; declaring them up front keeps the feature surface visible from day one.

## Error Handling

- Define errors using `thiserror`. Every public function returns `Result<T, RastreoError>`.
- Never `unwrap()` in this crate. Use `?` propagation or explicit error mapping.
- The structured error hierarchy uses sub-enums per failure domain (`ConfigError`, `ProbeError`, `EncoderError`, `RuntimeError`) accessed via the umbrella `RastreoError`. No blanket `From<std::io::Error>` — sink call sites map I/O failures to `RastreoError::Sink` explicitly.

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
