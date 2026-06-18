# rastreo-core — The Engine

This is the library crate. It owns **all** domain logic. If it probes a network, fuses enrichment data, classifies a device, encodes a record, or delivers output — it lives here.

## Module Layout

```
src/
└── lib.rs   ← public API surface. Currently exposes only `version()`. Future modules
              (probers, fusion, classification, encoders, sinks, errors, model) land here.
```

## Cargo Features

| Feature  | Default | Description |
|----------|---------|-------------|
| `config` | yes     | Enables `serde::Deserialize` impls on configuration types and pulls in `serde_yaml_ng` for YAML parsing. Disable for library consumers who construct configs in code. |
| `http`   | no      | Enables the HTTP prober and HTTP-based sinks. |
| `kafka`  | no      | Enables the Kafka sink for streaming discovered records. |
| `snmp`   | no      | Enables the SNMP prober for vendor / interface fingerprinting. |
| `arp`    | no      | Enables the ARP prober (requires raw-socket capability on the host). |

Features beyond `config` currently have no associated code — their dependency wiring is added together with the corresponding modules.

## Error Handling

- Define errors using `thiserror`. Every public function returns `Result<T, RastreoError>`.
- Never `unwrap()` in this crate. Use `?` propagation or explicit error mapping.
- The structured error hierarchy (sub-enums per failure domain) lands with the first non-trivial module.

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

To add a prober, encoder, or sink: implement the matching trait, register the implementation in its factory, and add unit tests covering happy path, edge cases, and error cases. Detailed steps will live in `.claude/skills/`.
