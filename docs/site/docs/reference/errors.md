---
description: Every RastreoError variant — its Display message, the situation that triggers it, and where to look to fix it.
---

# Error reference

`RastreoError` is the top-level error type returned by every fallible `rastreo-core` operation. It wraps five sub-enums by failure domain plus a direct `Sink` variant for I/O failures. The tables below enumerate every variant, its `Display` message, the situation that triggers it, and where to look to fix it. For symptom-to-fix walkthroughs, see [Troubleshooting](../integrate/troubleshooting.md).

The CLI prints the `Display` message to stderr and exits with code `1`. The HTTP server maps each variant to an HTTP status; see [Server response mapping](#server-response-mapping) below.

## Config errors

`RastreoError::Config(ConfigError)` covers invalid configuration values caught at validation time — before any probe runs. The Display prefix on the outer variant is `configuration error:`.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `ConfigError::InvalidValue(msg)` | The `msg` is rendered as-is. | A configured value failed validation (for example, a fuser `confidence_baseline` of `1.5`, a Kafka sink with an empty brokers list). | Read the message — it names the field and the rejected value. Fix the value in the scenario JSON or in the CLI flag. |

## Probe errors

Probe faults are typed data, not returned errors. When a probe faults, it records the reason as a named kind on the outcome and the scan keeps running. The named kinds you will see are `decode_failed`, `permission_denied`, `dns_failed`, and `other` — each explained in [Reachable, unreachable, and probe faults](../probe/index.md#reachable-unreachable-and-probe-faults). A `permission_denied` fault from a missing `CAP_NET_RAW` is covered in [ARP · Runtime privilege](../probe/arp.md#runtime-privilege).

!!! warning "A fault is the probe breaking, not a silent target"
    A timeout, a refused connection, an unreachable network, or a port that is not speaking the protocol you probed — each is a normal negative discovery result, and `error_counts` stays empty. A probe that learned something partial keeps it: a device that answers TCP but refuses the TLS handshake produces a record carrying the open port, no fault. One fault keeps the device even so — a reply rastreo cannot decode marks the target reachable, emits a record with no signals, and counts the fault as `decode_failed`.

The scan summary reports faults in three fields. `error_counts` tallies them by kind. `first_probe_error` holds the first fault as a two-element `[kind, detail]` array. `probes_by_kind` gives a per-prober `attempted` / `errored` breakdown. A scan fails only when target resolution, encoding, or the sink fails.

`RastreoError::Probe(ProbeError)` is separate and rare. It is returned only when a probe could not attempt a target at all, and the pipeline then counts that case under the `other` fault kind. The Display prefix on the outer variant is `probe error:`, and the HTTP server maps it to `500`.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `ProbeError::Other(msg)` | The `msg` is rendered as-is. | A probe could not attempt the target at all. | Read the message; it names the prober and the failure. |

## Resolver errors

`RastreoError::Resolver(ResolverError)` covers target-resolution failures — DNS lookups, CIDR expansion, range validation. The Display prefix on the outer variant is `resolver error:`.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `ResolverError::DnsLookupFailed { name }` | `DNS lookup failed for <name>` | The system resolver could not be reached or returned a transport error. | Check `/etc/resolv.conf`; try `dig <name>` from the same host. In containers, verify the container's resolver can reach your internal DNS — see [Troubleshooting](../integrate/troubleshooting.md#dns-resolution-failures). |
| `ResolverError::DnsNoRecords { name }` | `DNS lookup returned no records for <name>` | The name resolved but returned no `A` or `AAAA` records. | Confirm the name has the expected records (`dig <name> A`, `dig <name> AAAA`). |
| `ResolverError::CidrTooLarge { cidr, hosts, limit }` | `CIDR <cidr> expands to <N> hosts; exceeds the configured limit of <M>` | The CIDR expands to more hosts than the resolver's per-target limit. | Split the CIDR into smaller blocks, or relax the limit in the calling library. |
| `ResolverError::RangeTooLarge { start, end, hosts, limit }` | `IP range <start>..=<end> spans <N> addresses; exceeds the configured limit of <M>` | The IP range spans more addresses than the resolver's per-target limit. | Use a tighter range, or call the library with a higher limit. |
| `ResolverError::InvalidRange { start, end }` | `IP range is invalid: start <start> > end <end>` | The `start` address sorts after the `end` address. | Swap the two values, or correct the typo. |
| `ResolverError::MixedFamilyRange { start, end }` | `IP range mixes IPv4 and IPv6: start <start> end <end>` | One endpoint is IPv4 and the other is IPv6. | Use two separate ranges, one per address family. |

## Encoder errors

`RastreoError::Encoder(EncoderError)` covers serialization failures in the encoder. The Display prefix on the outer variant is `encoder error:`.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `EncoderError::SerializationFailed(source)` | `serialization failed` (`source`: the underlying `serde_json::Error`) | A `DeviceRecord` could not be serialised to JSON. Rare in normal operation. | Inspect the source error and the record; report as a bug with reproduction. |
| `EncoderError::NotSupported(msg)` | The `msg` is rendered as-is. | The encoder was asked to handle a record shape it does not support. | Use the documented encoders. |
| `EncoderError::Other(msg)` | The `msg` is rendered as-is. | Catch-all for encoder-side failures. | Read the message. |

## Sink errors

`RastreoError::Sink(std::io::Error)` is a flat variant — not a sub-enum. It carries the underlying I/O error directly. The Display prefix on the outer variant is `sink error:`, followed by the standard `io::Error` Display.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `RastreoError::Sink(err)` | `sink error: <io::Error message>` | The sink failed to write — typical causes include a closed stdout pipe, an unwritable file path, or a Kafka broker that closed the connection. | Read the inner message. For file sinks check permissions and disk space; for Kafka see [Troubleshooting · Kafka broker unreachable](../integrate/troubleshooting.md#kafka-broker-unreachable). |

## Runtime errors

`RastreoError::Runtime(RuntimeError)` covers scheduler and task-supervisor failures. The Display prefix on the outer variant is `runtime error:`.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `RuntimeError::TaskPanicked(msg)` | `task panicked: <msg>` | A spawned probe task panicked. | Capture stderr; report as a bug with the panic message and a reproduction. |
| `RuntimeError::TaskAborted { reason }` | `task aborted: <reason>` | A spawned task was cancelled — typically because the scheduler is shutting down. | Usually expected during shutdown; if it appears mid-scan, capture logs and report. |

## Server response mapping

When `POST /scans` returns an error, the HTTP status is derived from the `RastreoError` variant. The mapping is:

| Variant | HTTP status | Response body |
|---|---|---|
| `Config(_)` | `400 Bad Request` | `{"error": "<full error message>"}` |
| `Resolver(DnsLookupFailed { .. })` | `503 Service Unavailable` | `{"error": "<full error message>"}` |
| All other `Resolver(_)` variants | `400 Bad Request` | `{"error": "<full error message>"}` |
| `Probe(_)`, `Encoder(_)`, `Sink(_)`, `Runtime(_)` | `500 Internal Server Error` | `{"error": "internal server error"}` |

For `4xx` responses the body carries the full error message — these are caller-supplied input errors and the detail is safe to return. For `5xx` responses the body is redacted to `internal server error`; the full error is logged at server level with `tracing::error!` for operators to inspect. Empty `targets` or empty `probers` are validated before the variant flow above and return `400` with the message `scenario.targets must not be empty` or `scenario.probers must not be empty` respectively. Requests that exceed `--request-timeout-ms` return `503 Service Unavailable` from the timeout middleware layer.

## See also

- [CLI reference](cli.md) — flags for both binaries.
- [Scenario schema](scenario.md) — the JSON shape that triggers `Config` errors when invalid.
- [Troubleshooting](../integrate/troubleshooting.md) — symptom-to-fix walkthroughs.
