---
description: Every RastreoError variant — its Display message, the situation that triggers it, and where to look to fix it.
---

# Error reference

`RastreoError` is the top-level error type returned by every fallible `rastreo-core` operation. It wraps one type per failure domain: `Config`, `Probe`, `Resolver`, `Encoder`, `Sink`, `Runtime`, `Classifier`, and `Resume`. The tables below enumerate every variant, its `Display` message, the situation that triggers it, and where to look to fix it. For symptom-to-fix walkthroughs, see [Troubleshooting](../integrate/troubleshooting.md).

The CLI prints the message to stderr and exits with code `1`. Every level of the chain names its own layer of the failure and leaves the detail to the cause below it, so no message is printed twice; where a library error wraps its own cause in a message that merely restates it, rastreo drops that level rather than passing the repetition through.

```text
Error: output sink failed

Caused by:
    failed to open file sink at /var/log/rastreo/out.ndjson: No such file or directory (os error 2)
```

The HTTP server maps each variant to an HTTP status; see [Server response mapping](#server-response-mapping) below.

## Config errors

`RastreoError::Config(ConfigError)` covers invalid configuration values caught at validation time — before any probe runs.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `ConfigError::InvalidValue(msg)` | The `msg` is rendered as-is. | A configured value failed validation (for example, a fuser `confidence_baseline` of `1.5`, a Kafka sink with an empty brokers list). | Read the message — it names the field and the rejected value. Fix the value in the scenario JSON or in the CLI flag. |
| `ConfigError::UnknownProbeKind { name, available }` | `unknown probe kind '<name>'; available in this build: <list>` | `--probe` (or a `probe_kinds` entry) named a kind that does not exist — usually a typo. | Pick a name from the `available` list the message prints. |
| `ConfigError::ProbeKindNotCompiled { kind, feature }` | `probe kind '<kind>' requires the '<feature>' Cargo feature, which this binary was not built with` | The kind name is valid but this binary was built without its feature. | Rebuild with `--features <feature>`, or use the release image, which bundles them all. See [Build features](cli.md#build-features). |
| `ConfigError::ProbeKindMissingParam { kind, param }` | `probe kind '<kind>' requires <param>` | A selected kind needs a parameter that was not supplied — for example `--probe udp` with no `--udp-protocol`. | Supply the named parameter. The CLI adds a hint naming the exact flag. |
| `ConfigError::EmptyProbeSelection` | `no probe kinds selected` | Every requested kind was filtered out, or an empty selection was passed explicitly. | Name at least one kind with `--probe`, or drop the flag to run the default set. |

## Probe errors

Probe faults are typed data, not returned errors. When a probe faults, it records the reason as a named kind on the outcome and the scan keeps running. The named kinds you will see are `decode_failed`, `auth_failed`, `permission_denied`, `dns_failed`, and `other` — each explained in [Reachable, unreachable, and probe faults](../probe/index.md#reachable-unreachable-and-probe-faults). A `permission_denied` fault from a missing `CAP_NET_RAW` is covered in [ARP · Runtime privilege](../probe/arp.md#runtime-privilege).

!!! warning "A fault is the probe breaking, not a silent target"
    A timeout, a refused connection, an unreachable network, or a port that is not speaking the protocol you probed — each is a normal negative discovery result, and `error_counts` stays empty. A probe that learned something partial keeps it: a device that answers TCP but refuses the TLS handshake produces a record carrying the open port, no fault. One fault keeps the device even so — a reply rastreo cannot decode marks the target reachable, emits a record with no signals, and counts the fault as `decode_failed`.

The scan summary reports faults in three fields. `error_counts` tallies them by kind. `first_probe_error` holds the first fault as an object with a `kind` field and a `detail` field. `probes_by_kind` gives a per-prober `attempted` / `errored` breakdown. A scan fails only when target resolution, encoding, or the sink fails.

`RastreoError::Probe(ProbeError)` is separate and rare. It is returned only when a probe could not attempt a target at all, and the pipeline then counts that case under the `other` fault kind. The HTTP server maps it to `500`.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `ProbeError::Other(msg)` | The `msg` is rendered as-is. | A probe could not attempt the target at all. | Read the message; it names the prober and the failure. |

## Resolver errors

`RastreoError::Resolver(ResolverError)` covers target-resolution failures — DNS lookups, CIDR expansion, range validation.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `ResolverError::DnsLookupFailed { name }` | `DNS lookup failed for <name>` (`source`: the lookup failure itself — `no records found for Query { ... }`, `request timed out`, and so on) | The system resolver could not be reached or returned a transport error. | Check `/etc/resolv.conf`; try `dig <name>` from the same host. In containers, verify the container's resolver can reach your internal DNS — see [Troubleshooting](../integrate/troubleshooting.md#dns-resolution-failures). |
| `ResolverError::DnsNoRecords { name }` | `DNS lookup returned no records for <name>` | The name resolved but returned no `A` or `AAAA` records. | Confirm the name has the expected records (`dig <name> A`, `dig <name> AAAA`). |
| `ResolverError::CidrTooLarge { cidr, hosts, limit }` | `CIDR <cidr> expands to <N> hosts; exceeds the configured limit of <M>` | The CIDR expands to more hosts than the resolver's per-target limit. | Split the CIDR into smaller blocks, or relax the limit in the calling library. |
| `ResolverError::RangeTooLarge { start, end, hosts, limit }` | `IP range <start>..=<end> spans <N> addresses; exceeds the configured limit of <M>` | The IP range spans more addresses than the resolver's per-target limit. | Use a tighter range, or call the library with a higher limit. |
| `ResolverError::InvalidRange { start, end }` | `IP range is invalid: start <start> > end <end>` | The `start` address sorts after the `end` address. | Swap the two values, or correct the typo. |
| `ResolverError::MixedFamilyRange { start, end }` | `IP range mixes IPv4 and IPv6: start <start> end <end>` | One endpoint is IPv4 and the other is IPv6. | Use two separate ranges, one per address family. |
| `ResolverError::TargetNotAllowed { ip }` | `target <ip> is outside the configured allow-list` | Server only: a resolved target falls outside every range in `RASTREO_TARGET_ALLOWLIST`. | Add the range to the allow-list, or scan a target inside it. See [Allow-list](../deploy/server.md#allow-list). |
| `ResolverError::AggregateHostCapExceeded { hosts, limit }` | `scan resolves to <N> hosts; exceeds the configured aggregate limit of <M>` | Server only: the targets in one request sum to more hosts than `RASTREO_MAX_TOTAL_HOSTS`. | Split the request, or raise the cap. See [Aggregate host cap](../deploy/server.md#aggregate-host-cap). |

## Encoder errors

`RastreoError::Encoder(EncoderError)` covers serialization failures in the encoder.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `EncoderError::SerializationFailed(source)` | `serialization failed` (`source`: the underlying `serde_json::Error`) | A `DeviceRecord` could not be serialised to JSON. Rare in normal operation. | Inspect the source error and the record; report as a bug with reproduction. |
| `EncoderError::NotSupported(msg)` | The `msg` is rendered as-is. | The encoder was asked to handle a record shape it does not support. | Use the documented encoders. |
| `EncoderError::Other(msg)` | The `msg` is rendered as-is. | Catch-all for encoder-side failures. | Read the message. |

## Sink errors

`RastreoError::Sink(SinkError)` covers every failure of the configured output destination — opening it, writing to it, flushing it, publishing to it, or waiting for its acknowledgement. `SinkError` carries the underlying `io::Error` as the error's cause and a machine-readable `class` (`publish_failure`, `ack_rejection`, `produce_failure`, `write_failure`, `flush_failure`, `other`) that also labels the [`rastreo_server_sink_errors_total`](observability.md#error_class-taxonomy) metric and any dead-letter delivery.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `RastreoError::Sink(err)` | `output sink failed`, with the `io::Error` message printed below it under `Caused by:` | A closed stdout pipe, an unwritable file path, a Kafka broker that closed the connection, a NATS publish that was never acked. | Read the cause — it names the operation that failed and, for a file sink, the path. Check the directory exists and is writable, and check disk space; for Kafka see [Troubleshooting · Kafka broker unreachable](../integrate/troubleshooting.md#kafka-broker-unreachable). |

## Runtime errors

`RastreoError::Runtime(RuntimeError)` covers scheduler and task-supervisor failures.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `RuntimeError::TaskPanicked(msg)` | `task panicked: <msg>` | A spawned probe task panicked. | Capture stderr; report as a bug with the panic message and a reproduction. |
| `RuntimeError::TaskAborted { reason }` | `task aborted: <reason>` | A spawned task was cancelled — typically because the scheduler is shutting down. | Usually expected during shutdown; if it appears mid-scan, capture logs and report. |

## Classifier errors

`RastreoError::Classifier(ClassifierError)` covers a rejected [classification rule set](../discover/classification.md#extending-the-rule-set). The rules are compiled before the scan starts, so a bad rule fails the run rather than silently skipping the rule.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `ClassifierError::InvalidRegex { pattern }` | ``invalid regex `<pattern>` `` (`source`: the underlying `regex::Error`) | A `platform_rules` entry — or a `signal_match` role rule, which compiles its `pattern` the same way — carries a `pattern` that is not a valid regular expression. | Read the cause — it points at the offending position in the pattern. Escape the literal that broke it, or close the unbalanced group. |
| `ClassifierError::InvalidPlatformRule(msg)` | `invalid platform rule: <msg>` | A `platform_rules` entry splits a paired capture from what it versions: an `os_version_capture` with no `platform`, or an `http_version_capture` with no `http_server_capture`. The capture could never fire. | The message names the pattern. Add the missing half — the `platform` label the rule assigns, or the `http_server_capture` naming the server — or drop the version capture if the rule only extracts `ssh_version` or `http_server` from a service banner. |
| `ClassifierError::InvalidRoleRule(msg)` | `invalid role rule: <msg>` | A `role_rules` entry can never match: a `ports_open` rule with no ports, or a `sys_object_id_prefix` rule whose `prefix` is empty or is not dotted-decimal. The leading-dot form a MIB browser prints (`.1.3.6.1.4.1.9.1`) is the common case. | The message names the role. Give a `ports_open` rule the ports it matches on. For a `sys_object_id_prefix` rule, strip any leading dot and make the prefix two or more digit arcs joined by `.`, as in `1.3.6.1.4.1.9.1`. |

## Resume errors

`RastreoError::Resume(ResumeError)` covers [checkpoint and resume](../discover/cli.md#checkpoints) failures. Every variant but `Persist` is a refusal raised before the first probe, and none of them overwrites the checkpoint on disk. `Persist` is the one that fires mid-scan, when a checkpoint write itself fails.

| Variant | Display message | Common cause | Likely fix |
|---|---|---|---|
| `ResumeError::IdentityFuserNotResumable` | `scenario is not resume-safe: the identity fuser correlates records across the whole scan, which cannot be reconstructed from a partial checkpoint prefix` | `--checkpoint` on a scenario using the [`identity`](../discover/identity.md) fuser. | Switch the scenario to the `direct`, `oui_enrichment`, or `mib_enrichment` fuser, or run it without a checkpoint. |
| `ResumeError::SecondStreamProberNotResumable { kind }` | `scenario is not resume-safe: the <kind> prober feeds a second stream that cannot be replayed from a checkpoint` | `--checkpoint` on a scenario running the [`lldp`](../probe/lldp.md) or [`gnmi`](../probe/gnmi.md) prober. | Split the second-stream prober into its own uncheckpointed scenario. |
| `ResumeError::SinkNotResumable { sink }` | `scenario is not resume-safe: the <sink> sink has no durable append destination to resume into` | `--checkpoint` with the `stdout` or `memory` sink. | Use the `file`, `kafka`, or `nats` sink. |
| `ResumeError::FingerprintMismatch` | `checkpoint does not match the current scenario: the target sequence or append destination changed, so resuming would produce a different scan or append to the wrong destination` | `--resume` after the target list or the sink destination changed. | Resume with the original targets and sink, or delete the checkpoint and start a fresh scan. |
| `ResumeError::NoCheckpointToResume { path }` | `no checkpoint to resume at <path>; --resume requires an existing checkpoint at this path` | `--resume` pointed at a path with no checkpoint — often a typo, or a previous run that completed and removed it. | Check the path. A completed scan deletes its checkpoint; run without `--resume` to start fresh. |
| `ResumeError::CorruptCheckpoint { path }` | `checkpoint at <path> is unreadable or corrupt; delete it to restart the scan from zero` | The file at the checkpoint path is truncated, is not a checkpoint, or was written by an incompatible build. | Delete the file and rerun. The scan restarts from zero. |
| `ResumeError::UnknownVersion { found, expected }` | `checkpoint has version <N>, but this build understands version <M>; delete the checkpoint file to restart the scan from zero` | A checkpoint written by a different rastreo version. | Delete the file and rerun, or resume with the version that wrote it. |
| `ResumeError::CheckpointExists { path }` | `a checkpoint already exists at <path>; remove it to start a fresh scan` | `--checkpoint` at a path that already holds a checkpoint, without `--resume`. | Add `--resume` to continue that run, or remove the file to start over. |
| `ResumeError::Persist { path }` | `checkpoint could not be written to <path>` (`source`: the underlying `io::Error`) | The checkpoint directory is unwritable, missing, or full. | Read the cause. Check the directory exists, is writable by the running user, and has free space. |

## Server response mapping

When `POST /scans` returns an error, the HTTP status is derived from the `RastreoError` variant. The mapping is:

| Variant | HTTP status | Response body |
|---|---|---|
| `Config(_)` | `400 Bad Request` | `{"error": "<full error message>"}` |
| `Resolver(TargetNotAllowed { .. })` | `403 Forbidden` | `{"error": "<full error message>"}` |
| `Resolver(DnsLookupFailed { .. })` | `503 Service Unavailable` | `{"error": "internal server error"}` |
| All other `Resolver(_)` variants | `400 Bad Request` | `{"error": "<full error message>"}` |
| `Probe(_)`, `Encoder(_)`, `Sink(_)`, `Runtime(_)`, `Classifier(_)`, `Resume(_)` | `500 Internal Server Error` | `{"error": "internal server error"}` |

For `4xx` responses the body carries the full error message — these are caller-supplied input errors and the detail is safe to return. For `5xx` responses the body is redacted to `internal server error`; the full error is logged at server level with `tracing::error!` for operators to inspect. Empty `targets` or empty `probers` are validated before the variant flow above and return `400` with the message `scenario.targets must not be empty` or `scenario.probers must not be empty` respectively. Requests that exceed `--request-timeout-ms` return `503 Service Unavailable` from the timeout middleware layer.

## See also

- [CLI reference](cli.md) — flags for both binaries.
- [Scenario schema](scenario.md) — the JSON shape that triggers `Config` errors when invalid.
- [Troubleshooting](../integrate/troubleshooting.md) — symptom-to-fix walkthroughs.
