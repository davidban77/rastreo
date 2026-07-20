---
description: Wire schema for ScenarioFile emitted by rastreo.
---

# ScenarioFile

<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->

Wire schema for ScenarioFile emitted by rastreo.

- Schema ID: `https://davidban77.github.io/rastreo/schemas/scenario-v1.json`
- JSON Schema draft: `https://json-schema.org/draft/2020-12/schema`
- Source of truth: `rastreo-core/src/config/mod.rs`

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `defaults` | [`BaseProbeConfig`](#baseprobeconfig) | no | — |
| `kind` | [`ScenarioKind`](#scenariokind) | yes | — |
| `scenarios` | array<[`ScenarioEntry`](#scenarioentry)> | yes | — |
| `version` | uint8 | yes | — |

## Definitions

### `BaseProbeConfig` {#baseprobeconfig}

| Field | Type | Required | Description |
|---|---|---|---|
| `classifier` | [`ClassifierConfig`](#classifierconfig) \| null | no | — |
| `encoder` | [`EncoderConfig`](#encoderconfig) \| null | no | — |
| `fuser` | [`FuserConfig`](#fuserconfig) \| null | no | — |
| `max_concurrent` | uint32 \| null | no | Maximum probes in flight at once. |
| `name` | string \| null | no | — |
| `probe_rate` | uint32 \| null | no | Maximum probes started per second; unset means no rate limit. |
| `retries` | uint32 \| null | no | Retransmit attempts for connectionless probers that lack native retransmission (UDP, SNMP, DNS); 0 (default) issues a single request within the same total timeout. |
| `sink` | [`SinkConfig`](#sinkconfig) \| null | no | — |
| `timeout_ms` | uint64 \| null | no | — |

### `ClassifierConfig` {#classifierconfig}

One of:

- { `type`: `noop` }
- { `merge_mode`: [`MergeMode`](#mergemode), `platform_rules`: array<[`PlatformRule`](#platformrule)>, `role_rules`: array<[`RoleRule`](#rolerule)>, `type`: `rules` }

### `Community` {#community}

SNMP community string written verbatim in YAML; serialized as `<redacted:HHHHHHHH>` to keep the plaintext out of logs and NDJSON output.

Type: string

### `DeadLetterConfig` {#deadletterconfig}

Quarantine topic configuration for records the primary Kafka produce refused.

| Field | Type | Required | Description |
|---|---|---|---|
| `include_error_metadata` | boolean | no | — |
| `topic` | string | yes | — |

### `DiscoverScenarioConfig` {#discoverscenarioconfig}

| Field | Type | Required | Description |
|---|---|---|---|
| `classifier` | [`ClassifierConfig`](#classifierconfig) \| null | no | — |
| `encoder` | [`EncoderConfig`](#encoderconfig) \| null | no | — |
| `fuser` | [`FuserConfig`](#fuserconfig) \| null | no | — |
| `max_concurrent` | uint32 \| null | no | Maximum probes in flight at once. |
| `name` | string \| null | no | — |
| `probe_rate` | uint32 \| null | no | Maximum probes started per second; unset means no rate limit. |
| `probers` | array<[`ProberConfig`](#proberconfig)> | no | — |
| `retries` | uint32 \| null | no | Retransmit attempts for connectionless probers that lack native retransmission (UDP, SNMP, DNS); 0 (default) issues a single request within the same total timeout. |
| `sink` | [`SinkConfig`](#sinkconfig) \| null | no | — |
| `targets` | array<[`Target`](#target)> | yes | — |
| `timeout_ms` | uint64 \| null | no | — |

### `DnsQueryType` {#dnsquerytype}

Type: string

### `DnsTransport` {#dnstransport}

Type: string

### `EncoderConfig` {#encoderconfig}

One of:

- { `type`: `ndjson` }

### `FuserConfig` {#fuserconfig}

One of:

- { `confidence_baseline`: double \| null, `confidence_per_signal`: double \| null, `include_unreachable`: boolean \| null, `type`: `direct` }
- { `data_path`: string, `inner`: [`FuserConfig`](#fuserconfig), `type`: `oui_enrichment` }
- { `identity_hints`: [`IdentityHints`](#identityhints), `inner`: [`FuserConfig`](#fuserconfig), `type`: `identity` }

### `HttpScheme` {#httpscheme}

Type: string

### `IdentityHints` {#identityhints}

| Field | Type | Required | Description |
|---|---|---|---|
| `vrrp_groups` | array<[`VrrpGroup`](#vrrpgroup)> | no | — |

### `IpNet` {#ipnet}

An IPv4 or IPv6 address with prefix length

One of:

- [`Ipv4Net`](#ipv4net)
- [`Ipv6Net`](#ipv6net)

### `Ipv4Net` {#ipv4net}

An IPv4 address with prefix length

Type: string

### `Ipv6Net` {#ipv6net}

An IPv6 address with prefix length

Type: string

### `KafkaFlushMode` {#kafkaflushmode}

One of:

- { `type`: `per_record` }
- { `threshold_bytes`: uint, `type`: `batched` }

### `KafkaSasl` {#kafkasasl}

SASL credentials for the Kafka producer; composes independently with `KafkaTls`.

| Field | Type | Required | Description |
|---|---|---|---|
| `mechanism` | [`SaslMechanism`](#saslmechanism) | yes | — |
| `password` | [`Password`](#password) | yes | — |
| `username` | string | yes | — |

### `KafkaTls` {#kafkatls}

TLS for the Kafka producer; `verify` defaults to `false` (accept any certificate), mirroring the probers' permissive default.

| Field | Type | Required | Description |
|---|---|---|---|
| `ca_cert` | string \| null | no | — |
| `verify` | boolean | no | — |

### `MergeMode` {#mergemode}

How user-supplied rules combine with the baked-in default rules.

One of:

- `extend`
- `replace`

### `NatsCredentials` {#natscredentials}

One of:

- { `type`: `anonymous` }
- { `password`: [`Password`](#password), `type`: `user_pass`, `username`: string }
- { `token`: [`Password`](#password), `type`: `token` }
- { `creds_file`: string, `type`: `creds` }

### `NatsDeadLetterConfig` {#natsdeadletterconfig}

Quarantine JetStream target for records the primary NATS publish or ack rejected.

| Field | Type | Required | Description |
|---|---|---|---|
| `include_error_metadata` | boolean | no | — |
| `stream` | string | yes | — |
| `subject` | string | yes | — |

### `NatsFlushMode` {#natsflushmode}

One of:

- { `type`: `per_record` }
- { `threshold_bytes`: uint, `type`: `batched` }

### `Password` {#password}

Credential value written verbatim in YAML; serialized as `<redacted:HHHHHHHH>` to keep the plaintext out of logs and NDJSON output.

Type: string

### `PlatformRule` {#platformrule}

A single regex-based platform-detection rule.

| Field | Type | Required | Description |
|---|---|---|---|
| `http_server_capture` | string \| null | no | Named regex capture group whose matched text populates `DeviceRecord::http_server`. Only meaningful for `signal: HttpBanner`. |
| `http_version_capture` | string \| null | no | Named regex capture group whose matched text populates `DeviceRecord::http_version`. Only meaningful for `signal: HttpBanner`. |
| `os_version_capture` | string \| null | no | Named regex capture group (e.g. `version` for `(?P<version>\d+\.\d+)`) whose matched text populates `DeviceRecord::os_version`. When absent, or when the group is not present in the actual match, `os_version` stays `None`. |
| `pattern` | string | yes | — |
| `platform` | string | yes | — |
| `signal` | [`PlatformSignal`](#platformsignal) | yes | — |
| `ssh_version_capture` | string \| null | no | Named regex capture group whose matched text populates `DeviceRecord::ssh_version`. Only meaningful for `signal: SshBanner`. |

### `PlatformSignal` {#platformsignal}

Which probe-emitted signal a `PlatformRule` matches against.

Type: string

### `ProberConfig` {#proberconfig}

One of:

- { `ports`: array<uint16>, `type`: `tcp_connect` }
- { `path`: string, `ports`: array<uint16>, `scheme`: [`HttpScheme`](#httpscheme), `tls_verify`: boolean, `type`: `http`, `user_agent`: string }
- { `ports`: array<uint16>, `query_names`: array<string>, `query_type`: [`DnsQueryType`](#dnsquerytype), `recursion_desired`: boolean, `transport`: [`DnsTransport`](#dnstransport), `type`: `dns` }
- { `ports`: array<uint16>, `protocol`: [`UdpProtocol`](#udpprotocol), `type`: `udp` }
- { `community`: [`Community`](#community), `credentials`: [`UsmCredentials`](#usmcredentials), `ports`: array<uint16>, `type`: `snmp`, `version`: [`SnmpVersion`](#snmpversion) }
- { `community`: [`Community`](#community), `credentials`: [`UsmCredentials`](#usmcredentials), `max_rows`: uint, `ports`: array<uint16>, `type`: `lldp`, `version`: [`SnmpVersion`](#snmpversion) }
- { `interface`: string, `type`: `arp` }
- { `interface`: string, `type`: `ndp` }
- { `ports`: array<uint16>, `type`: `ssh` }
- { `count`: uint32, `interval_ms`: uint64, `type`: `icmp` }
- { `ports`: array<uint16>, `type`: `tls` }
- { `get_paths`: array<string>, `lldp`: boolean, `password`: [`Password`](#password), `plaintext`: boolean, `ports`: array<uint16>, `type`: `gnmi`, `username`: string }
- { `resolvers`: array<string (ip)>, `type`: `reverse_dns` }

### `RoleRule` {#rolerule}

A single role-detection rule. Two match strategies are supported: exact byte-prefix on `SnmpSysObjectId` and all-of set membership over `OpenPort` signals.

One of:

- { `prefix`: string, `role`: string, `type`: `sys_object_id_prefix` }
- { `ports`: array<uint16>, `role`: string, `type`: `ports_open` }

### `SaslMechanism` {#saslmechanism}

Type: string

### `ScenarioEntry` {#scenarioentry}

One of:

- { `classifier`: [`ClassifierConfig`](#classifierconfig) \| null, `encoder`: [`EncoderConfig`](#encoderconfig) \| null, `fuser`: [`FuserConfig`](#fuserconfig) \| null, `max_concurrent`: uint32 \| null, `name`: string \| null, `probe_rate`: uint32 \| null, `probers`: array<[`ProberConfig`](#proberconfig)>, `retries`: uint32 \| null, `signal_type`: `discover`, `sink`: [`SinkConfig`](#sinkconfig) \| null, `targets`: array<[`Target`](#target)>, `timeout_ms`: uint64 \| null }

### `ScenarioKind` {#scenariokind}

Type: string

### `SinkConfig` {#sinkconfig}

One of:

- { `type`: `stdout` }
- { `path`: string, `type`: `file` }
- { `type`: `memory` }
- { `brokers`: array<string>, `dead_letter`: [`DeadLetterConfig`](#deadletterconfig) \| null, `flush_mode`: [`KafkaFlushMode`](#kafkaflushmode), `links_topic`: string \| null, `retry`: [`SinkRetry`](#sinkretry), `sasl`: [`KafkaSasl`](#kafkasasl) \| null, `tls`: [`KafkaTls`](#kafkatls) \| null, `topic`: string, `type`: `kafka` }
- { `credentials`: [`NatsCredentials`](#natscredentials), `dead_letter`: [`NatsDeadLetterConfig`](#natsdeadletterconfig) \| null, `flush_mode`: [`NatsFlushMode`](#natsflushmode), `links_subject`: string \| null, `retry`: [`SinkRetry`](#sinkretry), `servers`: array<string>, `stream`: string, `subject`: string, `type`: `nats` }

### `SinkRetry` {#sinkretry}

Bounded exponential-backoff retry policy for a sink's primary delivery.

`max_attempts` counts total primary attempts: `1` disables retry (today's
immediate-DLQ behavior), `3` (the default) is the initial attempt plus two retries.

| Field | Type | Required | Description |
|---|---|---|---|
| `backoff_initial_ms` | uint64 | no | — |
| `backoff_max_ms` | uint64 | no | — |
| `max_attempts` | uint32 | no | — |

### `SnmpVersion` {#snmpversion}

Type: string

### `Target` {#target}

One of:

- { `Ip`: string (ip) }
- { `Cidr`: [`IpNet`](#ipnet) }
- { `Range`: object }
- { `DnsName`: string }

### `UdpProtocol` {#udpprotocol}

Type: string

### `UsmAuth` {#usmauth}

One of:

- { `algorithm`: `none` }
- { `algorithm`: `md5`, `password`: [`Password`](#password) }
- { `algorithm`: `sha1`, `password`: [`Password`](#password) }
- { `algorithm`: `sha224`, `password`: [`Password`](#password) }
- { `algorithm`: `sha256`, `password`: [`Password`](#password) }
- { `algorithm`: `sha384`, `password`: [`Password`](#password) }
- { `algorithm`: `sha512`, `password`: [`Password`](#password) }

### `UsmCredentials` {#usmcredentials}

| Field | Type | Required | Description |
|---|---|---|---|
| `auth` | [`UsmAuth`](#usmauth) | no | — |
| `privacy` | [`UsmPrivacy`](#usmprivacy) | no | — |
| `username` | string | no | — |

### `UsmPrivacy` {#usmprivacy}

One of:

- { `algorithm`: `none` }
- { `algorithm`: `des`, `password`: [`Password`](#password) }
- { `algorithm`: `aes128`, `password`: [`Password`](#password) }
- { `algorithm`: `aes192`, `password`: [`Password`](#password) }
- { `algorithm`: `aes256`, `password`: [`Password`](#password) }

### `VrrpGroup` {#vrrpgroup}

| Field | Type | Required | Description |
|---|---|---|---|
| `members` | array<string (ip)> | no | — |
| `virtual_ip` | string (ip) | yes | — |
| `virtual_mac` | string | yes | — |

