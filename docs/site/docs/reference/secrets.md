---
description: How rastreo loads secrets from environment variables and file mounts when it reads a scenario file or a sink config, keeping plaintext passwords out of checked-in YAML and out of Kubernetes ConfigMaps.
---

# Secrets

Config files often need to carry credential material — SNMPv3 auth and privacy passwords, SNMP v2c community strings on managed fleets, NATS sink passwords, Kafka SASL passwords, and so on. Writing those values inline is fine for a lab but a blocker for anything that ships. rastreo expands two syntaxes when it reads a config file, so credentials can live in the process environment or on a file mount instead of in the YAML.

Both syntaxes are resolved before deserialization runs, so a missing value fails at load with a clear error rather than showing up as an authentication failure during a probe. Secret rotation still changes `source_config_hash` because the plaintext feeds the redacted-value hash inside `Password` / `Community`; downstream consumers see the same "config changed" signal they would see for a manually-edited YAML file.

## Where expansion applies

| Config surface | `${VAR}` and `!file` |
|---|---|
| Scenario file — `rastreo discover --file`, `rastreo validate` | Expanded |
| Sink config file — `RASTREO_SINK_CONFIG_PATH` on `rastreo-server` | Expanded |
| `POST /scans` request body | Left literal |

Both file surfaces are written by whoever runs the process, so a reference in them resolves against that process's own environment and secret mounts. A `POST /scans` body is different: it arrives from a client. Expanding it would let any caller read the server's environment back out — a target named `${AWS_SECRET_ACCESS_KEY}` would be substituted with the value, which then comes back in a DNS error message or a device record. So `${VAR}` in a request body is passed through as literal text: the target above stays that literal string and fails resolution with `DNS lookup failed for ${AWS_SECRET_ACCESS_KEY}`. A client that needs a credential in a scan sends the credential itself.

## Environment variables (`${VAR}`)

Any string scalar in a scenario file or a sink config may reference an environment variable using the shell-style `${VAR}` syntax. The identifier must match `[A-Za-z_][A-Za-z0-9_]*` — the same character set as POSIX shell variable names.

```yaml
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    targets:
      - Ip: 192.0.2.10
    probers:
      - type: snmp
        version: v3
        credentials:
          username: probe
          auth:
            algorithm: sha256
            password: "${SNMP_AUTH_PASSWORD}"
          privacy:
            algorithm: aes128
            password: "${SNMP_PRIV_PASSWORD}"
```

Multiple references may appear in the same scalar and the surrounding text is preserved verbatim. `"nats://${NATS_USER}:${NATS_PASS}@nats:4222"` interpolates both variables.

A missing environment variable (`std::env::var` returns `NotPresent`) fails the load and names the file it was referenced from. A scenario file reports `environment variable NAME referenced in scenario is not set` under a `Caused by:` beneath `failed to parse scenario file '<path>'`; a sink config reports `environment variable NAME referenced in sink config is not set` beneath `failed to parse sink config at <path>`, which `rastreo-server` surfaces as `last_probe_error` on `/readyz`. A variable that is set to an empty string substitutes as an empty string with no error — this is a deliberate distinction so `unset` and `set-to-empty` remain distinguishable, and lets a deployment script export `AUTH_PASS=""` to select the SNMPv3 `noAuthNoPriv` code path without special-casing.

To include a literal `${VAR}` in the output — for example when a value legitimately contains braces — prefix the sequence with a second `$`: `$${VAR}` expands to `${VAR}` in the loaded value. No other escape syntax is recognised; a stray `${` with no closing brace or a malformed identifier like `${1foo}` or `${a-b}` is passed through untouched, on the theory that surprise-erroring on non-interpolation shapes is more annoying than useful.

Only string values are interpolated. Mapping keys are left literal — env-var expansion on a YAML key is a footgun that would silently rewrite scenario structure, and a canonical key like `password:` should never depend on the environment.

Only string scalars are affected. YAML booleans, numbers, sequences, and tagged values other than `!file` pass through unchanged. What matters more in practice is the field on the receiving end — see [A reference only fills a string field](#a-reference-only-fills-a-string-field).

## File-based secrets (`!file`)

Any string scalar may be replaced with the `!file` YAML tag followed by an absolute path. rastreo reads the file at load time and substitutes its contents (with the trailing newline trimmed) into the scalar position. This matches the Kubernetes secret-mount pattern where the secret material sits at `/run/secrets/<name>` in the pod filesystem.

```yaml
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    targets:
      - Ip: 192.0.2.10
    probers:
      - type: snmp
        version: v3
        credentials:
          username: probe
          auth:
            algorithm: sha256
            password: !file /run/secrets/snmp-auth-password
          privacy:
            algorithm: aes128
            password: !file /run/secrets/snmp-priv-password
```

Trailing whitespace (including the final newline that most secret-writing tools emit) is stripped via `str::trim_end`. Leading whitespace is preserved — a legitimate secret that starts with a space or tab is not silently truncated. Only the final trailing whitespace run is removed, not every internal whitespace character.

Missing files, unreadable files, and other I/O errors fail the load with a message that names the path:

| Error kind | Message shape |
|---|---|
| File not found | `file secret /run/secrets/foo not found` |
| Permission denied | `file secret /run/secrets/foo not readable: permission denied` |
| Other I/O failure | `file secret /run/secrets/foo could not be read: <os message>` |
| Non-UTF-8 contents | Same class as other I/O failures; the message names the path. |

The `!file` tag applies to the whole scalar. `!file /run/secrets/foo` reads the file and produces its contents as the value; there is no prefix / suffix concatenation. If you need a value like `prefix-<secret>-suffix`, use env-var interpolation instead and set the env var to `prefix-$(cat /run/secrets/foo)-suffix` in the wrapping script. Note that bash `$(...)` strips exactly one trailing newline; if the secret file could have multiple trailing newlines and you want the shell to match rastreo's `!file` behaviour (which trims all trailing whitespace), use `printf '%s' "$(< /run/secrets/foo)"` or pipe the value through `sed -E 's/[[:space:]]+$//'` before interpolating.

The two syntaxes do not compose. `${VAR}` interpolation runs only inside plain string scalars; `!file` runs only on `!file`-tagged scalars. A path passed to `!file` is not itself interpolated — write the literal path in the scenario.

A Kubernetes deployment snippet mounting an SNMP auth password as a secret and pointing the scenario at it:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rastreo-server
spec:
  template:
    spec:
      containers:
        - name: rastreo-server
          image: ghcr.io/davidban77/rastreo:latest
          volumeMounts:
            - name: snmp-secrets
              mountPath: /run/secrets
              readOnly: true
      volumes:
        - name: snmp-secrets
          secret:
            secretName: rastreo-snmp-credentials
            items:
              - key: auth-password
                path: snmp-auth-password
              - key: priv-password
                path: snmp-priv-password
```

The corresponding scenario references `!file /run/secrets/snmp-auth-password`. If the secret is rotated in Kubernetes, the mounted file's contents change and the next scenario load picks up the new value. The current run does not hot-reload — secrets are read once at load, and any change on disk during a live scan is only picked up on the next load.

## A reference only fills a string field

Both syntaxes substitute a **string**. So a reference works only where the field itself accepts a string. This is the limit of the feature, not a mistake you can fix by writing the reference differently.

| What the field holds | Reference works | Fields |
|---|---|---|
| Text | Yes | `password`, `community`, `username`, `path`, `topic`, `subject`, `stream`, and each entry inside `servers` or `brokers` |
| One word from a fixed set | Yes | `algorithm`, `mechanism`, and the `type:` line of a prober or a sink |
| A number | No | `timeout_ms`, `max_concurrent`, `probe_rate`, `retries`, `retry.max_attempts` |
| `true` or `false` | No | `tls_verify` |
| A list | No | `ports`, `servers`, `brokers` |
| A block with its own fields | No | `credentials`, `sasl`, `flush_mode` |

`servers` and `brokers` appear twice on purpose. The list itself cannot be a reference; each string inside it can.

A row marked **No** fails even when the variable holds a value that would be correct written inline. `retry.max_attempts` on a sink config sets how many times a failed write is retried. Writing it as `retry.max_attempts: "${ATTEMPTS}"` fails even with `ATTEMPTS=5` in the environment. The reference produced the text `5`, and the field takes a number:

```text
sink shape validation failed after secret expansion: invalid type: string "${ATTEMPTS}", expected u32 (references resolved; quoted as written, never as the value produced; expansion substitutes a string, so a reference can only fill a field that accepts one)
```

A scenario file fails the same way, with `scenario` in place of `sink` at the front of the message.

Every field that holds a credential accepts text, so this limit never blocks a secret. It matters because the numeric and boolean knobs sit in the same config block as the credential. That is where you will meet it. Set those knobs from a deployment template or a Helm value instead.

## Sink configs on `rastreo-server`

`rastreo-server` builds its sink from the YAML file at `RASTREO_SINK_CONFIG_PATH`, and that file goes through the same expansion as a scenario file. A broker credential can therefore stay in a Kubernetes Secret while the config file carries only a reference to it:

```yaml
type: nats
servers: ["nats://probe:${NATS_PASS}@nats.observability.svc:4222"]
subject: rastreo.discovery.records.v1
stream: RASTREO
```

Or, with the credential on a secret mount instead of in the environment:

```yaml
type: kafka
brokers: ["kafka.observability.svc:9092"]
topic: rastreo.discovery.records.v1
sasl:
  mechanism: scram_sha_512
  username: rastreo
  password: !file /run/secrets/kafka-sasl-password
```

This matters most on Kubernetes, where the sink config is usually a ConfigMap: plaintext at rest, readable by anyone with namespace access, and echoed back by `helm get values`. Referencing the credential keeps it in a Secret and out of both. See [Server deployment · sink reachability probe](../deploy/server.md#sink-reachability-probe) for the mount path and the Helm values.

!!! warning "Through the Helm chart, use `${VAR}` and not `!file`"
    The chart renders the sink config into the ConfigMap with Helm's own YAML handling. That drops the `!file` tag and keeps the path as plain text. The server then reads the path *as the credential*. A `${VAR}` reference survives unchanged. Write `!file` only into a sink config file you manage yourself.

An unresolvable reference does not crash the pod. Sink construction fails, `/readyz` returns `503` with `reason: "sink_unreachable"`, and `last_probe_error` names the variable and the config path — `environment variable NATS_PASS referenced in sink config is not set`.

`/readyz` is served without a bearer token. That is why no expanded credential is allowed to reach `last_probe_error` on any failure path. A connect failure strips the userinfo from the server URL: a failed connect to `nats://probe:hunter2@nats:4222` reports `nats://nats:4222`, and the dry-run plan render does the same. A config whose *shape* is wrong is reported against the file as written, so the message quotes the reference rather than the value it resolved to:

```text
sink shape validation failed after secret expansion: invalid type: string "nats://probe:${NATS_PASS}@nats.observability.svc:4222", expected a sequence (references resolved; quoted as written, never as the value produced; expansion substitutes a string, so a reference can only fill a field that accepts one)
```

Here `servers` is a string where a list is expected — the credential played no part in the failure and never appears. When the quoted text is a `!file` reference, it is the mount path, not the file's contents. Read the quoted scalar as the text in your file: it is never the substituted value. The closing note repeats the limit from [A reference only fills a string field](#a-reference-only-fills-a-string-field).

## Vault, AWS Secrets Manager, other secret backends

External secret backends are out of scope for rastreo itself. The recommended pattern is to wrap the rastreo binary in a small script that fetches secrets from the backend and exports them into the process environment (or writes them to a tmpfs mount for `!file` to pick up).

A minimal wrapper example that reads two secrets from HashiCorp Vault and hands them to rastreo as environment variables:

```bash
#!/usr/bin/env bash
set -euo pipefail
export SNMP_AUTH_PASSWORD="$(vault kv get -field=auth secret/snmp)"
export SNMP_PRIV_PASSWORD="$(vault kv get -field=priv secret/snmp)"
exec rastreo discover --file /etc/rastreo/scan.yml
```

The same shape works for AWS Secrets Manager (`aws secretsmanager get-secret-value --query SecretString --output text`), sops (`sops -d`), and any other backend that returns plaintext to stdout on stdout. Keeping the fetch step outside rastreo means the fleet's existing secret-management flow (rotation cadence, audit logs, access policies) applies uniformly, and rastreo itself does not need a new dependency for every backend.

## When it is safe to hardcode

Never in production. In a lab, when running a scenario file that never leaves the machine and is not checked into version control, hardcoding a plaintext community string or password is fine — the interpolation syntaxes are optional, not required. Every scenario field that accepts a secret still accepts a plain string.

The redacted-in-Debug wrappers (`Password`, `Community`) keep plaintext out of logs, panic messages, and NDJSON output regardless of how the value was loaded. But hardcoded credentials in a YAML file that lives on a shared host, in a shared git repo, or in a shared container image will end up somewhere they should not. Use env-var interpolation or `!file` as soon as the scenario leaves your workstation.

## See also

- [Scenario schema](scenario.md) — every field of a scenario file, including which ones accept secrets.
- [SNMP prober](../probe/snmp.md) — SNMPv3 credentials, the primary consumer of secret expansion.
- [NATS sink](../integrate/nats.md) — password and token fields on the NATS sink credentials block.
- [Server deployment](../deploy/server.md#sink-reachability-probe) — the sink config file `rastreo-server` reads, and how the Helm chart renders it.
