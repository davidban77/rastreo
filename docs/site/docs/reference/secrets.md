---
description: How rastreo loads secrets from environment variables and file mounts at scenario-load time, keeping plaintext passwords out of scenario YAML files.
---

# Secrets

Scenario files often need to carry credential material — SNMPv3 auth and privacy passwords, SNMP v2c community strings on managed fleets, NATS sink passwords, and so on. Writing those values inline is fine for a lab but a blocker for anything that ships. rastreo expands two syntaxes at scenario-load time so credentials can live in the process environment or on a file mount instead of in the checked-in YAML.

Both syntaxes are resolved before deserialization runs, so a missing value fails at load with a clear error rather than showing up as an authentication failure during a probe. Secret rotation still changes `source_config_hash` because the plaintext feeds the redacted-value hash inside `Password` / `Community`; downstream consumers see the same "config changed" signal they would see for a manually-edited YAML file.

## Environment variables (`${VAR}`)

Any string scalar in the scenario YAML may reference an environment variable using the shell-style `${VAR}` syntax. The identifier must match `[A-Za-z_][A-Za-z0-9_]*` — the same character set as POSIX shell variable names.

```yaml
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

A missing environment variable (`std::env::var` returns `NotPresent`) fails scenario load with `configuration error: environment variable NAME referenced in scenario is not set`. A variable that is set to an empty string substitutes as an empty string with no error — this is a deliberate distinction so `unset` and `set-to-empty` remain distinguishable, and lets a deployment script export `AUTH_PASS=""` to select the SNMPv3 `noAuthNoPriv` code path without special-casing.

To include a literal `${VAR}` in the output — for example when a value legitimately contains braces — prefix the sequence with a second `$`: `$${VAR}` expands to `${VAR}` in the loaded value. No other escape syntax is recognised; a stray `${` with no closing brace or a malformed identifier like `${1foo}` or `${a-b}` is passed through untouched, on the theory that surprise-erroring on non-interpolation shapes is more annoying than useful.

Only string values are interpolated. Mapping keys are left literal — env-var expansion on a YAML key is a footgun that would silently rewrite scenario structure, and a canonical key like `password:` should never depend on the environment.

Only string scalars in the scenario body are affected. YAML booleans, numbers, sequences, and tagged values other than `!file` pass through unchanged.

## File-based secrets (`!file`)

Any string scalar may be replaced with the `!file` YAML tag followed by an absolute path. rastreo reads the file at scenario load and substitutes its contents (with the trailing newline trimmed) into the scalar position. This matches the Kubernetes secret-mount pattern where the secret material sits at `/run/secrets/<name>` in the pod filesystem.

```yaml
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

Missing files, unreadable files, and other I/O errors fail at scenario load with a message that names the path:

| Error kind | Message shape |
|---|---|
| File not found | `configuration error: file secret /run/secrets/foo not found` |
| Permission denied | `configuration error: file secret /run/secrets/foo not readable: permission denied` |
| Other I/O failure | `configuration error: file secret /run/secrets/foo could not be read: <os message>` |
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
