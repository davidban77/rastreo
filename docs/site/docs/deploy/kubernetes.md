---
description: Install rastreo-server on Kubernetes with the bundled Helm chart — key values, image-source caveat, ServiceMonitor for Prometheus scraping, and chart-default security context.
---

# Kubernetes

The repository ships a Helm chart at `helm/rastreo/` that installs `rastreo-server` as a Deployment. The chart targets `rastreo-server` only — the CLI is a one-shot tool and is better run from a Kubernetes `Job` or from a laptop than from a long-lived pod. The chart's defaults match the bundled Docker image: non-root UID 65532, read-only root filesystem, and all capabilities dropped.

## Install

The published chart lives at `oci://ghcr.io/davidban77/charts/rastreo` — each `v*` tag pushes a fresh version. The current published chart version is `0.9.0`. <!-- x-release-please-version --> An install with no `--version` pulls the latest published chart. To pin an upgrade intentionally, add `--version` with that version.

The chart is fail-closed: `POST /scans` requires a bearer token, so an install with no token source stops before it creates anything. The production-safe path keeps the token in a `Secret` you manage and points the chart at it.

```bash
kubectl create secret generic rastreo-api-token \
  --from-literal=api-token="$(openssl rand -hex 32)"

helm install rastreo oci://ghcr.io/davidban77/charts/rastreo \
  --set auth.existingSecret=rastreo-api-token
```

For a quick lab install, let the chart generate the `Secret` from an inline token instead.

```bash
helm install rastreo oci://ghcr.io/davidban77/charts/rastreo \
  --set auth.token="$(openssl rand -hex 32)"
```

See [Authentication](#authentication) for all three token options, including how to run the endpoint unauthenticated on a trusted network.

Or install from the checked-out source tree without pulling from the registry. The same token source applies.

```bash
helm install rastreo ./helm/rastreo \
  --set auth.existingSecret=rastreo-api-token
```

Use `--values myvalues.yaml` to override defaults without forking the chart. Set a token source in the file or on the command line.

```bash
helm install rastreo oci://ghcr.io/davidban77/charts/rastreo \
  --values myvalues.yaml \
  --set auth.existingSecret=rastreo-api-token
```

## Key values

The most useful `values.yaml` knobs are:

| Key                              | Default                       | What it controls                                          |
|----------------------------------|-------------------------------|-----------------------------------------------------------|
| `replicaCount`                   | `1`                           | Number of `rastreo-server` pods.                          |
| `image.repository`               | `ghcr.io/davidban77/rastreo`  | The container image. See the caveat below.                |
| `image.tag`                      | chart `appVersion`            | Tag to pull; empty means use `appVersion`.                |
| `server.port`                    | `8080`                        | Port `rastreo-server` listens on inside the container.    |
| `server.maxResultBytes`          | `33554432`                    | Byte cap on the `POST /scans` response records (32 MiB). Renders `RASTREO_MAX_RESULT_BYTES`. Peak memory is ~3× this value, so raise `resources.limits.memory` before raising it. See [rastreo-server · Bounded response size](server.md#bounded-response-size). |
| `auth.enabled`                   | `true`                        | Require a bearer token on `POST /scans`. Fail-closed: render errors unless a token source is set. Set `false` to deploy unauthenticated. See [Authentication](#authentication). |
| `auth.token`                     | `""`                          | Inline bearer token. The chart renders a `Secret` holding it. Prefer `auth.existingSecret` in production. See [Authentication](#authentication). |
| `auth.existingSecret`            | `""`                          | Name of a pre-existing `Secret` holding the token. Takes precedence over `auth.token`. See [Authentication](#authentication). |
| `auth.secretKey`                 | `api-token`                   | Key within the `Secret` that holds the token value.       |
| `targetGuard.allowlist`          | `[]`                          | List of CIDRs (or bare IPs) the server may probe. Empty means allow any target. Renders `RASTREO_TARGET_ALLOWLIST`. See [Restricting scan targets](#restricting-scan-targets). |
| `targetGuard.maxTotalHosts`      | `262144`                      | Cap on the total resolved hosts across all targets in one request. `0` disables. Renders `RASTREO_MAX_TOTAL_HOSTS`. See [Restricting scan targets](#restricting-scan-targets). |
| `targetGuard.maxBodyBytes`       | `1048576`                     | `POST /scans` request body size limit in bytes. Renders `RASTREO_MAX_BODY_BYTES`. See [Restricting scan targets](#restricting-scan-targets). |
| `serviceAccount.create`          | `true`                        | Create a dedicated `ServiceAccount` with token automounting disabled. See [ServiceAccount](#serviceaccount). |
| `networkPolicy.enabled`          | `false`                       | Create a `NetworkPolicy` restricting which peers reach the pod. See [NetworkPolicy](#networkpolicy). |
| `service.type`                   | `ClusterIP`                   | `ClusterIP`, `NodePort`, or `LoadBalancer`.               |
| `resources.requests` / `.limits` | `100m`/`128Mi` / `500m`/`256Mi` | Pod CPU and memory requests and limits.                 |
| `autoscaling.enabled`            | `false`                       | Enable an HPA scaling between `minReplicas` and `maxReplicas`. |
| `podDisruptionBudget.enabled`    | `false`                       | Create a PDB with `minAvailable: 1`.                      |
| `ingress.enabled`                | `false`                       | Create an `Ingress` for the service.                      |
| `serviceMonitor.enabled`         | `false`                       | Create a Prometheus Operator `ServiceMonitor` that scrapes `/metrics`. |
| `alerts.enabled`                 | `false`                       | Create a Prometheus Operator `PrometheusRule` with four packaged alerts. See [Observability · Alerts](../reference/observability.md#alerts). |
| `readiness.maxInflightScans`     | unset (binary default `100`)  | `/readyz` gate: max concurrent `POST /scans` before the pod reports not-ready. Set to `0` to disable. Renders `RASTREO_MAX_INFLIGHT_SCANS`. See [Health endpoints · `/readyz`](../reference/health-endpoints.md#readyz-readiness). |
| `readiness.sinkErrorQuarantineSeconds` | unset (binary default `30`) | `/readyz` gate: quarantine window after any sink error. Set to `0` to disable. Renders `RASTREO_SINK_ERROR_QUARANTINE_SECS`. See [Health endpoints · `/readyz`](../reference/health-endpoints.md#readyz-readiness). |
| `readiness.scanErrorQuarantineSeconds` | unset (binary default `30`) | `/readyz` gate: quarantine window after any scan error. Set to `0` to disable. Renders `RASTREO_SCAN_ERROR_QUARANTINE_SECS`. See [Health endpoints · `/readyz`](../reference/health-endpoints.md#readyz-readiness). |
| `grafana.dashboardsEnabled`      | `false`                       | Deploy the bundled Grafana dashboard as a labeled `ConfigMap` for sidecar auto-discovery. See [Observability · Grafana dashboard](../reference/observability.md#grafana-dashboard). |
| `podSecurity.netRaw`             | `false`                       | Add `NET_RAW` to the container capabilities. Required for the ARP and NDP probers. See [`podSecurity.netRaw`](#podsecuritynetraw-arp-and-ndp-probers). |
| `logFormat`                      | unset (binary default `text`) | Log line format on stderr. Set to `json` for Loki / ELK / Splunk ingestion; renders `RASTREO_LOG_FORMAT` on the pod. See [Logging](../reference/logging.md). |
| `otlp.metricsEnabled`            | `false`                       | Push metrics via OpenTelemetry OTLP. Requires an OTLP-enabled image build (see `image.tag: X.Y.Z-otlp`). See [OTLP](../reference/otlp.md). |
| `otlp.logsEnabled`               | `false`                       | Push logs via OpenTelemetry OTLP. Requires an OTLP-enabled image build. See [OTLP](../reference/otlp.md). |
| `otlp.endpoint`                  | `""`                          | OTLP collector URL, e.g. `http://otel-collector.observability.svc:4317` (gRPC) or `http://otel-collector.observability.svc:4318` (HTTP+protobuf). Required when either OTLP toggle is on. |
| `otlp.protocol`                  | `grpc`                        | OTLP transport protocol. `grpc` targets a collector's gRPC port (4317). `http-protobuf` targets the HTTP+protobuf port (4318). See [OTLP · Transport protocol](../reference/otlp.md#transport-protocol). |
| `otlp.headers`                   | `""`                          | Custom headers on every OTLP export, for authenticating to a hosted collector. The chart renders a `Secret` holding the value. Prefer `otlp.headersExistingSecret` in production. See [Custom OTLP headers](#custom-otlp-headers). |
| `otlp.headersExistingSecret`     | `""`                          | Name of a pre-existing `Secret` holding the headers value. Takes precedence over `otlp.headers`. See [Custom OTLP headers](#custom-otlp-headers). |
| `otlp.headersSecretKey`          | `otlp-headers`                | Key within the `Secret` that holds the headers value.     |

!!! note "The result cap and the memory limit move together"
    `server.maxResultBytes` caps the `POST /scans` response at 32 MiB by default. Peak memory at response time is roughly 3× that cap, so the default fits under `resources.limits.memory` of `256Mi`. If you raise `server.maxResultBytes`, raise `resources.limits.memory` by the same proportion. A scan too large to return in one response still streams every record to a server-configured sink — see [rastreo-server · Bounded response size](server.md#bounded-response-size).

## Authentication

`POST /scans` is authenticated by default — see [rastreo-server · Authentication](server.md#authentication) for the request shape and the 401 response. On Kubernetes the chart supplies the bearer token to the pod for you.

The chart is fail-closed. With `auth.enabled: true` (the default), `helm template` and `helm install` error unless you supply a token source. This stops an unauthenticated scan endpoint from reaching the cluster by accident.

```text
Error: execution error at (rastreo/templates/deployment.yaml): auth.enabled is true but no token source is set: set auth.token to render a Secret, set auth.existingSecret to reference one, or set auth.enabled=false to run POST /scans unauthenticated (not recommended)
```

You have three ways to supply the token.

=== "Existing Secret (production)"

    Create the `Secret` with your own tooling, then point the chart at it with `auth.existingSecret`. The token never passes through Helm values or your shell history.

    ```bash
    kubectl create secret generic rastreo-api-token \
      --from-literal=api-token="$(openssl rand -hex 32)"

    helm install rastreo oci://ghcr.io/davidban77/charts/rastreo \
      --set auth.existingSecret=rastreo-api-token
    ```

    `auth.existingSecret` takes precedence over `auth.token`. The default key inside the `Secret` is `api-token`; set `auth.secretKey` if your `Secret` uses a different key.

=== "Inline token"

    Pass the token to the chart with `auth.token` and it renders a `Secret` for you. This is the simplest path for a lab, but the token is stored in your release values, so avoid it in production.

    ```bash
    helm install rastreo oci://ghcr.io/davidban77/charts/rastreo \
      --set auth.token="$(openssl rand -hex 32)"
    ```

=== "Unauthenticated (not recommended)"

    Deploy with no authentication. The pod starts with `RASTREO_AUTH_DISABLED=true` and logs a WARNING that the endpoint is open. Only do this on a trusted, isolated network.

    ```bash
    helm install rastreo oci://ghcr.io/davidban77/charts/rastreo \
      --set auth.enabled=false
    ```

!!! note "Read the token back for a client request"
    Fetch the stored token to build an authenticated call:

    ```bash
    kubectl get secret rastreo-api-token -o jsonpath='{.data.api-token}' | base64 -d
    ```

## Custom OTLP headers

Hosted OTLP collectors — Grafana Cloud, Honeycomb, Dynatrace, or a tenant-scoped Tempo or Mimir — usually need an authentication header on every export. The chart injects that header from a `Secret` and sets `RASTREO_OTLP_HEADERS` on the pod. See [OTLP · Custom headers](../reference/otlp.md#custom-headers) for the header format and the fail-fast behaviour.

The header value is a comma-separated list of `key=value` pairs, for example `authorization=Bearer <token>` or `authorization=Bearer <token>,x-scope-orgid=<tenant>`. A header value is a bearer token or API key, so supply it from a `Secret`. The chart renders the headers env only when an OTLP signal is enabled, so pair these values with `otlp.logsEnabled`, `otlp.metricsEnabled`, or `otlp.tracesEnabled`.

You have two ways to supply the headers.

=== "Existing Secret (production)"

    Create the `Secret` with your own tooling, then point the chart at it with `otlp.headersExistingSecret`. The token never passes through Helm values or your shell history.

    ```bash
    kubectl create secret generic rastreo-otlp-headers \
      --from-literal=otlp-headers="authorization=Bearer $OTLP_TOKEN"

    helm install rastreo oci://ghcr.io/davidban77/charts/rastreo \
      --set otlp.logsEnabled=true \
      --set otlp.endpoint=http://otel-collector.observability.svc:4318 \
      --set otlp.protocol=http-protobuf \
      --set otlp.headersExistingSecret=rastreo-otlp-headers
    ```

    `otlp.headersExistingSecret` takes precedence over `otlp.headers`. The default key inside the `Secret` is `otlp-headers`; set `otlp.headersSecretKey` if your `Secret` uses a different key.

=== "Inline value"

    Pass the headers to the chart with `otlp.headers` and it renders a `Secret` for you. This is the simplest path for a lab, but the value is stored in your release values, so avoid it in production.

    ```yaml
    otlp:
      logsEnabled: true
      endpoint: "http://otel-collector.observability.svc:4318"
      protocol: http-protobuf
      headers: "authorization=Bearer <token>,x-scope-orgid=<tenant>"
    ```

    The chart renders a `Secret` named `<release>-otlp` holding the value and mounts it into the pod as `RASTREO_OTLP_HEADERS`.

## Restricting scan targets

Authentication controls who may call `POST /scans`. The target guard controls which addresses the server is allowed to probe, and how large one request may be. See [rastreo-server · Restricting scan targets](server.md#restricting-scan-targets) for the full behaviour and the 403 / 400 / 413 responses.

The chart exposes three values under `targetGuard`:

- `targetGuard.allowlist` — a list of CIDRs (or bare IPs) the server may probe. Empty (the default) renders no `RASTREO_TARGET_ALLOWLIST`, so every target is allowed.
- `targetGuard.maxTotalHosts` — the cap on the total resolved hosts across all targets in one request. Default `262144`; `0` disables it.
- `targetGuard.maxBodyBytes` — the `POST /scans` request body size limit in bytes. Default `1048576` (1 MiB).

Set the allow-list and keep the two always-on caps at their defaults:

```bash
helm install rastreo oci://ghcr.io/davidban77/charts/rastreo \
  --set auth.existingSecret=rastreo-api-token \
  --set 'targetGuard.allowlist={10.0.0.0/8,192.168.0.0/16}'
```

Or set all three in a values file:

```yaml
targetGuard:
  allowlist:
    - 10.0.0.0/8
    - 192.168.0.0/16
  maxTotalHosts: 262144
  maxBodyBytes: 1048576
```

!!! note "The allow-list is opt-in and rejects the whole request"
    An empty `targetGuard.allowlist` (the default) allows any target. When you populate it, a scan whose resolved targets include any address outside the listed networks is rejected in full with `403` — nothing is probed.

## Image source

The chart's default `image.repository` is `ghcr.io/davidban77/rastreo` — a multi-arch image built from the same source tree, published on every `v*` tag. `image.tag` defaults to the chart's `appVersion`, so the install pulls the matching `ghcr.io/davidban77/rastreo` image.

To pin to a different image (a fork in a private registry, a mid-cycle build, or a specific SHA), override `image.repository` and `image.tag`:

```bash
helm install rastreo oci://ghcr.io/davidban77/charts/rastreo \
  --set image.repository=my-registry.example.com/rastreo \
  --set image.tag=X.Y.Z
```

## ServiceMonitor

Enable Prometheus scraping by setting `serviceMonitor.enabled: true`. `rastreo-server` exposes Prometheus-format metrics at `GET /metrics` — scan counts and outcomes, probe success/error totals, records emitted, sink errors, a request-duration histogram, uptime, and build info. The chart's default `serviceMonitor.path: /metrics` matches.

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
  scrapeTimeout: 10s
  path: "/metrics"
```

All metric names use the `rastreo_server_` prefix. See [rastreo-server · GET /metrics](server.md#get-metrics) for the per-metric table, and [Observability](../reference/observability.md) for the bundled Grafana dashboard and `PrometheusRule` alerts.

## `podSecurity.netRaw` — ARP and NDP probers

The ARP and NDP probers open `AF_PACKET` raw sockets to send Ethernet frames directly, which requires the `CAP_NET_RAW` Linux capability. The chart does NOT grant this by default because Pod Security Standards `restricted` and most managed Kubernetes distributions disallow capability additions. Opt in by setting `podSecurity.netRaw: true`:

```yaml
podSecurity:
  netRaw: true
```

When enabled, the rendered container `securityContext.capabilities.add` includes `NET_RAW` alongside the default `drop: [ALL]`. The Pod Security Standards `baseline` profile permits this; `restricted` does not — check the target namespace's Pod Security admission mode with `kubectl get ns <ns> -o yaml` before enabling. Some managed clusters (GKE Autopilot, EKS Fargate) prohibit capability additions cluster-wide and cannot run the ARP or NDP probers regardless of chart values.

The image ships with `CAP_NET_RAW` set on both `/rastreo` and `/rastreo-server` as a permitted-only file capability, and each binary raises it to effective in-process just before opening a raw socket. Because the capability is not effective at exec time, the default deploy — non-root, `drop: [ALL]`, no capability added — execs and runs cleanly; it does not crash-loop under a restricted `securityContext`. Setting `podSecurity.netRaw: true` adds `NET_RAW` to the container so the probers can actually open their sockets, while keeping the pod non-root and hardened.

Without this toggle, scenarios that reference `type: arp` or `type: ndp` record a clean `permission_denied` fault at probe time; the scan finishes with exit 0 and the pod keeps running. Only those specific probes fail — the container does not crash.

## Graceful shutdown and `terminationGracePeriodSeconds`

`rastreo-server` handles `SIGTERM` by refusing new connections, draining inflight `POST /scans` requests against the per-request timeout, and stopping the background sink-reachability probe. The process exits once both drains complete. A hard timeout bounds the wait so a stuck scan cannot block shutdown forever: `RASTREO_SHUTDOWN_TIMEOUT_SECS`, default 60 seconds. When the drain runs longer, the server logs a warning and force-exits. Set `terminationGracePeriodSeconds` on the pod spec to cover the longest expected scan plus the probe-iteration budget — for the binary defaults (60s request timeout, 5s probe timeout) `terminationGracePeriodSeconds: 75` gives a ~10s safety margin. The chart ships this value out of the box. If the grace period expires before drain completes, the kubelet sends `SIGKILL` and any inflight scan is aborted mid-flight without reaching the server-configured sink.

!!! note "The app timeout stays below the grace period"
    `RASTREO_SHUTDOWN_TIMEOUT_SECS` should stay below `terminationGracePeriodSeconds` so the app force-exits on its own before the kubelet sends `SIGKILL`. The defaults already do this: the app timeout is 60 seconds and the chart grace period is 75. The app exits first and logs a clean warning.

## Security context

The chart's `podSecurityContext` and container `securityContext` are restrictive by default:

- Non-root: `runAsNonRoot: true`, `runAsUser: 65532`, `runAsGroup: 65532`, `fsGroup: 65532`.
- Read-only root: `readOnlyRootFilesystem: true`.
- No new privileges: `allowPrivilegeEscalation: false`.
- All capabilities dropped: `capabilities.drop: [ALL]`.
- Seccomp: `seccompProfile.type: RuntimeDefault`.

These line up with Pod Security Standards `restricted` out of the box. Most clusters do not need to override them.

## ServiceAccount

The chart creates a dedicated `ServiceAccount` for the pod with token automounting turned off. `rastreo-server` never calls the Kubernetes API, so the pod carries no mounted API token.

- `serviceAccount.create` (default `true`) — create the `ServiceAccount`. Set `false` to use one you already manage.
- `serviceAccount.name` — the name to use. Empty derives it from the release name.
- `serviceAccount.annotations` — annotations to add, for example an IAM role binding.

The rendered `ServiceAccount` sets `automountServiceAccountToken: false`.

## NetworkPolicy

The chart can render a `NetworkPolicy` that limits which peers reach the pod. It is off by default because a correct policy depends on your cluster topology. With no configured sources on an enforcing CNI, the policy would deny all access.

Enable it and list the peers allowed to reach each port:

- `networkPolicy.enabled` — set to `true` to create the policy.
- `networkPolicy.ingress` — peers allowed to reach the API port, which serves `POST /scans` and the rest of the HTTP API.
- `networkPolicy.monitoring` — peers allowed to scrape `/metrics`, such as your monitoring namespace.

Each entry under `ingress` and `monitoring` is a standard `NetworkPolicyPeer`: a `namespaceSelector`, a `podSelector`, or both.

```yaml
networkPolicy:
  enabled: true
  ingress:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: automation
  monitoring:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
```

!!! warning "Health probes need node traffic, not a selector"
    Kubernetes liveness and readiness probes come from the kubelet on the node, not from a pod or namespace. A `namespaceSelector` or `podSelector` peer does NOT admit them. On a CNI that enforces host traffic, add the node or pod CIDR as an `ipBlock` peer. Otherwise the health probes fail and the pod restarts in a loop.

    `networkPolicy.monitoring` admits metrics scraping only. It does not admit the health probes.

    ```yaml
    networkPolicy:
      enabled: true
      ingress:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: automation
        - ipBlock:
            cidr: 10.244.0.0/16   # your node or pod CIDR — where health probes originate
    ```

## Structured logging

For log aggregation compatibility (Loki, ELK, Splunk, or any pipeline that expects one JSON object per line), set `logFormat: json` in `values.yaml`:

```yaml
logFormat: json
```

The chart renders `RASTREO_LOG_FORMAT=json` on the container's env. Leave the key unset (or `null`) to inherit the binary default of `text`. See [Logging](../reference/logging.md) for the JSON field shape and drop-in Promtail / Filebeat snippets.

## See also

- [Docker](docker.md) — the image the chart deploys.
- [rastreo-server](server.md) — the HTTP API the pods expose.
- [Observability](../reference/observability.md) — Grafana dashboard and PrometheusRule alerts shipped by the chart.
- [Logging](../reference/logging.md) — log format and aggregator ingestion examples.
- [OTLP](../reference/otlp.md) — OpenTelemetry OTLP export for metrics and logs.
