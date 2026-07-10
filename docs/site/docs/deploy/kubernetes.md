---
description: Install rastreo-server on Kubernetes with the bundled Helm chart — key values, image-source caveat, ServiceMonitor for Prometheus scraping, and chart-default security context.
---

# Kubernetes

The repository ships a Helm chart at `helm/rastreo/` that installs `rastreo-server` as a Deployment. The chart targets `rastreo-server` only — the CLI is a one-shot tool and is better run from a Kubernetes `Job` or from a laptop than from a long-lived pod. The chart's defaults match the bundled Docker image: non-root UID 65532, read-only root filesystem, and all capabilities dropped.

## Install

The published chart lives at `oci://ghcr.io/davidban77/charts/rastreo` — each `v*` tag pushes a fresh version. Pin the version explicitly so upgrades are intentional.

```bash
helm install rastreo oci://ghcr.io/davidban77/charts/rastreo --version 0.3.0
```

Or install from the checked-out source tree without pulling from the registry:

```bash
helm install rastreo ./helm/rastreo
```

Use `--values myvalues.yaml` to override defaults without forking the chart.

```bash
helm install rastreo oci://ghcr.io/davidban77/charts/rastreo --version 0.3.0 --values myvalues.yaml
```

## Key values

The most useful `values.yaml` knobs are:

| Key                              | Default                       | What it controls                                          |
|----------------------------------|-------------------------------|-----------------------------------------------------------|
| `replicaCount`                   | `1`                           | Number of `rastreo-server` pods.                          |
| `image.repository`               | `ghcr.io/davidban77/rastreo`  | The container image. See the caveat below.                |
| `image.tag`                      | chart `appVersion`            | Tag to pull; empty means use `appVersion`.                |
| `server.port`                    | `8080`                        | Port `rastreo-server` listens on inside the container.    |
| `service.type`                   | `ClusterIP`                   | `ClusterIP`, `NodePort`, or `LoadBalancer`.               |
| `resources.requests` / `.limits` | `100m`/`128Mi` / `500m`/`256Mi` | Pod CPU and memory requests and limits.                 |
| `autoscaling.enabled`            | `false`                       | Enable an HPA scaling between `minReplicas` and `maxReplicas`. |
| `podDisruptionBudget.enabled`    | `false`                       | Create a PDB with `minAvailable: 1`.                      |
| `ingress.enabled`                | `false`                       | Create an `Ingress` for the service.                      |
| `serviceMonitor.enabled`         | `false`                       | Create a Prometheus Operator `ServiceMonitor` that scrapes `/metrics`. |
| `alerts.enabled`                 | `false`                       | Create a Prometheus Operator `PrometheusRule` with four packaged alerts. See [Observability · Alerts](../reference/observability.md#alerts). |
| `grafana.dashboardsEnabled`      | `false`                       | Deploy the bundled Grafana dashboard as a labeled `ConfigMap` for sidecar auto-discovery. See [Observability · Grafana dashboard](../reference/observability.md#grafana-dashboard). |
| `podSecurity.netRaw`             | `false`                       | Add `NET_RAW` to the container capabilities. Required for the ARP and NDP probers. See [`podSecurity.netRaw`](#podsecuritynetraw-arp-and-ndp-probers). |
| `logFormat`                      | unset (binary default `text`) | Log line format on stderr. Set to `json` for Loki / ELK / Splunk ingestion; renders `RASTREO_LOG_FORMAT` on the pod. See [Logging](../reference/logging.md). |
| `otlp.metricsEnabled`            | `false`                       | Push metrics via OpenTelemetry OTLP gRPC. Requires an OTLP-enabled image build. See [OTLP](../reference/otlp.md). |
| `otlp.logsEnabled`               | `false`                       | Push logs via OpenTelemetry OTLP gRPC. Requires an OTLP-enabled image build. See [OTLP](../reference/otlp.md). |
| `otlp.endpoint`                  | `""`                          | OTLP gRPC collector URL, e.g. `http://otel-collector.observability.svc:4317`. Required when either OTLP toggle is on. |
| `config`                         | `{}`                          | Inline YAML mounted at `/etc/rastreo` as a `ConfigMap`.   |

A worked example of `config`:

```yaml
config:
  rastreo.yaml: |
    targets:
      - 10.0.0.0/24
    probers:
      - type: tcp_connect
        ports: [22, 80, 443]
```

Each key under `config` becomes a file at `/etc/rastreo/<key>`. The Deployment template adds a checksum annotation so pods restart when the ConfigMap changes.

## Image source

The chart's default `image.repository` is `ghcr.io/davidban77/rastreo` — a multi-arch image built from the same source tree, published on every `v*` tag. `image.tag` defaults to the chart's `appVersion`, so `helm install ... --version 0.3.0` pulls `ghcr.io/davidban77/rastreo:0.3.0` out of the box.

To pin to a different image (a fork in a private registry, a mid-cycle build, or a specific SHA), override `image.repository` and `image.tag`:

```bash
helm install rastreo oci://ghcr.io/davidban77/charts/rastreo --version 0.3.0 \
  --set image.repository=my-registry.example.com/rastreo \
  --set image.tag=0.3.0
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

The image ships with `cap_net_raw+ep` set on both `/rastreo` and `/rastreo-server` as a file capability, so the non-root runtime user picks the capability up automatically when the container has `NET_RAW` in its bounding set — no ambient-capability juggling required. Keeping `capabilities.add: [NET_RAW]` on the container is still what grants that bounding set, so the Helm toggle remains the load-bearing knob.

Without this toggle, scenarios that reference `type: arp` or `type: ndp` will fail at probe time with `raw socket permission denied; ARP requires CAP_NET_RAW` (or the analogous NDP message). The pod itself continues running; only those specific probes fail.

## Security context

The chart's `podSecurityContext` and container `securityContext` are restrictive by default:

- Non-root: `runAsNonRoot: true`, `runAsUser: 65532`, `runAsGroup: 65532`, `fsGroup: 65532`.
- Read-only root: `readOnlyRootFilesystem: true`.
- No new privileges: `allowPrivilegeEscalation: false`.
- All capabilities dropped: `capabilities.drop: [ALL]`.
- Seccomp: `seccompProfile.type: RuntimeDefault`.

These line up with Pod Security Standards `restricted` out of the box. Most clusters do not need to override them.

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
