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

All metric names use the `rastreo_server_` prefix. See [rastreo-server · GET /metrics](server.md#get-metrics) for the per-metric table.

## Security context

The chart's `podSecurityContext` and container `securityContext` are restrictive by default:

- Non-root: `runAsNonRoot: true`, `runAsUser: 65532`, `runAsGroup: 65532`, `fsGroup: 65532`.
- Read-only root: `readOnlyRootFilesystem: true`.
- No new privileges: `allowPrivilegeEscalation: false`.
- All capabilities dropped: `capabilities.drop: [ALL]`.
- Seccomp: `seccompProfile.type: RuntimeDefault`.

These line up with Pod Security Standards `restricted` out of the box. Most clusters do not need to override them.

## See also

- [Docker](docker.md) — the image the chart deploys.
- [rastreo-server](server.md) — the HTTP API the pods expose.
