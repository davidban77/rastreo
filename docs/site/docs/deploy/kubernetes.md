---
description: Install rastreo-server on Kubernetes with the bundled Helm chart — key values, image-source caveat, ServiceMonitor caveat, and chart-default security context.
---

# Kubernetes

The repository ships a Helm chart at `helm/rastreo/` that installs `rastreo-server` as a Deployment. The chart targets `rastreo-server` only — the CLI is a one-shot tool and is better run from a Kubernetes `Job` or from a laptop than from a long-lived pod. The chart's defaults match the bundled Docker image: non-root UID 65532, read-only root filesystem, and all capabilities dropped.

## Install

```bash
helm install rastreo ./helm/rastreo
```

Use `--values myvalues.yaml` to override defaults without forking the chart.

```bash
helm install rastreo ./helm/rastreo --values myvalues.yaml
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
| `serviceMonitor.enabled`         | `false`                       | Create a Prometheus Operator `ServiceMonitor`. See the caveat below. |
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

The chart's default `image.repository` is `ghcr.io/davidban77/rastreo`, but **no image is published to ghcr.io today**. The chart references the eventual published image; until then, build the image locally and push it to a registry your cluster can pull from, then override `image.repository` and `image.tag`.

```bash
docker build -t my-registry.example.com/rastreo:0.0.3 .
docker push my-registry.example.com/rastreo:0.0.3
helm install rastreo ./helm/rastreo \
  --set image.repository=my-registry.example.com/rastreo \
  --set image.tag=0.0.3
```

## ServiceMonitor caveat

!!! warning "`serviceMonitor.enabled: true` will produce 404 scrape errors today"
    The chart's `serviceMonitor.path` defaults to `/metrics`, but `rastreo-server` does not expose a `/metrics` endpoint today — the route table is `/health` and `/scans` only. The ServiceMonitor is forward-prepared for a future metrics endpoint; leave `serviceMonitor.enabled: false` (the default) until that endpoint exists.

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
