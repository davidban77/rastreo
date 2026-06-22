---
description: Build and run rastreo with Docker — multi-arch musl-static image, the bundled compose stack (Kafka + nginx targets + rastreo-server), and how to run the CLI inside the image.
---

# Docker

The repository ships a multi-arch `Dockerfile` that builds static musl binaries for `linux/amd64` and `linux/arm64`. The image bundles both `rastreo` and `rastreo-server` in a `FROM scratch` runtime layer, runs as non-root (UID 65532), and weighs about 4 MB. The repository also ships a `docker-compose.yml` for local development that brings up Kafka, three nginx target hosts, and `rastreo-server` on a private bridge network.

## Build

A native-arch build is one command from the repository root.

```bash
docker build -t rastreo .
```

For a multi-arch build, use `docker buildx` and pass the platforms you want. The Dockerfile cross-compiles to the right musl target per platform using `TARGETARCH`.

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t rastreo .
```

The default build does not include the `kafka` Cargo feature, so the produced image's `rastreo` binary will reject `--sink kafka`. To enable Kafka, edit the Dockerfile and append `--features kafka` to the final `cargo build` invocation, or maintain a Dockerfile overlay for the build configuration you want.

!!! warning "Kafka requires the `kafka` build feature"
    The image does not enable the `kafka` feature by default. To produce an image whose `rastreo` CLI accepts `--sink kafka`, change the `cargo build --release --target "${RUST_TARGET}" -p rastreo -p rastreo-server` line in the Dockerfile to add `--features kafka`. The same applies to `cargo install --path rastreo --features kafka` outside Docker.

## Run the CLI

The image's `ENTRYPOINT` is `/rastreo-server`. To run the CLI instead, override the entrypoint with `--entrypoint /rastreo`.

```bash
docker run --rm --entrypoint /rastreo rastreo --version
docker run --rm --entrypoint /rastreo rastreo discover --target 1.1.1.1 --port 443
```

## Run the server

The default entrypoint runs `rastreo-server`. Expose port 8080 and the server is reachable on the host.

```bash
docker run --rm -p 8080:8080 rastreo
# in another terminal
curl http://localhost:8080/health
```

## The compose stack

`docker compose up -d` brings up the full local development stack. The stack is a single bridge network (`rastreo-net`, subnet `10.50.0.0/24`) with four services.

| Service          | Address                | Ports               | Role                                                    |
|------------------|------------------------|---------------------|---------------------------------------------------------|
| `kafka`          | `10.50.0.2`            | `9092` (host)       | Single-node Kafka (`apache/kafka:4.2.0`). Dual listener — see below. |
| `rastreo-server` | `10.50.0.3`            | `8080` (host)       | The HTTP control plane, built from this repo's Dockerfile. |
| `target-1`       | `10.50.0.10`           | `80` (internal)     | `nginx:1.31-alpine`. HTTP listener for probe experiments. |
| `target-2`       | `10.50.0.11`           | `80` (internal)     | `nginx:1.31-alpine`. HTTP listener for probe experiments. |
| `target-3`       | `10.50.0.12`           | `80` (internal)     | `nginx:1.31-alpine`. HTTP listener for probe experiments. |

The Kafka broker advertises two listeners: `EXTERNAL://localhost:9092` (reachable from the host) and `INTERNAL://kafka:29092` (reachable from other containers on `rastreo-net`). A CLI running on the host points at `localhost:9092`; a CLI inside a container on `rastreo-net` points at `kafka:29092`. Mixing the two is the most common cause of broker-unreachable failures — see [Troubleshooting](../integrate/troubleshooting.md#kafka-broker-unreachable).

```bash
docker compose up -d
curl http://localhost:8080/health
# {"status":"ok"}
docker compose down -v
```

The three nginx target hosts sit on the bridge network and are not exposed on the host. To probe them, run the CLI from inside a container on `rastreo-net`.

```bash
docker compose exec rastreo-server /rastreo discover --target 10.50.0.10 --port 80
```

## Image security context

The runtime image is `FROM scratch` — no shell, no package manager, no system utilities. The image runs as UID 65532 (the upstream "nonroot" convention used by distroless and Chainguard images). The binaries are static musl, so no dynamic loader is needed. This makes the image friendly to clusters that enforce Pod Security Standards `restricted`: non-root, read-only root filesystem, all capabilities dropped, no privilege escalation. The Helm chart's default `securityContext` lines up with these properties — see [Kubernetes](kubernetes.md#security-context).

## See also

- [Kubernetes](kubernetes.md) — install the same image on a cluster via the Helm chart.
- [rastreo-server](server.md) — the HTTP API the image exposes.
