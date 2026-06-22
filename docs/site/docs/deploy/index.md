---
description: Run rastreo as a CLI, as the rastreo-server HTTP control plane, in Docker, or on Kubernetes via the bundled Helm chart.
---

# Deploy

This section covers the operational surfaces rastreo ships with. The CLI is the canonical entry point for laptop and CI use; `rastreo-server` is the long-lived HTTP control plane for scheduling scans over REST; the bundled Docker image and Helm chart package both binaries in a single musl-static container that runs on any Linux host or Kubernetes cluster.

Topics covered here include CLI invocation patterns, the `rastreo-server` REST API (`POST /scans`, `GET /health`), Docker Compose usage (the development stack ships in the repo), and Helm chart deployment with the optional ServiceMonitor for Prometheus scraping.

## Pages in this section

- [Docker](docker.md) — build and run the bundled multi-arch image, and walk through the local compose stack.
- [Kubernetes](kubernetes.md) — install `rastreo-server` on a cluster with the bundled Helm chart.
- [rastreo-server](server.md) — the HTTP API: routes, request and response shape, and configuration flags.
