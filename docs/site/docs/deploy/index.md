---
description: Run rastreo as a CLI, as the rastreo-server HTTP control plane, in Docker, or on Kubernetes via the bundled Helm chart.
---

# Deploy

This section covers the operational surfaces rastreo ships with. The CLI is the canonical entry point for laptop and CI use; `rastreo-server` is the long-lived HTTP control plane for scheduling scans over REST; the bundled Docker image and Helm chart package both binaries in a single musl-static container that runs on any Linux host or Kubernetes cluster.

<div class="grid cards" markdown>

-   :material-docker:{ .lg .middle } **Docker**

    ---

    Build and run the bundled multi-arch image, and walk through the local compose stack.

    [:octicons-arrow-right-24: Docker](docker.md)

-   :material-kubernetes:{ .lg .middle } **Kubernetes**

    ---

    Install `rastreo-server` on a cluster with the bundled Helm chart.

    [:octicons-arrow-right-24: Kubernetes](kubernetes.md)

-   :material-server-network:{ .lg .middle } **rastreo-server**

    ---

    The HTTP API: routes, request and response shape, and configuration flags.

    [:octicons-arrow-right-24: rastreo-server](server.md)

</div>

## See also

- [Glossary](../reference/glossary.md) — rastreo and networking terms used across the docs.
