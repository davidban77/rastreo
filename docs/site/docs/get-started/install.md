---
description: Install the rastreo CLI and the rastreo-server HTTP control plane via the install.sh script, prebuilt Docker image, Helm chart, or Cargo.
---

# Install

Installing rastreo gives you two binaries: `rastreo`, the CLI used to run one-shot discovery scans, and `rastreo-server`, the HTTP control plane that drives scans over an API. Pick the install path that matches how you'll run it.

## Quick install (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/davidban77/rastreo/main/install.sh | sh
```

The installer detects your OS and architecture, downloads the matching tarball plus the release's `SHA256SUMS`, verifies the checksum, and drops `rastreo` + `rastreo-server` into `/usr/local/bin`. Supported: linux amd64/arm64, macOS amd64/arm64.

Pin a specific version or install to a different directory via environment variables:

```bash
RASTREO_VERSION=vX.Y.Z curl -fsSL https://raw.githubusercontent.com/davidban77/rastreo/main/install.sh | sh
RASTREO_INSTALL_DIR=$HOME/.local/bin curl -fsSL https://raw.githubusercontent.com/davidban77/rastreo/main/install.sh | sh
```

## Docker

```bash
docker pull ghcr.io/davidban77/rastreo:latest
```

The image is multi-arch (linux amd64 + arm64) and ships both binaries. The default `ENTRYPOINT` is `rastreo-server` (port 8080); override to run the CLI:

```bash
docker run --rm --entrypoint /rastreo ghcr.io/davidban77/rastreo:latest discover --target 1.1.1.1
```

Pinned tags (`X.Y.Z`, `X.Y`, `X`) are available on every release. See [Docker](../deploy/docker.md) for the full surface.

## Helm chart (Kubernetes)

```bash
helm install rastreo oci://ghcr.io/davidban77/charts/rastreo
```

The chart deploys `rastreo-server` as a Deployment with sensible defaults (non-root UID, read-only rootfs, dropped capabilities). An install with no `--version` pulls the latest published chart. See [Kubernetes](../deploy/kubernetes.md) for values reference, version pinning, and ServiceMonitor setup.

## From source (Cargo)

Clone the repository and use `cargo install` to put the binaries on your `$PATH`. The CLI and the server are separate crates.

```bash
git clone https://github.com/davidban77/rastreo
cd rastreo
cargo install --path rastreo            # installs the `rastreo` CLI
cargo install --path rastreo-server     # installs `rastreo-server`
```

Both binaries are installed into `~/.cargo/bin/`. If `cargo` was set up by `rustup`, that directory is already on your `$PATH`.

!!! warning "A source build carries fewer probers than a release binary"
    The commands above build with default features, so only `tcp_connect`, `udp`, `dns`, and `reverse_dns` are compiled in. A scan with no `--probe` then runs `tcp_connect` and `reverse_dns` alone, where the released binaries run seven kinds. Name the features you want to match them:

    ```bash
    cargo install --path rastreo --features kafka,http,snmp,arp,ndp,oui,nats,ssh,icmp,tls,gnmi,lldp
    ```

    That is the set the release tarballs and the Docker image are built with. `--probe <kind>` on a build without the matching feature fails with a message naming the feature to add. See [Choosing probers](../discover/cli.md#choosing-probers).

## For development

When you are changing rastreo itself, build the whole workspace and run the debug binary directly out of `target/`.

```bash
cargo build --workspace
./target/debug/rastreo --version
./target/debug/rastreo discover --target 1.1.1.1
```

## Verify the install

```bash
rastreo --version
rastreo discover --help
```

`rastreo --version` prints the binary name and its version on one line. `rastreo discover --help` prints the full flag reference for the discovery subcommand — see [CLI](../discover/cli.md) for the same surface in long form.

## See also

- [First scan](first-scan.md) — run an end-to-end discovery scan and read the output.
- [CLI](../discover/cli.md) — every flag `rastreo discover` accepts.
