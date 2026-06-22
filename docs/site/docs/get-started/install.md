---
description: Install the rastreo CLI and the rastreo-server HTTP control plane from source or Docker.
---

# Install

Installing rastreo gives you two binaries: `rastreo`, the CLI used to run one-shot discovery scans, and `rastreo-server`, the HTTP control plane that drives scans over an API. Most readers want the CLI; install the server when you need a long-running process other systems can call.

There is no published crate on crates.io and no published Docker image yet, so every install path below builds from the source tree.

## From source (Cargo)

Clone the repository and use `cargo install` to put the binaries on your `$PATH`. The CLI and the server are separate crates, so they install independently.

```bash
git clone https://github.com/davidban77/rastreo
cd rastreo
cargo install --path rastreo            # installs the `rastreo` CLI
cargo install --path rastreo-server     # installs `rastreo-server`
```

Both binaries are installed into `~/.cargo/bin/`. If `cargo` was set up by `rustup`, that directory is already on your `$PATH`. If `rastreo --version` is not found after the install, add `~/.cargo/bin` to your shell `$PATH`.

## With Docker

The repository ships a multi-arch `Dockerfile` that builds static musl binaries for `linux/amd64` and `linux/arm64`. The image bundles both `rastreo` and `rastreo-server`. The default `ENTRYPOINT` is `rastreo-server` — to run the CLI inside a container, override the entrypoint.

```bash
docker build -t rastreo .

# run the CLI by overriding the entrypoint
docker run --rm --entrypoint /rastreo rastreo --version
docker run --rm --entrypoint /rastreo rastreo discover --target 1.1.1.1 --port 443

# build for both architectures with buildx
docker buildx build --platform linux/amd64,linux/arm64 -t rastreo .
```

## For development

When you are changing rastreo itself, build the whole workspace and run the debug binary directly out of `target/`. There is no install step.

```bash
cargo build --workspace
./target/debug/rastreo --version
./target/debug/rastreo discover --target 1.1.1.1 --port 443
```

## Verify the install

```bash
rastreo --version
rastreo discover --help
```

`rastreo --version` should print a version line such as `rastreo 0.0.3`. `rastreo discover --help` prints the full flag reference for the discovery subcommand — see [CLI](../discover/cli.md) for the same surface in long form.

## See also

- [First scan](first-scan.md) — run an end-to-end discovery scan and read the output.
- [CLI](../discover/cli.md) — every flag `rastreo discover` accepts.
