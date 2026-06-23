# syntax=docker/dockerfile:1

# Multi-arch Dockerfile for rastreo
#
# Supports linux/amd64 and linux/arm64 via docker buildx.
# Uses TARGETARCH (set automatically by buildx) to select the correct
# Rust target triple and cross-compilation toolchain.
#
# Usage:
#   docker build -t rastreo .                                                # native arch
#   docker buildx build --platform linux/amd64,linux/arm64 -t rastreo .     # multi-arch

# Build static binaries with musl
FROM rust:latest AS builder

# TARGETARCH is set by docker buildx (amd64, arm64, etc.)
ARG TARGETARCH

# Install cross-compilation toolchain based on target architecture.
# For amd64: musl-tools provides the native musl-gcc wrapper.
# For arm64: we use gcc-aarch64-linux-gnu as the linker.
RUN apt-get update && \
    apt-get install -y musl-tools && \
    if [ "${TARGETARCH}" = "arm64" ]; then \
      apt-get install -y gcc-aarch64-linux-gnu; \
    fi && \
    rm -rf /var/lib/apt/lists/*

# Set up Rust target and cross-compilation config
RUN case "${TARGETARCH}" in \
      amd64) echo "x86_64-unknown-linux-musl" > /tmp/rust-target ;; \
      arm64) echo "aarch64-unknown-linux-musl" > /tmp/rust-target ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    RUST_TARGET=$(cat /tmp/rust-target) && \
    rustup target add "${RUST_TARGET}" && \
    if [ "${TARGETARCH}" = "arm64" ]; then \
      mkdir -p /root/.cargo && \
      printf '[target.aarch64-unknown-linux-musl]\nlinker = "aarch64-linux-gnu-gcc"\n' \
        >> /root/.cargo/config.toml && \
      echo 'CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc' > /tmp/cross-env && \
      echo 'AR_aarch64_unknown_linux_musl=aarch64-linux-gnu-ar' >> /tmp/cross-env && \
      echo 'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc' >> /tmp/cross-env; \
    else \
      touch /tmp/cross-env; \
    fi

WORKDIR /build

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY rastreo-core/Cargo.toml rastreo-core/Cargo.toml
COPY rastreo/Cargo.toml rastreo/Cargo.toml
COPY rastreo-server/Cargo.toml rastreo-server/Cargo.toml

# Create dummy source files so cargo can fetch and cache dependencies
RUN mkdir -p rastreo-core/src rastreo/src rastreo-server/src && \
    echo "pub fn dummy() {}" > rastreo-core/src/lib.rs && \
    echo "fn main() {}" > rastreo/src/main.rs && \
    echo "fn main() {}" > rastreo-server/src/main.rs

RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    if [ -s /tmp/cross-env ]; then export $(cat /tmp/cross-env); fi && \
    cargo build --release --target "${RUST_TARGET}" --features kafka -p rastreo -p rastreo-server 2>/dev/null || true

# Copy real source and build
COPY rastreo-core/ rastreo-core/
COPY rastreo/ rastreo/
COPY rastreo-server/ rastreo-server/

# Touch source files to invalidate the dummy build cache
RUN touch rastreo-core/src/lib.rs rastreo/src/main.rs rastreo-server/src/main.rs

RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    if [ -s /tmp/cross-env ]; then export $(cat /tmp/cross-env); fi && \
    cargo build --release --target "${RUST_TARGET}" --features kafka -p rastreo -p rastreo-server

# Copy binaries to a known location regardless of target triple
RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    mkdir -p /out && \
    cp "target/${RUST_TARGET}/release/rastreo" /out/rastreo && \
    cp "target/${RUST_TARGET}/release/rastreo-server" /out/rastreo-server

# UID 65532 = upstream "nonroot" convention (distroless/nonroot, chainguard)
RUN echo 'rastreo:x:65532:65532::/:' > /tmp/passwd.rastreo

# Minimal runtime image
FROM scratch

COPY --from=builder /out/rastreo /rastreo
COPY --from=builder /out/rastreo-server /rastreo-server
COPY --from=builder /tmp/passwd.rastreo /etc/passwd

USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/rastreo-server"]
