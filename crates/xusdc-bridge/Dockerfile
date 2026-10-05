# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.98.1
ARG DEBIAN_RELEASE=bookworm

FROM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS builder
ARG CARGO_BUILD_JOBS=2
ARG TARGETARCH
RUN test "${TARGETARCH}" = arm64
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/xreserve-deposit-relayer/ crates/xreserve-deposit-relayer/
COPY crates/xusdc-light-attester/ crates/xusdc-light-attester/
COPY crates/xusdc-bridge/ crates/xusdc-bridge/
RUN --mount=type=cache,sharing=locked,id=xusdc-cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=locked,id=xusdc-cargo-git-${TARGETARCH},target=/usr/local/cargo/git/db \
    cargo build --release --locked --jobs "${CARGO_BUILD_JOBS}" \
        -p xusdc-bridge --bin xusdc-bridge && \
    install -Dm755 /app/target/release/xusdc-bridge /out/xusdc-bridge

# Export just the Linux ARM64 executable with:
# docker buildx build --file crates/xusdc-bridge/Dockerfile --platform linux/arm64 --target binary --output type=local,dest=dist .
FROM scratch AS binary
COPY --from=builder /out/xusdc-bridge /xusdc-bridge

FROM debian:${DEBIAN_RELEASE}-slim AS runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libgcc-s1 && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10001 xusdc && \
    useradd --uid 10001 --gid xusdc --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin xusdc && \
    install -d -m 0700 -o xusdc -g xusdc \
        /data /data/relayer /data/relayer/miden /data/attester
COPY --from=builder /out/xusdc-bridge /usr/local/bin/xusdc-bridge
ARG CREATED
ARG VERSION
ARG COMMIT
LABEL org.opencontainers.image.title="xUSDC bridge service" \
    org.opencontainers.image.description="Miden xUSDC deposit relayer and withdrawal attester" \
    org.opencontainers.image.source="https://github.com/0xMiden/miden-usdcx" \
    org.opencontainers.image.created="${CREATED}" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.revision="${COMMIT}"
USER xusdc
WORKDIR /data
VOLUME ["/data"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/xusdc-bridge"]
