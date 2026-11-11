# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.98.1
ARG DEBIAN_RELEASE=trixie

FROM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS builder
ARG CARGO_BUILD_JOBS=2
ARG TARGETARCH
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
COPY crates/usdcx-bridge/ crates/usdcx-bridge/
COPY crates/usdcx-telemetry/ crates/usdcx-telemetry/
COPY crates/usdcx-kms-signer/ crates/usdcx-kms-signer/
COPY crates/cctp-deposit-relayer/ crates/cctp-deposit-relayer/
COPY contracts/cctp-deposit-helper/interfaces/IMidenCctpDepositHelper.sol contracts/cctp-deposit-helper/interfaces/IMidenCctpDepositHelper.sol
RUN --mount=type=cache,sharing=locked,id=cctp-worker-cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=locked,id=cctp-worker-cargo-git-${TARGETARCH},target=/usr/local/cargo/git/db \
    cargo build --release --locked --jobs "${CARGO_BUILD_JOBS}" \
        -p cctp-deposit-relayer --bin cctp-deposit-relayer && \
    install -Dm755 /app/target/release/cctp-deposit-relayer /out/cctp-deposit-relayer

FROM debian:${DEBIAN_RELEASE}-slim AS runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libgcc-s1 && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10002 cctp && \
    useradd --uid 10002 --gid cctp --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin cctp && \
    install -d -m 0700 -o cctp -g cctp \
        /data
COPY --from=builder /out/cctp-deposit-relayer /usr/local/bin/cctp-deposit-relayer
ARG CREATED
ARG VERSION
ARG COMMIT
LABEL org.opencontainers.image.title="CCTP incoming deposit worker" \
    org.opencontainers.image.description="Independent CCTP discovery and fixed Arc helper completion" \
    org.opencontainers.image.source="https://github.com/0xMiden/miden-usdcx" \
    org.opencontainers.image.vendor="Miden" \
    org.opencontainers.image.created="${CREATED}" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.revision="${COMMIT}"
USER cctp
WORKDIR /data
VOLUME ["/data"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/cctp-deposit-relayer"]
