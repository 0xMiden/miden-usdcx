# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.98.1
ARG DEBIAN_RELEASE=bookworm
ARG BIN=xusdc-genesis

FROM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS builder
WORKDIR /app
ARG BIN
ARG PACKAGE=${BIN}
ARG TARGETARCH
ENV CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_RELEASE_DEBUG=0
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN --mount=type=cache,sharing=locked,id=usdcx-cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    cargo build --release --locked --package "${PACKAGE}" --bin "${BIN}" && \
    mkdir -p /app/bin && \
    cp "target/release/${BIN}" "/app/bin/${BIN}"

FROM debian:${DEBIAN_RELEASE}-slim AS runtime
RUN groupadd --gid 10001 miden && \
    useradd --uid 10001 --gid miden --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin miden && \
    mkdir -p /data && \
    chown miden:miden /data
ARG BIN
COPY --from=builder /app/bin/${BIN} /usr/local/bin/${BIN}
ARG CREATED
ARG VERSION
ARG COMMIT
LABEL org.opencontainers.image.title=${BIN} \
    org.opencontainers.image.description="Miden xUSDC genesis tooling" \
    org.opencontainers.image.source=https://github.com/0xMiden/miden-usdcx \
    org.opencontainers.image.documentation=https://github.com/0xMiden/miden-usdcx/tree/main/crates/xusdc-genesis \
    org.opencontainers.image.vendor=Miden \
    org.opencontainers.image.created=${CREATED} \
    org.opencontainers.image.version=${VERSION} \
    org.opencontainers.image.revision=${COMMIT}
WORKDIR /data
USER miden
ENV MIDEN_BIN=${BIN}
# Replace the shell with the selected binary and forward every CLI argument.
ENTRYPOINT ["/bin/sh", "-c", "exec \"/usr/local/bin/$MIDEN_BIN\" \"$@\"", "--"]
CMD ["--help"]
