test:
    cargo test --workspace --locked --release

fmt:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

run-relayer *args:
    cargo run --locked -p xreserve-deposit-relayer -- {{args}}

# Build one architecture and load the image into the local Docker engine.
build-bridge-image platform="linux/arm64" tag="usdcx-bridge:local":
    docker buildx build --file crates/usdcx-bridge/Dockerfile --platform {{quote(platform)}} --tag {{quote(tag)}} --load .
