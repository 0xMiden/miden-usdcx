test:
    cargo test --workspace --locked --release

fmt:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

test-relayer-lite:
    cargo test --locked -p xreserve-deposit-relayer-lite

build-relayer-lite:
    cargo build --locked -p xreserve-deposit-relayer-lite

run-relayer-lite config="crates/xreserve-deposit-relayer-lite/relayer.toml":
    cargo run --locked -p xreserve-deposit-relayer-lite -- {{config}}
