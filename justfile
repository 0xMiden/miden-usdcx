test:
    cargo test --workspace --locked --release

fmt:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

run-relayer *args:
    cargo run --locked -p xreserve-deposit-relayer -- {{args}}
