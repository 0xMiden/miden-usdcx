# xUSDC on Miden — common tasks. Run `just` with no argument to list everything.

# Every cargo invocation pins the lockfile. The protocol family is pinned to an exact release
# (ground rule 5), and a silent lockfile update is a dependency change nobody reviewed.
locked := "--locked"

# Resolve purely from the pinned cargo cache, contacting no registry:
#   just offline=--offline check
offline := ""

cargo := "cargo " + locked + " " + offline

# List the available recipes.
default:
    @just --list --unsorted

# ---- gates -------------------------------------------------------------------------------------

# The fast pre-commit loop: formatting, lints, and every suite except the slow MASM one.
check: fmt-check lint test

# The three CI jobs run these same three recipes and nothing else, and `rust-toolchain.toml` pins
# the compiler, so a green run here is a green run there.

# Exactly what CI runs.
ci: fmt-check lint test-all

# Format every crate in place.
fmt:
    cargo fmt --all

# Fail if anything is unformatted, changing nothing.
fmt-check:
    cargo fmt --all -- --check

# Clippy across every target — tests and examples included — with warnings as errors.
lint:
    {{cargo}} clippy --workspace --all-targets -- -D warnings

# ---- tests -------------------------------------------------------------------------------------

# Every suite, release profile. This is the CI `test` job verbatim; `xusdc-encoding` EXECUTES MASM
# on a mock chain, which is why the whole workspace runs in release.

# Every suite, release — what CI runs.
test-all:
    {{cargo}} test --workspace --release

# `xusdc-encoding` is excluded because its tests EXECUTE MASM on a mock chain and want the release
# profile — see `test-all` and `test-encoding`.

# Fast local loop: every suite except the slow MASM one.
test:
    {{cargo}} test --workspace --exclude xusdc-encoding

# Links the assembled MASM packages into the faucet account and executes the mint/burn/admin
# behaviour. Release, because debug-mode VM execution is slow enough to change how often you run it.

# THE behaviour gate for the faucet: execute the MASM.
test-encoding:
    {{cargo}} test -p xusdc-encoding --release

test-relayer:
    {{cargo}} test -p xreserve-deposit-relayer

test-listener:
    {{cargo}} test -p withdrawal-listener-attester

# ---- builds ------------------------------------------------------------------------------------

# Build every workspace member.
build:
    {{cargo}} build --workspace

# Compiles the crate AND assembles every `.masm` project: a MASM error fails here, before any test.
build-encoding:
    {{cargo}} build -p xusdc-encoding

build-relayer:
    {{cargo}} build -p xreserve-deposit-relayer

build-listener:
    {{cargo}} build -p withdrawal-listener-attester

# Its keccak/commitment deps sit behind the `vectors` feature so they never enter the normal build.

# Build the golden-vector generator.
build-gen-vectors:
    {{cargo}} build -p xusdc-encoding --features vectors --bin gen_vectors

# ---- run ---------------------------------------------------------------------------------------

# Regenerate the canonical golden-vector artifact both the MASM and Rust suites are driven from.
gen-vectors:
    {{cargo}} run -p xusdc-encoding --features vectors --bin gen_vectors

# ---- housekeeping ------------------------------------------------------------------------------

clean:
    cargo clean

# NOTE: `crates/xusdc-validation` (the real-local-node harness, LNV rows A–L) is deliberately OUTSIDE
# the workspace and has NO recipe here. It needs `miden-client`, whose newest release pins a protocol
# version no member resolves, so it cannot build alongside them; it also needs the four v0.15.1 node
# binaries on PATH. It un-parks at the migration onto a released v0.16.0 client/node pair — add its
# recipes then, with `--manifest-path crates/xusdc-validation/Cargo.toml`. Until then see that
# crate's README.
