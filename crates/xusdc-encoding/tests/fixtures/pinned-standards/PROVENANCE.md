# Vendored pinned-standards MASM fixtures (read-only test data)

These `.masm` files are **byte-identical** copies of the pinned `miden-standards` faucet source at the
git rev this crate builds against. They are NOT production MASM and are NOT compiled into any account —
they exist only so the CMP-B3 sole-supply-decrement audit (`tests/xreserve_receive_and_burn.rs`) can
prove, in CI, that the inherited supply-decrement primitive `exec.faucet::burn` has exactly one
standards caller (`receive_and_burn`) at the dependency baseline. The build dependency is a **git rev**,
not a path dep, so the real source lives in the non-portable cargo git cache and cannot be reached from
a test by a relative path — hence this vendored fixture + checksum + Cargo-rev-pin.

## Pinned rev

`miden-standards` (and `miden-protocol`, `miden-testing`, `miden-tx`) are pinned in
`crates/xusdc-encoding/Cargo.toml` to:

    rev = "681fc90584131560b87db8f7487685f4fa8420a8"

`tests/xreserve_receive_and_burn.rs::pinned_standards_rev_matches_cargo` asserts that pin still holds;
if the dependency rev is bumped, that test fails — **re-vendor and re-checksum** before proceeding.

## Source paths (in the resolved cargo git checkout)

    <cargo-git>/protocol-<hash>/681fc90/crates/miden-standards/asm/standards/faucets/fungible.masm
    <cargo-git>/protocol-<hash>/681fc90/crates/miden-standards/asm/standards/faucets/policies/policy_manager.masm

where `<cargo-git>` = `~/.cargo/git/checkouts`.

## Re-derivation (auditable; produces a byte-identical diff)

    SRC=~/.cargo/git/checkouts/protocol-*/681fc90/crates/miden-standards/asm/standards/faucets
    DST=crates/xusdc-encoding/tests/fixtures/pinned-standards
    cp "$SRC/fungible.masm"                "$DST/fungible.masm"
    cp "$SRC/policies/policy_manager.masm" "$DST/policy_manager.masm"
    diff "$SRC/fungible.masm" "$DST/fungible.masm"                 # empty
    diff "$SRC/policies/policy_manager.masm" "$DST/policy_manager.masm"  # empty

A drift tripwire on these committed copies is `pinned_standards_fixture_unchanged` (FNV-1a checksum).
