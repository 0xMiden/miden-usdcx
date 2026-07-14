# Vendored pinned-standards MASM fixtures (read-only test data)

These `.masm` files are **byte-identical** copies of the pinned `miden-standards` faucet source at
the crates.io release this crate builds against. They are NOT production MASM and are NOT compiled
into any account — they exist only so the CMP-B3 sole-supply-decrement audit
(`tests/xreserve_receive_and_burn.rs`) can prove, in CI, that the inherited supply-decrement
primitive `exec.faucet::burn` has exactly one standards caller (`receive_and_burn`) at the
dependency baseline. The build dependency is a **registry version pin**, so the real source lives
in the non-portable cargo registry cache and cannot be reached from a test by a relative path —
hence this vendored fixture + checksum + Cargo-pin anchor.

## Pinned version

`miden-standards` (and `miden-protocol`, `miden-testing`, `miden-tx`) are pinned in
`crates/xusdc-encoding/Cargo.toml` to:

    version = "=0.16.0-alpha.2"

`tests/xreserve_receive_and_burn.rs::pinned_standards_rev_matches_cargo` asserts that pin still
holds; if the dependency pin is bumped, that test fails — **re-vendor and re-checksum** before
proceeding.

## Source paths (in the resolved cargo registry checkout)

The alpha.2 crate ships the faucet MASM twice: the LOGIC libraries under `asm/standards/…`
(where `receive_and_burn`, `faucet::burn`, the supply write-back, and the policy dispatchers
live — the N1D anchors) and thin component RE-EXPORT wrappers under `asm/components/…` (no
burn/supply code). The vendored copies are the LOGIC libraries:

    <cargo-registry>/miden-standards-0.16.0-alpha.2/asm/standards/faucets/fungible.masm
    <cargo-registry>/miden-standards-0.16.0-alpha.2/asm/standards/faucets/policies/policy_manager.masm

where `<cargo-registry>` = `~/.cargo/registry/src/index.crates.io-<hash>/`.

## Re-derivation (auditable; produces a byte-identical diff)

    SRC=~/.cargo/registry/src/index.crates.io-*/miden-standards-0.16.0-alpha.2/asm/standards/faucets
    DST=crates/xusdc-encoding/tests/fixtures/pinned-standards
    cp "$SRC/fungible.masm"                "$DST/fungible.masm"
    cp "$SRC/policies/policy_manager.masm" "$DST/policy_manager.masm"
    diff "$SRC/fungible.masm" "$DST/fungible.masm"                 # empty
    diff "$SRC/policies/policy_manager.masm" "$DST/policy_manager.masm"  # empty

A drift tripwire on these committed copies is `pinned_standards_fixture_unchanged` (FNV-1a
checksum).
