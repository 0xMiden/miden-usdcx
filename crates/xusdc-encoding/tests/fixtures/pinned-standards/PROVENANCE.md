# Vendored pinned-standards MASM fixtures (read-only test data)

These `.masm` files are **byte-identical** copies of the pinned `miden-standards` faucet source at
the frozen protocol-monorepo git rev this crate builds against. They are NOT production MASM and
are NOT compiled into any account — they exist only so the CMP-B3 sole-supply-decrement audit
(`tests/xreserve_receive_and_burn.rs`) can prove, in CI, that the inherited supply-decrement
primitive `exec.faucet::burn` has exactly one standards caller (`receive_and_burn`) at the
dependency baseline. The build dependency is a **frozen git-rev pin**, so the real source lives in
the non-portable cargo git checkout cache and cannot be reached from a test by a relative path —
hence this vendored fixture + checksum + Cargo-pin anchor.

## Pinned rev

`miden-standards` (and `miden-protocol`, `miden-tx`, `miden-testing`) are pinned in
`crates/xusdc-encoding/Cargo.toml` to the protocol monorepo at:

    git = "https://github.com/0xMiden/protocol"
    rev = "4971ec4b38fb1f54e8f73969e6da81ee0cbf850c"

(one frozen rev of the `next` branch — the interim beta.1 bump of the V16-NOW migration,
`docs/MIGRATION-V16-NEXT.md`; all four protocol-repo crates carry the identical rev, so the
standards source is unambiguous.)

`tests/xreserve_receive_and_burn.rs::pinned_standards_rev_matches_cargo` asserts that pin still
holds; if the dependency pin is bumped, that test fails — **re-vendor and re-checksum** before
proceeding. At the alpha.4 → `next`-rev bump, `fungible.masm` stayed **byte-identical** (checksum
unchanged) while `policy_manager.masm` changed shape only (public-interface section reorg + doc
wording; no procedure added, removed, or re-signatured), so its committed copy and FNV-1a checksum
were re-derived per the steps below. At the subsequent `dbe4e38` → `4971ec4b3` interim beta.1
bump (+10 commits), **both** `fungible.masm` and `policy_manager.masm` stayed **byte-identical**
(both checksums unchanged; only the rev anchor above moved).

## Source paths (in the resolved cargo git checkout)

The crate ships the faucet MASM twice: the LOGIC libraries under `asm/standards/…`
(where `receive_and_burn`, `faucet::burn`, the supply write-back, and the policy dispatchers
live — the N1D anchors) and thin component RE-EXPORT wrappers under `asm/components/…` (no
burn/supply code). The vendored copies are the LOGIC libraries:

    <cargo-git>/protocol-<hash>/4971ec4/crates/miden-standards/asm/standards/faucets/fungible.masm
    <cargo-git>/protocol-<hash>/4971ec4/crates/miden-standards/asm/standards/faucets/policies/policy_manager.masm

where `<cargo-git>` = `~/.cargo/git/checkouts/`.

## Re-derivation (auditable; produces a byte-identical diff)

    SRC=~/.cargo/git/checkouts/protocol-*/4971ec4/crates/miden-standards/asm/standards/faucets
    DST=crates/xusdc-encoding/tests/fixtures/pinned-standards
    cp "$SRC/fungible.masm"                "$DST/fungible.masm"
    cp "$SRC/policies/policy_manager.masm" "$DST/policy_manager.masm"
    diff "$SRC/fungible.masm" "$DST/fungible.masm"                 # empty
    diff "$SRC/policies/policy_manager.masm" "$DST/policy_manager.masm"  # empty

A drift tripwire on these committed copies is `pinned_standards_fixture_unchanged` (FNV-1a
checksum).
