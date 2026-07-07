//! Mint-note transport grounding canary (P5-01 CMP-B1) — exposes the component MASM, its module
//! path, and the sentinel data so the MockChain test can assemble, bind, and exercise it on a
//! `FungibleFaucet` account. Scratch: this crate is an isolated workspace, depends only on the
//! pinned `protocol-pin-v0.15.3`, and decides nothing about the faucet's real mint-note wrapper.
//! It proves the note-transport primitive chain (`get_storage` from a call-entered account proc,
//! `find_attachment`, the hash-verified `write_attachment_to_memory` read, the post-verification
//! `adv.push_mapval` advice-stack surfacing + element-0-first pop order, the tampered-advice trap,
//! and the create-side `output_note::create` + `add_attachment` emit) EXECUTES AND COMMITS.
//! See `MINT-NOTE-TRANSPORT-GROUNDING-REPORT.md` (written in Phase 3).

use miden_protocol::{Felt, Word};

/// Fully-qualified component module path. Passed to `CodeBuilder::compile_component_code` and
/// imported by the note script via `use xusdc::canary::mint_note_transport->canary`. Must match
/// the namespace header in `asm/canary_transport.masm`.
pub const CANARY_PATH: &str = "xusdc::canary::mint_note_transport";

/// The hand-written, house-style component MASM source.
pub const CANARY_MASM: &str = include_str!("../asm/canary_transport.masm");

/// The canary note script: drops the note ARGS, then `call`s the probe proc in the account
/// context. Compiled with the canary component library linked so the `call` resolves to the same
/// proc installed on the account (the real `xreserve_mint_note.masm` shape).
pub const NOTE_SCRIPT_SRC: &str = "\
use xusdc::canary::mint_note_transport->canary\n\
\n\
@note_script\n\
pub proc main\n\
    dropw\n\
    call.canary::receive_and_probe\n\
end\n";

/// Sentinel attachment scheme — declared identically in the MASM (`ATTACHMENT_SCHEME = 7`).
pub const ATTACHMENT_SCHEME: u16 = 7;

/// Sentinel note-storage felts — declared identically in the MASM (first/last asserted there).
pub const STORAGE_SENTINELS: [u32; 6] = [1101, 1102, 1103, 1104, 1105, 1106];

/// Sentinel storage as felts.
pub fn storage_sentinel_felts() -> Vec<Felt> {
    STORAGE_SENTINELS.iter().copied().map(Felt::from).collect()
}

/// Sentinel attachment content: 9 words = 36 felts `[2001..=2036]`, DISTINCT per position so a
/// pop-order reversal or content scramble is detectable (first/second/last asserted in MASM).
pub fn attachment_sentinel_words() -> Vec<Word> {
    (0..9u32)
        .map(|w| {
            Word::from([
                2001 + 4 * w,
                2001 + 4 * w + 1,
                2001 + 4 * w + 2,
                2001 + 4 * w + 3,
            ])
        })
        .collect()
}
