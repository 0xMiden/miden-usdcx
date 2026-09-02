//! The structural half: **the things the orchestration must not be able
//! to do.**
//!
//! Its companion `listener_orchestration.rs` drives the flow and counts what happened. This file
//! asserts what nothing can do, which needs a different kind of test: no test can call a function
//! that must not be callable, or observe a route that does not exist. So these read the SOURCE, the
//! way `evidence_structural_absence.rs` and `submit_idempotency.rs`'s
//! `no_public_api_can_post_a_withdrawal_without_the_ledger` do — a decision the compiler cannot
//! hold is pinned mechanically, so it cannot quietly revert.
//!
//! Four absences, each of which would be a fund-safety defect:
//!
//! * **The orchestration cannot reach the raw signer.** `attester::sign` signs any 32 bytes by
//!   design, and it stays public because the structural test is its subject — but the withdrawal
//!   flow routes through `validate::sign_validated`, which consumes the validation token, and
//!   through nothing else.
//! * **The orchestration cannot build a batch beside the quorum.** `WithdrawBatch::new` accepts any
//!   `burnSignatures.len() >= 2` — the wire schema's rule, not Circle's verifier's. Only
//!   `build_withdraw_batch`, which takes a `QuorumBundle`, may assemble the submission.
//! * **A `QuorumBundle` cannot be manufactured.** Every shape check lives in `assemble_quorum`; a
//!   second construction site would be a bundle built beside them.
//! * **The payload and the depositor cannot come from different notes.** There is no
//!   independent-argument prepare-request builder to reach past `DiscoveredBurn`.

use withdrawal_listener_attester::attester::assemble_quorum;
use withdrawal_listener_attester::circle::schema::WithdrawBatch;

// THE RAW SIGNER IS UNREACHABLE FROM THE ORCHESTRATION
// ================================================================================================

/// **The orchestration never calls `attester::sign`.**
///
/// `sign` takes `&[u8]` and a key: it will sign anything, which is exactly right for the primitive
/// the structural tests and exactly wrong for the money path. The withdrawal flow's signing entry
/// is `validate::sign_validated`, which cannot be called without the `ValidatedWithdrawal` that
/// only a full field-by-field match mints — so routing through it is what makes "signed a response
/// that failed validation" untypeable rather than merely unreached.
///
/// Narrowing `sign` itself to `pub(crate)` would be the stronger fix and is deliberately NOT done:
/// it would break `tests/offchain_signing.rs`, which covers it's whole subject and an in-scope
/// caller. So the escape hatch stays, and its absence from THIS path is pinned here instead.
#[test]
fn the_orchestration_never_calls_the_raw_signer() {
    let source = listener_source();

    let calls = bare_calls_to("sign", &source);
    assert!(
        calls.is_empty(),
        "the orchestration reaches the raw `attester::sign` primitive at {calls:?} — the withdrawal \
         flow signs through `validate::sign_validated`, which consumes the B5 proof-of-validation \
         token, and through nothing else"
    );
    assert!(
        !source.contains("attester::sign("),
        "not under a path-qualified call either"
    );
    // the positive control: the gated signer IS on this path, so the sweep above is not passing
    // because there is no signing here at all.
    assert!(
        source.contains("sign_validated("),
        "the orchestration must sign through the gated `sign_validated`"
    );
}

// THE SUBMITTED BATCH CARRIES THE QUORUM'S SHAPE
// ================================================================================================

/// **The orchestration never calls `WithdrawBatch::new`.**
///
/// `WithdrawBatch` is the wire type. Its schema says `burnSignatures: minItems 2`, so its
/// constructor accepts three signatures, two in descending order, or the same signer twice — each a
/// submission Circle's exactly-2 / strictly-ascending / no-duplicate-signer verifier rejects
/// (`Attestable.sol:75,333-381`). It cannot refuse them: it must stay able to DECODE whatever
/// Circle sends.
///
/// The pre-submit allowlist gate does not cover the gap either, and this is the distinction the
/// whole slice turns on: it checks signer MEMBERSHIP, and **membership is not shape**. Two
/// signatures from one registered attester pass membership and fail the verifier.
///
/// So the orchestration builds through `withdrawal_api::build_withdraw_batch`, which takes a
/// `QuorumBundle` — a value only `assemble_quorum`'s full pass mints.
#[test]
fn the_orchestration_never_constructs_a_batch_beside_the_quorum() {
    let source = listener_source();

    assert!(
        !source.contains("WithdrawBatch::new("),
        "listener.rs constructs a WithdrawBatch directly — that is a batch whose signatures were \
         never checked against Circle's on-chain quorum shape"
    );
    assert!(
        source.contains("build_withdraw_batch("),
        "the orchestration must assemble through the QuorumBundle-taking builder"
    );
    assert!(
        source.contains("assemble_quorum("),
        "and the bundle must come from the quorum assembler"
    );
}

/// **The batch builder takes ONE burn intent, not a vector.**
///
/// The wire's `burnIntents` is `1..=10`, and the fan-in it permits is invisible to every check
/// upstream: a batch carrying the burn's own intent twice passes the payload-and-terms compare on
/// both copies, and the batch's single digest covers both, so one signature authorizes two releases
/// of one burn.
///
/// `listener_orchestration.rs` proves the runtime gate refuses that response. This pins the other
/// half — that even with the gate removed, a set could not be *expressed* on the wire, because the
/// builder's parameter is a single `BurnIntent`. The two are deliberately different mechanisms: the
/// gate is what refuses (and it must, so no signature is produced), and the type is what stops a
/// later edit from quietly restoring `.to_vec()`.
#[test]
fn the_batch_builder_cannot_express_an_intent_set() {
    let source = strip_comments(&read_src("withdrawal_api.rs"));

    assert!(
        source.contains("burn_intent: BurnIntent,"),
        "build_withdraw_batch must take ONE burn intent — a `Vec<BurnIntent>` parameter is the \
         fan-in (one burn, N releases) that B5 and the batch count both wave through"
    );
    assert!(
        !source.contains("burn_intents: Vec<BurnIntent>"),
        "no builder takes a burn intent SET; widening to one is a DEV-7 conversation, not a refactor"
    );

    let listener = listener_source();
    assert!(
        !listener.contains("burn_intents().to_vec()"),
        "the orchestration forwards the ONE gated intent, never the whole returned vector"
    );
}

/// …and a `QuorumBundle` cannot be manufactured: `assemble_quorum` is its only construction site,
/// so every bundle that exists passed the exactly-2 / verifies-to-its-claimed-signer / ascending /
/// no-duplicate checks. A second site anywhere would be a bundle built beside them, with the same
/// type and none of the guarantees — exactly what `EvidencePackage`'s sealed constructor forecloses
/// for the burn evidence.
#[test]
fn the_assembler_is_the_only_construction_site_for_a_quorum_bundle() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sites = Vec::new();

    for file in walk_rust_files(&src) {
        let text = strip_comments(&std::fs::read_to_string(&file).expect("a source file"));
        // `struct QuorumBundle {` and `impl QuorumBundle {` are the DECLARATION and its inherent
        // impl, not constructions — subtracting them is what keeps this a count of sites that MINT a
        // bundle rather than a count of the word.
        let count = text.matches("QuorumBundle {").count()
            - text.matches("struct QuorumBundle {").count()
            - text.matches("impl QuorumBundle {").count()
            + text.matches("QuorumBundle::new(").count();
        if count > 0 {
            sites.push(format!("{}: {count}", file.display()));
        }
    }

    assert_eq!(
        sites,
        vec![format!("{}: 1", src.join("attester.rs").display())],
        "exactly one construction site, and it is `assemble_quorum` in attester.rs"
    );
}

/// The functional half of the two absences above: the wire type genuinely DOES accept a shape
/// Circle rejects, so the structural routing is doing real work rather than guarding a door that is
/// already locked.
///
/// If this test ever fails because `WithdrawBatch::new` grew a shape check, that is a change to the
/// DECODE path — Circle's responses would start being refused for a rule the schema does not state
/// — and it should be a deliberate decision, not a silent one.
#[test]
fn the_wire_type_alone_would_accept_a_shape_circle_rejects() {
    let intents = withdraw_intents();
    let three_sigs = vec![
        hexbytes(&[0x11; 65]),
        hexbytes(&[0x22; 65]),
        hexbytes(&[0x33; 65]),
    ];
    assert!(
        WithdrawBatch::new(intents.clone(), three_sigs, "0xbeef".to_string(), false).is_ok(),
        "the wire type accepts an over-threshold batch — which is why the quorum bundle, not this \
         constructor, is what the orchestration builds through"
    );

    let duplicate = vec![hexbytes(&[0x11; 65]), hexbytes(&[0x11; 65])];
    assert!(
        WithdrawBatch::new(intents, duplicate, "0xbeef".to_string(), false).is_ok(),
        "and a duplicated signature — the shape Circle's verifier refuses at the fund-release boundary"
    );
}

/// And the assembler is not vacuously strict: the honest exactly-2 ascending set DOES produce a
/// bundle. Without this, every "no bundle" assertion above would pass for an assembler that never
/// produces one.
#[test]
fn the_assembler_mints_a_bundle_for_the_honest_shape() {
    use withdrawal_listener_attester::attester::{address_of, sign, SecretKey};

    let digest = [0x5au8; 32];
    let key = |b: u8| SecretKey::from_slice(&[b; 32]).expect("a valid scalar");
    let mut pairs: Vec<_> = [0x11u8, 0x22]
        .iter()
        .map(|b| {
            (
                address_of(&key(*b)),
                sign(&digest, &key(*b)).expect("signs"),
            )
        })
        .collect();
    pairs.sort_by_key(|(address, _)| *address);

    let bundle = assemble_quorum(&digest, pairs).expect("the honest shape assembles");
    assert_eq!(bundle.len(), 2);
}

// THE PAYLOAD AND THE DEPOSITOR COME FROM ONE NOTE
// ================================================================================================

/// **There is no independent-argument prepare-request builder.**
///
/// A `build_prepare_request` taking `(&BurnPayload, AccountId, &Config)` would make "burn A's
/// amount under burn B's depositor" a two-character mistake — and an undetectable one: Circle
/// returns the spec it was asked for, so the gate compares A's amount against A's amount and
/// passes, and the attesters sign a canonical intent that is wrong in the one field nothing checks.
///
/// The builder takes a `&DiscoveredBurn`, whose only constructor is the discovery gate's pass, so
/// both values come off one note by construction. This test pins the ABSENCE of the two-argument
/// form, because a builder kept "for convenience" beside it would restore the mistake with the
/// convention intact.
#[test]
fn there_is_no_independent_argument_prepare_request_builder() {
    let source = strip_comments(&read_src("withdrawal_api.rs"));

    assert!(
        source.contains("pub fn build_prepare_request("),
        "the DC-9 builder is still public"
    );
    assert!(
        source.contains("burn: &DiscoveredBurn"),
        "and it takes ONE DiscoveredBurn, so the payload and the depositor cannot be paired by hand"
    );
    assert!(
        !source.contains("sender: AccountId"),
        "no builder takes the sender as an argument independent of the payload — that pairing is \
         what the DiscoveredBurn exists to make unconstructible"
    );
}

/// The orchestration reads neither half out of the burn to re-pair them: `build_prepare_request`
/// gets the `DiscoveredBurn` whole.
#[test]
fn the_orchestration_passes_the_discovered_burn_whole() {
    let source = listener_source();

    assert!(
        source.contains("build_prepare_request(&burn,"),
        "B4 is built from the one DiscoveredBurn B3 minted"
    );
    assert!(
        source.contains("validate_returned(&response, &burn,"),
        "B5 validates the same DiscoveredBurn B4 used to build the request"
    );
    assert!(
        !source.contains("burn.depositor()"),
        "the orchestration never unpacks the depositor — doing so is how it gets re-paired with \
         another burn's payload"
    );
}

// NO PLACEHOLDER ON THE MONEY PATH
// ================================================================================================

/// No panicking placeholder in the orchestration. This service releases money and the module is
/// public: a caller reaching an unbuilt path should get a refusal it can handle, not a dead process
/// (`return-error-not-panic`).
///
/// These two `contains` calls are the only place either macro's name is written in this file, so
/// the gate's `grep -rn "todo!\|unimplemented!"` over the crate finds this test asserting their
/// absence and nothing else.
#[test]
fn the_orchestration_has_no_panicking_placeholder() {
    let source = listener_source();

    assert!(!source.contains("todo!"));
    assert!(!source.contains("unimplemented!"));
}

// SOURCE SWEEP MACHINERY
// ================================================================================================

/// The WHOLE `src/listener/` module — every file of it — with comments stripped, so what the sweeps
/// read is the DECLARATIONS rather than the prose about them.
///
/// Two things here are load-bearing. It reads the whole DIRECTORY, not `mod.rs`: the module was
/// split under that ceiling, and a sweep pointed at one file would silently stop covering whatever
/// moved out of it — which is precisely where a call to the raw signer would end up living. And it
/// strips comments, because the module documents at length that the raw signer must never be
/// reached and that the batch is never built beside the quorum, which is exactly the text these
/// sweeps hunt for; reading the explanation as the thing it forbids would assert the opposite of
/// what it means to (`evidence_structural_absence.rs` sidesteps the same trap the same way).
fn listener_source() -> String {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/listener");
    let files = walk_rust_files(&dir);
    assert!(
        !files.is_empty(),
        "the orchestration module must be where the sweep looks: {}",
        dir.display()
    );
    files
        .iter()
        .map(|file| strip_comments(&std::fs::read_to_string(file).expect("a source file")))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The comment-stripper must not become a way to hide a violation in a trailing comment, nor may it
/// strip so much that the sweeps run against an empty string. This pins both ends.
#[test]
fn the_source_sweep_reads_declarations_and_not_prose() {
    let source = listener_source();

    assert!(
        source.contains("pub async fn run_once"),
        "the sweep must still see the module's declarations"
    );
    assert!(
        !source.contains("uncallable"),
        "the sweep must not see the module's prose (this word appears only in its doc comments)"
    );
}

fn read_src(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn strip_comments(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every call to the BARE function `name` in `source` — i.e. every `name(` whose `name` is not the
/// tail of a longer identifier.
///
/// Substring matching alone would be useless here: `"sign("` appears inside `sign_validated(`…
/// nowhere, in fact, but `assign(`/`cosign(` would match it, and a sweep that fires on those is a
/// sweep that gets deleted. So the character before the identifier is checked, and only a genuine
/// call site is reported. The returned strings carry a little context, so a failure names the line
/// rather than the fact.
fn bare_calls_to(name: &str, source: &str) -> Vec<String> {
    let needle = format!("{name}(");
    let bytes = source.as_bytes();
    let mut found = Vec::new();
    let mut from = 0;

    while let Some(offset) = source[from..].find(&needle) {
        let at = from + offset;
        let preceding = at.checked_sub(1).map(|i| bytes[i] as char);
        let is_bare = !preceding.is_some_and(|c| c.is_alphanumeric() || c == '_');
        if is_bare {
            let end = (at + needle.len() + 24).min(source.len());
            found.push(source[at..end].replace('\n', " "));
        }
        from = at + needle.len();
    }

    found
}

/// `bare_calls_to` must distinguish a call from a longer identifier that ends in the same letters —
/// otherwise the sweep above is either blind or permanently red, and both end with it removed.
#[test]
fn the_bare_call_sweep_distinguishes_a_call_from_a_longer_identifier() {
    assert_eq!(bare_calls_to("sign", "let s = sign(digest, key);").len(), 1);
    assert_eq!(bare_calls_to("sign", "attester::sign(d, k);").len(), 1);
    assert!(bare_calls_to("sign", "sign_validated(v, k);").is_empty());
    assert!(bare_calls_to("sign", "let x = cosign(a);").is_empty());
    assert!(bare_calls_to("sign", "let assign = 1;").is_empty());
}

fn walk_rust_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)
        .expect("a readable directory")
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            files.extend(walk_rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// The frozen fixture's canonical burn intents — the same construction the other suites use, so
/// this file cannot drift onto a private idea of the shape.
fn withdraw_intents() -> Vec<withdrawal_listener_attester::circle::schema::BurnIntent> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/prepare_withdrawal_200.json");
    let fixture: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("the fixture")).expect("json");
    serde_json::from_value(fixture["batches"][0]["burnIntents"].clone())
        .expect("the fixture burnIntents deserialize")
}

fn hexbytes(bytes: &[u8; 65]) -> withdrawal_listener_attester::circle::wire::HexBytes {
    withdrawal_listener_attester::circle::wire::HexBytes::new(format!("0x{}", hex::encode(bytes)))
        .expect("valid 0x-hex")
}
