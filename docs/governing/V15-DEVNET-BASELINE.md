> **MIRROR — READ-ONLY (mirrored 2026-06-15).** Canonical source: `/Users/philipp/Documents/Work/Miden-Coding/agentic-template/ai-tasks/circle-integration/07-implementation-readiness/V15-DEVNET-BASELINE.md`. Do NOT edit this copy; if it diverges from the canonical source, the canonical source wins. Re-sync via `tools/sync-mirrors.sh`.

# V15-DEVNET-BASELINE — xUSDC-on-Miden Pin Matrix

**Status:** DRAFT (baseline ledger, not a `.draft` governing doc). **REVISION 2 (2026-06-10, post-Codex-audit):** the Codex audit of revision 1 returned `REVISE` — the canonical released pin has advanced. **Canonical released pin is now `protocol v0.15.3` (`681fc9058`), which locks the `0.23.3` VM/assembler crate family** (not `0.23.1`, which is what the historical `v0.15.1` locked and the spike verified — precompiles confirmed present on BOTH). `miden-node` now HAS a released `v0.15.0` tag (no longer PENDING). All pins below re-verified live via `git ls-remote` + tag manifests/locks on 2026-06-10 (post-audit re-check, per the revision-2 task's "upstream may have advanced" rule).
**Date established:** 2026-06-10 (all evidence re-derived this date from primary source; revision-2 re-verification same date).
**Author role:** pin research only — does NOT launch builders, does NOT finalize `.draft` docs, does NOT touch Circle `DEV-*`/`Q-*`.

---

## 0. Top-level target (human-authoritative)

| Field | Value |
|---|---|
| **Top-level target** | **Miden v0.15** |
| **Network** | **devnet** |
| **Reason** | **devnet runs v0.15.** **testnet is v0.14** — testnet is NOT the implementation/validation network. |
| **Superseded baseline** | The old `v0.16` / `protocol@0b662adfb` / `0.23`-as-target / `0.24`-retarget / testnet framing. See §5 for the `0b662adfb` reclassification. |

**Critical reclassification (memory was wrong):** the MASM grounding spike's pin `protocol@0b662adfb` was recorded in prior memory as "= v0.16.0". **It is NOT v0.16.0.** `git describe` resolves it to **`v0.15.0-21-g0b662adfb27d`** — i.e. **21 commits after the `v0.15.0` tag, on the v0.15 line (post-v0.15.0, pre-tag-divergence toward the `next` trunk).** The spike was therefore **already built on the v0.15 line**, not on v0.16. This means the spike's verified facts (precompile presence, CodeBuilder path, MockChain happy-path) carry over to the v0.15 baseline with **no retarget required**. See §5.

**Internal-dependency nuance (do not over-correct):** v0.15 of the protocol workspace *resolves* internal Miden crate versions like `miden-assembly 0.23.3`, `miden-core-lib 0.23.3`, `miden-crypto 0.25.1` (at the canonical `v0.15.3`; the historical `v0.15.1` locked `0.23.1`). These are **v0.15 DEPENDENCIES**, not stale top-level targets. They are correct and must be kept. Frame the target as "Miden v0.15 + devnet"; explain `0.23.x`/`0.25.x` as the crate versions v0.15 pulls in.

**⚠️ Per-repo cadence caveat (human correction, 2026-06-10 — critical):** the Miden repos do **NOT** all version in lockstep with the v0.15 umbrella. **`protocol`/`miden-base`, `miden-client`, `miden-node`, `web-sdk` follow the standard v0.15 tag cadence.** But **`miden-vm` is on a SEPARATE cadence (currently `0.23.x`)** and **`miden-assembly` is its own crate-release track (`0.23.x`)** — their `v0.15.x`/`v0.16.x` git tags are ancient (2025) and unrelated to the current Miden v0.15 release. **Never map a "miden-vm v0.15" tag onto the v0.15 baseline.** The VM/assembler dependency of the current v0.15 (`v0.15.3`) is the **`0.23.3` crate family** (from `miden-vm@v0.23.3`; `v0.15.1` historically locked `0.23.1`). See the corrected miden-vm row in §1. (`web-sdk` = the `@miden-sdk/*` JS packages; frontend is DEFERRED in this program, so web-sdk is out of the MASM-first builder critical path — note it follows the v0.15 cadence but is not a pin needed now.)

**Latest v0.15 patch (REVISION 2 — resolved):** `protocol` tags are `v0.15.0/v0.15.1/v0.15.2/v0.15.3` — **`v0.15.3` (`681fc90584131560b87db8f7487685f4fa8420a8`) is the latest released v0.15 patch and is now the CANONICAL released pin.** Verified live: `git ls-remote origin 'refs/tags/v0.15*'` → `v0.15.3 = 681fc9058`; `git show v0.15.3:Cargo.toml` → workspace `0.15.3`; `git show v0.15.3:Cargo.lock` → **`miden-assembly`/`miden-core`/`miden-core-lib`/`miden-processor` = `0.23.3`**, `miden-crypto`/`miden-field` = `0.25.1`. The earlier `v0.15.1` pin (locked `0.23.1`) is **historical** — it remains the tag the grounding spike's resolution was verified against; the Keccak/ECDSA precompiles are confirmed present on **both** `0.23.1` and `0.23.3` (§3), so the spike's toolchain evidence carries to the current pin.

---

## 1. Per-pin matrix

Legend for `pin_type`:
- **released-tag** — a `v0.15.x` git tag exists locally; pin to the tag.
- **next-commit (v0.15)** — repo workspace version is already `0.15.0` on `origin/next` but **no `v0.15.x` tag exists yet**; pin to a `next` commit until a tag ships.
- **pending** — exact v0.15 pin not establishable from local primary source; `PENDING V15 PIN` with owner/source.

| Crate / repo | pin_type | pin_value | top-level v0.15 version | internal_dep_note | evidence (date 2026-06-10) |
|---|---|---|---|---|---|
| **protocol** (= miden-base; monorepo) | released-tag | **`v0.15.3` (`681fc90584131560b87db8f7487685f4fa8420a8`)** — CANONICAL (rev-2); `v0.15.0`/`v0.15.1`/`v0.15.2` are earlier patches (`v0.15.1` = `625b66dc4`, historical — what the spike resolution was verified against) | `0.15.3` | workspace `version = "0.15.3"`; **locks miden-assembly/assembly-syntax/core/core-lib/processor = `0.23.3`**, miden-crypto/field = **`0.25.1`** — all v0.15 deps, keep them | `git ls-remote origin 'refs/tags/v0.15*'` → `v0.15.3 = 681fc9058`; `git show v0.15.3:Cargo.toml \| grep ^version` → `0.15.3`; `git show v0.15.3:Cargo.lock` → `0.23.3`/`0.25.1` (re-verified live 2026-06-10) |
| **miden-protocol** (crate of protocol) | released-tag | `v0.15.3` (in-repo crate) | `0.15.3` | crate `crates/miden-protocol/Cargo.toml`, name = `miden-protocol`, version inherits workspace `0.15.3`; node v0.15.0 deps `miden-protocol = "0.15.3"` | `protocol$ git show v0.15.3:crates/miden-protocol/Cargo.toml | grep name` → `miden-protocol`; `miden-node@29a876c3:Cargo.toml` → `miden-protocol = "0.15.3"` |
| **miden-standards** (crate of protocol) | released-tag | `v0.15.3` (in-repo crate) | `0.15.3` | provides `CodeBuilder` / `AccountComponent` / `TransactionKernel::assembler()` the MASM-first build path uses (spike §3) | `protocol$ git show v0.15.3` crate name = `miden-standards` at `crates/miden-standards/Cargo.toml`; `miden-node@29a876c3` deps `miden-standards = "0.15.3"` |
| **miden-testing** (crate of protocol) | released-tag | `v0.15.3` (in-repo crate) | `0.15.3` | MockChain path for the happy-path/create→consume tests; it is a **crate**, not a separate repo | `protocol$ git show v0.15.3` crate name = `miden-testing` at `crates/miden-testing/Cargo.toml`; `miden-node@29a876c3` deps `miden-testing = "0.15.3"` |
| **miden-tx** / **miden-tx-batch-prover** (crates of protocol) | released-tag | `v0.15.3` (in-repo crates) | `0.15.3` | client `next` deps on `miden-tx = "0.15"`, `miden-tx-batch-prover = "0.15"` | `protocol$ git show v0.15.3` crate names present; `miden-node@29a876c3:Cargo.toml` → `miden-tx = "0.15.3"`; client next → `miden-tx = "0.15"` |
| **miden-vm** (repo) | **separate cadence — NOT a v0.15 tag** | the CURRENT v0.15 protocol (`v0.15.3`) resolves its crates at **`0.23.3`**, published from **`miden-vm@v0.23.3`** (`ddd4da4a`, 2026-05-27); the historical `v0.15.1` locked `0.23.1` (from `miden-vm@v0.23.1`, 2026-05-20) | n/a (miden-vm does **not** version in the v0.15 line) | **CORRECTED (human caveat 2026-06-10): miden-vm is on its OWN release cadence and does NOT track the Miden v0.15 umbrella.** Its current tag line is `v0.20.0 … v0.23.3` (newest `v0.23.3`, 2026-05-27). The `miden-vm v0.15.0` tag is **ancient — dated 2025-06-06**, ~1 year stale, and is **NOT** the v0.15 VM. The assembler/VM crates the CURRENT v0.15 protocol (`v0.15.3`) actually uses are all **`0.23.3`**, published from **`miden-vm@v0.23.3`** (`v0.15.1` historically locked `0.23.1`). Pin the VM/assembler line at **`0.23.3`** (the current v0.15 protocol's resolved dependency), NOT at any "miden-vm v0.15" tag. | `miden-vm$ git for-each-ref --sort=-creatordate refs/tags` → newest `v0.23.3 (2026-05-27)`, `v0.23.1 (2026-05-20)`; `git log -1 v0.15.0` → **`2025-06-06`** (ancient); `protocol$ git show v0.15.3:Cargo.lock` → `miden-assembly/core/core-lib/processor = 0.23.3` (v0.15.1 locked `0.23.1`) |
| **miden-assembly** (crate) | released-tag (crate) | **`0.23.3`** (current, locked by `protocol v0.15.3`); `0.23.1` = historical (`v0.15.1`/spike) | n/a (v0.15 dep) | **v0.15 DEPENDENCY**, not a stale target. protocol v0.15.3 Cargo.lock locks `miden-assembly 0.23.3` + `miden-assembly-syntax 0.23.3`. Same `0.23.x` line the spike used (spike verified Q1–Q4 IDENTICAL on `0.23.1` and `0.23.3`). | `protocol$ git show v0.15.3:Cargo.lock | grep -A1 'name = "miden-assembly"'` → `0.23.3`; cargo cache has `miden-assembly-0.23.0/1/2/3` |
| **miden-core** (crate) | released-tag (crate) | **`0.23.3`** (current); `0.23.1` historical | v0.15 dep (resolved) | `protocol$ git show v0.15.3:Cargo.lock` → `miden-core 0.23.3`; cache has `miden-core-0.23.0/1/2/3` |
| **miden-core-lib** (crate) | released-tag (crate) | **`0.23.3`** (current); `0.23.1` historical | **v0.15 dep — carries the Keccak/ECDSA precompiles on BOTH `0.23.1` and `0.23.3` (see §3).** | `protocol$ git show v0.15.3:Cargo.lock` → `miden-core-lib 0.23.3`; cargo cache has BOTH `miden-core-lib-0.23.1` and `-0.23.3` with `asm/crypto/{hashes/keccak256,dsa/ecdsa_k256_keccak}.masm` |
| **miden-processor** (crate) | released-tag (crate) | **`0.23.3`** (current); `0.23.1` historical | v0.15 dep (resolved) | `protocol$ git show v0.15.3:Cargo.lock` → `miden-processor 0.23.3` |
| **miden-crypto** (crate) | released-tag (crate) | `0.25.1` | **v0.15 dep — note this is `0.25.x`, NOT `0.23.x`** (crypto family advances separately from the assembler stack) | `protocol$ git show v0.15.3:Cargo.toml` → `miden-crypto version = "0.25"`; v0.15.3 lockfile → `0.25.1` (unchanged from v0.15.1) |
| **miden-field** (crate) | released-tag (crate) | `0.25.1` | v0.15 dep; the field-math crate exists separately and tracks the crypto family at `0.25.x` (NOT a miden-vm `0.23` crate) | `protocol$ git show v0.15.3:Cargo.lock | grep -A1 'name = "miden-field"'` → `0.25.1` (unchanged) |
| **miden-client** (repo) | **next-commit (v0.15)** | `origin/next` = **`ed94b05d6faba126187e141f1ed8e85ca85a1652`** (re-verified live 2026-06-10; advanced from the rev-1 pin `733ee1a98`) | `0.15.0` (workspace, on `next`) | **STILL NO `v0.15.x` tag** (verified via live `git ls-remote 'refs/tags/v0.15*'` → none). `next` workspace is `0.15.0`, deps `miden-protocol/standards/testing/tx = "0.15"`, and node git deps pin `6649a4ce774bc842c08e6bdc314f6ddafb816282`. Pin to this `next` commit OR `PENDING V15 PIN` for a released tag. NOTE: client `next` moves fast — re-pin at builder launch. | `git ls-remote origin 'refs/tags/v0.15*' refs/heads/next` → next = `ed94b05d6`, no v0.15 tag; `git show ed94b05d6…:Cargo.toml` → version `0.15.0`, node rev `6649a4ce` |
| **miden-node** (repo) | **released-tag** (rev-2: tag NOW EXISTS) | **`v0.15.0` (`29a876c32ad4d3604101df089e8fbfeacfc91928`)** — `origin/next` was the same commit at the 2026-06-10 rev-2 verification (next has since advanced — the released TAG is the pin, not next) | `0.15.0` | **`miden-node v0.15.0` released (no longer PENDING / next-commit).** Workspace `0.15.0`; depends on protocol crates **`0.15.3`** (`miden-protocol/standards/testing/tx = "0.15.3"`) — consistent with the `protocol v0.15.3` canonical pin. This is the node binary for local-node validation (`miden-node bundled start`) and the devnet-equivalent v0.15 node. Supersedes the rev-1 `next 96f53e7d` pin. | `git ls-remote origin 'refs/tags/v0.15*' refs/heads/next` → `v0.15.0 = 29a876c3` (next == tag at rev-2 check; gate-B live re-check later the same day saw next advance — pin the TAG); `git show 29a876c3…:Cargo.toml` → version `0.15.0`, `miden-protocol = "0.15.3"` (re-verified live 2026-06-10) |
| **compiler / cargo-miden** (repo) | **PENDING V15 PIN** | local `origin/next` = `30544eb610c8315550aafbf07944b225f5399c76`, workspace `0.8.1`, targets **miden-assembly 0.22 / miden-core-lib 0.22** | n/a — compiler tracks its own `0.x` line | **OFF the MASM-first critical path** (faucet uses runtime `CodeBuilder`, NOT `cargo miden build`). BUT the local compiler clone targets **assembly 0.22**, which is BEHIND the current v0.15 protocol's **0.23.3** assembler. If any builder needs `cargo miden`, that 0.22-vs-0.23 gap must be resolved by the human. `PENDING V15 PIN` (owner: human; source: a compiler `next`/release that targets assembly 0.23, or confirm cargo-miden is unused for the MASM-first faucet). | `compiler$ git show origin/next:Cargo.toml | grep ^version` → `0.8.1`; same file → `miden-assembly = "0.22"`, `miden-core-lib = "0.22"`; local clone date 2026-06-01 |
| **guardian** (OpenZeppelin/guardian) | **N/A — third-party, NOT Miden-versioned** | `c8d54b96` (`main` HEAD, 2026-06-03) | n/a — OZ Guardian has its own versioning, does NOT track Miden v0.15 | **Third-party component (OpenZeppelin), OFF the xUSDC protocol critical path** (assessed off-path in earlier phases: zero bridge/attestation/mint/burn code). Its `c8d54b96` pin is the prior-phase assessment commit; it is **NOT** a Miden-v0.15 pin and should be cited as "third-party pin `c8d54b96`," NOT "`PENDING V15 PIN`." Live docs that say "guardian `c8d54b96` PENDING V15 PIN" should read "guardian `c8d54b96` — third-party, not Miden-versioned." | `guardian$ git rev-parse HEAD` → `c8d54b9662…`; `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:26` (OZ Guardian, main HEAD) |
| **midenup** (repo) | **PENDING V15 PIN** | local clone = `4cfafe6d…` (2026-03-24, **stale, pre-v0.15**); its `manifest/channel-manifest.json` pins the *then-current* toolchain (`miden-node 0.10.x`, `miden-vm 0.16.0/0.16.2/0.17.2`, etc.) — NOT a v0.15 devnet channel | n/a | The local midenup clone predates v0.15 and does NOT contain a v0.15/devnet channel manifest. `PENDING V15 PIN` (owner: human; source: a current midenup `next` / published `channel-manifest.json` with a v0.15 devnet channel, fetched fresh). Do NOT trust the stale local manifest's versions. | `midenup$ git show -s HEAD` → `2026-03-24 4cfafe6`; `manifest/channel-manifest.json` shows old-toolchain pins, no v0.15 devnet channel |

---

## 2. Devnet network endpoints (primary source: miden-client `origin/next`)

Established from `miden-client` `origin/next` Rust source (NOT testnet):

| Purpose | Devnet endpoint | Source (file:line) |
|---|---|---|
| **RPC node** | `https://rpc.devnet.miden.io` | `crates/rust-client/src/rpc/endpoint.rs:43-45` — `Endpoint::devnet()` = `Self::new("https", "rpc.devnet.miden.io", None)` |
| **Tx prover** | `https://tx-prover.devnet.miden.io` | `crates/rust-client/src/grpc_support/mod.rs:9` — `DEVNET_PROVER_ENDPOINT` |
| **Note transport** | `https://transport.devnet.miden.io` | `crates/rust-client/src/note_transport/mod.rs:36` — `NOTE_TRANSPORT_DEVNET_ENDPOINT` |
| **Client builder** | `RustClientBuilder::for_devnet()` | `crates/rust-client/src/builder.rs:245-256` — wires all three devnet endpoints |
| **NetworkId** | `NetworkId::Devnet` | `crates/rust-client/src/rpc/endpoint.rs:67-68` — `Endpoint::devnet()` maps to `NetworkId::Devnet` |

Cross-confirmed in `bin/integration-tests/README.md:135`:
`| devnet | rpc.devnet.miden.io | tx-prover.devnet.miden.io | transport.devnet.miden.io |`
and `bin/miden-bench/src/main.rs:166-178` (`Network::Devnet => Endpoint::devnet()`).

**Devnet status: ESTABLISHED** (not PENDING). Endpoints are first-class in the `0.15.0`-workspace client `next`. Do NOT substitute testnet (`rpc.testnet.miden.io` is the v0.14 network).

**Note (not a substitution):** for local-node validation the node is started locally via `miden-node bundled start --rpc.url http://0.0.0.0:57291` (the bundled local node, also v0.15 — built from the released `miden-node v0.15.0` tag (`29a876c3`), the node pin). Remote devnet RPC is `https://rpc.devnet.miden.io`. Both are v0.15; local-node is for the GATE step, remote devnet for deploy/validation against the live v0.15 network.

---

## 3. Load-bearing precompile check (Keccak / ECDSA)

**Question:** does the v0.15 line ship the `keccak256` and `ecdsa_k256_keccak` precompiles the grounding spike relied on?

**Answer: PRESENT — on BOTH `0.23.1` (historical `v0.15.1` lock, spike-verified) and `0.23.3` (the CURRENT `v0.15.3` lock).** Verified against the cargo registry cache for both crate versions (rev-2 re-check 2026-06-10: `miden-core-lib-0.23.3/asm/crypto/hashes/keccak256.masm` and `miden-core-lib-0.23.3/asm/crypto/dsa/ecdsa_k256_keccak.masm` both present).

Evidence (cargo registry cache, the crate as actually published/downloaded):
- `~/.cargo/registry/src/index.crates.io-…/miden-core-lib-0.23.1/Cargo.toml` → `version = "0.23.1"`.
- `asm/crypto/hashes/keccak256.masm` exists; exports `pub proc hash_bytes` (line 32), `pub proc hash` (50), `pub proc merge` (71).
- `asm/crypto/dsa/ecdsa_k256_keccak.masm` exists; exports `pub proc verify` (line 57), `pub proc verify_prehash` (123).

**Why this matters for the v0.15 retarget:** the spike was built on `protocol@0b662adfb` = `v0.15.0-21` (the v0.15 line, see §5), which resolves the **same** `miden-core-lib 0.23.1`. So:
- The "0.23-vs-0.24 retarget" is **NOT forced** by moving to the v0.15 baseline — the v0.15 line ships the precompiles at both of its locks (historical `v0.15.1` → `miden-core-lib 0.23.1`; current `v0.15.3` → `0.23.3`).
- The BUILDER-GATES `.draft` premise ("the resolved 0.23 stack carries the Keccak/ECDSA precompiles; 0.23 is sufficient; retarget not forced") is **confirmed against primary source** under the v0.15 framing.
- Build-hygiene caveat (carried from spike §0): a fresh resolve may pull `miden-core-lib 0.23.3` (cache also has `0.23.0/0.23.2`/assembly `0.23.3`). **Both 0.23.1 and 0.23.3 carry the precompiles.** To be deterministic, seed `Cargo.lock` to the **v0.15.3-locked `0.23.3`** (the current canonical pin; the spike's historical scaffold seeded the v0.15.1-locked `0.23.1`). The spike proved **presence + assembly-time linkability**, NOT execution-host wiring — precompile **execution** with registered `Host` handlers remains a later, human-gated unit (unchanged by this retarget).

---

## 4. The `0b662adfb` reclassification (was the memory wrong?)

| Claim (prior memory) | Reality (primary source, 2026-06-10) |
|---|---|
| `protocol@0b662adfb = v0.16.0` | **WRONG.** `protocol$ git describe --tags --abbrev=12 0b662adfb` → **`v0.15.0-21-g0b662adfb27d`**. It is 21 commits *after* `v0.15.0`, on the v0.15 line. |
| (implied) spike was on a different major than v0.15 | **No.** It is on the v0.15 line; the spike's facts carry to the v0.15 baseline directly. |
| `0b662adfb` is an ancestor of a v0.15 release tag | `git merge-base --is-ancestor 0b662adfb v0.15.1` → **NO**. It diverged from the v0.15.x patch line toward `next` after `v0.15.0` (its log top = `#2974` `TransferPolicy enum→struct`, `#2998`, `#3009` — post-0.15.0 `next` work). So pin clean released v0.15 work to the **current canonical released tag `protocol v0.15.3` (`681fc9058`)** — not to `0b662adfb` (a v0.15-line dev commit) and not to the historical `v0.15.1` (spike-context only); the spike's commit remains a valid v0.15-line proof point. |

**Consequence for the consortium:** treat `0b662adfb` as a **v0.15-line dev commit**, superseded as the canonical pin by **`protocol v0.15.3`** (current released tag; rev-1 briefly used `v0.15.1`), and keep all spike-verified facts — they hold on the `0.23.x` assembler line (spike verified Q1–Q4 + the precompile gate IDENTICAL on `0.23.1` and `0.23.3`).

---

## 5. PENDING items (owner / source to check)

| Item | Why pending | Owner | Source to establish the v0.15 pin |
|---|---|---|---|
| **miden-client released v0.15 tag** | live `ls-remote` (2026-06-10): still no `v0.15.x` tag; `next` = `ed94b05d6` (0.15.0 workspace). | human / Miden release | a published `miden-client v0.15.x` tag, or accept the `next` commit `ed94b05d6` as the pin (re-pin at builder launch — client `next` moves fast). |
| ~~miden-node released v0.15 tag~~ — **RESOLVED (rev-2)** | `miden-node v0.15.0` (`29a876c3`) released — **the TAG is the pin** (`next` equaled the tag at the 2026-06-10 rev-2 check; `next` has since advanced and is not the pin); deps protocol `0.15.3`. | — | — (see §1 node row). |
| **compiler / cargo-miden v0.15 alignment** | local compiler `next` targets **assembly 0.22**, behind v0.15's **0.23.3**. OFF the MASM-first critical path (faucet uses runtime CodeBuilder), but blocking IF any builder uses `cargo miden`. | human | a compiler `next`/release targeting assembly 0.23, OR explicit confirmation cargo-miden is unused for the MASM-first faucet. |
| **midenup v0.15 devnet channel** | local midenup clone is 2026-03-24 (pre-v0.15); its manifest pins old toolchain, no v0.15 devnet channel. | human | a fresh midenup `channel-manifest.json` carrying a v0.15 devnet channel (do NOT trust the stale local manifest). |

None of these PENDING items unblock a builder by themselves; **builders remain BLOCKED** per the consortium guards regardless.

---

## 6. Conflicts surfaced (do NOT force a tidy baseline)

1. **compiler assembly target lag (0.22 vs 0.23):** the local compiler `next` targets `miden-assembly 0.22` / `miden-core-lib 0.22`, while the current v0.15 protocol (`v0.15.3`) resolves `0.23.3`. Not a blocker for the MASM-first faucet (runtime CodeBuilder path, no `cargo miden`), but a genuine version skew if `cargo miden` is ever on the path. Surfaced as PENDING, not silently reconciled.
2. **No v0.15 release tag for the CLIENT (node resolved in rev-2):** `miden-node v0.15.0` is now released (`29a876c3` — the released TAG is the pin; `next` equaled it at the rev-2 check but has since advanced); `miden-client` is still `0.15.0` only on `origin/next` (`ed94b05d6`). The client is reported as `next-commit (v0.15)`, not upgraded to a fictional released tag.
3. **crates.io unreachable** in this environment (sandboxed and unsandboxed): could not independently confirm crates.io publication of `miden-protocol 0.15.x` / `miden-core-lib 0.23.x`. NOT load-bearing — local git tags + the cargo **registry cache** (which contains the actually-downloaded `miden-core-lib-0.23.1` AND `-0.23.3`, `miden-assembly-0.23.x`) are sufficient primary source for the pins.

---

*Ledger written by Agent 1 (Version/Pin Research). Per consortium guards: no builders launched, no `.draft` finalized, no Circle `DEV-*`/`Q-*` touched, MASM-first + PR #2927 `.claude/skills` mandate preserved, no commits/push/PRs. All version facts re-derived from primary source (local git tags/branches, in-repo Cargo.toml/Cargo.lock, cargo registry cache) on 2026-06-10.*
