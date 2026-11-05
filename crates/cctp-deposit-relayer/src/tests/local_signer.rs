use super::*;
use crate::{config::LocalEnv, local_signer::LocalEnvSigner};
use alloy_consensus::{transaction::SignerRecoverable, Transaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use std::{fs::OpenOptions, io::Write, path::Path};

fn dotenv(path: &Path, contents: &str) {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .unwrap()
        .write_all(contents.as_bytes())
        .unwrap();
}
fn select_local(c: &mut Config, dir: &tempfile::TempDir, key: &TestSigner) {
    c.chain_id = 5_042_002;
    c.signer = key.address();
    c.kms = None;
    let path = dir.path().join(".env");
    dotenv(
        &path,
        &format!(
            "CCTP_RELAYER_PRIVATE_KEY={}\n",
            hex::encode(key.0.to_bytes())
        ),
    );
    c.local_env = Some(LocalEnv { dotenv: path });
}
fn profile(dir: &tempfile::TempDir, c: &Config) -> std::path::PathBuf {
    let path = dir.path().join("profile.private.json");
    std::fs::write(&path, serde_json::to_vec(c).unwrap()).unwrap();
    path
}

#[tokio::test]
async fn local_signature_preserves_helper_request_commit_and_exact_retry() {
    let (dir, mut c, key, state, task) = server().await;
    select_local(&mut c, &dir, &key);
    c.validate().unwrap();
    state.lock().unwrap().config = c.clone();
    let signer = LocalEnvSigner::load(&c).unwrap();
    assert_eq!(
        signer.public_key().await.unwrap().address().unwrap(),
        c.signer
    );
    let mut store = Store::open(&c, true).unwrap();
    let m = admit(&mut store, &c, &B256::repeat_byte(1).to_string(), 1).remove(0);
    let arc = sender(&c).await;
    let p = arc
        .prepare(&c, &m, 0, &signer, circle::now())
        .await
        .unwrap();
    let tx = TxEnvelope::decode_2718(&mut p.raw.as_slice()).unwrap();
    assert_eq!(tx.recover_signer().unwrap(), c.signer);
    assert_eq!(tx.chain_id(), Some(5_042_002));
    assert_eq!(tx.nonce(), 0);
    assert_eq!(tx.to(), Some(c.helper));
    assert_eq!(tx.value(), U256::ZERO);
    let expected = abi::Helper::receiveAndDepositCall {
        message: m.bytes.clone().into(),
        attestation: m.attestation.clone().into(),
    }
    .abi_encode();
    assert_eq!(tx.input().as_ref(), expected);
    state.lock().unwrap().fail_send = true;
    assert!(arc.submit(&c, &mut store, &p).await.is_err());
    drop(store);
    let store = Store::open(&c, false).unwrap();
    let saved = store.pending().unwrap().unwrap();
    assert_eq!(saved.raw, p.raw);
    assert_eq!(store.next_nonce().unwrap(), 0);
    state.lock().unwrap().fail_send = false;
    arc.broadcast(&c, &saved).await.unwrap();
    let s = state.lock().unwrap();
    assert_eq!(s.sends.len(), 2);
    assert_eq!(s.sends[0], s.sends[1]);
    assert!(s.observed.iter().all(|committed| *committed));
    let secret = hex::encode(key.0.to_bytes());
    assert!(!serde_json::to_string(&c).unwrap().contains(&secret));
    assert!(!std::fs::read(&c.journal)
        .unwrap()
        .windows(secret.len())
        .any(|w| w == secret.as_bytes()));
    assert!(!std::fs::read(&c.journal)
        .unwrap()
        .windows(32)
        .any(|w| w == &key.0.to_bytes()[..]));
    drop(s);
    task.abort();
}

#[tokio::test]
async fn local_invalid_credentials_fail_before_rpc_or_journal_without_secret_errors() {
    let (dir, mut c, key, state, task) = server().await;
    select_local(&mut c, &dir, &key);
    let path = c.local_env.as_ref().unwrap().dotenv.clone();
    let sentinel = "SECRET_LOCAL_KEY_SENTINEL";
    for contents in [
        "# absent\n".to_owned(),
        format!("CCTP_RELAYER_PRIVATE_KEY={sentinel}\n"),
        format!("CCTP_RELAYER_PRIVATE_KEY=\"{sentinel}\n"),
        "CCTP_RELAYER_PRIVATE_KEY=0000000000000000000000000000000000000000000000000000000000000000\n".to_owned(),
        format!("CCTP_RELAYER_PRIVATE_KEY={}\nCCTP_RELAYER_PRIVATE_KEY={}\n", hex::encode(key.0.to_bytes()), hex::encode(key.0.to_bytes())),
        format!("CCTP_RELAYER_PRIVATE_KEY=${{{sentinel}}}\n"),
    ] {
        dotenv(&path, &contents);
        let error = run(&profile(&dir, &c), true, tokio_util::sync::CancellationToken::new()).await.unwrap_err();
        assert!(!format!("{error:?}").contains(sentinel));
        assert!(!c.journal.exists());
        assert!(state.lock().unwrap().calls.is_empty());
    }
    select_local(&mut c, &dir, &key);
    c.signer = TestSigner::new().address();
    let error = run(
        &profile(&dir, &c),
        true,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        crate::diagnostics::summary(&error),
        ("signer_connect", "signer_identity_mismatch")
    );
    assert!(!c.journal.exists());
    assert!(state.lock().unwrap().calls.is_empty());
    select_local(&mut c, &dir, &key);
    c.chain_id = 5042;
    assert!(LocalEnvSigner::load(&c).is_err());
    assert!(run(
        &profile(&dir, &c),
        true,
        tokio_util::sync::CancellationToken::new()
    )
    .await
    .is_err());
    assert!(!c.journal.exists());
    assert!(state.lock().unwrap().calls.is_empty());
    // A public testnet profile never permits a mainnet or other-chain RPC.
    select_local(&mut c, &dir, &key);
    let error = run(
        &profile(&dir, &c),
        true,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        crate::diagnostics::summary(&error),
        ("startup", "arc_chain_mismatch")
    );
    assert!(!c.journal.exists());
    task.abort();
}

#[test]
fn signer_mode_is_explicit_legacy_kms_shape_preserved_and_local_journal_bound() {
    let dir = tempfile::tempdir().unwrap();
    let key = TestSigner::new();
    let mut c = config(&dir, &key);
    let legacy = serde_json::to_value(&c).unwrap();
    assert!(legacy.get("local_env").is_none());
    assert_eq!(legacy["kms"]["region"], "ephemeral-loopback");
    let before = c.identity().unwrap();
    assert_eq!(
        serde_json::from_value::<Config>(legacy.clone())
            .unwrap()
            .identity()
            .unwrap(),
        before
    );
    c.kms = None;
    assert!(c.validate().is_err());
    select_local(&mut c, &dir, &key);
    c.validate().unwrap();
    assert!(serde_json::to_value(&c).unwrap().get("kms").is_none());
    assert_ne!(c.identity().unwrap(), before);
    let store = Store::open(&c, true).unwrap();
    drop(store);
    let mut changed = c.clone();
    changed.local_env.as_mut().unwrap().dotenv = dir.path().join("other.env");
    assert!(Store::open(&changed, false).is_err());
    changed = c.clone();
    changed.signer = TestSigner::new().address();
    assert!(Store::open(&changed, false).is_err());
    changed = c.clone();
    changed.local_env = None;
    changed.kms = serde_json::from_value(legacy["kms"].clone()).unwrap();
    assert!(Store::open(&changed, false).is_err());
    c.kms = changed.kms;
    assert!(c.validate().is_err());
}

#[cfg(unix)]
#[test]
fn local_dotenv_rejects_public_permissions_symlink_oversize_and_nonliteral_variables() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let key = TestSigner::new();
    let mut c = config(&dir, &key);
    select_local(&mut c, &dir, &key);
    let path = c.local_env.as_ref().unwrap().dotenv.clone();
    assert!(LocalEnvSigner::load(&c).is_ok());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(LocalEnvSigner::load(&c).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("link.env");
    symlink(&path, &link).unwrap();
    c.local_env.as_mut().unwrap().dotenv = link;
    assert!(LocalEnvSigner::load(&c).is_err());
    c.local_env.as_mut().unwrap().dotenv = path.clone();
    for contents in ["x".repeat(4097), "UNRELATED=value\n".to_owned()] {
        dotenv(&path, &contents);
        assert!(LocalEnvSigner::load(&c).is_err());
    }
}

#[tokio::test]
#[ignore = "owned child invoked with an empty process environment by local startup test"]
async fn local_startup_child() {
    let path = std::env::var("CCTP_TEST_PROFILE").unwrap();
    if let Err(error) = run(
        Path::new(&path),
        true,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    {
        report_failure(&error);
        panic!("local init failed");
    }
}

#[tokio::test]
async fn actual_local_startup_without_aws_and_restart_preserve_journal() {
    let (dir, mut c, key, state, task) = server().await;
    select_local(&mut c, &dir, &key);
    state.lock().unwrap().config = c.clone();
    state.lock().unwrap().final_nonce = 1;
    let error = run(
        &profile(&dir, &c),
        true,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        crate::diagnostics::summary(&error),
        ("startup", "sender_nonce_not_zero")
    );
    assert!(!c.journal.exists());
    state.lock().unwrap().final_nonce = 0;
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::local_signer::local_startup_child",
            "--ignored",
            "--nocapture",
        ])
        .env_clear()
        .env("CCTP_TEST_PROFILE", profile(&dir, &c))
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "local child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!state.lock().unwrap().calls.is_empty());
    let secret = hex::encode(key.0.to_bytes());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&secret));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&secret));
    let store = Store::open(&c, false).unwrap();
    assert_eq!(store.next_nonce().unwrap(), 0);
    drop(store);
    // The ordinary startup path reads the same journal and local adapter, then
    // exits from the already-cancelled token without signing or sending.
    let shutdown = tokio_util::sync::CancellationToken::new();
    shutdown.cancel();
    run(&profile(&dir, &c), false, shutdown).await.unwrap();
    assert!(state.lock().unwrap().sends.is_empty());
    let before = std::fs::read(&c.journal).unwrap();
    let other = TestSigner::new();
    dotenv(
        &c.local_env.as_ref().unwrap().dotenv,
        &format!(
            "CCTP_RELAYER_PRIVATE_KEY={}\n",
            hex::encode(other.0.to_bytes())
        ),
    );
    assert!(run(
        &profile(&dir, &c),
        false,
        tokio_util::sync::CancellationToken::new()
    )
    .await
    .is_err());
    assert_eq!(std::fs::read(&c.journal).unwrap(), before);
    task.abort();
}
