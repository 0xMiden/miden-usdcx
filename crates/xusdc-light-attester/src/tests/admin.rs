use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use reqwest::StatusCode;
use serde_json::json;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::instrument::WithSubscriber as _;
use tracing::Instrument as _;

use crate::admin::{AdminConfig, Command, HoldsPage, Operation, ReleaseRequest, Server};
use crate::circle::{CircleApi, CircleError, RawResponse, UnverifiedPrepareResponse};
use crate::store::{BurnHoldReason, HoldEntry, ReleaseError, ReleaseSelection};
use crate::{DiscoveredBurn, SavedSubmission};

use super::submit::{reply, Ledger};

struct PendingPost {
    inner: super::submit::ScriptedCircle,
    started: Arc<Notify>,
    finish: Arc<Notify>,
}

impl CircleApi for PendingPost {
    fn check_connection(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircleError>> + Send + '_>> {
        self.inner.check_connection()
    }
    fn prepare_withdrawal<'a>(
        &'a self,
        burn: &'a DiscoveredBurn,
        fee: u64,
    ) -> Pin<Box<dyn Future<Output = Result<UnverifiedPrepareResponse, CircleError>> + Send + 'a>>
    {
        self.inner.prepare_withdrawal(burn, fee)
    }
    fn post_submission<'a>(
        &'a self,
        saved: &'a SavedSubmission,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + 'a>> {
        Box::pin(async move {
            self.started.notify_one();
            self.finish.notified().await;
            self.inner.post_submission(saved).await
        })
    }
    fn get_withdrawal<'a>(
        &'a self,
        saved: &'a SavedSubmission,
        id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + 'a>> {
        self.inner.get_withdrawal(saved, id)
    }
}

#[tokio::test]
async fn admin_waits_for_the_post_and_its_persisted_outcome() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![]).await;
    let (inner, requests) = super::submit::ScriptedCircle::new(
        ledger.path(),
        vec![reply(400, json!({"message":"rejected"}))],
    );
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let finish = std::sync::Arc::new(tokio::sync::Notify::new());
    attester.circle = Box::new(PendingPost {
        inner,
        started: started.clone(),
        finish: finish.clone(),
    });
    let (sender, receiver) = mpsc::channel(16);
    let shutdown = CancellationToken::new();
    attester.attach_admin(receiver, shutdown.clone());
    let owner = async {
        ledger.submit(&mut attester, 0).await.unwrap();
        attester.admin_checkpoint().await;
    };
    let operator = async {
        started.notified().await;
        let revision = ledger.stored("SELECT MAX(seq) FROM submission_events");
        let (reply, mut receive) = oneshot::channel();
        sender
            .try_send(Command {
                operation: Operation::Release(
                    ReleaseSelection {
                        note_id: ledger.burns[0].note_id(),
                        expected_event_seq: revision,
                        circle_not_accepted: true,
                    },
                    reply,
                ),
                deadline: Instant::now() + Duration::from_secs(60),
            })
            .unwrap_or_else(|_| panic!());
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(
            matches!(receive.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
            "admin cannot interrupt a POST"
        );
        finish.notify_one();
        receive.await.unwrap()
    };
    let (_, result) = tokio::join!(owner, operator);
    assert!(
        matches!(result, Err(ReleaseError::Conflict)),
        "the POST outcome changed the revision before release was evaluated"
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(
        ledger.record(&attester, 0).status,
        crate::submission::SubmissionStatus::Held
    );
    assert_eq!(attester.store.holds_page(None).unwrap().len(), 1);
}

#[tokio::test]
async fn commands_run_between_complete_saved_submission_attempts() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger
        .start(vec![
            super::support::CircleState::TransportError,
            super::support::CircleState::TransportError,
        ])
        .await;
    for index in [0, 1] {
        ledger.submit(&mut attester, index).await.unwrap();
    }
    let (inner, requests) = super::submit::ScriptedCircle::new(
        ledger.path(),
        vec![reply(400, json!({})), reply(400, json!({}))],
    );
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let finish = std::sync::Arc::new(tokio::sync::Notify::new());
    attester.circle = Box::new(PendingPost {
        inner,
        started: started.clone(),
        finish: finish.clone(),
    });
    let (sender, receiver) = mpsc::channel(16);
    attester.attach_admin(receiver, CancellationToken::new());
    let saved = attester.store.submissions_to_recover().unwrap();
    let mut rate_limited = false;
    let owner = attester.advance_submissions(saved, &mut rate_limited);
    let operator = async {
        started.notified().await;
        let inspected = list_command(&sender);
        finish.notify_one();
        let page = inspected.await.unwrap().unwrap();
        assert_eq!(page.holds.len(), 1);
        assert_eq!(requests.lock().unwrap().len(), 1);
        started.notified().await;
        finish.notify_one();
    };
    let (result, _) = tokio::join!(owner, operator);
    result.unwrap();
    assert_eq!(attester.store.holds_page(None).unwrap().len(), 2);
}

#[tokio::test]
async fn pagination_is_bounded_and_uses_stored_note_bytes() {
    use miden_protocol::utils::serde::Serializable;
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![]).await;
    let mut ids = Vec::new();
    for index in 1..=103 {
        let burn = super::validation::discovered_burn(1_000, super::verify::serial(index), 9);
        let id = burn.note_id();
        let checkpoint = attester.store.checkpoint().unwrap().unwrap();
        attester
            .store
            .save_scan_progress(&[], &[burn], &checkpoint)
            .unwrap();
        attester
            .store
            .hold_burn(id, BurnHoldReason::PrepareRejected, None)
            .unwrap();
        ids.push(id);
    }
    ids.sort_by_key(|id| id.to_bytes());
    assert_eq!(
        attester.store.holds_page(None).unwrap().len(),
        101,
        "SQL projects only one extra row"
    );
    let (sender, receiver) = mpsc::channel(16);
    attester.attach_admin(receiver, CancellationToken::new());
    let inspected = list_command(&sender);
    attester.admin_checkpoint().await;
    let page = inspected.await.unwrap().unwrap();
    assert_eq!(page.holds.len(), 100);
    assert_eq!(page.next_after, Some(ids[99].to_string()));
    let rest = attester.store.holds_page(Some(ids[99])).unwrap();
    assert_eq!(
        rest.iter()
            .map(|hold| hold.note_id.clone())
            .collect::<Vec<_>>(),
        ids[100..]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn listing_does_not_change_signing_submission_polling_or_restart_recovery() {
    let ledger = Ledger::new().await;
    let (signers, calls) = super::service_map::signers(None).await;
    let replies = super::service_map::fresh_replies(&ledger, &ledger.fresh_indices);
    let (mut attester, requests, _) = ledger.runtime(replies, signers).await;
    let (sender, receiver) = mpsc::channel(16);
    attester.attach_admin(receiver, CancellationToken::new());
    let mut inspected = list_command(&sender);
    attester.run_one_cycle().await.unwrap();
    assert!(inspected.try_recv().unwrap().unwrap().holds.is_empty());
    assert_eq!(super::service_map::counts(&calls), [3, 3]);
    assert_eq!(requests.lock().unwrap().len(), 6);
    let identities: Vec<_> = (0..3)
        .map(|index| ledger.record(&attester, index).body)
        .collect();
    drop(attester);
    let (signers, calls) = super::service_map::signers(None).await;
    let replies = ledger
        .ordered_indices()
        .iter()
        .map(|&index| reply(200, ledger.response(index, "finalized")))
        .collect();
    let (mut attester, requests, _) = ledger.runtime(replies, signers).await;
    let (sender, receiver) = mpsc::channel(16);
    attester.attach_admin(receiver, CancellationToken::new());
    let mut inspected = list_command(&sender);
    attester.run_one_cycle().await.unwrap();
    assert!(inspected.try_recv().unwrap().is_ok());
    assert_eq!(super::service_map::counts(&calls), [0, 0]);
    assert!(requests
        .lock()
        .unwrap()
        .iter()
        .all(|request| matches!(request, super::support::ObservedRequest::Lookup { .. })));
    for (index, identity) in identities.iter().enumerate() {
        assert_eq!(
            ledger.record(&attester, index).status,
            crate::submission::SubmissionStatus::Finalized
        );
        assert_eq!(&ledger.record(&attester, index).body, identity);
    }
}

#[tokio::test]
async fn ready_catch_up_yields_to_commands_before_the_last_block() {
    let mut factory = super::support::BlockFactory::new();
    for _ in 0..30 {
        factory.push(vec![], vec![]);
    }
    let directory = tempfile::tempdir().unwrap();
    let (mut attester, chain) = super::discovery::start(
        &directory,
        factory.blocks(),
        super::support::scan_limits(29, 29),
    )
    .await;
    let (sender, receiver) = mpsc::channel(16);
    attester.attach_admin(receiver, CancellationToken::new());
    let discovery = attester.discover_burns();
    let operator = async {
        let result = list_command(&sender).await.unwrap().unwrap();
        assert!(result.holds.is_empty());
        assert!(
            chain.requests.lock().unwrap().len() < 30,
            "block catch-up must admit commands"
        );
        tokio::task::yield_now().await;
        list_command(&sender).await.unwrap().unwrap();
        assert!(chain.requests.lock().unwrap().len() < 30);
    };
    let (discovered, _) = tokio::join!(discovery, operator);
    discovered.unwrap();
}

#[tokio::test(start_paused = true)]
async fn due_idle_deadline_wins_under_continuous_admin_traffic() {
    let ledger = Ledger::new().await;
    let (signers, _) = super::service_map::signers(None).await;
    let (mut attester, _, chain) = ledger.runtime(vec![], signers).await;
    for burn in &ledger.burns {
        attester
            .store
            .hold_burn(burn.note_id(), BurnHoldReason::PrepareRejected, None)
            .unwrap();
    }
    let shutdown = CancellationToken::new();
    let (sender, receiver) = mpsc::channel(16);
    attester.attach_admin(receiver, shutdown.clone());
    let run = attester.run(shutdown.clone());
    let traffic = async {
        list_command(&sender).await.unwrap().unwrap();
        // Complete the first cycle and enter its original idle pause.
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_millis(100)).await;
        for _ in 0..4 {
            let replies: Vec<_> = (0..16).map(|_| list_command(&sender)).collect();
            for reply in replies {
                reply.await.unwrap().unwrap();
            }
        }
        assert!(
            *chain.scan_limit_requests.lock().unwrap() >= 2,
            "queued commands cannot postpone a due cycle"
        );
        shutdown.cancel();
    };
    let (result, _) = tokio::join!(run, traffic);
    result.unwrap();
}

#[test]
fn admin_run_flags_are_optional_paired_and_local() {
    let directory = tempfile::tempdir().unwrap();
    let mut args = super::startup::TestArgs::new(&directory);
    args.replace("--store-path", directory.path().join("state.sqlite3"));
    assert!(args.config().unwrap().admin().is_none());
    args.append("--admin-listen", "127.0.0.1:8090");
    assert!(args.parse().is_err());
    args.append("--admin-token-file", "/private/operator/token");
    assert!(args.config().unwrap().admin().is_some());
    args.replace("--admin-listen", "0.0.0.0:8090");
    assert!(args.parse().is_err());
    args.remove("--admin-listen");
    assert!(args.parse().is_err());
}

#[tokio::test]
async fn invalid_token_fails_before_external_service_initialization() {
    let directory = tempfile::tempdir().unwrap();
    let mut args = super::startup::TestArgs::new(&directory);
    args.replace("--store-path", directory.path().join("state.sqlite3"));
    args.append("--admin-listen", "127.0.0.1:0");
    args.append("--admin-token-file", directory.path().join("missing-token"));
    let result = crate::service::AttesterService::start(args.load()).await;
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("cannot open admin token file"));
}

fn selection(hold: &HoldEntry, checked: bool) -> ReleaseSelection {
    ReleaseSelection {
        note_id: crate::admin::parse_note_id(&hold.note_id).unwrap(),
        expected_event_seq: hold.event_seq,
        circle_not_accepted: checked,
    }
}

#[tokio::test]
async fn releasing_a_burn_hold_keeps_its_earlier_expired_request() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger
        .start(vec![reply(201, json!([ledger.response(0, "expired")]))])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let expired = ledger.record(&attester, 0);
    attester
        .store
        .hold_burn(
            ledger.burns[0].note_id(),
            BurnHoldReason::PrepareRejected,
            None,
        )
        .unwrap();
    let held = attester.store.holds_page(None).unwrap();
    assert_eq!(
        attester
            .store
            .release_checked(&selection(&held[0], false))
            .unwrap(),
        (1, 0)
    );
    assert_eq!(ledger.record(&attester, 0), expired);
}

pub(super) fn list_command(
    sender: &mpsc::Sender<Command>,
) -> oneshot::Receiver<Result<HoldsPage, ReleaseError>> {
    let (reply, receiver) = oneshot::channel();
    sender
        .try_send(Command {
            operation: Operation::List(None, reply),
            deadline: Instant::now() + Duration::from_secs(60),
        })
        .unwrap_or_else(|_| panic!("test inbox full"));
    receiver
}

#[tokio::test]
async fn selected_release_leaves_other_holds_and_cannot_release_a_new_hold() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger
        .start(vec![reply(400, json!({"message": "rejected"}))])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    for index in [1, 2] {
        attester
            .store
            .hold_burn(
                ledger.burns[index].note_id(),
                BurnHoldReason::PrepareRejected,
                None,
            )
            .unwrap();
    }
    assert!(
        ledger.open_store().is_err(),
        "owner keeps the exclusive store lock"
    );
    let page = attester.store.holds_page(None).unwrap();
    let withdrawal = page.iter().find(|hold| hold.kind == "withdrawal").unwrap();
    let burn = page
        .iter()
        .find(|hold| hold.note_id == ledger.burns[1].note_id().to_string())
        .unwrap();
    let mut signed = selection(withdrawal, false);
    assert!(matches!(
        attester.store.release_checked(&signed),
        Err(ReleaseError::CircleCheck)
    ));
    assert_eq!(attester.store.holds_page(None).unwrap().len(), 3);
    signed.circle_not_accepted = true;
    let mut stale = signed.clone();
    stale.expected_event_seq += 1;
    assert!(matches!(
        attester.store.release_checked(&stale),
        Err(ReleaseError::Conflict)
    ));
    assert_eq!(attester.store.holds_page(None).unwrap().len(), 3);
    assert_eq!(attester.store.release_checked(&signed).unwrap(), (0, 1));
    assert_eq!(attester.store.holds_page(None).unwrap().len(), 2);
    let selected = selection(burn, false);
    assert_eq!(attester.store.release_checked(&selected).unwrap(), (1, 0));
    assert_eq!(attester.store.holds_page(None).unwrap().len(), 1);
    attester
        .store
        .hold_burn(
            ledger.burns[1].note_id(),
            BurnHoldReason::PrepareRejected,
            None,
        )
        .unwrap();
    assert!(matches!(
        attester.store.release_checked(&selected),
        Err(ReleaseError::Conflict)
    ));
    let new = attester.store.holds_page(None).unwrap();
    assert!(
        new.iter()
            .find(|hold| hold.note_id == burn.note_id)
            .unwrap()
            .event_seq
            > burn.event_seq
    );
    // A note the store never held has no hold to release, rather than a hold that changed.
    let unknown = ReleaseSelection {
        note_id: crate::admin::parse_note_id(&format!("0x{}", "11".repeat(32))).unwrap(),
        expected_event_seq: 1,
        circle_not_accepted: true,
    };
    assert!(matches!(
        attester.store.release_checked(&unknown),
        Err(ReleaseError::NotHeld(note)) if note == unknown.note_id
    ));
}

/// A selection naming a note with nothing to release, at that note's current revision, names no
/// hold: nothing changed since any listing, and listing again would not show it.
#[tokio::test]
async fn a_selection_of_a_note_with_nothing_to_release_is_not_held() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger
        .start(vec![reply(201, json!([ledger.response(0, "created")]))])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let note_id = ledger.burns[0].note_id();
    let selection = ReleaseSelection {
        note_id,
        expected_event_seq: attester.store.revision(note_id).unwrap().unwrap(),
        circle_not_accepted: true,
    };
    assert!(matches!(
        attester.store.release_checked(&selection),
        Err(ReleaseError::NotHeld(note)) if note == note_id
    ));
}

#[tokio::test]
async fn checked_history_write_failure_preserves_the_hold() {
    use opentelemetry::trace::{SpanId, Status, TracerProvider as _};
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
    use tracing_opentelemetry::OpenTelemetryLayer;
    use tracing_subscriber::layer::SubscriberExt as _;

    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![]).await;
    for index in [0, 1] {
        attester
            .store
            .hold_burn(
                ledger.burns[index].note_id(),
                BurnHoldReason::PrepareRejected,
                None,
            )
            .unwrap();
    }
    let selected = selection(&attester.store.holds_page(None).unwrap()[0], false);
    drop(attester);
    ledger.sql("CREATE TRIGGER fail_admin_release BEFORE INSERT ON submission_events WHEN NEW.kind = 'BURN_RELEASED' BEGIN SELECT RAISE(FAIL, 'disk full'); END;");
    let mut store = ledger.open_store().unwrap();
    assert!(matches!(
        store.release_checked(&selected),
        Err(ReleaseError::Store(_))
    ));
    assert_eq!(store.holds_page(None).unwrap().len(), 2);
    drop(store);

    // Drop the reply while the owner reports the failed transaction.
    let (mut attester, _) = ledger.start(vec![]).await;
    let (sender, receiver) = mpsc::channel(1);
    attester.attach_admin(receiver, CancellationToken::new());
    let (reply, receive) = oneshot::channel();
    sender
        .try_send(Command {
            operation: Operation::Release(selected, reply),
            deadline: Instant::now() + Duration::from_secs(60),
        })
        .unwrap_or_else(|_| panic!());
    let receive = Arc::new(std::sync::Mutex::new(Some(receive)));
    let output = tempfile::NamedTempFile::new().unwrap();
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer({
            let receive = receive.clone();
            let file = output.reopen().unwrap();
            move || {
                receive.lock().unwrap().take();
                file.try_clone().unwrap()
            }
        })
        .finish()
        .with(OpenTelemetryLayer::new(provider.tracer("test")));
    async {
        attester
            .admin_checkpoint()
            .instrument(tracing::info_span!("attester.discover"))
            .await;
    }
    .with_subscriber(subscriber)
    .await;
    assert!(
        receive.lock().unwrap().is_none(),
        "reply was dropped before the send"
    );
    let logged = std::fs::read_to_string(output.path()).unwrap();
    assert_eq!(logged.matches("admin store operation failed").count(), 1);
    assert!(
        logged.contains("disk full"),
        "underlying store error must survive: {logged}"
    );
    assert!(!logged.contains("operator released a hold"));
    let spans = exporter.get_finished_spans().unwrap();
    let admin = spans
        .iter()
        .find(|span| span.name == "attester.admin")
        .unwrap();
    assert_eq!(admin.parent_span_id, SpanId::INVALID);
    assert_eq!(admin.status, Status::error("store"));
    let discover = spans
        .iter()
        .find(|span| span.name == "attester.discover")
        .unwrap();
    assert_eq!(discover.status, Status::Unset);
    assert_eq!(attester.store.holds_page(None).unwrap().len(), 2);
}

#[tokio::test]
async fn owner_skips_abandoned_commands_and_lost_success_does_not_repeat() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![]).await;
    attester
        .store
        .hold_burn(
            ledger.burns[0].note_id(),
            BurnHoldReason::PrepareRejected,
            None,
        )
        .unwrap();
    let selected = selection(&attester.store.holds_page(None).unwrap()[0], false);
    let (sender, receiver) = mpsc::channel(16);
    attester.attach_admin(receiver, CancellationToken::new());
    for abandoned in [false, true] {
        let (reply, receive) = oneshot::channel();
        let deadline = if abandoned {
            Instant::now() + Duration::from_secs(60)
        } else {
            Instant::now()
        };
        sender
            .try_send(Command {
                operation: Operation::Release(selected.clone(), reply),
                deadline,
            })
            .unwrap_or_else(|_| panic!());
        if abandoned {
            drop(receive);
        } else {
            let _receive = receive;
            attester.admin_checkpoint().await;
        }
        attester.admin_checkpoint().await;
        assert_eq!(attester.store.holds_page(None).unwrap().len(), 1);
    }
    let (reply, receive) = oneshot::channel();
    sender
        .try_send(Command {
            operation: Operation::Release(selected.clone(), reply),
            deadline: Instant::now() + Duration::from_secs(60),
        })
        .unwrap_or_else(|_| panic!());
    let output = tempfile::NamedTempFile::new().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(output.reopen().unwrap())
        .finish();
    attester
        .admin_checkpoint()
        .with_subscriber(subscriber)
        .await;
    drop(receive); // The transaction committed even though its successful reply was lost.
    let logged = std::fs::read_to_string(output.path()).unwrap();
    assert_eq!(logged.matches("operator released a hold").count(), 1);
    assert!(logged.contains(&format!("note_id={}", selected.note_id)));
    assert!(logged.contains(&format!("event_seq={}", selected.expected_event_seq)));
    assert!(logged.contains("burns=1 withdrawals=0"));
    assert!(matches!(
        attester.store.release_checked(&selected),
        Err(ReleaseError::Conflict)
    ));
    drop(sender);
    attester.admin_checkpoint().await;
}

#[tokio::test]
async fn authenticated_transport_and_client_release_selected_holds() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![]).await;
    for index in [0, 1, 2] {
        attester
            .store
            .hold_burn(
                ledger.burns[index].note_id(),
                BurnHoldReason::PrepareRejected,
                Some((400, br#"{"message":"safe\n message\u001b[2J"}"#)),
            )
            .unwrap();
    }
    let secret = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(secret.path(), "ab".repeat(32)).unwrap();
    let (server, receiver) = Server::bind(&AdminConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        token_file: secret.path().into(),
    })
    .await
    .unwrap();
    let address = server.address();
    let shutdown = CancellationToken::new();
    attester.attach_admin(receiver, shutdown.clone());
    let serve = server.run(shutdown.clone());
    let owner = async {
        while !shutdown.is_cancelled() {
            attester.admin_checkpoint().await;
            tokio::task::yield_now().await;
        }
    };
    let client = async {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let url = format!("http://{address}/admin/attester/holds");
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let page: HoldsPage = client
            .get(&url)
            .bearer_auth("ab".repeat(32))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(page.holds.len(), 3);
        assert!(page.holds.iter().all(|hold| !hold
            .circle_message
            .as_deref()
            .unwrap()
            .chars()
            .any(char::is_control)));
        assert!(!page.faucet_account_id.is_empty());
        let next: HoldsPage = client
            .get(&url)
            .query(&[("after", &page.holds[0].note_id)])
            .bearer_auth("ab".repeat(32))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(next.holds.len(), 2);
        let release = format!("{url}/release");
        let body = json!(ReleaseRequest {
            note_id: page.holds[0].note_id.clone(),
            expected_event_seq: page.holds[0].event_seq,
            circle_not_accepted: false,
        });
        let mut extra_field = body.clone();
        extra_field["extra"] = json!(true);
        for body in [json!({"holds": []}), extra_field] {
            let response = client
                .post(&release)
                .bearer_auth("ab".repeat(32))
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response.json::<serde_json::Value>().await.unwrap(),
                json!({"code": "invalid_input", "message": "invalid release body"})
            );
        }
        assert_eq!(
            client
                .post(&release)
                .bearer_auth("ab".repeat(32))
                .header("content-type", "application/json")
                .body(" ".repeat(16 * 1024 + 1))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let response: serde_json::Value = client
            .post(&release)
            .bearer_auth("ab".repeat(32))
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(response, json!({"burns": 1, "withdrawals": 0}));
        assert_eq!(
            client
                .post(&release)
                .bearer_auth("ab".repeat(32))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        use clap::Parser;
        let base = format!("http://{address}");
        let invocation = crate::config::Invocation::try_parse_from([
            "xusdc-attester",
            "admin",
            "--url",
            &base,
            "--token-file",
            secret.path().to_str().unwrap(),
            "holds",
        ])
        .unwrap();
        crate::service::run_command(invocation.command.unwrap())
            .await
            .unwrap();
        let selected = format!("{}:{}", page.holds[1].note_id, page.holds[1].event_seq);
        let invocation = crate::config::Invocation::try_parse_from([
            "xusdc-attester",
            "admin",
            "--url",
            &base,
            "--token-file",
            secret.path().to_str().unwrap(),
            "release-holds",
            "--hold",
            &selected,
        ])
        .unwrap();
        crate::service::run_command(invocation.command.unwrap())
            .await
            .unwrap();
        shutdown.cancel();
    };
    let (result, _, _) = tokio::join!(serve, owner, client);
    result.unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    assert_eq!(attester.store.holds_page(None).unwrap().len(), 1);
}

#[tokio::test]
async fn service_shutdown_keeps_its_pending_post_and_cleans_up_connections() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![]).await;
    let first = ledger.fresh_indices[0];
    for &index in &ledger.fresh_indices[1..] {
        attester
            .store
            .hold_burn(
                ledger.burns[index].note_id(),
                BurnHoldReason::PrepareRejected,
                None,
            )
            .unwrap();
    }
    let (inner, requests) = super::submit::ScriptedCircle::new(
        ledger.path(),
        vec![
            reply(200, ledger.prepared_response(first)),
            reply(400, json!({"message":"rejected"})),
        ],
    );
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let finish = std::sync::Arc::new(tokio::sync::Notify::new());
    attester.circle = Box::new(PendingPost {
        inner,
        started: started.clone(),
        finish: finish.clone(),
    });
    let secret = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(secret.path(), "ab".repeat(32)).unwrap();
    let (server, receiver) = Server::bind(&AdminConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        token_file: secret.path().into(),
    })
    .await
    .unwrap();
    let address = server.address();
    let accepted = server.accepted.clone();
    let service = crate::service::AttesterService::for_test(attester, server, receiver);
    let shutdown = CancellationToken::new();
    let run = service.run(shutdown.clone());
    let operator = async {
        use tokio::io::AsyncWriteExt;
        started.notified().await;
        let mut slow = tokio::net::TcpStream::connect(address).await.unwrap();
        slow.write_all(b"GET /admin/attester/holds HTTP/1.1\r\n")
            .await
            .unwrap();
        accepted.notified().await;
        shutdown.cancel();
        let stopped_at = Instant::now();
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "prepare completed but POST is still pending"
        );
        finish.notify_one();
        use tokio::io::AsyncReadExt;
        let closed = tokio::time::timeout(Duration::from_secs(6), slow.read(&mut [0]))
            .await
            .expect("accepted connection must close within the cleanup bound");
        assert!(
            matches!(closed, Ok(0))
                || closed.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
        );
        stopped_at
    };
    let (result, stopped_at) = tokio::time::timeout(Duration::from_secs(7), async {
        tokio::join!(run, operator)
    })
    .await
    .expect("service cleanup must be bounded");
    result.unwrap();
    assert!(stopped_at.elapsed() < Duration::from_secs(6));
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert_eq!(
        ledger.stored("SELECT count(*) FROM submissions WHERE status = 'HELD'"),
        1
    );
    assert!(ledger.open_store().is_ok());
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}
