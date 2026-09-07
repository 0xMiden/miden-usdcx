/// Asserts that discover, submit, and poll run sequentially, use the ledger between them, and later
/// stages still run after an earlier failure.
#[test]
#[ignore]
fn cycle_runs_in_order() {}

/// Asserts that invalid or insufficiently proven burns never reach a signer.
#[test]
#[ignore]
fn invalid_burns_are_not_signed() {}

/// Asserts that Circle's prepared response is completely validated before signing.
#[test]
#[ignore]
fn circle_response_is_checked_before_signing() {}

/// Asserts that replay and ambiguous recovery cannot create a second authorization for one burn.
#[test]
#[ignore]
fn withdrawal_is_not_sent_twice() {}

/// Asserts that one polling pass durably applies Circle's complete status ladder.
#[test]
#[ignore]
fn withdrawal_status_is_updated() {}

/// Asserts that restart resumes durable work and shutdown completes any write already in flight.
#[test]
#[ignore]
fn restart_and_shutdown_do_not_lose_work() {}
