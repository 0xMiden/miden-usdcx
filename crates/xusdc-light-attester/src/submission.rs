//! Saves signed requests before sending them, then resumes uncertain submissions unchanged.

use alloy_primitives::B256;
use miden_protocol::note::NoteId;
use reqwest::StatusCode;
use tracing::{info, warn};

use crate::attester::Attester;
use crate::circle::{self, CircleError, ConflictResponse, RawResponse, WithdrawalResponse};
use crate::signer::SignerError;
use crate::verify::SignedWithdrawal;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubmitError {
    #[error("submission request is invalid")]
    InvalidRequest,
    #[error("attester store failed")]
    Store(#[from] anyhow::Error),
    #[error("could not encode the signed withdrawal")]
    Encoding(#[source] serde_json::Error),
    #[error("Circle prepare failed")]
    Prepare(#[from] CircleError),
    #[error("Circle's prepared withdrawal failed verification")]
    Verification(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("withdrawal signing failed")]
    Signing(#[from] SignerError),
    #[error("system time cannot be used for withdrawal capacity accounting")]
    Clock,
}

impl SubmitError {
    /// A failure that stops the rest of the cycle: the store can no longer record what Circle
    /// answers, or the clock cannot be used for capacity accounting.
    pub(crate) fn is_fatal(&self) -> bool {
        matches!(self, Self::Store(_) | Self::Clock)
    }
}

/// Failed and expired attempts can be replaced; they do not permanently retire the burn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubmissionStatus {
    Submitting,
    Submitted,
    Finalized,
    Expired,
    Failed,
    Held,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HoldReason {
    HttpRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedSubmission {
    pub(crate) note_id: NoteId,
    pub(crate) endpoint: String,
    pub(crate) body: Vec<u8>,
    pub(crate) transfer_spec_hash: B256,
    pub(crate) use_circle_forwarding: bool,
    pub(crate) status: SubmissionStatus,
    pub(crate) withdrawal_id: Option<String>,
    pub(crate) hold_reason: Option<HoldReason>,
    pub(crate) last_http_status: Option<u16>,
    pub(crate) last_response: Option<Vec<u8>>,
    pub(crate) last_error: Option<String>,
}

impl Attester {
    pub(crate) async fn submit_signed_withdrawal(
        &mut self,
        withdrawal: &SignedWithdrawal,
    ) -> Result<(), SubmitError> {
        let endpoint = circle::submission_endpoint(self.config.circle_api_base_url())
            .map_err(|_| SubmitError::InvalidRequest)?;
        let (saved, amount) = withdrawal.submission(endpoint)?;
        let previous = self.store.submission(saved.note_id)?;
        // The final fit check, reservation and exact request become durable together.
        if !self.store.admit_submission(
            &saved,
            amount,
            self.now_ms()?,
            self.config.withdrawal_window_ms(),
            self.config.withdrawal_limit(),
        )? {
            return Ok(());
        }
        // Only an expired or failed attempt can be replaced; keep its Circle id in the log.
        if let Some(previous) = previous {
            info!(
                note_id = %saved.note_id,
                previous_withdrawal_id = previous.withdrawal_id.as_deref().unwrap_or("not assigned"),
                previous_status = ?previous.status,
                "replaced an earlier submission"
            );
        }
        self.send_admitted_submission(saved, true).await
    }

    /// Sends each given saved request once: the saved POST while Circle's withdrawal ID is
    /// unknown, a status lookup once it is known. Circle's answer is written back onto the row; a
    /// final status closes it, and any other answer or a lost reply leaves it for the next cycle,
    /// which supplies the delay between attempts. A store write failure stops the pass so no
    /// answer is lost unrecorded.
    pub(crate) async fn advance_submissions(
        &mut self,
        submissions: Vec<SavedSubmission>,
    ) -> Result<(), SubmitError> {
        for saved in submissions {
            self.advance_submission(saved).await?;
        }
        Ok(())
    }

    /// After reviewing an HTTP rejection, queue the unchanged request for another attempt.
    /// This does not retry failed or expired Circle withdrawals.
    pub fn retry_held_submission(&mut self, note_id: NoteId) -> Result<(), SubmitError> {
        self.store
            .retry_held_submission(note_id)
            .map_err(Into::into)
    }

    /// After Circle's prepare refused this burn and the cause is fixed, let the burn be checked
    /// again. Capacity reservations and any cap-rejection cooldown remain unchanged.
    pub fn release_burn_hold(&mut self, note_id: NoteId) -> Result<(), SubmitError> {
        self.store.release_burn_hold(note_id).map_err(Into::into)
    }

    pub(crate) fn now_ms(&self) -> Result<i64, SubmitError> {
        let elapsed = (self.now)()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| SubmitError::Clock)?;
        elapsed
            .as_millis()
            .try_into()
            .map_err(|_| SubmitError::Clock)
    }

    pub(crate) async fn advance_submission(
        &mut self,
        saved: SavedSubmission,
    ) -> Result<(), SubmitError> {
        // After a 429 the rest of the cycle leaves Circle alone; the row stays queued.
        if self.circle.rate_limited() {
            return Ok(());
        }
        // GET needs no capacity. Before each retry POST, renew the one reservation for this
        // note: the previous attempt may have been accepted even if its response was lost.
        if saved.withdrawal_id.is_none()
            && !self.store.renew_submission(
                saved.note_id,
                self.now_ms()?,
                self.config.withdrawal_window_ms(),
                self.config.withdrawal_limit(),
            )?
        {
            info!(
                note_id = %saved.note_id,
                "saved request waits for capacity before it is sent again"
            );
            return Ok(());
        }
        self.send_admitted_submission(saved, false).await
    }

    /// Sends the saved request once. `first_send` is true only when these signed bytes have never
    /// been sent before, so no earlier attempt can have been accepted.
    async fn send_admitted_submission(
        &mut self,
        mut saved: SavedSubmission,
        first_send: bool,
    ) -> Result<(), SubmitError> {
        let mut response = self.send_saved_request(&mut saved).await;
        if saved.withdrawal_id.is_none()
            && response.as_ref().is_some_and(|reply| {
                is_limit_rejection(reply, self.config.withdrawal_cap_error_message())
            })
        {
            if !first_send {
                // An earlier send of these bytes may have been accepted, so the burn is never
                // signed again: the same request stays queued and goes out in a later cycle.
                saved.last_error = Some("Circle's withdrawal limit is reached".into());
                return self.save_outcome(&saved);
            }
            // Only a confirmed cap rejection releases capacity. Discard its signed bytes;
            // after the cooldown it must be prepared and signed again, not replayed stale.
            self.store.record_cap_rejection(saved.note_id)?;
            info!(
                note_id = %saved.note_id,
                "withdrawal waiting after Circle's capacity rejection"
            );
            return Ok(());
        }
        if saved.withdrawal_id.is_none()
            && response
                .as_ref()
                .is_some_and(|reply| reply.status == StatusCode::CONFLICT)
        {
            if !saved.read_conflict() {
                return self.save_outcome(&saved);
            }
            // The conflict ID is a lookup handle, not proof of success. Save it before GET so
            // a lost GET response or restart does not send another POST.
            self.save_outcome(&saved)?;
            response = self.send_saved_request(&mut saved).await;
        }
        if let Some(response) = response {
            saved.read_response(response);
        }
        self.save_outcome(&saved)
    }

    async fn send_saved_request(&self, saved: &mut SavedSubmission) -> Option<RawResponse> {
        let result = match &saved.withdrawal_id {
            Some(id) => self.circle.get_withdrawal(saved, id).await,
            None => self.circle.post_submission(saved).await,
        };
        // One line per attempt, before anything is written, so a failed store write cannot lose
        // what Circle answered.
        let method = if saved.withdrawal_id.is_some() {
            "GET"
        } else {
            "POST"
        };
        let withdrawal_id = saved.withdrawal_id.as_deref().unwrap_or("not assigned");
        match &result {
            Ok(response) => info!(
                note_id = %saved.note_id,
                method,
                withdrawal_id,
                http_status = response.status.as_u16(),
                "Circle answered"
            ),
            Err(error) => warn!(
                note_id = %saved.note_id,
                method,
                withdrawal_id,
                error = error as &dyn std::error::Error,
                "Circle request failed"
            ),
        }
        match result {
            Ok(response) => {
                saved.last_http_status = Some(response.status.as_u16());
                saved.last_response = Some(response.body.clone());
                saved.last_error = None;
                Some(response)
            }
            Err(error) => {
                // A lost response says nothing about whether Circle accepted the request.
                saved.last_http_status = None;
                saved.last_response = None;
                saved.last_error = Some(error.to_string());
                None
            }
        }
    }

    fn save_outcome(&self, saved: &SavedSubmission) -> Result<(), SubmitError> {
        self.store.save_submission_outcome(saved)?;
        if saved.hold_reason.is_some()
            || saved.last_error.is_some()
            || saved.status == SubmissionStatus::Failed
        {
            // For a failed withdrawal the saved text is Circle's own failure reason: outside text
            // that stays in the store and out of the log. Every other saved text is one of ours.
            let reason = saved
                .last_error
                .as_deref()
                .filter(|_| saved.status != SubmissionStatus::Failed);
            warn!(
                note_id = %saved.note_id,
                withdrawal_id = saved.withdrawal_id.as_deref().unwrap_or("not assigned"),
                status = ?saved.status,
                http_status = ?saved.last_http_status,
                hold_reason = ?saved.hold_reason,
                reason,
                "withdrawal submission needs attention"
            );
        }
        Ok(())
    }
}

impl SavedSubmission {
    fn hold(&mut self, reason: HoldReason, message: &str) {
        self.status = SubmissionStatus::Held;
        self.hold_reason = Some(reason);
        self.last_error = Some(message.into());
    }

    pub(crate) fn read_conflict(&mut self) -> bool {
        let conflict = self
            .last_response
            .as_deref()
            .and_then(|body| serde_json::from_slice::<ConflictResponse>(body).ok())
            .and_then(|response| response.conflict);
        if let Some(conflict) = conflict {
            if conflict
                .burn_note_id
                .as_ref()
                .is_some_and(|id| !self.matches_note(id))
            {
                self.last_error = Some("conflict names another burn note".into());
                return false;
            }
            if let Some(id) = conflict.withdrawal_id.filter(|id| !id.trim().is_empty()) {
                if !is_well_formed_id(&id) {
                    self.last_error = Some("conflict names a malformed withdrawal ID".into());
                    return false;
                }
                self.withdrawal_id = Some(id);
                return true;
            }
        }
        // Circle confirms this race is retryable. Keep the same bytes queued for the next
        // paced cycle; do not guess an ID, re-sign, or retry immediately inside this pass.
        self.last_error = Some("conflict has no withdrawal ID yet".into());
        false
    }

    pub(crate) fn read_response(&mut self, response: RawResponse) {
        let lookup = self.withdrawal_id.is_some();
        let expected_status = if lookup {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        };
        if response.status != expected_status {
            // Only a 400 to the POST, unless it is Circle's configured capacity message, is a
            // definite no from Circle: a blocked burner or recipient, or data Circle refuses. Any
            // other answer says nothing final, so the row stays queued and the next pass sends the
            // same request again.
            if !lookup && response.status == StatusCode::BAD_REQUEST {
                self.hold(
                    HoldReason::HttpRejected,
                    "HTTP response needs operator review",
                );
            } else {
                self.last_error = Some(format!("Circle returned HTTP {}", response.status));
            }
            return;
        }

        let withdrawal = if lookup {
            serde_json::from_slice::<WithdrawalResponse>(&response.body).ok()
        } else {
            match serde_json::from_slice::<Vec<WithdrawalResponse>>(&response.body) {
                Ok(mut withdrawals) if withdrawals.len() <= 1 => withdrawals.pop(),
                Ok(_) => {
                    self.last_error = Some("response contains extra withdrawals".into());
                    return;
                }
                Err(_) => None,
            }
        };
        let Some(withdrawal) = withdrawal else {
            self.last_error = Some("Circle returned an incomplete or malformed response".into());
            return;
        };

        if !is_well_formed_id(&withdrawal.withdrawal_id)
            || !self.matches_note(&withdrawal.burn_note_id)
            || withdrawal.use_circle_forwarding != self.use_circle_forwarding
            || withdrawal.transfer_spec_hashes.len() != 1
            || withdrawal.transfer_spec_hashes[0].parse::<B256>().ok()
                != Some(self.transfer_spec_hash)
            || self
                .withdrawal_id
                .as_ref()
                .is_some_and(|id| id != &withdrawal.withdrawal_id)
        {
            self.last_error = Some("response does not identify the saved withdrawal".into());
            return;
        }

        self.withdrawal_id = Some(withdrawal.withdrawal_id);
        self.status = match withdrawal.status.as_str() {
            "created" | "verified" | "confirmed" => SubmissionStatus::Submitted,
            "finalized" => SubmissionStatus::Finalized,
            "expired" => SubmissionStatus::Expired,
            "failed" => {
                // Circle allows re-signing/resubmitting after the cause is fixed, without a
                // reset on their side. Keep the reason; do not retry every failure automatically.
                self.last_error = withdrawal.failure_reason;
                SubmissionStatus::Failed
            }
            _ => {
                self.last_error = Some("Circle returned an unknown withdrawal status".into());
                return;
            }
        };
    }

    fn matches_note(&self, id: &str) -> bool {
        id.eq_ignore_ascii_case(&self.note_id.to_hex())
    }
}

/// Whether Circle refused a withdraw POST because its withdrawal limit is reached: a 400 whose
/// `message` starts with the configured text. Circle's limit message goes on with the current
/// total and the limit, so only its fixed start is configured.
pub(crate) fn is_limit_rejection(response: &RawResponse, message_start: Option<&str>) -> bool {
    response.status == StatusCode::BAD_REQUEST
        && message_start.is_some_and(|start| {
            serde_json::from_slice::<serde_json::Value>(&response.body).is_ok_and(|body| {
                body["message"]
                    .as_str()
                    .is_some_and(|message| message.starts_with(start))
            })
        })
}

/// Circle's withdrawal IDs are UUIDs; the ID becomes a URL path segment, so nothing else passes.
fn is_well_formed_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
