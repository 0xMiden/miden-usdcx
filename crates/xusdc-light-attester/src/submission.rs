//! Saves signed requests before sending them, then resumes uncertain submissions unchanged.

use alloy_primitives::B256;
use miden_protocol::note::NoteId;
use reqwest::StatusCode;

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
        let saved = withdrawal.submission(endpoint)?;
        // Only confirmed failed/expired attempts may receive a fresh authorization.
        self.store.save_submission(&saved)?;
        self.advance_submission(saved).await
    }

    /// Resends each given saved request whose outcome is still unknown, one attempt each, and
    /// writes Circle's answer back onto its row; the outer cycle supplies the delay between
    /// attempts. A store write failure stops the pass so no answer is lost unrecorded.
    pub(crate) async fn recover_submissions(
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

    pub(crate) async fn advance_submission(
        &mut self,
        mut saved: SavedSubmission,
    ) -> Result<(), SubmitError> {
        // After a 429 the rest of the cycle leaves Circle alone; the row stays queued.
        if self.circle.rate_limited() {
            return Ok(());
        }
        let mut response = self.send_saved_request(&mut saved).await;
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
            eprintln!(
                "withdrawal note={} id={} status={:?} HTTP={:?} hold={:?}: {}",
                saved.note_id,
                saved.withdrawal_id.as_deref().unwrap_or("not assigned"),
                saved.status,
                saved.last_http_status,
                saved.hold_reason,
                saved
                    .last_error
                    .as_deref()
                    .unwrap_or("Circle omitted the failure reason")
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
            // Only a 400 to the POST is a definite no from Circle: a blocked burner or recipient,
            // or data Circle refuses. Any other answer says nothing final, so the row stays queued
            // and the next pass sends the same request again.
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

/// Circle's withdrawal IDs are UUIDs; the ID becomes a URL path segment, so nothing else passes.
fn is_well_formed_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
