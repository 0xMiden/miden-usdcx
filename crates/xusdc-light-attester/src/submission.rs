//! Saves signed requests before sending them, then resumes uncertain submissions unchanged.

use alloy_primitives::B256;
use miden_protocol::note::NoteId;
use reqwest::{StatusCode, Url};

use crate::attester::Attester;
use crate::circle::{self, CircleError, ConflictResponse, RawResponse, WithdrawalResponse};
use crate::signer::SignerError;
use crate::verify::SignedWithdrawal;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubmitError {
    #[error("submission request is invalid")]
    InvalidRequest(#[source] CircleError),
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

impl SubmitError {
    /// A failure that stops the rest of the cycle: the store can no longer record what Circle
    /// answers.
    pub(crate) fn is_fatal(&self) -> bool {
        matches!(self, Self::Store(_))
    }
}

/// A submission's status, stored under the name given here. A fresh authorization can replace an
/// expired withdrawal, but not a failed one: that stays for an operator to investigate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr, strum::EnumString)]
pub(crate) enum SubmissionStatus {
    #[strum(serialize = "SUBMITTING")]
    Submitting,
    #[strum(serialize = "SUBMITTED")]
    Submitted,
    #[strum(serialize = "FINALIZED")]
    Finalized,
    #[strum(serialize = "EXPIRED")]
    Expired,
    #[strum(serialize = "FAILED")]
    Failed,
    #[strum(serialize = "HELD")]
    Held,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HoldReason {
    HttpRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedSubmission {
    pub(crate) note_id: NoteId,
    pub(crate) endpoint: Url,
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

impl SavedSubmission {
    /// Where the signed withdrawal request is sent.
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// The signed withdrawal request, exactly as it is sent.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl Attester {
    /// `rate_limited` belongs to the current cycle: once Circle answers 429 it is set, and the
    /// rest of the cycle leaves Circle alone.
    pub(crate) async fn submit_signed_withdrawal(
        &mut self,
        withdrawal: &SignedWithdrawal,
        rate_limited: &mut bool,
    ) -> Result<(), SubmitError> {
        let endpoint = circle::submission_endpoint(self.config.circle_api_base_url())
            .map_err(SubmitError::InvalidRequest)?;
        let saved = withdrawal.submission(endpoint)?;
        // Only a confirmed expired attempt may receive a fresh authorization.
        self.store.save_submission(&saved)?;
        self.advance_submission(saved, rate_limited).await
    }

    /// Sends each given saved request once: the saved POST while Circle's withdrawal ID is
    /// unknown, a status lookup once it is known. Circle's answer is written back onto the row; a
    /// final status closes it, and any other answer or a lost reply leaves it for the next cycle,
    /// which supplies the delay between attempts. A store write failure stops the pass so no
    /// answer is lost unrecorded. After a 429 the rest wait for the next cycle.
    pub(crate) async fn advance_submissions(
        &mut self,
        submissions: Vec<SavedSubmission>,
        rate_limited: &mut bool,
    ) -> Result<(), SubmitError> {
        for saved in submissions {
            self.advance_submission(saved, rate_limited).await?;
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
        rate_limited: &mut bool,
    ) -> Result<(), SubmitError> {
        // After a 429 the rest of the cycle leaves Circle alone; the row stays queued.
        if *rate_limited {
            return Ok(());
        }
        let mut response = self.send_saved_request(&mut saved, rate_limited).await;
        if saved.withdrawal_id.is_none()
            && response
                .as_ref()
                .is_some_and(|reply| reply.status == StatusCode::CONFLICT)
        {
            if !saved.read_conflict() {
                return self.save_outcome(&saved);
            }
            // Save the conflict ID before checking it with GET. If that reply is lost or the process
            // restarts, recovery uses the saved ID instead of sending another POST. The ID alone does not
            // prove success.
            self.save_outcome(&saved)?;
            response = self.send_saved_request(&mut saved, rate_limited).await;
        }
        if let Some(response) = response {
            saved.read_response(response);
        }
        self.save_outcome(&saved)
    }

    async fn send_saved_request(
        &self,
        saved: &mut SavedSubmission,
        rate_limited: &mut bool,
    ) -> Option<RawResponse> {
        let result = match &saved.withdrawal_id {
            Some(id) => self.circle.get_withdrawal(saved, id).await,
            None => self.circle.post_submission(saved).await,
        };
        let response = match result {
            Ok(response) => response,
            // A 429 ends Circle traffic for this cycle, before anything is written; Circle's
            // reply is kept like any other.
            Err(CircleError::RateLimited {
                body: Some(body), ..
            }) => {
                *rate_limited = true;
                RawResponse::new(StatusCode::TOO_MANY_REQUESTS, body)
            }
            Err(error) => {
                *rate_limited |= matches!(error, CircleError::RateLimited { .. });
                // A lost response says nothing about whether Circle accepted the request.
                saved.last_http_status = None;
                saved.last_response = None;
                saved.last_error = Some(error.to_string());
                return None;
            }
        };
        saved.last_http_status = Some(response.status.as_u16());
        saved.last_response = Some(response.body.clone());
        saved.last_error = None;
        Some(response)
    }

    fn save_outcome(&mut self, saved: &SavedSubmission) -> Result<(), SubmitError> {
        self.store.update_submission_outcome(saved)?;
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
                // Circle allows re-signing and resubmitting once the cause is fixed. The attester
                // does not: it keeps Circle's reason and leaves the withdrawal to an operator.
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
pub(crate) fn is_well_formed_id(id: &str) -> bool {
    // The hyphenated form Circle returns: 8-4-4-4-12 hex digits.
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}
