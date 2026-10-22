//! Tries remote proving first, then proves the same transaction locally if it fails.

use std::time::Duration;

use miden_client::remote_prover::RemoteTransactionProver;
use miden_client::transaction::{
    LocalTransactionProver, TransactionProver, TransactionProverError,
};
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use tracing::warn;
use url::Url;

/// Proves on the remote prover within `timeout`, and proves the same transaction locally when the
/// remote attempt fails or times out.
pub(crate) struct RemoteProver {
    inner: RemoteTransactionProver,
    timeout: Duration,
}

impl RemoteProver {
    pub(crate) fn new(url: &Url, timeout: Duration) -> Self {
        Self {
            inner: RemoteTransactionProver::new(url.as_str()).with_timeout(timeout),
            timeout,
        }
    }
}

#[async_trait::async_trait]
impl TransactionProver for RemoteProver {
    async fn prove(
        &self,
        inputs: TransactionInputs,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        let remote = tokio::time::timeout(self.timeout, self.inner.prove(&inputs))
            .await
            .map_err(|error| {
                TransactionProverError::other_with_source("remote proving timed out", error)
            })
            .and_then(|result| result);
        match remote {
            Ok(proof) => Ok(proof),
            Err(error) => {
                let error = anyhow::Error::new(error);
                warn!(error = %format_args!("{error:#}"), "remote proving failed; proving the same transaction locally");
                LocalTransactionProver::default().prove(inputs)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::account::{Account, AccountCode, AccountStorage};
    use miden_protocol::asset::AssetVault;
    use miden_protocol::block::BlockHeader;
    use miden_protocol::protocol_config::ProtocolConfig;
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
    use miden_protocol::transaction::{InputNotes, PartialBlockchain};
    use miden_protocol::ONE;
    use rstest::rstest;
    use tokio::io::AsyncWriteExt;

    use super::*;

    fn inputs() -> TransactionInputs {
        let account = Account::new_existing(
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE
                .try_into()
                .unwrap(),
            AssetVault::default(),
            AccountStorage::mock(),
            AccountCode::mock(),
            ONE,
        );
        let chain = PartialBlockchain::default();
        TransactionInputs::new(
            (&account).into(),
            BlockHeader::mock(0, Some(chain.peaks().hash_peaks()), None, &[]),
            ProtocolConfig::mock(),
            chain,
            InputNotes::default(),
        )
        .unwrap()
    }

    /// How the remote prover fails.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RemoteFailure {
        /// Nothing listens at the prover URL.
        Refused,
        /// The prover accepts the connection and never answers.
        Silent,
        /// The prover answers with something that is not gRPC.
        Malformed,
    }

    #[rstest]
    #[case::refused(RemoteFailure::Refused)]
    #[case::silent(RemoteFailure::Silent)]
    #[case::malformed(RemoteFailure::Malformed)]
    #[tokio::test]
    async fn a_failed_remote_attempt_returns_the_local_result(#[case] failure: RemoteFailure) {
        let inputs = inputs();
        let local_error = LocalTransactionProver::default()
            .prove(inputs.clone())
            .unwrap_err();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = if failure != RemoteFailure::Refused {
            let malformed = failure == RemoteFailure::Malformed;
            Some(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                if malformed {
                    stream.write_all(b"not a gRPC response\r\n").await.unwrap();
                } else {
                    std::future::pending::<()>().await;
                }
            }))
        } else {
            drop(listener);
            None
        };
        let prover = RemoteProver::new(&url, Duration::from_millis(100));
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            TransactionProver::prove(&prover, inputs),
        )
        .await
        .expect("remote proving did not reach local fallback within its timeout")
        .unwrap_err();
        assert_eq!(format!("{error:?}"), format!("{local_error:?}"));
        if let Some(server) = server {
            server.abort();
            if let Err(error) = server.await {
                assert!(error.is_cancelled());
            }
        }
    }
}
