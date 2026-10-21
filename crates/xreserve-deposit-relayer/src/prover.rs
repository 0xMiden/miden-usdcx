//! Bounds connection setup and proving without changing the SDK's submission path.

use std::time::Duration;

use miden_client::remote_prover::{RemoteProverClientError, RemoteTransactionProver};
use miden_client::transaction::{TransactionProver, TransactionProverError};
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use url::Url;

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
        tokio::time::timeout(self.timeout, self.inner.prove(&inputs))
            .await
            .map_err(|error| {
                TransactionProverError::other_with_source("remote proving timed out", error)
            })?
    }
}

pub(crate) fn is_remote_transport_error(error: &TransactionProverError) -> bool {
    let TransactionProverError::Other {
        source: Some(source),
        ..
    } = error
    else {
        return false;
    };
    source.is::<RemoteProverClientError>()
        || source.is::<tokio::time::error::Elapsed>()
        || source
            .downcast_ref::<tonic::Status>()
            .is_some_and(|status| {
                matches!(
                    status.code(),
                    tonic::Code::Unavailable
                        | tonic::Code::DeadlineExceeded
                        | tonic::Code::Cancelled
                )
            })
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

    #[rstest]
    #[case::refused(false)]
    #[case::silent(true)]
    #[tokio::test]
    async fn an_unavailable_prover_fails_within_the_deadline(#[case] accepts: bool) {
        let inputs = inputs();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = if accepts {
            Some(tokio::spawn(async move {
                let (_stream, _) = listener.accept().await.unwrap();
                std::future::pending::<()>().await;
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
        .expect("remote proving exceeded its timeout")
        .unwrap_err();
        assert!(is_remote_transport_error(&error), "{error:?}");
        if accepts {
            assert!(
                matches!(&error, TransactionProverError::Other { source: Some(source), .. }
                if source.is::<tokio::time::error::Elapsed>()),
                "{error:?}"
            );
        }
        if let Some(server) = server {
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
        }
    }
}
