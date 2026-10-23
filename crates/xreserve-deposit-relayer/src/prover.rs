//! Tries remote proving first, then proves the same transaction locally if it fails.

use std::time::Duration;

use miden_client::remote_prover::RemoteTransactionProver;
use miden_client::transaction::{
    LocalTransactionProver, TransactionProver, TransactionProverError,
};
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs, TransactionVerifier};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use tracing::warn;
use url::Url;

/// Proves on the remote prover within `timeout`, and proves the same transaction locally when the
/// remote attempt fails, times out, or returns an invalid proof.
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
            .and_then(|result| result)
            .and_then(|proof| {
                // Batching settles any valid deferred precompiles.
                let _ = TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL)
                    .verify(&proof)
                    .map_err(|error| {
                        TransactionProverError::other_with_source(
                            "remote proof verification failed",
                            error,
                        )
                    })?;
                Ok(proof)
            });
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
    use std::convert::Infallible;

    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::server::conn::http2;
    use hyper::service::service_fn;
    use hyper::Response;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use miden_objects::prost::Message;
    use miden_objects::proto::transaction::ProvenTransaction as ProvenTransactionMessage;
    use miden_objects::{BuildUnchecked, DecodeMessage};
    use miden_protocol::account::{Account, AccountCode, AccountStorage};
    use miden_protocol::asset::AssetVault;
    use miden_protocol::block::BlockHeader;
    use miden_protocol::errors::TransactionVerifierError;
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

    fn remote_transaction() -> ProvenTransactionMessage {
        // Public transaction from a local-node capture, without submission inputs or secrets.
        ProvenTransactionMessage::decode(
            &include_bytes!("../tests/fixtures/proven_transaction.bin")[..],
        )
        .unwrap()
    }

    async fn prove_with_response(
        transaction: ProvenTransactionMessage,
        inputs: TransactionInputs,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        // ProveResponse carries the transaction in protobuf field 1.
        let mut message = vec![0x0a];
        transaction.encode_length_delimited(&mut message).unwrap();
        let mut body = vec![0];
        body.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
        body.extend(message);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                assert_eq!(
                    request.uri().path(),
                    "/miden.remote_prover.v1.ProverService/Prove"
                );
                let body = body.clone();
                async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("content-type", "application/grpc")
                            .header("grpc-status", "0")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                }
            });
            http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });
        let prover = RemoteProver::new(&url, Duration::from_secs(5));
        let result = TransactionProver::prove(&prover, inputs).await;
        server.abort();
        if let Err(error) = server.await {
            assert!(error.is_cancelled());
        }
        result
    }

    #[tokio::test]
    async fn a_valid_remote_proof_is_returned() {
        let transaction = remote_transaction();
        let returned = prove_with_response(transaction.clone(), inputs())
            .await
            .unwrap();
        assert_eq!(ProvenTransactionMessage::from(&returned), transaction);
    }

    #[tokio::test]
    async fn an_invalid_remote_proof_returns_the_local_result() {
        let original_message = remote_transaction();
        let original = original_message
            .clone()
            .decode_fields()
            .unwrap()
            .build_unchecked()
            .unwrap();
        let mut transaction = original_message.clone();
        transaction.proof.as_mut().unwrap().encoded[128] ^= 1;
        let invalid = transaction
            .clone()
            .decode_fields()
            .unwrap()
            .build_unchecked()
            .unwrap();
        assert_eq!(invalid.id(), original.id());
        let mut public_fields = transaction.clone();
        public_fields.proof = original_message.proof.clone();
        assert_eq!(public_fields, original_message);
        assert!(matches!(
            TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&invalid),
            Err(TransactionVerifierError::TransactionVerificationFailed(_))
        ));

        let inputs = inputs();
        let local_error = LocalTransactionProver::default()
            .prove(inputs.clone())
            .unwrap_err();
        let Err(error) = prove_with_response(transaction, inputs).await else {
            panic!("invalid remote proof bypassed local fallback");
        };
        assert_eq!(format!("{error:?}"), format!("{local_error:?}"));
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
