//! Read-only credential-path check: DescribeKey and GetPublicKey, never Sign.
use std::time::Duration;
use usdcx_kms_signer::{KmsSigner, Signer};

#[tokio::main]
async fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.len() != 2 {
        eprintln!("usage: inspect_key <region> <immutable-key-arn>");
        std::process::exit(2);
    }
    let result = async {
        let client = KmsSigner::client(&arguments[0], Duration::from_secs(10)).await;
        let signer = KmsSigner::connect(client, &arguments[1]).await?;
        signer.public_key().await?.address()
    }
    .await;
    match result {
        Ok(address) => println!("KMS_READ_ONLY_KEY_VERIFIED {address}"),
        Err(_) => {
            eprintln!(
                "KMS read-only verification failed; check credential session, role and key pins"
            );
            std::process::exit(1);
        }
    }
}
