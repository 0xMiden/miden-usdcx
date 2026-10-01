use anyhow::{Context, Result};
use clap::Parser;
use miden_protocol::block::BlockNumber;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use xusdc_attester::attester::{list_holds, release_holds};
use xusdc_attester::config::{
    parse_faucet_account_id, parse_note_ids, parse_trusted_anchor_commitment, Command, Config,
    Invocation,
};
use xusdc_attester::service::AttesterService;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    init_tracing();
    let invocation = Invocation::parse();
    if let Some(Command::ReleaseHolds {
        store_path,
        faucet_account_id,
        trusted_anchor_block,
        trusted_anchor_commitment,
        note_id,
        note_ids_file,
    }) = invocation.command
    {
        let faucet_account_id = parse_faucet_account_id(&faucet_account_id)?;
        let trusted_anchor_commitment =
            parse_trusted_anchor_commitment(&trusted_anchor_commitment)?;
        let store_path = std::path::Path::new(&store_path);
        let anchor_block = BlockNumber::from(trusted_anchor_block);
        if note_id.is_empty() && note_ids_file.is_none() {
            let holds = list_holds(
                store_path,
                faucet_account_id,
                anchor_block,
                trusted_anchor_commitment,
            )
            .context("failed to list held burns and withdrawals")?;
            for hold in holds {
                println!("{hold}");
            }
            return Ok(());
        }
        let note_ids = parse_note_ids(&note_id, note_ids_file.as_deref())?;
        let (burns, withdrawals) = release_holds(
            store_path,
            faucet_account_id,
            anchor_block,
            trusted_anchor_commitment,
            &note_ids,
        )
        .context("failed to release held burns and withdrawals")?;
        info!(burns, withdrawals, "released held burns and withdrawals");
        return Ok(());
    }
    let config = Config::try_from(invocation.run.context("missing run arguments")?)
        .context("invalid configuration")?;
    let miden_rpc_url = config.miden_rpc_url().clone();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;
    let shutdown = CancellationToken::new();
    let signal_token = shutdown.clone();
    let signal_task = tokio::spawn(async move {
        tokio::select! {
            Some(()) = sigterm.recv() => {}
            Ok(()) = tokio::signal::ctrl_c() => {}
            else => return,
        }
        signal_token.cancel();
    });
    let result = async {
        let service = AttesterService::start(config).await?;
        warn!(%miden_rpc_url, "attester started");
        service.run(shutdown).await
    }
    .await;
    signal_task.abort();
    result
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        .init();
}
