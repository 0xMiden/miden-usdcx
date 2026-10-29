use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, ensure, Context};
use clap::{Args, Subcommand};
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

use super::{parse_note_id, HoldsPage, Released, Reply, Request};

const REPLY_LIMIT: u64 = 256 * 1024;
const REPLY_WAIT: Duration = Duration::from_secs(75);

/// Arguments of the `admin` command, which talks to a running attester's admin socket.
#[derive(Debug, Args)]
pub struct AdminArgs {
    /// The running attester's admin socket.
    #[arg(long)]
    socket: PathBuf,
    #[command(subcommand)]
    operation: AdminOperation,
}

/// What the `admin` command asks the attester to do.
#[derive(Debug, Subcommand)]
pub enum AdminOperation {
    /// List held burns and withdrawals.
    Holds {
        /// The `next_after` value printed by the previous page.
        #[arg(long, value_parser = parse_cursor)]
        after: Option<String>,
    },
    /// Persistently stop automatic work for one consumed burn; payment is not confirmed.
    ExcludeBurn {
        #[arg(long, value_parser = parse_cursor)]
        note_id: String,
        /// Immutable reason: 1–256 UTF-8 bytes after trimming, without control characters.
        #[arg(long)]
        reason: String,
    },
    /// Release one hold from the list.
    ReleaseHolds {
        /// Note ID and event sequence from the holds list, separated by a colon.
        #[arg(long, required = true, value_parser = parse_selection)]
        hold: (String, i64),
        /// Confirm you checked that Circle did not accept this withdrawal.
        #[arg(long)]
        circle_not_accepted: bool,
    },
}

/// Checks that a page cursor is a canonical note ID, keeping it as text for the request.
fn parse_cursor(value: &str) -> Result<String, String> {
    parse_note_id(value).map_err(|error| error.to_string())?;
    Ok(value.into())
}

/// Parses a `NOTE_ID:EVENT_SEQ` hold selection, as the holds list prints it.
fn parse_selection(value: &str) -> Result<(String, i64), String> {
    let (id, seq) = value
        .rsplit_once(':')
        .ok_or("hold must be NOTE_ID:EVENT_SEQ")?;
    let id = parse_cursor(id)?;
    let revision: i64 = seq
        .parse()
        .map_err(|_| "event sequence must be a positive integer")?;
    if revision <= 0 {
        return Err("event sequence must be positive".into());
    }
    Ok((id, revision))
}

/// Sends one request and reads its one reply. A lost reply leaves the outcome unknown, so nothing
/// is retried.
async fn exchange<T: DeserializeOwned>(args: &AdminArgs, request: &Request) -> anyhow::Result<T> {
    let mut stream = UnixStream::connect(&args.socket)
        .await
        .context("cannot connect to the admin socket")?;
    let mut line = serde_json::to_vec(request).context("cannot encode admin request")?;
    line.push(b'\n');
    let mut bytes = Vec::new();
    tokio::time::timeout(REPLY_WAIT, async {
        stream.write_all(&line).await?;
        stream.shutdown().await?;
        (&mut stream)
            .take(REPLY_LIMIT + 1)
            .read_to_end(&mut bytes)
            .await
    })
    .await
    .context("admin reply timed out; outcome may be unknown; list holds before another release, or repeat the exact exclude-burn command")?
    .context("admin reply lost; outcome may be unknown; list holds before another release, or repeat the exact exclude-burn command")?;
    ensure!(
        bytes.len() as u64 <= REPLY_LIMIT,
        "admin reply exceeds limit; outcome may be unknown; list holds before another release, or repeat the exact exclude-burn command"
    );
    match serde_json::from_slice(&bytes).context("invalid admin reply")? {
        Reply::Ok(value) => Ok(value),
        Reply::Error(error) => bail!("admin request failed ({}): {}", error.code, error.message),
    }
}

/// Sends one request to the admin socket and prints its answer.
pub(crate) async fn run(args: AdminArgs) -> anyhow::Result<()> {
    match &args.operation {
        AdminOperation::Holds { after } => {
            let request = Request::Holds {
                after: after.clone(),
            };
            let page: HoldsPage = exchange(&args, &request).await?;
            println!(
                "faucet {}\ntrusted anchor {} {}",
                page.faucet_account_id, page.trusted_anchor_block, page.trusted_anchor_commitment
            );
            for hold in page.holds {
                println!(
                    "{}\t{}\t{}\t{}\t{}\tevent_seq={}",
                    hold.note_id,
                    hold.kind,
                    hold.reason,
                    hold.http_status
                        .map_or_else(|| "-".into(), |value| value.to_string()),
                    hold.circle_message.as_deref().unwrap_or("-"),
                    hold.event_seq
                );
            }
            if let Some(after) = page.next_after {
                println!("next_after={after}");
            }
        }
        AdminOperation::ExcludeBurn { note_id, reason } => {
            let request = Request::ExcludeBurn {
                note_id: note_id.clone(),
                reason: reason.clone(),
            };
            exchange::<()>(&args, &request).await?;
            println!(
                "burn {note_id} persistently excluded (survives restart; payment is not confirmed)"
            );
        }
        AdminOperation::ReleaseHolds {
            hold: (note_id, expected_event_seq),
            circle_not_accepted,
        } => {
            let request = Request::Release {
                note_id: note_id.clone(),
                expected_event_seq: *expected_event_seq,
                circle_not_accepted: *circle_not_accepted,
            };
            let released: Released = exchange(&args, &request).await?;
            println!(
                "released burns={} withdrawals={} (release committed; payout is not confirmed)",
                released.burns, released.withdrawals
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Command, Invocation};
    use clap::Parser;

    #[test]
    fn release_selects_one_inspected_revision() {
        let id = format!("0x{}", "11".repeat(32));
        for seq in ["0", "-1", "9223372036854775808", "1.0", "one"] {
            assert!(parse_selection(&format!("{id}:{seq}")).is_err());
        }
        let admin = [
            "xusdc-attester",
            "admin",
            "--socket",
            "/data/attester/admin.sock",
        ];
        let selected = format!("{id}:123");
        let cli = Invocation::try_parse_from(admin.iter().copied().chain([
            "release-holds",
            "--hold",
            &selected,
            "--circle-not-accepted",
        ]))
        .unwrap();
        let Some(Command::Admin(args)) = cli.command else {
            panic!()
        };
        let AdminOperation::ReleaseHolds {
            hold,
            circle_not_accepted,
        } = args.operation
        else {
            panic!()
        };
        assert_eq!(hold, (id.clone(), 123));
        assert!(circle_not_accepted);
        let repeated = format!("{id}:124");
        let repeated = Invocation::try_parse_from(admin.iter().copied().chain([
            "release-holds",
            "--hold",
            &selected,
            "--hold",
            &repeated,
        ]))
        .unwrap_err();
        assert_eq!(repeated.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
