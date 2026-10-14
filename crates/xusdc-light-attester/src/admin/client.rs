use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, ensure, Context};
use clap::{Args, Subcommand};
use reqwest::{Client, Url};

use super::{load_token, parse_note_id, ErrorBody, HoldsPage, ReleaseSelection, Released};

#[derive(Debug, Args)]
pub struct AdminArgs {
    /// Literal loopback HTTP URL of the running attester, with no extra path.
    #[arg(long, value_parser = parse_url)]
    url: Url,
    /// Private file containing the 64-hex-character admin bearer token.
    #[arg(long)]
    token_file: PathBuf,
    #[command(subcommand)]
    operation: AdminOperation,
}

#[derive(Debug, Subcommand)]
pub enum AdminOperation {
    /// List held burns and withdrawals.
    Holds {
        #[arg(long, value_parser = parse_cursor)]
        after: Option<String>,
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

fn parse_cursor(value: &str) -> Result<String, String> {
    parse_note_id(value).map_err(|error| error.to_string())?;
    Ok(value.into())
}

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

fn parse_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "invalid admin URL")?;
    let address: IpAddr = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.into(),
        Some(url::Host::Ipv6(ip)) => ip.into(),
        _ => return Err("admin URL requires a literal loopback address".into()),
    };
    if url.scheme() != "http"
        || !address.is_loopback()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "admin URL must be loopback HTTP without credentials, extra path, query or fragment"
                .into(),
        );
    }
    Ok(url)
}

pub(crate) async fn run(args: AdminArgs) -> anyhow::Result<()> {
    let token = hex::encode(load_token(&args.token_file)?);
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(75))
        .build()
        .context("cannot initialize admin client")?;
    let listing = matches!(args.operation, AdminOperation::Holds { .. });
    let request = match args.operation {
        AdminOperation::Holds { after } => {
            let mut url = args.url.join("admin/attester/holds")?;
            if let Some(after) = after {
                url.query_pairs_mut().append_pair("after", &after);
            }
            client.get(url)
        }
        AdminOperation::ReleaseHolds {
            hold: (note_id, expected_event_seq),
            circle_not_accepted,
        } => client
            .post(args.url.join("admin/attester/holds/release")?)
            .json(&ReleaseSelection {
                note_id,
                expected_event_seq,
                circle_not_accepted,
            }),
    };
    let mut response = request
        .bearer_auth(token)
        .send()
        .await
        .context("admin request failed; list holds before selecting another release")?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("admin reply lost; list holds before selecting another release")?
    {
        ensure!(
            bytes.len() + chunk.len() <= 256 * 1024,
            "admin response exceeds limit; list holds before selecting another release"
        );
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let error: ErrorBody =
            serde_json::from_slice(&bytes).context("invalid admin error response")?;
        bail!(
            "admin request failed ({status}, {}): {}",
            error.code,
            error.message
        );
    }
    if listing {
        let page: HoldsPage = serde_json::from_slice(&bytes).context("invalid holds response")?;
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
    } else {
        let released: Released =
            serde_json::from_slice(&bytes).context("invalid release response")?;
        println!(
            "released burns={} withdrawals={} (release committed; payout is not confirmed)",
            released.burns, released.withdrawals
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Command, Invocation};
    use clap::Parser;

    #[test]
    fn client_commands_accept_only_local_literal_urls_and_inspected_revisions() {
        for url in ["http://127.0.0.1:8090", "http://[::1]:8090/"] {
            assert!(matches!(
                Invocation::try_parse_from([
                    "xusdc-attester",
                    "admin",
                    "--url",
                    url,
                    "--token-file",
                    "private-token",
                    "holds"
                ])
                .unwrap()
                .command,
                Some(Command::Admin(_))
            ));
        }
        for url in [
            "https://127.0.0.1:8090",
            "http://localhost:8090",
            "http://192.0.2.1:8090",
            "http://user@127.0.0.1:8090",
            "http://127.0.0.1:8090/path",
            "http://127.0.0.1:8090/?x=1",
            "http://127.0.0.1:8090/#x",
        ] {
            assert!(parse_url(url).is_err());
        }
        let id = format!("0x{}", "11".repeat(32));
        for seq in ["0", "-1", "9223372036854775808", "1.0", "one"] {
            assert!(parse_selection(&format!("{id}:{seq}")).is_err());
        }
        let cli = Invocation::try_parse_from([
            "xusdc-attester",
            "admin",
            "--url",
            "http://127.0.0.1:8090",
            "--token-file",
            "private-token",
            "release-holds",
            "--hold",
            &format!("{id}:123"),
            "--circle-not-accepted",
        ])
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
        let repeated = Invocation::try_parse_from([
            "xusdc-attester",
            "admin",
            "--url",
            "http://127.0.0.1:8090",
            "--token-file",
            "private-token",
            "release-holds",
            "--hold",
            &format!("{id}:123"),
            "--hold",
            &format!("{id}:124"),
        ])
        .unwrap_err();
        assert_eq!(repeated.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
