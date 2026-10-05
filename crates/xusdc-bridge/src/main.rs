mod config;
mod supervisor;

use std::ffi::OsString;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.len() == 2 && (args[1] == "--help" || args[1] == "-h") {
        return config::print_help();
    }
    if args.len() == 2 && (args[1] == "--version" || args[1] == "-V") {
        println!("xusdc-bridge {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let config = match config::Config::parse_from(args) {
        Ok(config) => config,
        Err(error) => {
            if let Some(error) = error.downcast_ref::<clap::Error>() {
                error.exit();
            }
            return Err(error);
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_writer(std::io::stdout)
        .init();
    let signals = supervisor::Signals::install()?;
    supervisor::run(config, signals).await
}
