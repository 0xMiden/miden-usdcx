use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;

use xusdc_attester::chain::MidenChainReader;
use xusdc_attester::circle::ReqwestTransport;
use xusdc_attester::config::Config;
use xusdc_attester::Attester;

const STARTUP_FAILED: u8 = 1;
const CONFIG_FAILED: u8 = 2;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let config_path = match config_path_from_args() {
        Ok(path) => path,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(CONFIG_FAILED);
        }
    };

    let config = match Config::load(&config_path) {
        Ok(config) => config,
        Err(error) => {
            report_error(&format!("failed to load {}", config_path.display()), &error);
            return ExitCode::from(CONFIG_FAILED);
        }
    };
    let circle_transport = match ReqwestTransport::new() {
        Ok(transport) => transport,
        Err(error) => {
            report_error("failed to initialize Circle HTTP client", &error);
            return ExitCode::from(STARTUP_FAILED);
        }
    };

    match Attester::start(
        config,
        Box::new(MidenChainReader::devnet()),
        Box::new(circle_transport),
    )
    .await
    {
        Ok(_attester) => {
            println!("startup preflight passed; the attester loop is not implemented yet");
            ExitCode::SUCCESS
        }
        Err(error) => {
            report_error("startup failed", &error);
            ExitCode::from(STARTUP_FAILED)
        }
    }
}

fn report_error(context: &str, error: &dyn Error) {
    eprintln!("{context}: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("caused by: {cause}");
        source = cause.source();
    }
}

fn config_path_from_args() -> Result<PathBuf, &'static str> {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    if args.next().is_some() {
        Err("usage: xusdc-attester [CONFIG_PATH]")
    } else {
        Ok(path)
    }
}
