#![warn(clippy::all, clippy::pedantic)]

mod fetch;
mod file_system;
mod parse;

use clap::Parser;
use fetch::Client as FetchClient;
use file_system::{get_blocklists_from_config_file, write_blocklist_rpz_file, Blocklists};
use log::warn;
use num_format::{Locale, ToFormattedString};
use std::{collections::HashSet, path::PathBuf, process};
use url::Host;

#[derive(Parser)]
#[clap(author,version,about,long_about=None)]
struct Cli {
    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    /// Config file path (default: ./blocklist-generator.toml)
    #[clap(short, long, value_parser)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = &Cli::parse();
    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

    let default_config_path = PathBuf::from("blocklist-generator.toml");
    let config_path = match &cli.config {
        Some(value) => value,
        None => &default_config_path,
    };

    let Blocklists {
        hostfile_blocklist_urls,
        domain_blocklist_urls,
    } = get_blocklists_from_config_file(config_path);

    let fetch_client = FetchClient::default();
    let mut set: HashSet<Host> = HashSet::new();
    for url in hostfile_blocklist_urls {
        match fetch_client.hostfile(&url, &mut set).await {
            Ok(()) => {}
            Err(error) => {
                log::error!("{error}");
                eprintln!("[ ERROR ]: {error}");
                process::exit(1);
            }
        }
    }
    for url in domain_blocklist_urls {
        if let Err(error) = fetch_client.domainlist(&url, &mut set).await {
            log::error!("{error}");
            return Err(error.into());
        };
    }
    set.remove(&Host::parse("0.0.0.0").unwrap());
    set.remove(&Host::parse("127.0.0.1").unwrap());
    set.remove(&Host::parse("255.255.255.255").unwrap());

    let mut result: Vec<Host> = set.into_iter().collect();
    result.sort();

    write_blocklist_rpz_file(&result);

    println!("{} results", result.len().to_formatted_string(&Locale::en));
    Ok(())
}
