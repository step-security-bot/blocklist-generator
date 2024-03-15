use askama::Template;
use humansize::{format_size, DECIMAL};
use log::{error, info};
use serde::Deserialize;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};
use url::Host;

#[derive(Deserialize)]
pub struct Blocklists {
    pub hosts_file_blocklist_urls: Vec<String>,
    pub domain_blocklist_urls: Vec<String>,
}

#[derive(Deserialize)]
struct Config {
    blocklists: Blocklists,
}

pub fn get_blocklists_from_config_file<P: AsRef<Path>>(config_file_path: P) -> Blocklists {
    let config_file_content =
        fs::read_to_string(config_file_path).expect("Unable to open or read config file");
    let config: Config = toml::from_str(&config_file_content).expect("Unable to parse TOML config");

    let Config { blocklists } = config;

    blocklists
}

#[derive(Template)]
#[template(escape = "none", path = "blocklist.rpz")]
struct BlocklistRPZTemplate<'a> {
    domains: &'a str,
}

fn domain_to_blocklist_rpz_domain(host: &Host) -> String {
    let domain = host.to_string();
    format!("{domain}\tCNAME\t.\n*.{domain}\tCNAME\t.\n")
}

fn write_to_file<P: AsRef<Path>>(content: &str, output_path: &P) {
    let output_display_path = output_path.as_ref().display().to_string();
    let Ok(mut outfile) = File::create(output_path) else {
        error!("Unable to create output file");
        panic!("Error creating output file {output_display_path}")
    };
    if outfile.write_all(content.as_bytes()).is_err() {
        error!("Unable to write to output file {output_display_path}");
        panic!("Error writing to output file");
    }
    info!("Wrote data to file: {output_display_path}");
}

pub fn write_blocklist_rpz_file(blocklist_domains: &[Host]) {
    let domains = blocklist_domains
        .iter()
        .fold(String::new(), |mut acc, val| {
            acc.push_str(&domain_to_blocklist_rpz_domain(val));
            acc
        });
    let template = BlocklistRPZTemplate { domains: &domains };
    let file_content = template
        .render()
        .expect("Unexpected error rendering template");
    let output_path = PathBuf::from("./blocklist.rpz");
    write_to_file(&file_content, &output_path);
    if let Ok(value) = fs::metadata(&output_path) {
        let bytes = value.len();
        let display_bytes = format_size(bytes, DECIMAL);
        let display_path = output_path.display();
        std::println!("Written {display_bytes} to {display_path}");
    }
}
