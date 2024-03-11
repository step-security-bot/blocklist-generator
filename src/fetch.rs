use crate::parse::{domainlist as parse_domainlist, hostfile as parse_hostfile};
use log::info;
use std::{collections::HashSet, error::Error};
use url::Host;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Error fetching blocklist `{url}`: only received part of the file.  The network connection may be unstable.")]
    IncompleteBody { url: String },

    #[error("Error fetching blocklist `{url}`: no response data or incomplete data.  The network connection may be unstable.")]
    FetchBody { url: String },

    #[error(
        "Error parsing fetched data for blocklist `{url}`.  It might be worth retrying later."
    )]
    FetchParse { url: String },

    #[error("Error fetching blocklist `{url}`: error requesting data.  The URL might be invalid, or there might be a network issue.")]
    FetchRequest { url: String },

    #[error("Error fetching blocklist `{url}`.  Check the URL is correct an connection is up.")]
    Fetch { url: String },
}

pub struct Client {
    client: reqwest::Client,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            client: reqwest::Client::new(),
        }
    }
}

impl Client {
    fn handle_fetch_error(url: &str, error: &reqwest::Error) -> AppError {
        log::error!("{error}");
        if error.is_body() {
            if let Some(hyper_error) = error.source().unwrap().downcast_ref::<hyper::Error>() {
                if hyper_error.is_incomplete_message() {
                    return AppError::IncompleteBody { url: url.into() };
                }
            } else {
                return AppError::FetchBody { url: url.into() };
            };
        }
        if error.is_request() {
            return AppError::FetchRequest { url: url.into() };
        }
        AppError::Fetch { url: url.into() }
    }

    async fn get_html_body(&self, url: &str) -> Result<String, AppError> {
        let response = match self.client.get(url).send().await {
            Ok(value) => value,
            Err(error) => return Err(Client::handle_fetch_error(url, &error)),
        };

        match response.text().await {
            Ok(value) => Ok(value),
            Err(_) => Err(AppError::FetchParse { url: url.into() }),
        }
    }

    pub async fn domainlist(&self, url: &str, set: &mut HashSet<Host>) -> Result<(), AppError> {
        info!("Fetching hostfile: {url}");
        let body = self.get_html_body(url).await?;
        info!("Fetched!");
        parse_domainlist(&body, set);
        Ok(())
    }

    pub async fn hostfile(&self, url: &str, set: &mut HashSet<Host>) -> Result<(), AppError> {
        info!("Fetching hostfile: {url}");
        let body = self.get_html_body(url).await?;
        info!("Fetched!");
        parse_hostfile(&body, set);
        Ok(())
    }
}
