/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::network::acme::{AcmeError, AcmeResult};
use chrono::{DateTime, Utc};
use hyper::{
    Method, StatusCode,
    header::{CONTENT_TYPE, USER_AGENT},
};
use reqwest::Response;
use std::time::Duration;

#[allow(unused_mut)]
pub(crate) async fn https(
    url: impl AsRef<str>,
    method: Method,
    body: Option<String>,
    max_retries: u32,
) -> AcmeResult<Response> {
    let url = url.as_ref();
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .http1_only();

    #[cfg(any(feature = "dev_mode", feature = "test_mode"))]
    {
        builder = builder.danger_accept_invalid_certs(
            url.starts_with("https://localhost") || url.starts_with("https://127.0.0.1"),
        );
    }

    let mut request = builder
        .build()?
        .request(method, url)
        .header(USER_AGENT, crate::USER_AGENT);

    if let Some(body) = body {
        request = request
            .header(CONTENT_TYPE, "application/jose+json")
            .body(body);
    }

    let response = request.send().await?;
    if response.status().is_success() {
        Ok(response)
    } else if matches!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
    ) {
        Err(AcmeError::Backoff {
            wait: parse_retry_after(&response),
            max_retries,
        })
    } else {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        Err(AcmeError::HttpStatus(format!(
            "Unexpected status {}: {}",
            status, text
        )))
    }
}

pub(crate) fn get_header(response: &Response, header: &'static str) -> AcmeResult<String> {
    match response.headers().get_all(header).iter().next_back() {
        Some(value) => Ok(value
            .to_str()
            .map_err(|err| {
                AcmeError::Invalid(format!("Failed to read header {}: {}", header, err))
            })?
            .to_string()),
        None => Err(AcmeError::Invalid(format!("Missing header: {}", header))),
    }
}

pub(crate) fn parse_alternate_links(response: &Response) -> Vec<String> {
    alternate_links(
        response
            .headers()
            .get_all("Link")
            .iter()
            .filter_map(|value| value.to_str().ok()),
    )
}

fn alternate_links<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut urls = Vec::new();
    for value in values {
        for link in value.split(',') {
            let mut url = None;
            let mut is_alternate = false;
            for (index, part) in link.split(';').enumerate() {
                let part = part.trim();
                if index == 0 {
                    url = part
                        .strip_prefix('<')
                        .and_then(|part| part.strip_suffix('>'));
                } else if let Some(rel) = part.strip_prefix("rel=") {
                    is_alternate = rel.trim_matches('"') == "alternate";
                }
            }
            if is_alternate && let Some(url) = url {
                urls.push(url.to_string());
            }
        }
    }
    urls
}

pub(crate) fn parse_retry_after(response: &Response) -> Option<Duration> {
    let value = response.headers().get("Retry-After")?.to_str().ok()?;
    if let Ok(secs) = value.parse::<u64>() {
        Some(Duration::from_secs(secs + 1))
    } else if let Ok(dt) = DateTime::parse_from_rfc2822(value) {
        Utc::now()
            .signed_duration_since(dt.with_timezone(&Utc))
            .to_std()
            .map(|dur| dur + Duration::from_secs(1))
            .ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::alternate_links;

    #[test]
    fn parses_single_alternate_link() {
        let links =
            alternate_links([r#"<https://acme.example/cert/1/1>;rel="alternate""#].into_iter());
        assert_eq!(links, vec!["https://acme.example/cert/1/1".to_string()]);
    }

    #[test]
    fn parses_multiple_alternates_in_one_header() {
        let links = alternate_links(
            [r#"<https://acme.example/cert/1/1>;rel="alternate", <https://acme.example/cert/1/2>;rel="alternate""#]
                .into_iter(),
        );
        assert_eq!(
            links,
            vec![
                "https://acme.example/cert/1/1".to_string(),
                "https://acme.example/cert/1/2".to_string(),
            ]
        );
    }

    #[test]
    fn parses_alternates_across_multiple_headers() {
        let links = alternate_links(
            [
                r#"<https://acme.example/cert/1/1>;rel="alternate""#,
                r#"<https://acme.example/cert/1/2>;rel="alternate""#,
            ]
            .into_iter(),
        );
        assert_eq!(
            links,
            vec![
                "https://acme.example/cert/1/1".to_string(),
                "https://acme.example/cert/1/2".to_string(),
            ]
        );
    }

    #[test]
    fn ignores_non_alternate_relations() {
        let links = alternate_links(
            [r#"<https://acme.example/index>;rel="index", <https://acme.example/cert/1/1>;rel="alternate""#]
                .into_iter(),
        );
        assert_eq!(links, vec!["https://acme.example/cert/1/1".to_string()]);
    }

    #[test]
    fn tolerates_unquoted_rel_and_extra_whitespace() {
        let links =
            alternate_links([r#" <https://acme.example/cert/1/1> ; rel=alternate "#].into_iter());
        assert_eq!(links, vec!["https://acme.example/cert/1/1".to_string()]);
    }

    #[test]
    fn returns_empty_when_no_alternates() {
        let links = alternate_links([r#"<https://acme.example/dir>;rel="index""#].into_iter());
        assert!(links.is_empty());
    }
}
