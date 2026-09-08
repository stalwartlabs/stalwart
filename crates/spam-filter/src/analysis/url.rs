/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ElementLocation, is_trusted_domain, is_url_redirector};
use crate::modules::dnsbl::check_dnsbl;
use crate::modules::expression::StringResolver;
use crate::modules::html::SRC;
use crate::{
    Hostname, SpamFilterContext, TextPart,
    analysis::to_lowercase_cow,
    modules::html::{A, HREF, HtmlToken},
};
use common::Server;
use common::config::mailstore::spamfilter::{Element, IpResolver, Location};
use common::scripts::IsMixedCharset;
use common::scripts::functions::unicode::CharUtils;
use hyper::{Uri, header::LOCATION};
use nlp::tokenizers::types::TokenType;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::{borrow::Cow, future::Future, time::Duration};

const HTTPS_SCHEME: &str = "https://";

pub trait SpamFilterAnalyzeUrl: Sync + Send {
    fn spam_filter_analyze_url(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

#[derive(Clone, Debug)]
pub struct UrlParts<'x> {
    pub url: String,
    pub url_original: Cow<'x, str>,
    pub url_parsed: Option<UrlParsed>,
    pub has_scheme: bool,
}

#[derive(Clone, Debug)]
pub struct UrlParsed {
    pub parts: Uri,
    pub host: Hostname,
}

impl SpamFilterAnalyzeUrl for Server {
    async fn spam_filter_analyze_url(&self, ctx: &mut SpamFilterContext<'_>) {
        // Extract URLs
        let mut urls = collect_urls(ctx);

        if !ctx.input.is_train {
            let mut redirected_urls = HashSet::new();
            let mut has_zwsp = false;
            let mut has_suspicious = false;
            let mut trusted_domains: HashSet<String> = HashSet::new();

            {
                let mut checked_domains: HashSet<&str> = HashSet::new();
                for url in &urls {
                    if let Some(url_parsed) = &url.element.url_parsed {
                        let host_sld = url_parsed.host.sld_or_default();
                        if checked_domains.insert(host_sld)
                            && is_trusted_domain(self, host_sld, ctx.input.span_id).await
                        {
                            trusted_domains.insert(host_sld.into());
                        }
                    }
                }
            }

            for url in &urls {
                if !(has_zwsp && has_suspicious) && !url.element.url.is_ascii() {
                    for ch in url.element.url.chars() {
                        if ch.is_zwsp() {
                            has_zwsp = true;
                            ctx.result.add_tag("ZERO_WIDTH_SPACE_URL");
                        }

                        if ch.is_obscured() {
                            has_suspicious = true;
                            ctx.result.add_tag("SUSPICIOUS_URL");
                        }
                    }
                }

                // Skip non-URLs such as 'data:' and 'mailto:'
                if !url.element.url.contains("://") {
                    continue;
                }

                // Obtain parse url
                let url_parsed = if let Some(url_parsed) = &url.element.url_parsed {
                    url_parsed
                } else {
                    // URL could not be parsed
                    ctx.result.add_tag("UNPARSABLE_URL");
                    continue;
                };
                let host_sld = url_parsed.host.sld_or_default();

                // Skip local and trusted domains
                if trusted_domains.contains(host_sld) {
                    continue;
                }

                if let Some(ip) = url_parsed.host.ip {
                    // Check IP DNSBL
                    check_dnsbl(self, ctx, &IpResolver::new(ip), Element::Ip, url.location).await;
                } else if is_url_redirector(self, host_sld, ctx.input.span_id).await {
                    // Check for redirectors
                    ctx.result.add_tag("REDIRECTOR_URL");

                    if !ctx.result.has_tag("URL_REDIRECTOR_NESTED") {
                        let mut redirect_count = 1;
                        let mut url_redirect = Cow::Borrowed(url.element.url.as_str());

                        while redirect_count <= 3 {
                            match http_get_header(
                                self,
                                url_redirect.as_ref(),
                                LOCATION,
                                Duration::from_secs(5),
                            )
                            .await
                            {
                                Ok(Some(location)) => {
                                    let location = UrlParts::new(location);
                                    if let Some(location_parsed) = &location.url_parsed {
                                        if is_url_redirector(
                                            self,
                                            location_parsed.host.sld_or_default(),
                                            ctx.input.span_id,
                                        )
                                        .await
                                        {
                                            url_redirect = Cow::Owned(location.url);
                                            redirect_count += 1;
                                            continue;
                                        } else {
                                            if is_trusted_domain(
                                                self,
                                                location_parsed.host.sld_or_default(),
                                                ctx.input.span_id,
                                            )
                                            .await
                                            {
                                                trusted_domains.insert(
                                                    location_parsed.host.sld_or_default().into(),
                                                );
                                            }

                                            redirected_urls.insert(ElementLocation::new(
                                                location,
                                                url.location,
                                            ));
                                        }
                                    }
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    trc::error!(err.span_id(ctx.input.span_id));
                                }
                            }
                            break;
                        }

                        if redirect_count > 3 {
                            ctx.result.add_tag("URL_REDIRECTOR_NESTED");
                        }
                    }
                }
            }

            urls.extend(redirected_urls);

            for (el, url_parsed) in urls.iter().filter_map(|el| {
                el.element
                    .url_parsed
                    .as_ref()
                    .map(|url_parsed| (el, url_parsed))
            }) {
                let host = &url_parsed.host;
                let is_explicit_link = el.element.is_explicit_link();

                if host.ip.is_none() {
                    if !host.fqdn.is_ascii() {
                        if let Ok(cured_host) =
                            decancer::cure(&host.fqdn, decancer::Options::default())
                        {
                            let cured_host = cured_host.to_string();
                            if cured_host != host.fqdn
                                && matches!(self.dns_exists_ip(&cured_host).await, Ok(true))
                            {
                                ctx.result.add_tag("HOMOGRAPH_URL");
                            }
                        }

                        if host.fqdn.is_mixed_charset() {
                            ctx.result.add_tag("MIXED_CHARSET_URL");
                        }
                    }

                    // Check Domain DNSBL
                    if is_explicit_link
                        && let Some(sld) = &host.sld
                        && !trusted_domains.contains(sld.as_str())
                    {
                        check_dnsbl(
                            self,
                            ctx,
                            &StringResolver(sld),
                            Element::Domain,
                            el.location,
                        )
                        .await;
                    }
                } else {
                    // URL is an ip address
                    ctx.result.add_tag("SUSPICIOUS_URL");
                }

                // Check URL DNSBL
                if is_explicit_link {
                    check_dnsbl(self, ctx, &el.element, Element::Url, el.location).await;
                }
            }
        }

        // Update context
        ctx.output.urls = urls;
    }
}

pub fn collect_urls(
    ctx: &mut SpamFilterContext<'_>,
) -> HashSet<ElementLocation<UrlParts<'static>>> {
    let mut urls: HashSet<ElementLocation<UrlParts<'static>>> = HashSet::new();
    let mut inferred_urls: HashSet<ElementLocation<UrlParts<'static>>> = HashSet::new();
    for token in &ctx.output.subject_tokens {
        if let TokenType::Url(url) | TokenType::UrlNoScheme(url) = token {
            collect_url(
                &mut urls,
                &mut inferred_urls,
                url.as_ref(),
                Location::HeaderSubject,
            );
        }
    }
    for (part_id, part) in ctx.output.text_parts.iter().enumerate() {
        let part_id = part_id as u32;
        let is_body = ctx.input.message.text_body.contains(&part_id)
            || ctx.input.message.html_body.contains(&part_id);
        let text_location = if is_body {
            Location::BodyText
        } else {
            Location::Attachment
        };

        let tokens = match part {
            TextPart::Plain { tokens, .. } => tokens,
            TextPart::Html {
                html_tokens,
                tokens,
                ..
            } => {
                for token in html_tokens {
                    if let HtmlToken::StartTag { attributes, .. } = token {
                        for (attr, value) in attributes {
                            match value {
                                Some(value) if [HREF, SRC].contains(attr) => {
                                    let value = value.trim();
                                    if !urls.contains(to_lowercase_cow(value).as_ref()) {
                                        urls.insert(ElementLocation::new(
                                            UrlParts::new(value.to_string()),
                                            if is_body {
                                                Location::BodyHtml
                                            } else {
                                                Location::Attachment
                                            },
                                        ));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                tokens
            }
            TextPart::None => &[][..],
        };

        for token in tokens {
            match token {
                TokenType::Url(url) | TokenType::UrlNoScheme(url) => {
                    if !ctx.input.is_train
                        && is_body
                        && !ctx.result.has_tag("RCPT_DOMAIN_IN_BODY")
                        && let Some(url_parsed) = &url.url_parsed
                    {
                        let host = url_parsed.host.sld_or_default();
                        for rcpt in ctx.output.all_recipients() {
                            if rcpt.email.domain_part.sld_or_default() == host {
                                ctx.result.add_tag("RCPT_DOMAIN_IN_BODY");
                                break;
                            }
                        }
                    }

                    collect_url(&mut urls, &mut inferred_urls, url.as_ref(), text_location);
                }
                _ => {}
            }
        }

        if is_body && !ctx.input.is_train {
            let is_single = match part {
                TextPart::Plain { tokens, .. } => is_single_url(tokens),
                TextPart::Html {
                    html_tokens,
                    tokens,
                    ..
                } => is_single_html_url(html_tokens, tokens),
                TextPart::None => false,
            };

            if is_single {
                ctx.result.add_tag("URL_ONLY");
            }
        }
    }

    urls.extend(inferred_urls);

    urls
}

#[allow(unreachable_code)]
#[allow(unused_variables)]
async fn http_get_header(
    server: &Server,
    url: &str,
    header: hyper::header::HeaderName,
    timeout: Duration,
) -> trc::Result<Option<String>> {
    #[cfg(feature = "test_mode")]
    {
        return if url.contains("redirect.") {
            Ok(url.split_once("/?").unwrap().1.to_string().into())
        } else {
            Ok(None)
        };
    }
    server
        .core
        .spam
        .url_client
        .get(url)
        .timeout(timeout)
        .send()
        .await
        .map_err(|err| {
            trc::SieveEvent::RuntimeError
                .into_err()
                .reason(err)
                .details("Failed to send request")
        })
        .map(|response| {
            response
                .headers()
                .get(header)
                .and_then(|h| h.to_str().ok())
                .map(|h| h.to_string())
        })
}

fn collect_url(
    urls: &mut HashSet<ElementLocation<UrlParts<'static>>>,
    inferred_urls: &mut HashSet<ElementLocation<UrlParts<'static>>>,
    url: &UrlParts<'_>,
    location: Location,
) {
    let urls = if url.is_explicit_link() {
        urls
    } else {
        inferred_urls
    };

    if !urls.contains(url.url.as_str()) {
        urls.insert(ElementLocation::new(url.to_owned(), location));
    }
}

fn is_single_url<T, E, U, I>(tokens: &[TokenType<T, E, U, I>]) -> bool {
    let mut url_count = 0;
    let mut word_count = 0;

    for token in tokens {
        match token {
            TokenType::Alphabetic(_)
            | TokenType::Alphanumeric(_)
            | TokenType::Integer(_)
            | TokenType::Email(_)
            | TokenType::Float(_) => {
                word_count += 1;
            }
            TokenType::Url(_) | TokenType::UrlNoScheme(_) => {
                url_count += 1;
            }
            _ => {}
        }
    }

    url_count == 1 && word_count <= 1
}

fn is_single_html_url<T, E, U, I>(
    html_tokens: &[HtmlToken<'_>],
    tokens: &[TokenType<T, E, U, I>],
) -> bool {
    let mut url_count = 0;
    let mut word_count = 0;

    for token in tokens {
        match token {
            TokenType::Alphabetic(_)
            | TokenType::Alphanumeric(_)
            | TokenType::Integer(_)
            | TokenType::Email(_)
            | TokenType::Float(_) => {
                word_count += 1;
            }
            TokenType::Url(_) | TokenType::UrlNoScheme(_) => {
                url_count += 1;
            }
            _ => {}
        }
    }

    if word_count > 1 || url_count != 1 {
        return false;
    }

    url_count = 0;

    for token in html_tokens {
        if matches!(token, HtmlToken::StartTag { name, attributes, .. } if *name == A && attributes.iter().any(|(k, _)| *k == HREF))
        {
            url_count += 1;
        }
    }

    url_count == 1
}

impl PartialEq for UrlParts<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Eq for UrlParts<'_> {}

impl Hash for UrlParts<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

impl<'x> UrlParts<'x> {
    pub fn new(url: impl Into<Cow<'x, str>>) -> Self {
        let url_original = url.into();
        let url = url_original.trim().to_lowercase();

        Self {
            url_parsed: Self::parse(&url),
            url,
            url_original,
            has_scheme: true,
        }
    }

    pub fn no_scheme(url: impl Into<Cow<'x, str>>) -> Self {
        let url_original = url.into();
        let trimmed = url_original.trim();
        let mut url = String::with_capacity(HTTPS_SCHEME.len() + trimmed.len());
        url.push_str(HTTPS_SCHEME);
        if trimmed.is_ascii() {
            url.push_str(trimmed);
            url.make_ascii_lowercase();
        } else {
            url.push_str(&trimmed.to_lowercase());
        }

        Self {
            url_parsed: Self::parse(&url),
            url,
            url_original,
            has_scheme: false,
        }
    }

    pub fn is_explicit_link(&self) -> bool {
        self.has_scheme
            || self.url_original.contains(['/', '?'])
            || self
                .url_parsed
                .as_ref()
                .is_some_and(|url| url.host.fqdn.starts_with("www."))
    }

    fn parse(url: &str) -> Option<UrlParsed> {
        match url.as_bytes().first() {
            None | Some(b'/') => return None,
            _ => {}
        }

        url.parse::<Uri>().ok().and_then(|parts| {
            parts
                .host()
                .map(Hostname::new)
                .map(|host| UrlParsed { host, parts })
        })
    }

    pub fn to_owned(&self) -> UrlParts<'static> {
        UrlParts {
            url: self.url.clone(),
            url_original: Cow::Owned(self.url_original.clone().into_owned()),
            url_parsed: self.url_parsed.clone(),
            has_scheme: self.has_scheme,
        }
    }
}
