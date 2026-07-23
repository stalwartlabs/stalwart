/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

pub mod bimap;
pub mod cache;
pub mod chained_bytes;
pub mod cheeky_hash;
pub mod codec;
pub mod cron;
pub mod glob;
pub mod http;
pub mod map;
pub mod snowflake;
pub mod template;
pub mod tls;
pub mod topological;
pub mod url_params;

use compact_str::ToCompactString;
use futures::StreamExt;
pub use reqwest::Client;
use reqwest::Response;
pub use reqwest::header::HeaderMap;
use std::borrow::Cow;
use std::fmt::Write;

pub trait HttpLimitResponse: Sync + Send {
    fn bytes_with_limit(
        self,
        limit: usize,
    ) -> impl std::future::Future<Output = reqwest::Result<Option<Vec<u8>>>> + Send;
}

impl HttpLimitResponse for Response {
    async fn bytes_with_limit(self, limit: usize) -> reqwest::Result<Option<Vec<u8>>> {
        if self
            .content_length()
            .is_some_and(|len| len as usize > limit)
        {
            return Ok(None);
        }

        let mut bytes = Vec::with_capacity(std::cmp::min(limit, 1024));
        let mut stream = self.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len() + chunk.len() > limit {
                return Ok(None);
            }
            bytes.extend_from_slice(&chunk);
        }

        Ok(Some(bytes))
    }
}

pub trait UnwrapFailure<T> {
    fn failed(self, action: &str) -> T;
}

impl<T> UnwrapFailure<T> for Option<T> {
    fn failed(self, message: &str) -> T {
        match self {
            Some(result) => result,
            None => {
                trc::event!(
                    Server(trc::ServerEvent::StartupError),
                    Details = message.to_compact_string()
                );
                eprintln!("{message}");
                std::process::exit(1);
            }
        }
    }
}

impl<T, E: std::fmt::Display> UnwrapFailure<T> for Result<T, E> {
    fn failed(self, message: &str) -> T {
        match self {
            Ok(result) => result,
            Err(err) => {
                trc::event!(
                    Server(trc::ServerEvent::StartupError),
                    Details = message.to_compact_string(),
                    Reason = err.to_compact_string()
                );

                #[cfg(feature = "test_mode")]
                panic!("{message}: {err}");

                #[cfg(not(feature = "test_mode"))]
                {
                    eprintln!("{message}: {err}");
                    std::process::exit(1);
                }
            }
        }
    }
}

pub fn failed(message: &str) -> ! {
    trc::event!(
        Server(trc::ServerEvent::StartupError),
        Details = message.to_compact_string(),
    );
    eprintln!("{message}");
    std::process::exit(1);
}

pub async fn wait_for_shutdown() {
    #[cfg(not(target_env = "msvc"))]
    let signal = {
        use tokio::signal::unix::{SignalKind, signal};

        let mut h_term = signal(SignalKind::terminate()).failed("start signal handler");
        let mut h_int = signal(SignalKind::interrupt()).failed("start signal handler");

        tokio::select! {
            _ = h_term.recv() => "SIGTERM",
            _ = h_int.recv() => "SIGINT",
        }
    };

    #[cfg(target_env = "msvc")]
    let signal = {
        match tokio::signal::ctrl_c().await {
            Ok(()) => "SIGINT",
            Err(err) => {
                trc::event!(
                    Server(trc::ServerEvent::ThreadError),
                    Details = "Unable to listen for shutdown signal",
                    Reason = err.to_string(),
                );
                "Error"
            }
        }
    };

    trc::event!(Server(trc::ServerEvent::Shutdown), CausedBy = signal);
}

pub trait DomainPart {
    fn to_lowercase_address(&self, lower_local: bool) -> String;
    fn domain_part(&self) -> &str;
    fn try_domain_part(&self) -> Option<&str>;
    fn try_local_part(&self) -> Option<&str>;
    fn to_ascii_domain(&self) -> Option<Cow<'_, str>>;
}

impl<T: AsRef<str>> DomainPart for T {
    fn to_lowercase_address(&self, lower_local: bool) -> String {
        let address = self.as_ref();
        if let Some((local, domain)) = address.rsplit_once('@') {
            let mut address = String::with_capacity(address.len());
            if lower_local {
                for ch in local.chars() {
                    for ch in ch.to_lowercase() {
                        address.push(ch);
                    }
                }
            } else {
                address.push_str(local);
            }
            address.push('@');
            if domain.is_ascii() {
                for ch in domain.chars() {
                    for ch in ch.to_lowercase() {
                        address.push(ch);
                    }
                }
            } else {
                let domain =
                    idna::domain_to_ascii(domain).unwrap_or_else(|_| domain.to_lowercase());
                address.push_str(&domain);
            }
            address
        } else {
            address.to_lowercase()
        }
    }

    #[inline(always)]
    fn try_domain_part(&self) -> Option<&str> {
        self.as_ref().rsplit_once('@').map(|(_, d)| d)
    }

    #[inline(always)]
    fn try_local_part(&self) -> Option<&str> {
        self.as_ref().rsplit_once('@').map(|(l, _)| l)
    }

    #[inline(always)]
    fn domain_part(&self) -> &str {
        self.as_ref()
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or_default()
    }

    #[inline(always)]
    fn to_ascii_domain(&self) -> Option<Cow<'_, str>> {
        let domain = self.as_ref();

        if domain.is_ascii() {
            Some(Cow::Borrowed(domain))
        } else {
            idna::domain_to_ascii(domain).ok().map(Cow::Owned)
        }
    }
}

pub trait HexEncode {
    fn hex_encode(&self) -> String;
}

impl<T: AsRef<[u8]>> HexEncode for T {
    fn hex_encode(&self) -> String {
        let bytes = self.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            let _ = write!(&mut s, "{b:02x}");
        }
        s
    }
}

static NIL_CHAR: char = char::from_u32(0).unwrap();

// Basic email sanitizer
pub fn sanitize_email(email: &str) -> Option<String> {
    let mut result = String::with_capacity(email.len());
    let mut last_ch = NIL_CHAR;
    let mut chars = email.chars();

    for ch in chars.by_ref() {
        match ch {
            '.' => {
                if last_ch == NIL_CHAR || last_ch == '.' {
                    return None;
                }
                result.push('.');
            }
            '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '/' | '=' | '?' | '^' | '_'
            | '`' | '{' | '|' | '}' | '~' => {
                result.push(ch);
            }
            ' ' | '\x09'..='\x0d' => continue,
            '@' => {
                if result.is_empty() || last_ch == '.' {
                    return None;
                }
                last_ch = ch;
                result.push(ch);
                break;
            }
            _ => {
                if ch.is_uppercase() {
                    for ch in ch.to_lowercase() {
                        result.push(ch);
                    }
                } else if ch.is_alphanumeric() {
                    result.push(ch);
                } else {
                    return None;
                }
            }
        }

        last_ch = ch;
    }

    if last_ch != '@' {
        return None;
    }

    last_ch = NIL_CHAR;
    let domain_start = result.len();
    let mut domain_is_ascii = true;

    for ch in chars {
        match ch {
            '.' => {
                if !last_ch.is_alphanumeric() {
                    return None;
                }
                result.push('.');
            }
            '-' | '_' => {
                if last_ch == NIL_CHAR || last_ch == '.' {
                    return None;
                }
                result.push(ch);
            }
            ' ' | '\x09'..='\x0d' => continue,
            _ => {
                if !ch.is_ascii() {
                    domain_is_ascii = false;
                }
                if ch.is_uppercase() {
                    for ch in ch.to_lowercase() {
                        result.push(ch);
                    }
                } else if ch.is_alphanumeric() {
                    result.push(ch);
                } else {
                    return None;
                }
            }
        }

        last_ch = ch;
    }

    if !last_ch.is_alphanumeric() {
        return None;
    }

    if domain_is_ascii {
        is_valid_domain(&result[domain_start..]).then_some(result)
    } else {
        let domain = idna::domain_to_ascii(&result[domain_start..]).ok()?;
        if !is_valid_domain(&domain) {
            return None;
        }
        result.truncate(domain_start);
        result.push_str(&domain);
        Some(result)
    }
}

pub fn sanitize_email_local(local: &str) -> Option<String> {
    let mut result = String::with_capacity(local.len());
    let mut last_ch = NIL_CHAR;

    for ch in local.chars() {
        match ch {
            '.' => {
                if last_ch == NIL_CHAR || last_ch == '.' {
                    return None;
                }
                result.push('.');
            }
            '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '/' | '=' | '?' | '^' | '_'
            | '`' | '{' | '|' | '}' | '~' => {
                result.push(ch);
            }
            ' ' | '\x09'..='\x0d' => continue,
            _ => {
                if ch.is_uppercase() {
                    for ch in ch.to_lowercase() {
                        result.push(ch);
                    }
                } else if ch.is_alphanumeric() {
                    result.push(ch);
                } else {
                    return None;
                }
            }
        }

        last_ch = ch;
    }

    if !result.is_empty() && last_ch != '.' {
        Some(result)
    } else {
        None
    }
}

pub fn sanitize_domain(domain: &str) -> Option<String> {
    let mut result = String::with_capacity(domain.len());
    let mut found_dot = false;
    let mut last_ch = char::from(0);
    let mut is_ascii = true;

    for ch in domain.chars() {
        if !ch.is_whitespace() {
            if ch == '.' {
                found_dot = true;
                if !(last_ch.is_alphanumeric() || last_ch == '-' || last_ch == '_') {
                    return None;
                }
            } else if !ch.is_ascii() {
                is_ascii = false;
            }
            last_ch = ch;
            for ch in ch.to_lowercase() {
                result.push(ch);
            }
        }
    }

    if !(found_dot && last_ch != '.') {
        return None;
    }

    if is_ascii {
        is_valid_domain(&result).then_some(result)
    } else {
        let domain = idna::domain_to_ascii(&result).ok()?;
        is_valid_domain(&domain).then_some(domain)
    }
}

pub fn is_valid_domain(domain: &str) -> bool {
    const RESERVED_TLDS: &[&str] = &[
        "test",
        "localhost",
        "local",
        "internal",
        "lan",
        "home",
        "corp",
        "intranet",
        "private",
        "localdomain",
    ];
    psl::domain(domain.as_bytes()).is_some_and(|d| d.suffix().typ().is_some())
        || RESERVED_TLDS.contains(&domain)
        || domain
            .rsplit_once('.')
            .is_some_and(|(_, tld)| RESERVED_TLDS.contains(&tld))
}

#[cfg(test)]
mod tests {
    use crate::DomainPart;

    use super::{sanitize_domain, sanitize_email};

    #[test]
    fn idn_domains_canonicalize_to_a_label() {
        assert_eq!(
            sanitize_domain("straß6.de").as_deref(),
            Some("xn--stra6-oqa.de")
        );
        assert_eq!(
            sanitize_domain("STRASS.straß6.DE").as_deref(),
            Some("strass.xn--stra6-oqa.de")
        );
        assert_eq!(
            sanitize_domain("münchen.de").as_deref(),
            Some("xn--mnchen-3ya.de")
        );
    }

    #[test]
    fn a_label_and_ascii_domains_are_idempotent() {
        assert_eq!(
            sanitize_domain("xn--stra6-oqa.de").as_deref(),
            Some("xn--stra6-oqa.de")
        );
        assert_eq!(
            sanitize_domain(&sanitize_domain("straß6.de").unwrap()).as_deref(),
            Some("xn--stra6-oqa.de")
        );
        assert_eq!(
            sanitize_domain("Example.COM").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn email_domain_part_canonicalizes_local_part_preserved() {
        assert_eq!(
            sanitize_email("cornelius_strauss@straß6.de").as_deref(),
            Some("cornelius_strauss@xn--stra6-oqa.de")
        );
        assert_eq!(
            sanitize_email("Foo.Bar@münchen.de").as_deref(),
            Some("foo.bar@xn--mnchen-3ya.de")
        );
        assert_eq!(
            sanitize_email("user@example.com").as_deref(),
            Some("user@example.com")
        );
    }

    #[test]
    fn a_label_email_domains_are_accepted_and_idempotent() {
        assert_eq!(
            sanitize_email("user@xn--fsqu00a.com").as_deref(),
            Some("user@xn--fsqu00a.com")
        );
        assert_eq!(
            sanitize_email("User@例子.com").as_deref(),
            sanitize_email("user@xn--fsqu00a.com").as_deref()
        );
    }

    #[test]
    fn to_ascii_domain_borrows_ascii_owns_idn() {
        assert!(matches!(
            "example.com".to_ascii_domain(),
            Some(std::borrow::Cow::Borrowed(_))
        ));
        assert!(matches!(
            "straß6.de".to_ascii_domain(),
            Some(std::borrow::Cow::Owned(_))
        ));
    }
}
