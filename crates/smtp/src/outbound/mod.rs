/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    outbound::{client::BoxResponse, error::ClientError},
    queue::{Error, ErrorDetails, HostResponse, Status, UnexpectedResponse},
};
use common::config::{
    server::ServerProtocol,
    smtp::queue::{HostOrIp, MxConfig, RelayConfig},
};
use directory::Credentials;
use mail_auth::{DnssecStatus, IpLookupStrategy};
use smtp_proto::{Response, Severity};
use std::{borrow::Cow, net::IpAddr};

pub mod client;
pub mod dane;
pub mod delivery;
pub mod error;
pub mod local;
pub mod lookup;
pub mod mta_sts;
pub mod session;

pub(super) enum DeliveryResult {
    Domain {
        status: Status<HostResponse<Box<str>>, ErrorDetails>,
        rcpt_idxs: Vec<usize>,
    },
    Account {
        status: Status<HostResponse<Box<str>>, ErrorDetails>,
        rcpt_idx: usize,
    },
    RateLimited {
        rcpt_idxs: Vec<usize>,
        retry_at: u64,
    },
}

impl Status<HostResponse<Box<str>>, ErrorDetails> {
    pub fn from_smtp_error(hostname: &str, command: &str, err: ClientError) -> Self {
        match err {
            ClientError::Io(_)
            | ClientError::Tls(_)
            | ClientError::Base64(_)
            | ClientError::UnparseableReply
            | ClientError::AuthenticationFailed(_)
            | ClientError::MissingCredentials
            | ClientError::MissingMailFrom
            | ClientError::MissingRcptTo
            | ClientError::Timeout => Status::TemporaryFailure(ErrorDetails {
                entity: hostname.into(),
                details: Error::ConnectionError(err.to_string().into_boxed_str()),
            }),

            ClientError::UnexpectedReply(response) => {
                if response.severity() == Severity::PermanentNegativeCompletion {
                    Status::PermanentFailure(ErrorDetails {
                        entity: hostname.into(),
                        details: Error::UnexpectedResponse(UnexpectedResponse {
                            command: command.trim().into(),
                            response: response.into_box(),
                        }),
                    })
                } else {
                    Status::TemporaryFailure(ErrorDetails {
                        entity: hostname.into(),
                        details: Error::UnexpectedResponse(UnexpectedResponse {
                            command: command.trim().into(),
                            response: response.into_box(),
                        }),
                    })
                }
            }

            ClientError::InvalidChallenge
            | ClientError::UnsupportedAuthMechanism
            | ClientError::InvalidTLSName
            | ClientError::MissingStartTls => Status::PermanentFailure(ErrorDetails {
                entity: hostname.into(),
                details: Error::ConnectionError(err.to_string().into_boxed_str()),
            }),
        }
    }

    pub fn from_starttls_error(hostname: &str, response: Option<Response<Box<str>>>) -> Self {
        let entity = hostname.into();
        if let Some(response) = response {
            if response.severity() == Severity::PermanentNegativeCompletion {
                Status::PermanentFailure(ErrorDetails {
                    entity,
                    details: Error::UnexpectedResponse(UnexpectedResponse {
                        command: "STARTTLS".into(),
                        response,
                    }),
                })
            } else {
                Status::TemporaryFailure(ErrorDetails {
                    entity,
                    details: Error::UnexpectedResponse(UnexpectedResponse {
                        command: "STARTTLS".into(),
                        response,
                    }),
                })
            }
        } else {
            Status::PermanentFailure(ErrorDetails {
                entity,
                details: Error::TlsError("STARTTLS not advertised by host.".into()),
            })
        }
    }

    pub fn from_tls_error(hostname: &str, err: ClientError) -> Self {
        match err {
            ClientError::InvalidTLSName => Status::PermanentFailure(ErrorDetails {
                entity: hostname.into(),
                details: Error::TlsError("Invalid hostname".into()),
            }),
            ClientError::Timeout => Status::TemporaryFailure(ErrorDetails {
                entity: hostname.into(),
                details: Error::TlsError("TLS handshake timed out".into()),
            }),
            ClientError::Tls(err) => Status::TemporaryFailure(ErrorDetails {
                entity: hostname.into(),
                details: Error::TlsError(format!("Handshake failed: {err}").into_boxed_str()),
            }),
            ClientError::Io(err) => Status::TemporaryFailure(ErrorDetails {
                entity: hostname.into(),
                details: Error::TlsError(format!("I/O error: {err}").into_boxed_str()),
            }),
            _ => Status::PermanentFailure(ErrorDetails {
                entity: hostname.into(),
                details: Error::TlsError("Other TLS error".into()),
            }),
        }
    }

    pub fn timeout(hostname: &str, stage: &str) -> Self {
        Status::TemporaryFailure(ErrorDetails {
            entity: hostname.into(),
            details: Error::ConnectionError(format!("Timeout while {stage}").into_boxed_str()),
        })
    }

    pub fn local_error() -> Self {
        Status::TemporaryFailure(ErrorDetails {
            entity: "localhost".into(),
            details: Error::ConnectionError("Could not deliver message locally.".into()),
        })
    }

    pub fn from_mail_auth_error(entity: &str, err: mail_auth::Error) -> Self {
        match &err {
            mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(code)) => {
                Status::PermanentFailure(ErrorDetails {
                    entity: entity.into(),
                    details: Error::DnsError(
                        format!("Domain not found: {code:?}").into_boxed_str(),
                    ),
                })
            }
            _ => Status::TemporaryFailure(ErrorDetails {
                entity: entity.into(),
                details: Error::DnsError(err.to_string().into_boxed_str()),
            }),
        }
    }

    pub fn from_mta_sts_error(entity: &str, err: mta_sts::Error) -> Self {
        match &err {
            mta_sts::Error::Dns(err) => match err {
                mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(code)) => {
                    Status::PermanentFailure(ErrorDetails {
                        entity: entity.into(),
                        details: Error::MtaStsError(
                            format!("Record not found: {code:?}").into_boxed_str(),
                        ),
                    })
                }
                mail_auth::Error::Dns(mail_auth::DnsError::InvalidRecordType) => {
                    Status::PermanentFailure(ErrorDetails {
                        entity: entity.into(),
                        details: Error::MtaStsError("Failed to parse MTA-STS DNS record.".into()),
                    })
                }
                _ => Status::TemporaryFailure(ErrorDetails {
                    entity: entity.into(),
                    details: Error::MtaStsError(
                        format!("DNS lookup error: {err}").into_boxed_str(),
                    ),
                }),
            },
            mta_sts::Error::Http(err) => {
                if err.is_timeout() {
                    Status::TemporaryFailure(ErrorDetails {
                        entity: entity.into(),
                        details: Error::MtaStsError("Timeout fetching policy.".into()),
                    })
                } else if err.is_connect() {
                    Status::TemporaryFailure(ErrorDetails {
                        entity: entity.into(),
                        details: Error::MtaStsError("Could not reach policy host.".into()),
                    })
                } else if err.is_status()
                    & err
                        .status()
                        .is_some_and(|s| s == reqwest::StatusCode::NOT_FOUND)
                {
                    Status::PermanentFailure(ErrorDetails {
                        entity: entity.into(),
                        details: Error::MtaStsError("Policy not found.".into()),
                    })
                } else {
                    Status::TemporaryFailure(ErrorDetails {
                        entity: entity.into(),
                        details: Error::MtaStsError("Failed to fetch policy.".into()),
                    })
                }
            }
            mta_sts::Error::InvalidPolicy(err) => Status::PermanentFailure(ErrorDetails {
                entity: entity.into(),
                details: Error::MtaStsError(
                    format!("Failed to parse policy: {err}").into_boxed_str(),
                ),
            }),
        }
    }
}

#[derive(Debug)]
pub enum NextHop<'x> {
    Relay(&'x RelayConfig),
    MX {
        is_implicit: bool,
        host: &'x str,
        config: &'x MxConfig,
        dnssec_status: DnssecStatus,
    },
}

impl NextHop<'_> {
    #[inline(always)]
    pub fn hostname(&self) -> &str {
        match self {
            NextHop::MX { host, .. } => {
                if let Some(host) = host.strip_suffix('.') {
                    host
                } else {
                    host
                }
            }
            NextHop::Relay(host) => match &host.address {
                HostOrIp::Host(host) => host.as_ref(),
                HostOrIp::Ip(ip) => ip.ip_str.as_ref(),
            },
        }
    }

    #[inline(always)]
    pub fn fqdn_hostname(&self) -> HostOrIp<Cow<'_, str>, IpAddr> {
        match self {
            NextHop::MX { host, .. } => {
                if !host.ends_with('.') {
                    HostOrIp::Host(format!("{host}.").into())
                } else {
                    HostOrIp::Host((*host).into())
                }
            }
            NextHop::Relay(host) => match &host.address {
                HostOrIp::Host(host) => HostOrIp::Host(host.as_ref().into()),
                HostOrIp::Ip(ip) => HostOrIp::Ip(ip.ip),
            },
        }
    }

    #[inline(always)]
    pub fn max_multi_homed(&self) -> usize {
        match self {
            NextHop::MX { config, .. } => config.max_multi_homed,
            NextHop::Relay(_) => 10,
        }
    }

    #[inline(always)]
    pub fn ip_lookup_strategy(&self) -> IpLookupStrategy {
        match self {
            NextHop::MX { config, .. } => config.ip_lookup_strategy,
            NextHop::Relay(_) => IpLookupStrategy::Ipv4thenIpv6,
        }
    }

    #[inline(always)]
    fn port(&self) -> u16 {
        match self {
            #[cfg(feature = "test_mode")]
            NextHop::MX { .. } => 9925,
            #[cfg(not(feature = "test_mode"))]
            NextHop::MX { .. } => 25,
            NextHop::Relay(host) => host.port,
        }
    }

    #[inline(always)]
    fn credentials(&self) -> Option<&Credentials> {
        match self {
            NextHop::MX { .. } => None,
            NextHop::Relay(host) => host.auth.as_ref(),
        }
    }

    #[inline(always)]
    fn allow_invalid_certs(&self) -> bool {
        #[cfg(feature = "test_mode")]
        {
            true
        }
        #[cfg(not(feature = "test_mode"))]
        match self {
            NextHop::MX { .. } => false,
            NextHop::Relay(host) => host.tls_allow_invalid_certs,
        }
    }

    #[inline(always)]
    fn implicit_tls(&self) -> bool {
        match self {
            NextHop::MX { .. } => false,
            NextHop::Relay(host) => host.tls_implicit,
        }
    }

    #[inline(always)]
    fn is_smtp(&self) -> bool {
        match self {
            NextHop::MX { .. } => true,
            NextHop::Relay(host) => host.protocol == ServerProtocol::Smtp,
        }
    }

    fn dnssec_status(&self) -> DnssecStatus {
        match self {
            NextHop::MX { dnssec_status, .. } => *dnssec_status,
            NextHop::Relay(_) => DnssecStatus::Indeterminate,
        }
    }
}

impl DeliveryResult {
    pub fn domain(
        status: Status<HostResponse<Box<str>>, ErrorDetails>,
        rcpt_idxs: Vec<usize>,
    ) -> Self {
        DeliveryResult::Domain { status, rcpt_idxs }
    }

    pub fn rate_limited(rcpt_idxs: Vec<usize>, retry_at: u64) -> Self {
        DeliveryResult::RateLimited {
            rcpt_idxs,
            retry_at,
        }
    }

    pub fn account(status: Status<HostResponse<Box<str>>, ErrorDetails>, rcpt_idx: usize) -> Self {
        DeliveryResult::Account { status, rcpt_idx }
    }
}
