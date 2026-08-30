/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::NextHop;
use super::dane::dnssec::{TlsaLookup, least_secure};
use crate::queue::{Error, ErrorDetails, HostResponse, Status};
use common::{
    Server,
    config::smtp::queue::{ConnectionStrategy, HostOrIp, IpAndHost, MxConfig},
    expr::functions::ResolveVariable,
};
use mail_auth::{DnssecStatus, IpLookupStrategy, MX, RecordSet};
use rand::{RngExt, seq::SliceRandom};
use registry::schema::enums::ExpressionVariable;
use std::{future::Future, net::IpAddr, sync::Arc};

pub struct ResolvedHost {
    pub ips: Vec<IpAddr>,
    pub dnssec_status: DnssecStatus,
}

pub trait DnsLookup: Sync + Send {
    fn ip_lookup(
        &self,
        key: &str,
        strategy: IpLookupStrategy,
        max_results: usize,
        dnssec: bool,
    ) -> impl Future<Output = mail_auth::Result<(Vec<IpAddr>, DnssecStatus)>> + Send;

    fn resolve_host(
        &self,
        remote_host: &NextHop<'_>,
        envelope: &impl ResolveVariable,
        dnssec: bool,
    ) -> impl Future<Output = Result<ResolvedHost, Status<HostResponse<Box<str>>, ErrorDetails>>> + Send;
}

impl DnsLookup for Server {
    async fn ip_lookup(
        &self,
        key: &str,
        strategy: IpLookupStrategy,
        max_results: usize,
        dnssec: bool,
    ) -> mail_auth::Result<(Vec<IpAddr>, DnssecStatus)> {
        let (has_ipv4, has_ipv6, v4_first) = match strategy {
            IpLookupStrategy::Ipv4Only => (true, false, false),
            IpLookupStrategy::Ipv6Only => (false, true, false),
            IpLookupStrategy::Ipv4thenIpv6 => (true, true, true),
            IpLookupStrategy::Ipv6thenIpv4 => (true, true, false),
        };
        let mut dnssec_status: Option<DnssecStatus> = None;

        let ipv4_addrs = if has_ipv4 {
            let result = if dnssec {
                self.ipv4_lookup_dnssec(key).await
            } else {
                self.core
                    .smtp
                    .resolvers
                    .dns
                    .ipv4_lookup(key, Some(&self.inner.cache.dns_ipv4))
                    .await
            };

            match result {
                Ok(addrs) => {
                    if !addrs.rrset.is_empty() {
                        dnssec_status = Some(addrs.dnssec_status);
                    }
                    addrs.rrset
                }
                Err(_) if has_ipv6 => Arc::new([]),
                Err(err) => return Err(err),
            }
        } else {
            Arc::new([])
        };

        let ipv6_addrs = if has_ipv6 {
            let result = if dnssec {
                self.ipv6_lookup_dnssec(key).await
            } else {
                self.core
                    .smtp
                    .resolvers
                    .dns
                    .ipv6_lookup(key, Some(&self.inner.cache.dns_ipv6))
                    .await
            };

            match result {
                Ok(addrs) => {
                    if !addrs.rrset.is_empty() {
                        dnssec_status = Some(match dnssec_status {
                            Some(status) => least_secure(status, addrs.dnssec_status),
                            None => addrs.dnssec_status,
                        });
                    }
                    addrs.rrset
                }
                Err(_) if !ipv4_addrs.is_empty() => Arc::new([]),
                Err(err) => return Err(err),
            }
        } else {
            Arc::new([])
        };

        let remote_ips = if v4_first {
            ipv4_addrs
                .iter()
                .copied()
                .map(IpAddr::from)
                .chain(ipv6_addrs.iter().copied().map(IpAddr::from))
                .take(max_results)
                .collect()
        } else {
            ipv6_addrs
                .iter()
                .copied()
                .map(IpAddr::from)
                .chain(ipv4_addrs.iter().copied().map(IpAddr::from))
                .take(max_results)
                .collect()
        };

        Ok((
            remote_ips,
            dnssec_status.unwrap_or(DnssecStatus::Indeterminate),
        ))
    }

    async fn resolve_host(
        &self,
        remote_host: &NextHop<'_>,
        envelope: &impl ResolveVariable,
        dnssec: bool,
    ) -> Result<ResolvedHost, Status<HostResponse<Box<str>>, ErrorDetails>> {
        let (mut remote_ips, dnssec_status) = match remote_host.fqdn_hostname() {
            HostOrIp::Host(hostname) => self
                .ip_lookup(
                    hostname.as_ref(),
                    remote_host.ip_lookup_strategy(),
                    remote_host.max_multi_homed(),
                    dnssec,
                )
                .await
                .map_err(|err| {
                    if let mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(_)) = &err {
                        if matches!(
                            remote_host,
                            NextHop::MX {
                                is_implicit: true,
                                ..
                            }
                        ) {
                            Status::PermanentFailure(Box::new(ErrorDetails {
                                entity: remote_host.hostname().into(),
                                details: Error::DnsError("no MX record found.".into()),
                            }))
                        } else {
                            Status::PermanentFailure(Box::new(ErrorDetails {
                                entity: remote_host.hostname().into(),
                                details: Error::ConnectionError("record not found for MX".into()),
                            }))
                        }
                    } else {
                        Status::TemporaryFailure(Box::new(ErrorDetails {
                            entity: remote_host.hostname().into(),
                            details: Error::ConnectionError(
                                format!("lookup error: {err}").into_boxed_str(),
                            ),
                        }))
                    }
                })?,
            HostOrIp::Ip(ip) => (vec![ip], DnssecStatus::Indeterminate),
        };

        if !remote_ips.is_empty() {
            if !remote_host.allow_loopback() && remote_ips.iter().any(|ip| ip.is_loopback()) {
                remote_ips.retain(|ip| !ip.is_loopback());
                if remote_ips.is_empty() {
                    return Err(Status::PermanentFailure(Box::new(ErrorDetails {
                        entity: remote_host.hostname().into(),
                        details: Error::ConnectionError("host resolves loopback address".into()),
                    })));
                }
            }

            Ok(ResolvedHost {
                ips: remote_ips,
                dnssec_status,
            })
        } else {
            Err(Status::TemporaryFailure(Box::new(ErrorDetails {
                entity: remote_host.hostname().into(),
                details: Error::DnsError(
                    format!(
                        "No IP addresses found for {:?}.",
                        envelope
                            .resolve_variable(ExpressionVariable::Mx)
                            .to_string()
                    )
                    .into_boxed_str(),
                ),
            })))
        }
    }
}

pub trait SourceIp {
    fn source_ip(&self, is_v4: bool) -> Option<&IpAndHost>;
}

impl SourceIp for ConnectionStrategy {
    fn source_ip(&self, is_v4: bool) -> Option<&IpAndHost> {
        let ips = if is_v4 {
            &self.source_ipv4
        } else {
            &self.source_ipv6
        };
        match ips.len().cmp(&1) {
            std::cmp::Ordering::Equal => ips.first(),
            std::cmp::Ordering::Greater => Some(&ips[rand::rng().random_range(0..ips.len())]),
            std::cmp::Ordering::Less => None,
        }
    }
}

pub trait ToNextHop {
    fn to_remote_hosts<'x, 'y: 'x>(
        &'x self,
        domain: &'y str,
        config: &'x MxConfig,
    ) -> Option<Vec<NextHop<'x>>>;
}

impl ToNextHop for RecordSet<MX> {
    fn to_remote_hosts<'x, 'y: 'x>(
        &'x self,
        domain: &'y str,
        config: &'x MxConfig,
    ) -> Option<Vec<NextHop<'x>>> {
        if !self.rrset.is_empty() {
            // Obtain max number of MX hosts to process
            let mut remote_hosts = Vec::with_capacity(config.max_mx);

            'outer: for mx in self.rrset.iter() {
                if mx.exchanges.len() > 1 {
                    let mut slice = mx.exchanges.iter().collect::<Vec<_>>();
                    slice.shuffle(&mut rand::rng());
                    for remote_host in slice {
                        remote_hosts.push(NextHop::MX {
                            host: remote_host.as_ref(),
                            is_implicit: false,
                            dnssec_status: self.dnssec_status,
                            config,
                        });
                        if remote_hosts.len() == config.max_mx {
                            break 'outer;
                        }
                    }
                } else if let Some(remote_host) = mx.exchanges.first() {
                    // Check for Null MX
                    if mx.preference == 0 && remote_host.as_ref() == "." {
                        return None;
                    }
                    remote_hosts.push(NextHop::MX {
                        host: remote_host.as_ref(),
                        is_implicit: false,
                        dnssec_status: self.dnssec_status,
                        config,
                    });
                    if remote_hosts.len() == config.max_mx {
                        break;
                    }
                }
            }
            remote_hosts.into()
        } else {
            // If an empty list of MXs is returned, the address is treated as if it was
            // associated with an implicit MX RR with a preference of 0, pointing to that host.
            vec![NextHop::MX {
                host: domain,
                is_implicit: true,
                dnssec_status: self.dnssec_status,
                config,
            }]
            .into()
        }
    }
}
