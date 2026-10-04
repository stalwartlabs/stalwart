/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::expression::SpamFilterResolver;
use crate::SpamFilterContext;
use common::{
    Server,
    config::mailstore::spamfilter::{DnsBlServer, Element, IpResolver, Location},
    expr::functions::ResolveVariable,
};
use mail_auth::common::resolver::ToFqdn;
#[cfg(not(feature = "test_mode"))]
use mail_auth::hickory_resolver::{
    net::{DnsError, NetError},
    proto::rr::{Name, RData},
};
#[cfg(feature = "test_mode")]
use mail_auth::{DnsError, Error};
use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};
use trc::SpamEvent;

const MAX_NEGATIVE_TTL: u32 = 3600;

enum DnsblAnswer {
    Listed {
        ips: Vec<Ipv4Addr>,
        expires: Instant,
    },
    NotListed {
        expires: Option<Instant>,
    },
}

pub(crate) async fn check_dnsbl(
    server: &Server,
    ctx: &mut SpamFilterContext<'_>,
    resolver: &impl ResolveVariable,
    scope: Element,
    location: Location,
) {
    let (mut checks, max_checks) = match scope {
        Element::Email => (
            ctx.result.rbl_email_checks,
            server.core.spam.dnsbl.max_email_checks,
        ),
        Element::Ip => (
            ctx.result.rbl_ip_checks,
            server.core.spam.dnsbl.max_ip_checks,
        ),
        Element::Url => (
            ctx.result.rbl_url_checks,
            server.core.spam.dnsbl.max_url_checks,
        ),
        Element::Domain => (
            ctx.result.rbl_domain_checks,
            server.core.spam.dnsbl.max_domain_checks,
        ),
        Element::Header | Element::Body | Element::Any => unreachable!(),
    };

    for dnsbl in &server.core.spam.dnsbl.servers {
        if dnsbl.scope == scope
            && checks < max_checks
            && let Some(codes) = dnsbl_codes(
                server,
                dnsbl,
                SpamFilterResolver::new(ctx, resolver, location),
                scope,
                &mut checks,
            )
            .await
        {
            for code in codes.iter() {
                let tag = server
                    .eval_if::<String, _>(
                        &dnsbl.tags,
                        &SpamFilterResolver::new(ctx, code, location),
                        ctx.input.span_id,
                    )
                    .await;

                if let Some(tag) = tag {
                    ctx.result.add_tag(tag);
                }
            }
        }
    }

    match scope {
        Element::Email => ctx.result.rbl_email_checks = checks,
        Element::Ip => ctx.result.rbl_ip_checks = checks,
        Element::Url => ctx.result.rbl_url_checks = checks,
        Element::Domain => ctx.result.rbl_domain_checks = checks,
        Element::Header | Element::Body | Element::Any => unreachable!(),
    }
}

async fn dnsbl_codes(
    server: &Server,
    config: &DnsBlServer,
    resolver: SpamFilterResolver<'_, impl ResolveVariable>,
    element: Element,
    checks: &mut usize,
) -> Option<Arc<[IpResolver]>> {
    let time = Instant::now();
    let zone = server
        .eval_if::<String, _>(&config.zone, &resolver, resolver.ctx.input.span_id)
        .await?;

    #[cfg(feature = "test_mode")]
    {
        if zone.contains(".11.20.") {
            let parts = zone.split('.').collect::<Vec<_>>();

            return if config.tags.if_then.iter().any(|i| i.expr.items.len() == 3) && parts[0] != "2"
            {
                None
            } else {
                Some(Arc::from([IpResolver::new(
                    format!("127.0.{}.{}", parts[1], parts[0]).parse().unwrap(),
                )]))
            };
        }
    }

    if let Some(codes) = server.inner.cache.dns_rbl.get(zone.as_str()) {
        return codes;
    }

    *checks += 1;

    match resolve_zone(server, zone.to_fqdn().as_ref()).await {
        Ok(DnsblAnswer::Listed { ips, expires }) => {
            trc::event!(
                Spam(SpamEvent::Dnsbl),
                Hostname = zone.clone(),
                Result = ips
                    .iter()
                    .map(|ip| trc::Value::from(ip.to_string()))
                    .collect::<Vec<_>>(),
                Details = element.as_str(),
                Elapsed = time.elapsed()
            );

            let codes: Arc<[IpResolver]> = ips
                .into_iter()
                .map(|ip| IpResolver::new(ip.into()))
                .collect();

            server.inner.cache.dns_rbl.insert_with_expiry(
                zone.into(),
                Some(codes.clone()),
                expires,
            );

            Some(codes)
        }
        Ok(DnsblAnswer::NotListed { expires }) => {
            trc::event!(
                Spam(SpamEvent::Dnsbl),
                Hostname = zone.clone(),
                Result = trc::Value::None,
                Details = element.as_str(),
                Elapsed = time.elapsed()
            );

            if let Some(expires) = expires {
                server
                    .inner
                    .cache
                    .dns_rbl
                    .insert_with_expiry(zone.into(), None, expires);
            }

            None
        }
        Err(err) => {
            trc::event!(
                Spam(SpamEvent::DnsblError),
                Hostname = zone,
                Elapsed = time.elapsed(),
                Details = element.as_str(),
                CausedBy = err
            );

            None
        }
    }
}

#[cfg(not(feature = "test_mode"))]
async fn resolve_zone(server: &Server, zone: &str) -> Result<DnsblAnswer, String> {
    let name = Name::from_str_relaxed(zone).map_err(|err| err.to_string())?;

    match server.core.smtp.resolvers.dns.0.ipv4_lookup(name).await {
        Ok(lookup) => {
            let expires = lookup.valid_until();
            let ips = lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::A(a) => Some(a.0),
                    _ => None,
                })
                .collect::<Vec<_>>();

            Ok(if !ips.is_empty() {
                DnsblAnswer::Listed { ips, expires }
            } else {
                DnsblAnswer::NotListed {
                    expires: Some(expires),
                }
            })
        }
        Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => Ok(DnsblAnswer::NotListed {
            expires: no_records
                .negative_ttl
                .filter(|ttl| *ttl > 0)
                .map(|ttl| Instant::now() + Duration::from_secs(ttl.min(MAX_NEGATIVE_TTL).into())),
        }),
        Err(err) => Err(err.to_string()),
    }
}

#[cfg(feature = "test_mode")]
async fn resolve_zone(server: &Server, zone: &str) -> Result<DnsblAnswer, String> {
    match server.core.smtp.resolvers.dns.ipv4_lookup_raw(zone).await {
        Ok(result) => Ok(DnsblAnswer::Listed {
            ips: result.entry.to_vec(),
            expires: result.expires,
        }),
        Err(Error::Dns(DnsError::RecordNotFound(_))) => Ok(DnsblAnswer::NotListed {
            expires: Some(Instant::now() + Duration::from_secs(MAX_NEGATIVE_TTL.into())),
        }),
        Err(err) => Err(err.to_string()),
    }
}
