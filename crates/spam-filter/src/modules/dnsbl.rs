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
    expr::{Bump, Variable, functions::ResolveVariable},
};
use compact_str::{CompactString, ToCompactString};
use mail_auth::{Error, dns::ToFqdn};
use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};
use trc::SpamEvent;

enum Zone {
    Cached(Option<Arc<IpResolver>>),
    Lookup(Box<str>),
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

    let mut arena = std::mem::take(ctx.arena.get_mut());
    for dnsbl in &server.core.spam.dnsbl.servers {
        if dnsbl.scope == scope
            && checks < max_checks
            && let Some(tag) = is_dnsbl(
                server,
                dnsbl,
                SpamFilterResolver::new(
                    &ctx.input,
                    &ctx.output,
                    &ctx.result.tags,
                    resolver,
                    location,
                ),
                scope,
                &mut checks,
                &mut arena,
            )
            .await
        {
            ctx.result.add_tag(tag);
        }
    }
    *ctx.arena.get_mut() = arena;

    match scope {
        Element::Email => ctx.result.rbl_email_checks = checks,
        Element::Ip => ctx.result.rbl_ip_checks = checks,
        Element::Url => ctx.result.rbl_url_checks = checks,
        Element::Domain => ctx.result.rbl_domain_checks = checks,
        Element::Header | Element::Body | Element::Any => unreachable!(),
    }
}

async fn is_dnsbl(
    server: &Server,
    config: &DnsBlServer,
    resolver: SpamFilterResolver<'_, impl ResolveVariable>,
    element: Element,
    checks: &mut usize,
    arena: &mut Bump,
) -> Option<CompactString> {
    let time = Instant::now();
    let span_id = resolver.input.span_id;
    let dns_rbl = &server.inner.cache.dns_rbl;
    let zone = server
        .eval_if_with(&config.zone, &resolver, arena, span_id, |zone| match zone {
            Variable::String(zone) => Some(match dns_rbl.get(zone) {
                Some(entry) => Zone::Cached(entry),
                None => Zone::Lookup(zone.into()),
            }),
            _ => None,
        })
        .await
        .flatten()?;

    let result = match zone {
        Zone::Cached(entry) => entry?,
        Zone::Lookup(zone) => {
            #[cfg(feature = "test_mode")]
            {
                if zone.contains(".11.20.") {
                    let parts = zone.split('.').collect::<Vec<_>>();

                    return if config.tags.if_then.iter().any(|i| i.expr.items.len() == 3)
                        && parts[0] != "2"
                    {
                        None
                    } else {
                        dnsbl_tag(
                            server,
                            config,
                            &resolver,
                            &IpResolver::new(
                                format!("127.0.{}.{}", parts[1], parts[0]).parse().unwrap(),
                            ),
                            arena,
                        )
                        .await
                    };
                }
            }

            *checks += 1;

            match server
                .core
                .smtp
                .resolvers
                .dns
                .ipv4_lookup_raw(zone.to_fqdn().as_ref())
                .await
            {
                Ok(result) => {
                    trc::event!(
                        Spam(SpamEvent::Dnsbl),
                        Hostname = zone.clone(),
                        Result = result
                            .entry
                            .iter()
                            .map(|ip| trc::Value::from(ip.to_compact_string()))
                            .collect::<Vec<_>>(),
                        Details = element.as_str(),
                        Elapsed = time.elapsed()
                    );

                    let entry = Arc::new(IpResolver::new(
                        result
                            .entry
                            .iter()
                            .copied()
                            .next()
                            .unwrap_or(Ipv4Addr::BROADCAST)
                            .into(),
                    ));

                    dns_rbl.insert_with_expiry(zone, Some(entry.clone()), result.expires);

                    entry
                }
                Err(Error::Dns(mail_auth::DnsError::RecordNotFound(_))) => {
                    trc::event!(
                        Spam(SpamEvent::Dnsbl),
                        Hostname = zone.clone(),
                        Result = trc::Value::None,
                        Details = element.as_str(),
                        Elapsed = time.elapsed()
                    );

                    dns_rbl.insert(zone, None, Duration::from_secs(86400));

                    return None;
                }
                Err(err) => {
                    trc::event!(
                        Spam(SpamEvent::DnsblError),
                        Hostname = zone,
                        Elapsed = time.elapsed(),
                        Details = element.as_str(),
                        CausedBy = err.to_compact_string()
                    );

                    return None;
                }
            }
        }
    };

    dnsbl_tag(server, config, &resolver, result.as_ref(), arena).await
}

async fn dnsbl_tag(
    server: &Server,
    config: &DnsBlServer,
    resolver: &SpamFilterResolver<'_, impl ResolveVariable>,
    result: &IpResolver,
    arena: &mut Bump,
) -> Option<CompactString> {
    let tags = resolver.tags;
    server
        .eval_if_with(
            &config.tags,
            &SpamFilterResolver::new(
                resolver.input,
                resolver.output,
                tags,
                result,
                resolver.location,
            ),
            arena,
            resolver.input.span_id,
            |tag| match tag {
                Variable::String(tag) if !tags.contains(tag) => Some(CompactString::from(tag)),
                _ => None,
            },
        )
        .await
        .flatten()
}
