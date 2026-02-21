/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::{
    config::server::ServerProtocol,
    expr::{
        if_block::{BootstrapExprExt, IfBlock},
        *,
    },
};
use ahash::AHashMap;
use mail_auth::IpLookupStrategy;
use mail_send::Credentials;
use registry::schema::{
    enums::{self, ExpressionConstant, ExpressionVariable, MtaRequiredOrOptional},
    prelude::ObjectType,
    structs::{
        DsnReportSettings, MtaConnectionStrategy, MtaDeliveryExpiration, MtaDeliverySchedule,
        MtaInboundThrottle, MtaOutboundStrategy, MtaOutboundThrottle, MtaQueueQuota, MtaRoute,
        MtaTlsStrategy, MtaVirtualQueue,
    },
};
use std::{
    fmt::Display,
    hash::{Hash, Hasher},
    net::IpAddr,
    time::Duration,
};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    serde::Deserialize,
)]
#[rkyv(derive(Debug, Clone, Copy, PartialEq), compare(PartialEq))]
#[repr(transparent)]
pub struct QueueName([u8; 8]);

pub const DEFAULT_QUEUE_NAME: QueueName = QueueName([b'd', b'e', b'f', b'a', b'u', b'l', b't', 0]);

#[derive(Clone)]
pub struct QueueConfig {
    // Strategy resolver
    pub route: IfBlock,
    pub queue: IfBlock,
    pub connection: IfBlock,
    pub tls: IfBlock,

    // DSN
    pub dsn: Dsn,

    // Rate limits
    pub inbound_limiters: QueueRateLimiters,
    pub outbound_limiters: QueueRateLimiters,
    pub quota: QueueQuotas,

    // Strategies
    pub queue_strategy: AHashMap<String, QueueStrategy>,
    pub connection_strategy: AHashMap<String, ConnectionStrategy>,
    pub routing_strategy: AHashMap<String, RoutingStrategy>,
    pub tls_strategy: AHashMap<String, TlsStrategy>,
    pub virtual_queues: AHashMap<QueueName, VirtualQueue>,
}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub enum RoutingStrategy {
    Local,
    Mx(MxConfig),
    Relay(RelayConfig),
}

#[derive(Clone, Debug)]
pub struct MxConfig {
    pub max_mx: usize,
    pub max_multi_homed: usize,
    pub ip_lookup_strategy: IpLookupStrategy,
}

#[derive(Clone)]
pub struct Dsn {
    pub name: IfBlock,
    pub address: IfBlock,
    pub sign: IfBlock,
}

#[derive(Clone, Debug)]
pub struct VirtualQueue {
    pub threads: usize,
}

#[derive(Clone, Debug)]
pub struct QueueStrategy {
    pub retry: Vec<u64>,
    pub notify: Vec<u64>,
    pub expiry: QueueExpiry,
    pub virtual_queue: QueueName,
}

#[derive(
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Deserialize,
)]
pub enum QueueExpiry {
    Ttl(u64),
    Attempts(u32),
}

#[derive(Clone, Debug)]
pub struct TlsStrategy {
    pub dane: RequireOptional,
    pub mta_sts: RequireOptional,
    pub tls: RequireOptional,
    pub allow_invalid_certs: bool,

    pub timeout_tls: Duration,
    pub timeout_mta_sts: Duration,
}

#[derive(Clone, Debug)]
pub struct ConnectionStrategy {
    pub source_ipv4: Vec<IpAndHost>,
    pub source_ipv6: Vec<IpAndHost>,
    pub ehlo_hostname: Option<String>,

    pub timeout_connect: Duration,
    pub timeout_greeting: Duration,
    pub timeout_ehlo: Duration,
    pub timeout_mail: Duration,
    pub timeout_rcpt: Duration,
    pub timeout_data: Duration,
}

#[derive(Clone, Debug)]
pub struct IpAndHost {
    pub ip: IpAddr,
    pub host: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct QueueRateLimiters {
    pub sender: Vec<QueueRateLimiter>,
    pub rcpt: Vec<QueueRateLimiter>,
    pub remote: Vec<QueueRateLimiter>,
}

#[derive(Clone, Default)]
pub struct QueueQuotas {
    pub sender: Vec<QueueQuota>,
    pub rcpt: Vec<QueueQuota>,
    pub rcpt_domain: Vec<QueueQuota>,
}

#[derive(Clone)]
pub struct QueueQuota {
    pub id: ObjectId,
    pub expr: Expression,
    pub keys: u16,
    pub size: Option<u64>,
    pub messages: Option<u64>,
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct RelayConfig {
    pub address: String,
    pub port: u16,
    pub protocol: ServerProtocol,
    pub auth: Option<Credentials<String>>,
    pub tls_implicit: bool,
    pub tls_allow_invalid_certs: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum RequireOptional {
    #[default]
    Optional,
    Require,
    Disable,
}

impl QueueConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let st = bp.setting_infallible::<MtaOutboundStrategy>().await;
        let dsn = bp.setting_infallible::<DsnReportSettings>().await;

        let mut queue = QueueConfig {
            route: bp.compile_expr(ObjectType::MtaOutboundStrategy.singleton(), &st.ctx_route()),
            queue: bp.compile_expr(
                ObjectType::MtaOutboundStrategy.singleton(),
                &st.ctx_schedule(),
            ),
            connection: bp.compile_expr(
                ObjectType::MtaOutboundStrategy.singleton(),
                &st.ctx_connection(),
            ),
            tls: bp.compile_expr(ObjectType::MtaOutboundStrategy.singleton(), &st.ctx_tls()),
            dsn: Dsn {
                name: bp.compile_expr(
                    ObjectType::DsnReportSettings.singleton(),
                    &dsn.ctx_from_name(),
                ),
                address: bp.compile_expr(
                    ObjectType::DsnReportSettings.singleton(),
                    &dsn.ctx_from_address(),
                ),
                sign: bp.compile_expr(
                    ObjectType::DsnReportSettings.singleton(),
                    &dsn.ctx_dkim_sign_domain(),
                ),
            },
            inbound_limiters: QueueRateLimiters::parse_inbound(bp).await,
            outbound_limiters: QueueRateLimiters::parse_outbound(bp).await,
            quota: QueueQuotas::parse(bp).await,
            queue_strategy: Default::default(),
            connection_strategy: Default::default(),
            routing_strategy: Default::default(),
            tls_strategy: Default::default(),
            virtual_queues: Default::default(),
        };

        // Parse virtual queues
        let mut queue_id_to_name = AHashMap::new();
        for obj in bp.list_infallible::<MtaVirtualQueue>().await {
            if let Some(queue_name) = QueueName::new(&obj.object.name) {
                queue_id_to_name.insert(obj.id.id(), queue_name);
                queue.virtual_queues.insert(
                    queue_name,
                    VirtualQueue {
                        threads: obj.object.threads_per_node as usize,
                    },
                );
            }
        }

        // Parse queue strategies
        for obj in bp.list_infallible::<MtaDeliverySchedule>().await {
            let virtual_queue = if let Some(name) = queue_id_to_name.get(&obj.object.queue_id) {
                *name
            } else {
                bp.build_error(
                    obj.id,
                    format!("Virtual queue ID '{}' does not exist.", obj.object.queue_id),
                );
                continue;
            };
            queue.queue_strategy.insert(
                obj.object.name,
                QueueStrategy {
                    retry: obj
                        .object
                        .retry
                        .into_iter()
                        .map(|d| d.into_inner().as_secs())
                        .collect(),
                    notify: obj
                        .object
                        .notify
                        .into_iter()
                        .map(|d| d.into_inner().as_secs())
                        .collect(),
                    expiry: match obj.object.expiry {
                        MtaDeliveryExpiration::Ttl(exp) => {
                            QueueExpiry::Ttl(exp.expire.into_inner().as_secs())
                        }
                        MtaDeliveryExpiration::Attempts(exp) => {
                            QueueExpiry::Attempts(exp.max_attempts as u32)
                        }
                    },
                    virtual_queue,
                },
            );
        }

        // Parse connection strategies
        for obj in bp.list_infallible::<MtaConnectionStrategy>().await {
            let mut source_ipv4 = Vec::new();
            let mut source_ipv6 = Vec::new();

            for ip_host in obj.object.source_ips {
                let ip_host = IpAndHost {
                    ip: ip_host.source_ip.into_inner(),
                    host: ip_host.ehlo_hostname,
                };
                if ip_host.ip.is_ipv4() {
                    source_ipv4.push(ip_host);
                } else {
                    source_ipv6.push(ip_host);
                }
            }

            queue.connection_strategy.insert(
                obj.object.name,
                ConnectionStrategy {
                    source_ipv4,
                    source_ipv6,
                    ehlo_hostname: obj.object.ehlo_hostname,
                    timeout_connect: obj.object.connect_timeout.into_inner(),
                    timeout_greeting: obj.object.greeting_timeout.into_inner(),
                    timeout_ehlo: obj.object.ehlo_timeout.into_inner(),
                    timeout_mail: obj.object.mail_from_timeout.into_inner(),
                    timeout_rcpt: obj.object.rcpt_to_timeout.into_inner(),
                    timeout_data: obj.object.data_timeout.into_inner(),
                },
            );
        }

        // Parse routing strategies
        for obj in bp.list_infallible::<MtaRoute>().await {
            match obj.object {
                MtaRoute::Mx(route) => {
                    queue.routing_strategy.insert(
                        route.name,
                        RoutingStrategy::Mx(MxConfig {
                            max_mx: route.max_mx_hosts as usize,
                            max_multi_homed: route.max_multihomed as usize,
                            ip_lookup_strategy: match route.ip_lookup_strategy {
                                enums::MtaIpStrategy::V4ThenV6 => IpLookupStrategy::Ipv4thenIpv6,
                                enums::MtaIpStrategy::V6ThenV4 => IpLookupStrategy::Ipv6thenIpv4,
                                enums::MtaIpStrategy::V4Only => IpLookupStrategy::Ipv4Only,
                                enums::MtaIpStrategy::V6Only => IpLookupStrategy::Ipv6Only,
                            },
                        }),
                    );
                }
                MtaRoute::Relay(route) => {
                    queue.routing_strategy.insert(
                        route.name,
                        RoutingStrategy::Relay(RelayConfig {
                            address: route.address,
                            port: route.port as u16,
                            protocol: match route.protocol {
                                enums::MtaProtocol::Smtp => ServerProtocol::Smtp,
                                enums::MtaProtocol::Lmtp => ServerProtocol::Lmtp,
                            },
                            auth: route
                                .auth_username
                                .and_then(|user| route.auth_secret.map(|secret| (user, secret)))
                                .map(|(user, secret)| Credentials::new(user, secret)),
                            tls_implicit: route.implicit_tls,
                            tls_allow_invalid_certs: route.allow_invalid_certs,
                        }),
                    );
                }
                MtaRoute::Local(route) => {
                    queue
                        .routing_strategy
                        .insert(route.name, RoutingStrategy::Local);
                }
            }
        }

        // Parse TLS strategies
        for obj in bp.list_infallible::<MtaTlsStrategy>().await {
            queue.tls_strategy.insert(
                obj.object.name,
                TlsStrategy {
                    dane: match obj.object.dane {
                        MtaRequiredOrOptional::Optional => RequireOptional::Optional,
                        MtaRequiredOrOptional::Require => RequireOptional::Require,
                        MtaRequiredOrOptional::Disable => RequireOptional::Disable,
                    },
                    mta_sts: match obj.object.mta_sts {
                        MtaRequiredOrOptional::Optional => RequireOptional::Optional,
                        MtaRequiredOrOptional::Require => RequireOptional::Require,
                        MtaRequiredOrOptional::Disable => RequireOptional::Disable,
                    },
                    tls: match obj.object.start_tls {
                        MtaRequiredOrOptional::Optional => RequireOptional::Optional,
                        MtaRequiredOrOptional::Require => RequireOptional::Require,
                        MtaRequiredOrOptional::Disable => RequireOptional::Disable,
                    },
                    allow_invalid_certs: obj.object.allow_invalid_certs,
                    timeout_tls: obj.object.tls_timeout.into_inner(),
                    timeout_mta_sts: obj.object.mta_sts_timeout.into_inner(),
                },
            );
        }

        queue
    }
}

impl QueueRateLimiters {
    async fn parse_inbound(bp: &mut Bootstrap) -> QueueRateLimiters {
        let mut throttle = QueueRateLimiters::default();

        for obj in bp.list_infallible::<MtaInboundThrottle>().await {
            if !obj.object.enable {
                continue;
            }

            let limiter = QueueRateLimiter {
                expr: bp.compile_expr(obj.id, &obj.object.ctx_match_()).default,
                id: obj.id,
                keys: obj
                    .object
                    .key
                    .iter()
                    .map(|key| match key {
                        enums::MtaInboundThrottleKey::Rcpt => THROTTLE_RCPT,
                        enums::MtaInboundThrottleKey::RcptDomain => THROTTLE_RCPT_DOMAIN,
                        enums::MtaInboundThrottleKey::Sender => THROTTLE_SENDER,
                        enums::MtaInboundThrottleKey::SenderDomain => THROTTLE_SENDER_DOMAIN,
                        enums::MtaInboundThrottleKey::AuthenticatedAs => THROTTLE_AUTH_AS,
                        enums::MtaInboundThrottleKey::Listener => THROTTLE_LISTENER,
                        enums::MtaInboundThrottleKey::RemoteIp => THROTTLE_REMOTE_IP,
                        enums::MtaInboundThrottleKey::LocalIp => THROTTLE_LOCAL_IP,
                        enums::MtaInboundThrottleKey::HeloDomain => THROTTLE_HELO_DOMAIN,
                    })
                    .fold(0, |acc, key| acc | key),
                rate: obj.object.rate,
            };

            if (limiter.keys & (THROTTLE_RCPT | THROTTLE_RCPT_DOMAIN)) != 0
                || limiter.expr.items().iter().any(|c| {
                    matches!(
                        c,
                        ExpressionItem::Variable(
                            ExpressionVariable::Rcpt | ExpressionVariable::RcptDomain
                        )
                    )
                })
            {
                throttle.rcpt.push(limiter);
            } else if (limiter.keys
                & (THROTTLE_SENDER
                    | THROTTLE_SENDER_DOMAIN
                    | THROTTLE_HELO_DOMAIN
                    | THROTTLE_AUTH_AS))
                != 0
                || limiter.expr.items().iter().any(|c| {
                    matches!(
                        c,
                        ExpressionItem::Variable(
                            ExpressionVariable::Sender
                                | ExpressionVariable::SenderDomain
                                | ExpressionVariable::HeloDomain
                                | ExpressionVariable::AuthenticatedAs
                        )
                    )
                })
            {
                throttle.sender.push(limiter);
            } else {
                throttle.remote.push(limiter);
            }
        }

        throttle
    }

    async fn parse_outbound(bp: &mut Bootstrap) -> QueueRateLimiters {
        // Parse throttle
        let mut throttle = QueueRateLimiters::default();

        for obj in bp.list_infallible::<MtaOutboundThrottle>().await {
            if !obj.object.enable {
                continue;
            }

            let limiter = QueueRateLimiter {
                expr: bp.compile_expr(obj.id, &obj.object.ctx_match_()).default,
                id: obj.id,
                keys: obj
                    .object
                    .key
                    .iter()
                    .map(|key| match key {
                        enums::MtaOutboundThrottleKey::RcptDomain => THROTTLE_RCPT_DOMAIN,
                        enums::MtaOutboundThrottleKey::Sender => THROTTLE_SENDER,
                        enums::MtaOutboundThrottleKey::SenderDomain => THROTTLE_SENDER_DOMAIN,
                        enums::MtaOutboundThrottleKey::Mx => THROTTLE_MX,
                        enums::MtaOutboundThrottleKey::RemoteIp => THROTTLE_REMOTE_IP,
                        enums::MtaOutboundThrottleKey::LocalIp => THROTTLE_LOCAL_IP,
                    })
                    .fold(0, |acc, key| acc | key),
                rate: obj.object.rate,
            };
            if (limiter.keys & (THROTTLE_MX | THROTTLE_REMOTE_IP | THROTTLE_LOCAL_IP)) != 0
                || limiter.expr.items().iter().any(|c| {
                    matches!(
                        c,
                        ExpressionItem::Variable(
                            ExpressionVariable::Mx
                                | ExpressionVariable::RemoteIp
                                | ExpressionVariable::LocalIp
                        )
                    )
                })
            {
                throttle.remote.push(limiter);
            } else if (limiter.keys & (THROTTLE_RCPT_DOMAIN)) != 0
                || limiter
                    .expr
                    .items()
                    .iter()
                    .any(|c| matches!(c, ExpressionItem::Variable(ExpressionVariable::RcptDomain)))
            {
                throttle.rcpt.push(limiter);
            } else {
                throttle.sender.push(limiter);
            }
        }

        throttle
    }
}

impl QueueQuotas {
    async fn parse(bp: &mut Bootstrap) -> QueueQuotas {
        let mut capacities = QueueQuotas {
            sender: Vec::new(),
            rcpt: Vec::new(),
            rcpt_domain: Vec::new(),
        };

        for obj in bp.list_infallible::<MtaQueueQuota>().await {
            if !obj.object.enable {
                continue;
            }

            let quota = QueueQuota {
                expr: bp.compile_expr(obj.id, &obj.object.ctx_match_()).default,
                id: obj.id,
                keys: obj
                    .object
                    .key
                    .iter()
                    .map(|key| match key {
                        enums::MtaQueueQuotaKey::Rcpt => THROTTLE_RCPT,
                        enums::MtaQueueQuotaKey::RcptDomain => THROTTLE_RCPT_DOMAIN,
                        enums::MtaQueueQuotaKey::Sender => THROTTLE_SENDER,
                        enums::MtaQueueQuotaKey::SenderDomain => THROTTLE_SENDER_DOMAIN,
                    })
                    .fold(0, |acc, key| acc | key),
                size: obj.object.size,
                messages: obj.object.messages,
            };

            if (quota.keys & THROTTLE_RCPT) != 0
                || quota
                    .expr
                    .items()
                    .iter()
                    .any(|c| matches!(c, ExpressionItem::Variable(ExpressionVariable::Rcpt)))
            {
                capacities.rcpt.push(quota);
            } else if (quota.keys & THROTTLE_RCPT_DOMAIN) != 0
                || quota
                    .expr
                    .items()
                    .iter()
                    .any(|c| matches!(c, ExpressionItem::Variable(ExpressionVariable::RcptDomain)))
            {
                capacities.rcpt_domain.push(quota);
            } else {
                capacities.sender.push(quota);
            }
        }

        capacities
    }
}

impl<'x> TryFrom<Variable<'x>> for RequireOptional {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Constant(ExpressionConstant::Optional) => Ok(RequireOptional::Optional),
            Variable::Constant(ExpressionConstant::Require) => Ok(RequireOptional::Require),
            Variable::Constant(ExpressionConstant::Disable) => Ok(RequireOptional::Disable),
            _ => Err(()),
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for IpLookupStrategy {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Constant(value) => match value {
                ExpressionConstant::Ipv4Only => Ok(IpLookupStrategy::Ipv4Only),
                ExpressionConstant::Ipv6Only => Ok(IpLookupStrategy::Ipv6Only),
                ExpressionConstant::Ipv6ThenIpv4 => Ok(IpLookupStrategy::Ipv6thenIpv4),
                ExpressionConstant::Ipv4ThenIpv6 => Ok(IpLookupStrategy::Ipv4thenIpv6),
                _ => Err(()),
            },
            Variable::String(value) => {
                match value.as_str() {
                    "ipv4_only" => Ok(IpLookupStrategy::Ipv4Only),
                    "ipv6_only" => Ok(IpLookupStrategy::Ipv6Only),
                    //"ipv4_and_ipv6" => IpLookupStrategy::Ipv4AndIpv6,
                    "ipv6_then_ipv4" => Ok(IpLookupStrategy::Ipv6thenIpv4),
                    "ipv4_then_ipv6" => Ok(IpLookupStrategy::Ipv4thenIpv6),
                    _ => Err(()),
                }
            }
            _ => Err(()),
        }
    }
}

impl std::fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayConfig")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("protocol", &self.protocol)
            .field("tls_implicit", &self.tls_implicit)
            .field("tls_allow_invalid_certs", &self.tls_allow_invalid_certs)
            .finish()
    }
}

impl TlsStrategy {
    #[inline(always)]
    pub fn try_dane(&self) -> bool {
        matches!(
            self.dane,
            RequireOptional::Require | RequireOptional::Optional
        )
    }

    #[inline(always)]
    pub fn try_start_tls(&self) -> bool {
        matches!(
            self.tls,
            RequireOptional::Require | RequireOptional::Optional
        )
    }

    #[inline(always)]
    pub fn is_dane_required(&self) -> bool {
        matches!(self.dane, RequireOptional::Require)
    }

    #[inline(always)]
    pub fn try_mta_sts(&self) -> bool {
        matches!(
            self.mta_sts,
            RequireOptional::Require | RequireOptional::Optional
        )
    }

    #[inline(always)]
    pub fn is_mta_sts_required(&self) -> bool {
        matches!(self.mta_sts, RequireOptional::Require)
    }

    #[inline(always)]
    pub fn is_tls_required(&self) -> bool {
        matches!(self.tls, RequireOptional::Require)
            || self.is_dane_required()
            || self.is_mta_sts_required()
    }
}

impl Hash for MxConfig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.max_mx.hash(state);
        self.max_multi_homed.hash(state);
    }
}

impl PartialEq for MxConfig {
    fn eq(&self, other: &Self) -> bool {
        self.max_mx == other.max_mx && self.max_multi_homed == other.max_multi_homed
    }
}

impl Eq for MxConfig {}

impl QueueName {
    pub fn new(name: impl AsRef<[u8]>) -> Option<Self> {
        let name_bytes = name.as_ref();
        if (1..=8).contains(&name_bytes.len()) {
            let mut bytes = [0; 8];
            bytes[..name_bytes.len()].copy_from_slice(name_bytes);
            QueueName(bytes).into()
        } else {
            None
        }
    }

    pub fn from_bytes(name: &[u8]) -> Option<Self> {
        name.try_into().ok().map(|bytes: [u8; 8]| QueueName(bytes))
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0)
            .unwrap_or_default()
            .trim_end_matches('\0')
    }

    pub fn into_inner(self) -> [u8; 8] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl ArchivedQueueName {
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.0.as_ref())
            .unwrap_or_default()
            .trim_end_matches('\0')
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Default for QueueName {
    fn default() -> Self {
        DEFAULT_QUEUE_NAME
    }
}

impl Display for QueueName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl Display for ArchivedQueueName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl AsRef<[u8]> for QueueName {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
