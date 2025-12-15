/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::throttle::parse_queue_rate_limiter;
use super::*;
use crate::{
    config::server::ServerProtocol,
    expr::{if_block::IfBlock, *},
};
use ahash::AHashMap;
use mail_auth::IpLookupStrategy;
use mail_send::Credentials;
use std::{
    fmt::Display,
    hash::{Hash, Hasher},
    net::IpAddr,
    time::Duration,
};
use throttle::parse_queue_rate_limiter_key;
use utils::config::{Config, utils::ParseValue};

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
    pub id: String,
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

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            route: IfBlock::new::<()>(
                "queue.strategy.route",
                #[cfg(not(feature = "test_mode"))]
                [("is_local_domain('*', rcpt_domain)", "'local'")],
                #[cfg(feature = "test_mode")]
                [],
                "'mx'",
            ),
            queue: IfBlock::new::<()>(
                "queue.strategy.schedule",
                #[cfg(not(feature = "test_mode"))]
                [
                    ("is_local_domain('*', rcpt_domain)", "'local'"),
                    ("source == 'dsn'", "'dsn'"),
                    ("source == 'report'", "'report'"),
                ],
                #[cfg(feature = "test_mode")]
                [],
                #[cfg(not(feature = "test_mode"))]
                "'remote'",
                #[cfg(feature = "test_mode")]
                "'default'",
            ),
            connection: IfBlock::new::<()>("queue.strategy.connection", [], "'default'"),
            tls: IfBlock::new::<()>(
                "queue.strategy.tls",
                #[cfg(not(feature = "test_mode"))]
                [("retry_num > 0 && last_error == 'tls'", "'invalid-tls'")],
                #[cfg(feature = "test_mode")]
                [],
                "'default'",
            ),
            dsn: Dsn {
                name: IfBlock::new::<()>("report.dsn.from-name", [], "'Mail Delivery Subsystem'"),
                address: IfBlock::new::<()>(
                    "report.dsn.from-address",
                    [],
                    "'MAILER-DAEMON@' + config_get('report.domain')",
                ),
                sign: IfBlock::new::<()>(
                    "report.dsn.sign",
                    [],
                    "['rsa-' + config_get('report.domain'), 'ed25519-' + config_get('report.domain')]",
                ),
            },
            inbound_limiters: QueueRateLimiters::default(),
            outbound_limiters: QueueRateLimiters::default(),
            quota: QueueQuotas::default(),
            queue_strategy: Default::default(),
            virtual_queues: Default::default(),
            connection_strategy: Default::default(),
            routing_strategy: Default::default(),
            tls_strategy: Default::default(),
        }
    }
}

impl QueueConfig {
    pub fn parse(config: &mut Config) -> Self {
        let mut queue = QueueConfig::default();
        let rcpt_vars = TokenMap::default().with_variables(SMTP_QUEUE_RCPT_VARS);
        let sender_vars = TokenMap::default().with_variables(SMTP_QUEUE_SENDER_VARS);
        let host_vars = TokenMap::default().with_variables(SMTP_QUEUE_HOST_VARS);

        for (value, key, token_map) in [
            (&mut queue.route, "queue.strategy.route", &rcpt_vars),
            (&mut queue.queue, "queue.strategy.schedule", &rcpt_vars),
            (
                &mut queue.connection,
                "queue.strategy.connection",
                &host_vars,
            ),
            (&mut queue.tls, "queue.strategy.tls", &host_vars),
            (&mut queue.dsn.name, "report.dsn.from-name", &sender_vars),
            (
                &mut queue.dsn.address,
                "report.dsn.from-address",
                &sender_vars,
            ),
            (&mut queue.dsn.sign, "report.dsn.sign", &sender_vars),
        ] {
            if let Some(if_block) = IfBlock::try_parse(config, key, token_map) {
                *value = if_block;
            }
        }

        // Parse strategies
        queue.virtual_queues = parse_virtual_queues(config);
        queue.queue_strategy = parse_queue_strategies(config, &queue.virtual_queues);
        queue.connection_strategy = parse_connection_strategies(config);
        queue.routing_strategy = parse_routing_strategies(config);
        queue.tls_strategy = parse_tls_strategies(config);

        // Parse rate limiters
        queue.inbound_limiters = parse_inbound_rate_limiters(config);
        queue.outbound_limiters = parse_outbound_rate_limiters(config);
        queue.quota = parse_queue_quota(config);
        queue
    }
}

fn parse_queue_strategies(
    config: &mut Config,
    queues: &AHashMap<QueueName, VirtualQueue>,
) -> AHashMap<String, QueueStrategy> {
    let mut entries = AHashMap::new();
    for key in config.sub_keys_with_suffixes(
        "queue.schedule",
        &[
            ".queue-name",
            ".retry",
            ".notify",
            ".expire",
            ".max-attempts",
        ],
    ) {
        if let Some(strategy) = parse_queue_strategy(config, &key, queues) {
            entries.insert(key, strategy);
        }
    }
    entries
}

fn parse_queue_strategy(
    config: &mut Config,
    id: &str,
    queues: &AHashMap<QueueName, VirtualQueue>,
) -> Option<QueueStrategy> {
    let virtual_queue = config
        .property_require::<QueueName>(("queue.schedule", id, "queue-name"))
        .unwrap_or_default();
    if virtual_queue != DEFAULT_QUEUE_NAME && !queues.contains_key(&virtual_queue) {
        config.new_parse_error(
            ("queue.schedule", id, "queue-name"),
            format!("Virtual queue '{virtual_queue}' does not exist."),
        );
        return None;
    }
    let mut retry: Vec<u64> = config
        .properties::<Duration>(("queue.schedule", id, "retry"))
        .into_iter()
        .map(|(_, d)| d.as_secs())
        .collect();
    let mut notify: Vec<u64> = config
        .properties::<Duration>(("queue.schedule", id, "notify"))
        .into_iter()
        .map(|(_, d)| d.as_secs())
        .collect();
    if retry.is_empty() {
        config.new_parse_error(
            ("queue.schedule", id, "retry"),
            "At least one 'retry' duration must be specified.".to_string(),
        );
        retry.push(60 * 60); // Default to 1 minute
    }
    if notify.is_empty() {
        notify.push(10000 * 86400); // Disable notifications by default
    }

    Some(QueueStrategy {
        retry,
        notify,
        expiry: match (
            config.property::<Duration>(("queue.schedule", id, "expire")),
            config.property::<u32>(("queue.schedule", id, "max-attempts")),
        ) {
            (Some(duration), None) => QueueExpiry::Ttl(duration.as_secs()),
            (None, Some(count)) => QueueExpiry::Attempts(count),
            (Some(_), Some(_)) => {
                config.new_parse_error(
                    ("queue.schedule", id, "expire"),
                    "Cannot specify both 'expire' and 'max-attempts'.".to_string(),
                );
                return None;
            }
            (None, None) => QueueExpiry::Ttl(60 * 60 * 24 * 3), // Default to 3 days
        },
        virtual_queue,
    })
}

fn parse_virtual_queues(config: &mut Config) -> AHashMap<QueueName, VirtualQueue> {
    let mut entries = AHashMap::new();
    for key in config.sub_keys("queue.virtual", ".threads-per-node") {
        if let Some(queue_name) = QueueName::new(&key) {
            if let Some(queue) = parse_virtual_queue(config, &key) {
                entries.insert(queue_name, queue);
            }
        } else {
            config.new_parse_error(
                ("queue.virtual", &key, "threads-per-node"),
                format!("Invalid virtual queue name: {key:?}. Must be 1-8 bytes long."),
            );
        }
    }
    entries
}

fn parse_virtual_queue(config: &mut Config, id: &str) -> Option<VirtualQueue> {
    Some(VirtualQueue {
        threads: config
            .property_require::<usize>(("queue.virtual", id, "threads-per-node"))
            .unwrap_or(1),
    })
}

fn parse_routing_strategies(config: &mut Config) -> AHashMap<String, RoutingStrategy> {
    let mut entries = AHashMap::new();
    for key in config.sub_keys("queue.route", ".type") {
        if let Some(strategy) = parse_route(config, &key) {
            entries.insert(key, strategy);
        }
    }
    entries
}

fn parse_route(config: &mut Config, id: &str) -> Option<RoutingStrategy> {
    match config.value_require_non_empty(("queue.route", id, "type"))? {
        "relay" => RoutingStrategy::Relay(RelayConfig {
            address: config.property_require(("queue.route", id, "address"))?,
            port: config
                .property_require(("queue.route", id, "port"))
                .unwrap_or(25),
            protocol: config
                .property_require(("queue.route", id, "protocol"))
                .unwrap_or(ServerProtocol::Smtp),
            auth: if let (Some(username), Some(secret)) = (
                config.value(("queue.route", id, "auth.username")),
                config.value(("queue.route", id, "auth.secret")),
            ) {
                Credentials::new(username.to_string(), secret.to_string()).into()
            } else {
                None
            },
            tls_implicit: config
                .property(("queue.route", id, "tls.implicit"))
                .unwrap_or(true),
            tls_allow_invalid_certs: config
                .property(("queue.route", id, "tls.allow-invalid-certs"))
                .unwrap_or(false),
        })
        .into(),
        "local" => RoutingStrategy::Local.into(),
        "mx" => RoutingStrategy::Mx(MxConfig {
            max_mx: config
                .property(("queue.route", id, "limits.mx"))
                .unwrap_or(5),
            max_multi_homed: config
                .property(("queue.route", id, "limits.multihomed"))
                .unwrap_or(2),
            ip_lookup_strategy: config
                .property(("queue.route", id, "ip-lookup"))
                .unwrap_or(IpLookupStrategy::Ipv4thenIpv6),
        })
        .into(),
        invalid => {
            let details =
                format!("Invalid route type: {invalid:?}. Expected 'relay', 'local', or 'mx'.");
            config.new_parse_error(("queue.route", id, "type"), details);
            None
        }
    }
}

fn parse_tls_strategies(config: &mut Config) -> AHashMap<String, TlsStrategy> {
    let mut entries = AHashMap::new();
    for key in config.sub_keys_with_suffixes(
        "queue.tls",
        &[
            ".allow-invalid-certs",
            ".dane",
            ".starttls",
            ".timeout.tls",
            ".timeout.mta-sts",
        ],
    ) {
        if let Some(strategy) = parse_tls(config, &key) {
            entries.insert(key, strategy);
        }
    }
    entries
}

fn parse_tls(config: &mut Config, id: &str) -> Option<TlsStrategy> {
    Some(TlsStrategy {
        dane: config
            .property::<RequireOptional>(("queue.tls", id, "dane"))
            .unwrap_or(RequireOptional::Optional),
        mta_sts: config
            .property::<RequireOptional>(("queue.tls", id, "mta-sts"))
            .unwrap_or(RequireOptional::Optional),
        tls: config
            .property::<RequireOptional>(("queue.tls", id, "starttls"))
            .unwrap_or(RequireOptional::Optional),
        allow_invalid_certs: config
            .property::<bool>(("queue.tls", id, "allow-invalid-certs"))
            .unwrap_or(false),
        timeout_tls: config
            .property::<Duration>(("queue.tls", id, "timeout.tls"))
            .unwrap_or(Duration::from_secs(3 * 60)),
        timeout_mta_sts: config
            .property::<Duration>(("queue.tls", id, "timeout.mta-sts"))
            .unwrap_or(Duration::from_secs(5 * 60)),
    })
}

fn parse_connection_strategies(config: &mut Config) -> AHashMap<String, ConnectionStrategy> {
    let mut entries = AHashMap::new();
    for key in config.sub_keys_with_suffixes(
        "queue.connection",
        &[
            ".timeout.connect",
            ".timeout.greeting",
            ".timeout.ehlo",
            ".timeout.mail-from",
            ".timeout.rcpt-to",
            ".timeout.data",
            ".ehlo-hostname",
        ],
    ) {
        if let Some(strategy) = parse_connection(config, &key) {
            entries.insert(key, strategy);
        }
    }
    entries
}

fn parse_connection(config: &mut Config, id: &str) -> Option<ConnectionStrategy> {
    let mut source_ipv4 = Vec::new();
    let mut source_ipv6 = Vec::new();

    for (_, ip) in config.properties::<IpAddr>(("queue.connection", id, "source-ips")) {
        let ip_and_host = IpAndHost {
            ip,
            host: config.property::<String>(("queue.source-ip", ip.to_string(), "ehlo-hostname")),
        };

        if ip.is_ipv4() {
            source_ipv4.push(ip_and_host);
        } else {
            source_ipv6.push(ip_and_host);
        }
    }

    Some(ConnectionStrategy {
        source_ipv4,
        source_ipv6,
        ehlo_hostname: config.property::<String>(("queue.connection", id, "ehlo-hostname")),
        timeout_connect: config
            .property::<Duration>(("queue.connection", id, "timeout.connect"))
            .unwrap_or(Duration::from_secs(5 * 60)),
        timeout_greeting: config
            .property::<Duration>(("queue.connection", id, "timeout.greeting"))
            .unwrap_or(Duration::from_secs(5 * 60)),
        timeout_ehlo: config
            .property::<Duration>(("queue.connection", id, "timeout.ehlo"))
            .unwrap_or(Duration::from_secs(5 * 60)),
        timeout_mail: config
            .property::<Duration>(("queue.connection", id, "timeout.mail-from"))
            .unwrap_or(Duration::from_secs(5 * 60)),
        timeout_rcpt: config
            .property::<Duration>(("queue.connection", id, "timeout.rcpt-to"))
            .unwrap_or(Duration::from_secs(5 * 60)),
        timeout_data: config
            .property::<Duration>(("queue.connection", id, "timeout.data"))
            .unwrap_or(Duration::from_secs(10 * 60)),
    })
}

fn parse_inbound_rate_limiters(config: &mut Config) -> QueueRateLimiters {
    let mut throttle = QueueRateLimiters::default();
    let all_throttles = parse_queue_rate_limiter(
        config,
        "queue.limiter.inbound",
        &TokenMap::default().with_variables(SMTP_RCPT_TO_VARS),
        THROTTLE_LISTENER
            | THROTTLE_REMOTE_IP
            | THROTTLE_LOCAL_IP
            | THROTTLE_AUTH_AS
            | THROTTLE_HELO_DOMAIN
            | THROTTLE_RCPT
            | THROTTLE_RCPT_DOMAIN
            | THROTTLE_SENDER
            | THROTTLE_SENDER_DOMAIN,
    );
    for t in all_throttles {
        if (t.keys & (THROTTLE_RCPT | THROTTLE_RCPT_DOMAIN)) != 0
            || t.expr.items().iter().any(|c| {
                matches!(
                    c,
                    ExpressionItem::Variable(V_RECIPIENT | V_RECIPIENT_DOMAIN)
                )
            })
        {
            throttle.rcpt.push(t);
        } else if (t.keys
            & (THROTTLE_SENDER | THROTTLE_SENDER_DOMAIN | THROTTLE_HELO_DOMAIN | THROTTLE_AUTH_AS))
            != 0
            || t.expr.items().iter().any(|c| {
                matches!(
                    c,
                    ExpressionItem::Variable(
                        V_SENDER | V_SENDER_DOMAIN | V_HELO_DOMAIN | V_AUTHENTICATED_AS
                    )
                )
            })
        {
            throttle.sender.push(t);
        } else {
            throttle.remote.push(t);
        }
    }

    throttle
}

fn parse_outbound_rate_limiters(config: &mut Config) -> QueueRateLimiters {
    // Parse throttle
    let mut throttle = QueueRateLimiters::default();

    let all_throttles = parse_queue_rate_limiter(
        config,
        "queue.limiter.outbound",
        &TokenMap::default().with_variables(SMTP_QUEUE_HOST_VARS),
        THROTTLE_RCPT_DOMAIN
            | THROTTLE_SENDER
            | THROTTLE_SENDER_DOMAIN
            | THROTTLE_MX
            | THROTTLE_REMOTE_IP
            | THROTTLE_LOCAL_IP,
    );
    for t in all_throttles {
        if (t.keys & (THROTTLE_MX | THROTTLE_REMOTE_IP | THROTTLE_LOCAL_IP)) != 0
            || t.expr
                .items()
                .iter()
                .any(|c| matches!(c, ExpressionItem::Variable(V_MX | V_REMOTE_IP | V_LOCAL_IP)))
        {
            throttle.remote.push(t);
        } else if (t.keys & (THROTTLE_RCPT_DOMAIN)) != 0
            || t.expr
                .items()
                .iter()
                .any(|c| matches!(c, ExpressionItem::Variable(V_RECIPIENT_DOMAIN)))
        {
            throttle.rcpt.push(t);
        } else {
            throttle.sender.push(t);
        }
    }

    throttle
}

fn parse_queue_quota(config: &mut Config) -> QueueQuotas {
    let mut capacities = QueueQuotas {
        sender: Vec::new(),
        rcpt: Vec::new(),
        rcpt_domain: Vec::new(),
    };

    for quota_id in config.sub_keys("queue.quota", "") {
        if let Some(quota) = parse_queue_quota_item(config, ("queue.quota", &quota_id), &quota_id) {
            if (quota.keys & THROTTLE_RCPT) != 0
                || quota
                    .expr
                    .items()
                    .iter()
                    .any(|c| matches!(c, ExpressionItem::Variable(V_RECIPIENT)))
            {
                capacities.rcpt.push(quota);
            } else if (quota.keys & THROTTLE_RCPT_DOMAIN) != 0
                || quota
                    .expr
                    .items()
                    .iter()
                    .any(|c| matches!(c, ExpressionItem::Variable(V_RECIPIENT_DOMAIN)))
            {
                capacities.rcpt_domain.push(quota);
            } else {
                capacities.sender.push(quota);
            }
        }
    }

    capacities
}

fn parse_queue_quota_item(config: &mut Config, prefix: impl AsKey, id: &str) -> Option<QueueQuota> {
    let prefix = prefix.as_key();

    // Skip disabled throttles
    if !config
        .property::<bool>((prefix.as_str(), "enable"))
        .unwrap_or(true)
    {
        return None;
    }

    let mut keys = 0;
    for (key_, value) in config
        .values((&prefix, "key"))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<Vec<_>>()
    {
        match parse_queue_rate_limiter_key(&value) {
            Ok(key) => {
                if (key
                    & (THROTTLE_RCPT_DOMAIN
                        | THROTTLE_RCPT
                        | THROTTLE_SENDER
                        | THROTTLE_SENDER_DOMAIN))
                    != 0
                {
                    keys |= key;
                } else {
                    let err = format!("Quota key {value:?} is not available in this context");
                    config.new_build_error(key_, err);
                }
            }
            Err(err) => {
                config.new_parse_error(key_, err);
            }
        }
    }

    let quota = QueueQuota {
        id: id.to_string(),
        expr: Expression::try_parse(
            config,
            (prefix.as_str(), "match"),
            &TokenMap::default().with_variables(SMTP_QUEUE_HOST_VARS),
        )
        .unwrap_or_default(),
        keys,
        size: config
            .property::<Option<u64>>((prefix.as_str(), "size"))
            .filter(|&v| v.as_ref().is_some_and(|v| *v > 0))
            .unwrap_or_default(),
        messages: config
            .property::<Option<u64>>((prefix.as_str(), "messages"))
            .filter(|&v| v.as_ref().is_some_and(|v| *v > 0))
            .unwrap_or_default(),
    };

    // Validate
    if quota.size.is_none() && quota.messages.is_none() {
        config.new_parse_error(
            prefix.as_str(),
            concat!(
                "Queue quota needs to define a ",
                "valid 'size' and/or 'messages' property."
            )
            .to_string(),
        );
        None
    } else {
        Some(quota)
    }
}

impl ParseValue for RequireOptional {
    fn parse_value(value: &str) -> Result<Self, String> {
        match value {
            "optional" => Ok(RequireOptional::Optional),
            "require" | "required" => Ok(RequireOptional::Require),
            "disable" | "disabled" | "none" | "false" => Ok(RequireOptional::Disable),
            _ => Err(format!("Invalid TLS option value {:?}.", value,)),
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for RequireOptional {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Integer(2) => Ok(RequireOptional::Optional),
            Variable::Integer(1) => Ok(RequireOptional::Require),
            Variable::Integer(0) => Ok(RequireOptional::Disable),
            _ => Err(()),
        }
    }
}

impl From<RequireOptional> for Constant {
    fn from(value: RequireOptional) -> Self {
        Constant::Integer(match value {
            RequireOptional::Optional => 2,
            RequireOptional::Require => 1,
            RequireOptional::Disable => 0,
        })
    }
}

impl ConstantValue for RequireOptional {
    fn add_constants(token_map: &mut crate::expr::tokenizer::TokenMap) {
        token_map
            .add_constant("optional", RequireOptional::Optional)
            .add_constant("require", RequireOptional::Require)
            .add_constant("required", RequireOptional::Require)
            .add_constant("disable", RequireOptional::Disable)
            .add_constant("disabled", RequireOptional::Disable)
            .add_constant("none", RequireOptional::Disable)
            .add_constant("false", RequireOptional::Disable);
    }
}

impl<'x> TryFrom<Variable<'x>> for IpLookupStrategy {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Integer(value) => match value {
                2 => Ok(IpLookupStrategy::Ipv4Only),
                3 => Ok(IpLookupStrategy::Ipv6Only),
                4 => Ok(IpLookupStrategy::Ipv6thenIpv4),
                5 => Ok(IpLookupStrategy::Ipv4thenIpv6),
                _ => Err(()),
            },
            Variable::String(value) => {
                IpLookupStrategy::parse_value(value.as_str()).map_err(|_| ())
            }
            _ => Err(()),
        }
    }
}

impl From<IpLookupStrategy> for Constant {
    fn from(value: IpLookupStrategy) -> Self {
        Constant::Integer(match value {
            IpLookupStrategy::Ipv4Only => 2,
            IpLookupStrategy::Ipv6Only => 3,
            IpLookupStrategy::Ipv6thenIpv4 => 4,
            IpLookupStrategy::Ipv4thenIpv6 => 5,
        })
    }
}

impl ConstantValue for IpLookupStrategy {
    fn add_constants(token_map: &mut crate::expr::tokenizer::TokenMap) {
        token_map
            .add_constant("ipv4_only", IpLookupStrategy::Ipv4Only)
            .add_constant("ipv6_only", IpLookupStrategy::Ipv6Only)
            .add_constant("ipv6_then_ipv4", IpLookupStrategy::Ipv6thenIpv4)
            .add_constant("ipv4_then_ipv6", IpLookupStrategy::Ipv4thenIpv6);
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

impl ParseValue for QueueName {
    fn parse_value(value: &str) -> Result<Self, String> {
        if let Some(name) = QueueName::new(value.trim().as_bytes()) {
            Ok(name)
        } else {
            Err(format!(
                "Queue name '{value}' is too long. Maximum length is 8 bytes."
            ))
        }
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
