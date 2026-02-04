/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;
use mail_auth::{
    MessageAuthenticator,
    hickory_resolver::{
        TokioResolver,
        config::{NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts},
        name_server::TokioConnectionProvider,
        system_conf::read_system_conf,
    },
};
use registry::schema::{
    enums::{DnsResolverProtocol, PolicyEnforcement},
    prelude::Object,
    structs::{DnsResolver, MtaSts},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    hash::{DefaultHasher, Hash, Hasher},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};
use store::registry::bootstrap::Bootstrap;
use utils::cache::CacheItemWeight;

pub struct Resolvers {
    pub dns: MessageAuthenticator,
    pub dnssec: DnssecResolver,
}

#[derive(Clone)]
pub struct DnssecResolver {
    pub resolver: TokioResolver,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsaEntry {
    pub is_end_entity: bool,
    pub is_sha256: bool,
    pub is_spki: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tlsa {
    pub entries: Vec<TlsaEntry>,
    pub has_end_entities: bool,
    pub has_intermediates: bool,
}

#[derive(Debug, PartialEq, Eq, Hash, Default, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    Enforce,
    Testing,
    #[default]
    None,
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MxPattern {
    Equals(String),
    StartsWith(String),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub mode: Mode,
    pub mx: Box<[MxPattern]>,
    pub max_age: u64,
}

impl CacheItemWeight for Tlsa {
    fn weight(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| (entry.data.len() + std::mem::size_of::<TlsaEntry>()) as u64)
            .sum::<u64>()
            + std::mem::size_of::<Tlsa>() as u64
    }
}

impl CacheItemWeight for Policy {
    fn weight(&self) -> u64 {
        (std::mem::size_of::<Policy>()
            + self
                .mx
                .iter()
                .map(|mx| match mx {
                    MxPattern::Equals(t) => t.len(),
                    MxPattern::StartsWith(t) => t.len(),
                })
                .sum::<usize>()) as u64
    }
}

impl Resolvers {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let mut resolver_config: ResolverConfig;
        let mut opts = ResolverOpts::default();

        match bp.setting_infallible::<DnsResolver>().await {
            DnsResolver::System(resolver) => match read_system_conf() {
                Ok((config, options)) => {
                    resolver_config = config;
                    opts = options;
                    opts.num_concurrent_reqs = resolver.concurrency as usize;
                    opts.timeout = resolver.timeout.into_inner();
                    opts.preserve_intermediates = resolver.preserve_intermediates;
                    opts.try_tcp_on_error = resolver.tcp_on_error;
                    opts.attempts = resolver.attempts as usize;
                    opts.edns0 = resolver.enable_edns;
                }
                Err(err) => {
                    bp.build_error(
                        Object::DnsResolver.singleton(),
                        format!("Failed to read system DNS config: {err}"),
                    );
                    resolver_config = ResolverConfig::cloudflare();
                }
            },
            DnsResolver::Custom(resolver) => {
                resolver_config = ResolverConfig::default();

                for server in resolver.servers {
                    resolver_config.add_name_server(NameServerConfig::new(
                        SocketAddr::new(server.address.into_inner(), server.port as u16),
                        match server.protocol {
                            DnsResolverProtocol::Udp => ProtocolConfig::Udp,
                            DnsResolverProtocol::Tcp => ProtocolConfig::Tcp,
                            DnsResolverProtocol::Tls => ProtocolConfig::Tls {
                                server_name: Arc::from(server.address.to_string()),
                            },
                        },
                    ));
                }

                opts.num_concurrent_reqs = resolver.concurrency as usize;
                opts.timeout = resolver.timeout.into_inner();
                opts.preserve_intermediates = resolver.preserve_intermediates;
                opts.try_tcp_on_error = resolver.tcp_on_error;
                opts.attempts = resolver.attempts as usize;
                opts.edns0 = resolver.enable_edns;
            }
            DnsResolver::Cloudflare(resolver) => {
                resolver_config = if resolver.use_tls {
                    ResolverConfig::cloudflare_tls()
                } else {
                    ResolverConfig::cloudflare()
                };

                opts.num_concurrent_reqs = resolver.concurrency as usize;
                opts.timeout = resolver.timeout.into_inner();
                opts.preserve_intermediates = resolver.preserve_intermediates;
                opts.try_tcp_on_error = resolver.tcp_on_error;
                opts.attempts = resolver.attempts as usize;
                opts.edns0 = resolver.enable_edns;
            }
            DnsResolver::Quad9(resolver) => {
                resolver_config = if resolver.use_tls {
                    ResolverConfig::quad9_tls()
                } else {
                    ResolverConfig::quad9()
                };
                opts.num_concurrent_reqs = resolver.concurrency as usize;
                opts.timeout = resolver.timeout.into_inner();
                opts.preserve_intermediates = resolver.preserve_intermediates;
                opts.try_tcp_on_error = resolver.tcp_on_error;
                opts.attempts = resolver.attempts as usize;
                opts.edns0 = resolver.enable_edns;
            }
            DnsResolver::Google(resolver) => {
                resolver_config = ResolverConfig::google();
                opts.num_concurrent_reqs = resolver.concurrency as usize;
                opts.timeout = resolver.timeout.into_inner();
                opts.preserve_intermediates = resolver.preserve_intermediates;
                opts.try_tcp_on_error = resolver.tcp_on_error;
                opts.attempts = resolver.attempts as usize;
                opts.edns0 = resolver.enable_edns;
            }
        }

        // We already have a cache, so disable the built-in cache
        opts.cache_size = 0;

        // Prepare DNSSEC resolver options
        let config_dnssec = resolver_config.clone();
        let mut opts_dnssec = opts.clone();
        opts_dnssec.validate = true;

        Resolvers {
            dns: MessageAuthenticator::new(resolver_config, opts).unwrap(),
            dnssec: DnssecResolver {
                resolver: TokioResolver::builder_with_config(
                    config_dnssec,
                    TokioConnectionProvider::default(),
                )
                .with_options(opts_dnssec)
                .build(),
            },
        }
    }
}

impl Policy {
    pub async fn try_parse(bp: &mut Bootstrap) -> Option<Self> {
        let mta = bp.setting_infallible::<MtaSts>().await;
        if !mta.mx_hosts.is_empty() {
            let mut policy = Policy {
                id: Default::default(),
                mode: match mta.mode {
                    PolicyEnforcement::Enforce => Mode::Enforce,
                    PolicyEnforcement::Testing => Mode::Testing,
                    PolicyEnforcement::Disable => Mode::None,
                },
                mx: mta
                    .mx_hosts
                    .into_iter()
                    .map(|mx| {
                        if let Some(mx) = mx.strip_prefix("*.") {
                            MxPattern::StartsWith(mx.to_string())
                        } else {
                            MxPattern::Equals(mx)
                        }
                    })
                    .collect(),
                max_age: mta.max_age.into_inner().as_secs(),
            };

            policy.mx.sort_unstable();
            policy.id = policy.hash().to_string();

            Some(policy)
        } else {
            None
        }
    }

    pub fn try_build<I, T>(mut self, names: I) -> Option<Self>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        if self.mx.is_empty() {
            for name in names {
                let name = name.as_ref();
                if let Some(domain) = name.strip_prefix('.') {
                    self.mx.push(MxPattern::StartsWith(domain.to_string()));
                } else if name != "*" && !name.is_empty() {
                    self.mx.push(MxPattern::Equals(name.to_string()));
                }
            }

            if !self.mx.is_empty() {
                self.mx.sort_unstable();
                self.id = self.hash().to_string();
                Some(self)
            } else {
                None
            }
        } else {
            Some(self)
        }
    }

    fn hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        self.mode.hash(&mut s);
        self.max_age.hash(&mut s);
        self.mx.hash(&mut s);
        s.finish()
    }
}

impl Server {
    pub fn build_mta_sts_policy(&self) -> Option<Policy> {
        self.core
            .smtp
            .session
            .mta_sts_policy
            .clone()
            .and_then(|policy| {
                policy.try_build(
                    self.inner
                        .data
                        .tls_certificates
                        .load()
                        .keys()
                        .filter(|key| {
                            !key.starts_with("mta-sts.")
                                && !key.starts_with("autoconfig.")
                                && !key.starts_with("autodiscover.")
                        }),
                )
            })
    }
}

impl FromStr for Mode {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "enforce" => Ok(Self::Enforce),
            "testing" | "test" => Ok(Self::Testing),
            "none" => Ok(Self::None),
            _ => Err(format!("Invalid mode value {value:?}")),
        }
    }
}

impl Default for Resolvers {
    fn default() -> Self {
        let (config, opts) = match read_system_conf() {
            Ok(conf) => conf,
            Err(_) => (ResolverConfig::cloudflare(), ResolverOpts::default()),
        };

        let config_dnssec = config.clone();
        let mut opts_dnssec = opts.clone();
        opts_dnssec.validate = true;

        Self {
            dns: MessageAuthenticator::new(config, opts).expect("Failed to build DNS resolver"),
            dnssec: DnssecResolver {
                resolver: TokioResolver::builder_with_config(
                    config_dnssec,
                    TokioConnectionProvider::default(),
                )
                .with_options(opts_dnssec)
                .build(),
            },
        }
    }
}

impl Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("version: STSv1\r\n")?;
        f.write_str("mode: ")?;
        match self.mode {
            Mode::Enforce => f.write_str("enforce")?,
            Mode::Testing => f.write_str("testing")?,
            Mode::None => unreachable!(),
        }
        f.write_str("\r\nmax_age: ")?;
        self.max_age.fmt(f)?;
        f.write_str("\r\n")?;

        for mx in &self.mx {
            f.write_str("mx: ")?;
            mx.fmt(f)?;
            f.write_str("\r\n")?;
        }

        Ok(())
    }
}

impl Display for MxPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MxPattern::Equals(mx) => f.write_str(mx),
            MxPattern::StartsWith(mx) => {
                f.write_str("*.")?;
                f.write_str(mx)
            }
        }
    }
}

impl Clone for Resolvers {
    fn clone(&self) -> Self {
        Self {
            dns: self.dns.clone(),
            dnssec: self.dnssec.clone(),
        }
    }
}
