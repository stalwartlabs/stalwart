/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::expr::{if_block::IfBlock, tokenizer::TokenMap};
use ahash::AHashSet;
use std::{hash::Hasher, time::Duration};
use utils::config::{Config, Rate, http::parse_http_headers, utils::ParseValue};
use xxhash_rust::xxh3::Xxh3Builder;

#[derive(Clone)]
pub struct Network {
    pub node_id: u64,
    pub roles: ClusterRoles,
    pub server_name: String,
    pub report_domain: String,
    pub security: Security,
    pub http: Http,
    pub contact_form: Option<ContactForm>,
    pub asn_geo_lookup: AsnGeoLookupConfig,
}

#[derive(Clone)]
pub struct Http {
    pub rate_authenticated: Option<Rate>,
    pub rate_anonymous: Option<Rate>,
    pub response_url: IfBlock,
    pub allowed_endpoint: IfBlock,
    pub response_headers: Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>,
    pub use_forwarded: bool,
}

#[derive(Clone)]
pub struct ContactForm {
    pub rcpt_to: Vec<String>,
    pub max_size: usize,
    pub rate: Option<Rate>,
    pub validate_domain: bool,
    pub from_email: FieldOrDefault,
    pub from_subject: FieldOrDefault,
    pub from_name: FieldOrDefault,
    pub field_honey_pot: Option<String>,
}

#[derive(Clone, Default)]
pub struct ClusterRoles {
    pub purge_stores: ClusterRole,
    pub purge_accounts: ClusterRole,
    pub push_notifications: ClusterRole,
    pub fts_indexing: ClusterRole,
    pub spam_training: ClusterRole,
    pub imip_processing: ClusterRole,
    pub merge_threads: ClusterRole,
    pub calendar_alerts: ClusterRole,
    pub renew_acme: ClusterRole,
    pub calculate_metrics: ClusterRole,
    pub push_metrics: ClusterRole,
}

#[derive(Clone, Copy, Default)]
pub enum ClusterRole {
    #[default]
    Enabled,
    Disabled,
    Sharded {
        shard_id: u32,
        total_shards: u32,
    },
}

#[derive(Clone, Default)]
pub enum AsnGeoLookupConfig {
    Resource {
        expires: Duration,
        timeout: Duration,
        max_size: usize,
        headers: HeaderMap,
        asn_resources: Vec<String>,
        geo_resources: Vec<String>,
    },
    Dns {
        zone_ipv4: String,
        zone_ipv6: String,
        separator: String,
        index_asn: usize,
        index_asn_name: Option<usize>,
        index_country: Option<usize>,
    },
    #[default]
    Disabled,
}

#[derive(Clone)]
pub struct FieldOrDefault {
    pub field: Option<String>,
    pub default: String,
}

pub(crate) const HTTP_VARS: &[u32; 11] = &[
    ExpressionVariable::Listener,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemotePort,
    ExpressionVariable::LocalIp,
    ExpressionVariable::LocalPort,
    ExpressionVariable::Protocol,
    ExpressionVariable::IsTls,
    ExpressionVariable::Url,
    ExpressionVariable::UrlPath,
    ExpressionVariable::Headers,
    ExpressionVariable::Method,
];

impl Default for Network {
    fn default() -> Self {
        Self {
            security: Default::default(),
            contact_form: None,
            node_id: 1,
            http_response_url: IfBlock::new_default(
                "http.url",
                [],
                "protocol + '://' + config_get('server.hostname') + ':' + local_port",
            ),
            http_allowed_endpoint: IfBlock::new_default("http.allowed-endpoint", [], "200"),
            asn_geo_lookup: AsnGeoLookupConfig::Disabled,
            server_name: Default::default(),
            report_domain: Default::default(),
            roles: ClusterRoles::default(),
        }
    }
}

impl ContactForm {
    pub fn parse(bp: &mut Bootstrap) -> Option<Self> {
        if !config
            .property_or_default::<bool>("form.enable", "false")
            .unwrap_or_default()
        {
            return None;
        }

        let form = ContactForm {
            rcpt_to: config
                .values("form.deliver-to")
                .filter_map(|(_, addr)| {
                    if addr.contains('@') && addr.contains('.') {
                        Some(addr.trim().to_lowercase())
                    } else {
                        None
                    }
                })
                .collect(),
            max_size: config.property("form.max-size").unwrap_or(100 * 1024),
            validate_domain: config
                .property_or_default::<bool>("form.validate-domain", "true")
                .unwrap_or(true),
            from_email: FieldOrDefault::parse(config, "form.email", "postmaster@localhost"),
            from_subject: FieldOrDefault::parse(config, "form.subject", "Contact form submission"),
            from_name: FieldOrDefault::parse(config, "form.name", "Anonymous"),
            field_honey_pot: config.value("form.honey-pot.field").map(|v| v.into()),
            rate: config
                .property_or_default::<Option<Rate>>("form.rate-limit", "5/1h")
                .unwrap_or_default(),
        };

        if !form.rcpt_to.is_empty() {
            Some(form)
        } else {
            config.new_build_error("form.deliver-to", "No valid email addresses found");
            None
        }
    }
}

impl FieldOrDefault {
    pub fn parse(bp: &mut Bootstrap, key: &str, default: &str) -> Self {
        FieldOrDefault {
            field: config.value((key, "field")).map(|s| s.to_string()),
            default: config
                .value((key, "default"))
                .unwrap_or(default)
                .to_string(),
        }
    }
}

impl Network {
    pub fn parse(bp: &mut Bootstrap) -> Self {
        let server_name = config
            .value("server.hostname")
            .map(|v| v.to_string())
            .or_else(|| {
                config
                    .value("lookup.default.hostname")
                    .map(|v| v.to_lowercase())
            })
            .unwrap_or_else(|| {
                hostname::get()
                    .map(|v| v.to_string_lossy().to_lowercase())
                    .unwrap_or_else(|_| "localhost".to_string())
            });
        let report_domain = config
            .value("report.domain")
            .map(|v| v.to_lowercase())
            .or_else(|| {
                config
                    .value("lookup.default.domain")
                    .map(|v| v.to_lowercase())
            })
            .unwrap_or_else(|| {
                psl::domain_str(&server_name)
                    .unwrap_or(server_name.as_str())
                    .to_string()
            });

        let mut network = Network {
            node_id: config.property("cluster.node-id").unwrap_or(1),
            report_domain,
            server_name,
            security: Security::parse(config),
            contact_form: ContactForm::parse(config),
            asn_geo_lookup: AsnGeoLookupConfig::parse(config).unwrap_or_default(),
            ..Default::default()
        };
        let token_map = &TokenMap::default().with_variables(HTTP_VARS);

        // Node roles
        for (value, key) in [
            (
                &mut network.roles.purge_stores,
                "cluster.roles.purge.stores",
            ),
            (
                &mut network.roles.purge_accounts,
                "cluster.roles.purge.accounts",
            ),
            (&mut network.roles.renew_acme, "cluster.roles.acme.renew"),
            (
                &mut network.roles.calculate_metrics,
                "cluster.roles.metrics.calculate",
            ),
            (
                &mut network.roles.push_metrics,
                "cluster.roles.metrics.push",
            ),
            (
                &mut network.roles.push_notifications,
                "cluster.roles.push-notifications",
            ),
            (
                &mut network.roles.fts_indexing,
                "cluster.roles.fts-indexing",
            ),
            (
                &mut network.roles.spam_training,
                "cluster.roles.spam-training",
            ),
            (
                &mut network.roles.imip_processing,
                "cluster.roles.imip-processing",
            ),
            (
                &mut network.roles.calendar_alerts,
                "cluster.roles.calendar-alerts",
            ),
            (
                &mut network.roles.merge_threads,
                "cluster.roles.merge-threads",
            ),
        ] {
            let shards = config
                .properties::<NodeList>(key)
                .into_iter()
                .map(|(_, v)| v)
                .collect::<Vec<_>>();
            let shard_size = shards.len() as u32;
            let mut found_node = false;
            for (shard_id, shard) in shards.iter().enumerate() {
                if shard.0.contains(&network.node_id) {
                    if shard_size > 1 {
                        *value = ClusterRole::Sharded {
                            shard_id: shard_id as u32,
                            total_shards: shard_size,
                        };
                    }
                    found_node = true;
                    break;
                }
            }

            if !shards.is_empty() && !found_node {
                *value = ClusterRole::Disabled;
            }
        }

        for (value, key) in [
            (&mut network.http_response_url, "http.url"),
            (&mut network.http_allowed_endpoint, "http.allowed-endpoint"),
        ] {
            if let Some(if_block) = IfBlock::try_parse(config, key, token_map) {
                *value = if_block;
            }
        }

        network
    }
}

impl Http {
    pub fn parse(bp: &mut Bootstrap) -> Option<Self> {
        // Parse HTTP headers
        let mut http_headers = config
            .values("http.headers")
            .map(|(_, v)| {
                if let Some((k, v)) = v.split_once(':') {
                    Ok((
                        hyper::header::HeaderName::from_str(k.trim()).map_err(|err| {
                            format!("Invalid header found in property \"http.headers\": {}", err)
                        })?,
                        hyper::header::HeaderValue::from_str(v.trim()).map_err(|err| {
                            format!("Invalid header found in property \"http.headers\": {}", err)
                        })?,
                    ))
                } else {
                    Err(format!(
                        "Invalid header found in property \"http.headers\": {}",
                        v
                    ))
                }
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(|e| config.new_parse_error("http.headers", e))
            .unwrap_or_default();
        // Add permissive CORS headers
        if config
            .property::<bool>("http.permissive-cors")
            .unwrap_or(false)
        {
            http_headers.push((
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                hyper::header::HeaderValue::from_static("*"),
            ));
            http_headers.push((
                hyper::header::ACCESS_CONTROL_ALLOW_HEADERS,
                hyper::header::HeaderValue::from_static(
                    "Authorization, Content-Type, Accept, X-Requested-With",
                ),
            ));
            http_headers.push((
                hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
                hyper::header::HeaderValue::from_static(
                    "POST, GET, PATCH, PUT, DELETE, HEAD, OPTIONS",
                ),
            ));
        }

        // Add HTTP Strict Transport Security
        if config.property::<bool>("http.hsts").unwrap_or(false) {
            http_headers.push((
                hyper::header::STRICT_TRANSPORT_SECURITY,
                hyper::header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            ));
        }
        //            http_use_forwarded: config.property("http.use-x-forwarded").unwrap_or(false),

        /*

           rate_authenticated: jmap
               .property_or_default::<Option<Rate>>("http.rate-limit.account", "1000/1m")
               .unwrap_or_default(),
           rate_anonymous: jmap
               .property_or_default::<Option<Rate>>("http.rate-limit.anonymous", "100/1m")
               .unwrap_or_default(),

        */

        todo!()
    }
}

struct NodeList(AHashSet<u64>);

impl ParseValue for NodeList {
    fn parse_value(value: &str) -> utils::config::Result<Self> {
        value
            .split(',')
            .map(|s| s.trim().parse::<u64>().map_err(|e| e.to_string()))
            .collect::<Result<AHashSet<u64>, String>>()
            .map(NodeList)
    }
}

impl AsnGeoLookupConfig {
    pub fn parse(bp: &mut Bootstrap) -> Option<Self> {
        match config.value("asn.type")? {
            "dns" => AsnGeoLookupConfig::Dns {
                zone_ipv4: config.value_require_non_empty("asn.zone.ipv4")?.to_string(),
                zone_ipv6: config.value_require_non_empty("asn.zone.ipv6")?.to_string(),
                separator: config.value_require_non_empty("asn.separator")?.to_string(),
                index_asn: config.property_require("asn.index.asn")?,
                index_asn_name: config.property("asn.index.asn-name"),
                index_country: config.property("asn.index.country"),
            }
            .into(),
            "resource" => {
                let asn_resources = config
                    .values("asn.urls.asn")
                    .map(|(_, v)| v.to_string())
                    .collect::<Vec<_>>();
                let geo_resources = config
                    .values("asn.urls.geo")
                    .map(|(_, v)| v.to_string())
                    .collect::<Vec<_>>();

                if asn_resources.is_empty() && geo_resources.is_empty() {
                    config.new_build_error("asn.urls", "No resources found");
                    return None;
                }

                AsnGeoLookupConfig::Resource {
                    headers: parse_http_headers(config, "asn"),
                    expires: config.property_or_default::<Duration>("asn.expires", "1d")?,
                    timeout: config.property_or_default::<Duration>("asn.timeout", "5m")?,
                    max_size: config.property("asn.max-size").unwrap_or(100 * 1024 * 1024),
                    asn_resources,
                    geo_resources,
                }
                .into()
            }
            "disable" | "disabled" | "none" | "false" => AsnGeoLookupConfig::Disabled.into(),
            _ => {
                config.new_build_error("asn.type", "Invalid value");
                None
            }
        }
    }
}

impl ClusterRole {
    pub fn is_enabled_or_sharded(&self) -> bool {
        matches!(self, ClusterRole::Enabled | ClusterRole::Sharded { .. })
    }

    pub fn is_enabled_for_integer(&self, value: u32) -> bool {
        match self {
            ClusterRole::Enabled => true,
            ClusterRole::Disabled => false,
            ClusterRole::Sharded {
                shard_id,
                total_shards,
            } => (value % total_shards) == *shard_id,
        }
    }

    pub fn is_enabled_for_hash(&self, item: &impl std::hash::Hash) -> bool {
        match self {
            ClusterRole::Enabled => true,
            ClusterRole::Disabled => false,
            ClusterRole::Sharded {
                shard_id,
                total_shards,
            } => {
                let mut hasher = Xxh3Builder::new().with_seed(191179).build();
                item.hash(&mut hasher);
                hasher.finish() % (*total_shards as u64) == *shard_id as u64
            }
        }
    }
}
