/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::{
    expr::if_block::{BootstrapExprExt, IfBlock},
    network::{
        autoconfig::pacc::{
            Authentication, Configuration, HttpServer, Info, Logo, OAuthPublic, Protocols,
            Provider, TextServer,
        },
        security::Security,
    },
};
use registry::schema::{
    enums::{AcmeChallengeType, ClusterTaskType, ProviderInfo, ServiceProtocol},
    prelude::{ObjectType, Property},
    structs::{
        self, AcmeProvider, Asn, ClusterTaskGroup, HttpForm, MailExchanger, Rate, Service,
        SystemSettings, TaskManager,
    },
};
use std::{str::FromStr, time::Duration};
use utils::map::vec_map::VecMap;

#[derive(Clone)]
pub struct Network {
    pub node_id: u64,
    pub roles: ClusterRoles,
    pub server_name: String,
    pub security: Security,
    pub http: Http,
    pub contact_form: Option<ContactForm>,
    pub asn_geo_lookup: AsnGeoLookupConfig,
    pub task_manager: TaskManager,
    pub has_acme_tls_challenge: bool,
    pub has_acme_http_challenge: bool,
    pub info: NetworkInfo,
}

#[derive(Clone)]
pub struct NetworkInfo {
    pub pacc: Pacc,
    pub mxs: Vec<MailExchanger>,
    pub services: VecMap<ServiceProtocol, Service>,
}

#[derive(Clone)]
pub struct Pacc {
    pub prefix: String,
    pub suffix: String,
}

#[derive(Clone)]
pub struct Http {
    pub rate_authenticated: Option<Rate>,
    pub rate_anonymous: Option<Rate>,
    pub url_https: String,
    pub allowed_endpoint: IfBlock,
    pub response_headers: Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>,
    pub use_forwarded: bool,
    pub redirect_root: Option<String>,
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

#[derive(Clone)]
pub struct ClusterRoles {
    pub store_maintenance: bool,
    pub account_maintenance: bool,
    pub push_notifications: bool,
    pub search_indexing: bool,
    pub spam_training: bool,
    pub metrics_calculate: bool,
    pub metrics_push: bool,
    pub outbound_mta: bool,
    pub task_scheduler: bool,
    pub task_manager: bool,
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

impl ContactForm {
    pub async fn parse(bp: &mut Bootstrap) -> Option<Self> {
        let form = bp.setting_infallible::<HttpForm>().await;

        if !form.enable {
            return None;
        } else if form.deliver_to.is_empty() {
            bp.build_error(
                ObjectType::HttpForm.singleton(),
                "Contact form is enabled but no recipient addresses are configured",
            );
            return None;
        }

        Some(ContactForm {
            rcpt_to: form.deliver_to.into_inner(),
            max_size: form.max_size as usize,
            validate_domain: form.validate_domain,
            from_email: FieldOrDefault {
                field: form.field_email,
                default: form.default_from_address,
            },
            from_subject: FieldOrDefault {
                field: form.field_subject,
                default: form.default_subject,
            },
            from_name: FieldOrDefault {
                field: form.field_name,
                default: form.default_name,
            },
            field_honey_pot: form.field_honey_pot,
            rate: form.rate_limit,
        })
    }
}

impl Network {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let system = bp.setting_infallible::<SystemSettings>().await;
        let mut has_acme_tls_challenge = false;
        let mut has_acme_http_challenge = false;
        let mut has_acme_challenges = false;

        for provider in bp.list_infallible::<AcmeProvider>().await {
            match provider.object.challenge_type {
                AcmeChallengeType::Http01 => has_acme_http_challenge = true,
                AcmeChallengeType::TlsAlpn01 => has_acme_tls_challenge = true,
                _ => {}
            }
            has_acme_challenges = true;
        }

        if !has_acme_challenges {
            // Assume this is an initial deployment and optimistically set both to true
            // to avoid requiring a reload after ACME providers are added
            has_acme_http_challenge = true;
            has_acme_tls_challenge = true;
        }

        const SPLIT_HERE: &str = "$$__SPLIT_HERE__$$";
        let mut pacc = Configuration {
            protocols: Protocols::default(),
            authentication: Some(Authentication {
                oauth_public: Some(OAuthPublic {
                    issuer: SPLIT_HERE.to_string(),
                }),
                password: true,
            }),
            info: Info {
                provider: Provider {
                    name: "Stalwart".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let default_hostname = if !system.default_hostname.is_empty() {
            system.default_hostname.as_str()
        } else {
            bp.registry.local_hostname()
        };
        let mut http_host = default_hostname.to_string();
        for (service, details) in &system.services {
            let hostname = details.hostname.as_deref().unwrap_or(default_hostname);

            match service {
                ServiceProtocol::Jmap => {
                    if hostname != http_host {
                        http_host = hostname.to_string();
                    }
                    pacc.protocols.jmap = HttpServer {
                        url: format!("https://{hostname}/jmap/session",),
                    }
                    .into();
                }
                ServiceProtocol::Caldav => {
                    pacc.protocols.caldav = HttpServer {
                        url: format!("https://{hostname}/dav/cal/",),
                    }
                    .into();
                }
                ServiceProtocol::Carddav => {
                    pacc.protocols.carddav = HttpServer {
                        url: format!("https://{hostname}/dav/card/",),
                    }
                    .into();
                }
                ServiceProtocol::Webdav => {
                    pacc.protocols.webdav = HttpServer {
                        url: format!("https://{hostname}/dav/file/",),
                    }
                    .into();
                }
                ServiceProtocol::Imap => {
                    pacc.protocols.imap = TextServer {
                        host: hostname.to_string(),
                    }
                    .into();
                }
                ServiceProtocol::Pop3 => {
                    pacc.protocols.pop3 = TextServer {
                        host: hostname.to_string(),
                    }
                    .into();
                }
                ServiceProtocol::Smtp => {
                    pacc.protocols.smtp = TextServer {
                        host: hostname.to_string(),
                    }
                    .into();
                }
                ServiceProtocol::Managesieve => {
                    pacc.protocols.managesieve = TextServer {
                        host: hostname.to_string(),
                    }
                    .into();
                }
            }
        }

        for (tag, text) in system.provider_info {
            match tag {
                ProviderInfo::ProviderName => pacc.info.provider.name = text,
                ProviderInfo::ProviderShortName => pacc.info.provider.short_name = Some(text),
                ProviderInfo::UserDocumentation => {
                    pacc.info.help.get_or_insert_default().documentation = Some(text)
                }
                ProviderInfo::DeveloperDocumentation => {
                    pacc.info.help.get_or_insert_default().developer = Some(text)
                }
                ProviderInfo::ContactUri => {
                    pacc.info
                        .help
                        .get_or_insert_default()
                        .contact
                        .get_or_insert_default()
                        .push(text);
                }
                ProviderInfo::LogoUrl => {
                    let logo = pacc.info.provider.logo.get_or_insert_default();
                    if logo.is_empty() {
                        logo.push(Logo {
                            url: text,
                            ..Default::default()
                        });
                    } else {
                        logo[0].url = text;
                    }
                }
                ProviderInfo::LogoWidth => {
                    let logo = pacc.info.provider.logo.get_or_insert_default();
                    if logo.is_empty() {
                        logo.push(Logo {
                            width: text.parse().ok(),
                            ..Default::default()
                        });
                    } else {
                        logo[0].width = text.parse().ok();
                    }
                }
                ProviderInfo::LogoHeight => {
                    let logo = pacc.info.provider.logo.get_or_insert_default();
                    if logo.is_empty() {
                        logo.push(Logo {
                            height: text.parse().ok(),
                            ..Default::default()
                        });
                    } else {
                        logo[0].height = text.parse().ok();
                    }
                }
            }
        }

        let (prefix, suffix) = serde_json::to_string(&pacc)
            .unwrap_or_default()
            .rsplit_once(SPLIT_HERE)
            .map(|(prefix, suffix)| (prefix.to_string(), suffix.to_string()))
            .unwrap();
        let mut network = Network {
            node_id: bp.node_id() as u64,
            server_name: default_hostname.to_string(),
            security: Security::parse(bp).await,
            contact_form: ContactForm::parse(bp).await,
            asn_geo_lookup: AsnGeoLookupConfig::parse(bp).await.unwrap_or_default(),
            roles: ClusterRoles::default(),
            http: Http::parse(bp, &http_host).await,
            task_manager: bp.setting_infallible::<TaskManager>().await,
            has_acme_tls_challenge,
            has_acme_http_challenge,
            info: NetworkInfo {
                mxs: system.mail_exchangers.into_iter().collect(),
                services: system.services,
                pacc: Pacc { prefix, suffix },
            },
        };

        if let Some(role) = &bp.role {
            match &role.tasks {
                ClusterTaskGroup::EnableAll => {}
                ClusterTaskGroup::DisableAll => {
                    for network_role in network.roles.all_mut() {
                        *network_role = false;
                    }
                }
                ClusterTaskGroup::EnableSome(group) => {
                    for network_role in network.roles.all_mut() {
                        *network_role = false;
                    }
                    for task_type in group.task_types.iter() {
                        network.roles.set_role(*task_type, true);
                    }
                }
                ClusterTaskGroup::DisableSome(group) => {
                    for task_type in group.task_types.iter() {
                        network.roles.set_role(*task_type, false);
                    }
                }
            }
        }

        network
    }
}

impl Http {
    #[cfg_attr(
        any(feature = "dev_mode", feature = "test_mode"),
        allow(unused_variables)
    )]
    pub async fn parse(bp: &mut Bootstrap, server_name: &str) -> Self {
        let http = bp.setting_infallible::<structs::Http>().await;

        // Parse HTTP headers
        let mut http_headers = http
            .response_headers
            .iter()
            .map(|(k, v)| {
                Ok((
                    hyper::header::HeaderName::from_str(k.trim()).map_err(|err| {
                        format!("Invalid header found in property \"http.headers\": {}", err)
                    })?,
                    hyper::header::HeaderValue::from_str(v.trim()).map_err(|err| {
                        format!("Invalid header found in property \"http.headers\": {}", err)
                    })?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(|e| {
                bp.build_error(
                    ObjectType::Http.singleton(),
                    format!("Failed to parse HTTP headers: {}", e),
                )
            })
            .unwrap_or_default();

        // Add permissive CORS headers
        #[cfg(feature = "dev_mode")]
        let use_permissive_cors = true;

        #[cfg(not(feature = "dev_mode"))]
        let use_permissive_cors = http.use_permissive_cors || bp.registry.is_recovery_mode();

        if use_permissive_cors {
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
        if http.enable_hsts {
            http_headers.push((
                hyper::header::STRICT_TRANSPORT_SECURITY,
                hyper::header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            ));
        }

        #[cfg(any(feature = "dev_mode", feature = "test_mode"))]
        let server_name = "127.0.0.1";

        Http {
            url_https: if !bp.registry.is_recovery_mode() {
                if let Some(url) = bp.registry.public_url() {
                    url.to_string()
                } else {
                    format!("https://{server_name}")
                }
            } else {
                String::new()
            },
            allowed_endpoint: if bp.registry.is_recovery_mode() {
                IfBlock::empty(ObjectType::Http.singleton(), Property::AllowedEndpoints)
            } else {
                bp.compile_expr(ObjectType::Http.singleton(), &http.ctx_allowed_endpoints())
            },
            rate_authenticated: if bp.registry.is_recovery_mode() {
                None
            } else {
                http.rate_limit_authenticated
            },
            rate_anonymous: if bp.registry.is_recovery_mode() {
                None
            } else {
                http.rate_limit_anonymous
            },
            response_headers: http_headers,
            use_forwarded: http.use_x_forwarded,
            redirect_root: http.redirect_root,
        }
    }
}

impl AsnGeoLookupConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Option<Self> {
        match bp.setting_infallible::<Asn>().await {
            Asn::Resource(asn) => Some(AsnGeoLookupConfig::Resource {
                expires: asn.expires.into_inner(),
                timeout: asn.timeout.into_inner(),
                max_size: asn.max_size as usize,
                headers: asn
                    .http_auth
                    .build_headers(asn.http_headers, None)
                    .await
                    .map_err(|err| {
                        bp.build_error(
                            ObjectType::Asn.singleton(),
                            format!("Unable to build HTTP headers: {}", err),
                        )
                    })
                    .ok()?,
                asn_resources: asn.asn_urls.into_inner(),
                geo_resources: asn.geo_urls.into_inner(),
            }),
            Asn::Dns(asn) => Some(AsnGeoLookupConfig::Dns {
                zone_ipv4: asn.zone_ip_v4,
                zone_ipv6: asn.zone_ip_v6,
                separator: asn.separator,
                index_asn: asn.index_asn as usize,
                index_asn_name: asn.index_asn_name.map(|v| v as usize),
                index_country: asn.index_country.map(|v| v as usize),
            }),
            Asn::Disabled => None,
        }
    }
}

impl ClusterRoles {
    fn all_mut(&mut self) -> impl Iterator<Item = &mut bool> {
        [
            &mut self.store_maintenance,
            &mut self.account_maintenance,
            &mut self.push_notifications,
            &mut self.search_indexing,
            &mut self.spam_training,
            &mut self.outbound_mta,
            &mut self.task_manager,
            &mut self.task_scheduler,
            &mut self.metrics_calculate,
            &mut self.metrics_push,
        ]
        .into_iter()
    }

    fn set_role(&mut self, role: ClusterTaskType, enabled: bool) {
        match role {
            ClusterTaskType::StoreMaintenance => self.store_maintenance = enabled,
            ClusterTaskType::AccountMaintenance => self.account_maintenance = enabled,
            ClusterTaskType::PushNotifications => self.push_notifications = enabled,
            ClusterTaskType::SearchIndexing => self.search_indexing = enabled,
            ClusterTaskType::SpamClassifierTraining => self.spam_training = enabled,
            ClusterTaskType::MetricsCalculate => self.metrics_calculate = enabled,
            ClusterTaskType::MetricsPush => self.metrics_push = enabled,
            ClusterTaskType::OutboundMta => self.outbound_mta = enabled,
            ClusterTaskType::TaskQueueProcessing => self.task_manager = enabled,
            ClusterTaskType::TaskScheduler => self.task_scheduler = enabled,
        }
    }
}

impl Default for ClusterRoles {
    fn default() -> Self {
        ClusterRoles {
            store_maintenance: true,
            account_maintenance: true,
            push_notifications: true,
            search_indexing: true,
            spam_training: true,
            metrics_calculate: true,
            metrics_push: true,
            outbound_mta: true,
            task_manager: true,
            task_scheduler: true,
        }
    }
}
