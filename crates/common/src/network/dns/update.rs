/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Core, Server};
use base64::{Engine, engine::general_purpose};
use dns_update::{
    DnsRecord, DnsRecordType, TsigAlgorithm,
    providers::{ovh::OvhEndpoint, rfc2136::DnsAddress},
};
use registry::schema::{
    enums,
    structs::{DnsManagement, DnsServer, Domain},
};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use trc::DnsEvent;
use types::id::Id;

pub struct DnsUpdater {
    pub updater: dns_update::DnsUpdater,
    pub polling_interval: Duration,
    pub propagation_timeout: Duration,
    pub propagation_delay: Option<Duration>,
    pub ttl: Duration,
    core: Arc<Core>,
}

#[cfg(feature = "test_mode")]
pub static DNS_RECORDS: std::sync::LazyLock<
    Arc<std::sync::Mutex<Vec<dns_update::NamedDnsRecord>>>,
> = std::sync::LazyLock::new(|| Arc::new(std::sync::Mutex::new(Vec::new())));

impl DnsUpdater {
    pub async fn build(server: DnsServer, core: Arc<Core>) -> Result<Self, String> {
        match server {
            DnsServer::Tsig(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_rfc2136_tsig(
                    match server.protocol {
                        enums::IpProtocol::Tcp => DnsAddress::Tcp(SocketAddr::new(
                            server.host.into_inner(),
                            server.port as u16,
                        )),
                        enums::IpProtocol::Udp => DnsAddress::Udp(SocketAddr::new(
                            server.host.into_inner(),
                            server.port as u16,
                        )),
                    },
                    server.key_name,
                    general_purpose::STANDARD
                        .decode(server.key.secret().await?.as_bytes())
                        .map_err(|err| format!("Failed to base64 decode TSIG key: {err}"))?,
                    match server.tsig_algorithm {
                        enums::TsigAlgorithm::HmacMd5 => TsigAlgorithm::HmacMd5,
                        enums::TsigAlgorithm::Gss => TsigAlgorithm::Gss,
                        enums::TsigAlgorithm::HmacSha1 => TsigAlgorithm::HmacSha1,
                        enums::TsigAlgorithm::HmacSha224 => TsigAlgorithm::HmacSha224,
                        enums::TsigAlgorithm::HmacSha256 => TsigAlgorithm::HmacSha256,
                        enums::TsigAlgorithm::HmacSha256128 => TsigAlgorithm::HmacSha256_128,
                        enums::TsigAlgorithm::HmacSha384 => TsigAlgorithm::HmacSha384,
                        enums::TsigAlgorithm::HmacSha384192 => TsigAlgorithm::HmacSha384_192,
                        enums::TsigAlgorithm::HmacSha512 => TsigAlgorithm::HmacSha512,
                        enums::TsigAlgorithm::HmacSha512256 => TsigAlgorithm::HmacSha512_256,
                    },
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Cloudflare(server) => {
                let updater = {
                    #[cfg(feature = "test_mode")]
                    match server.secret.secret().await.unwrap().as_ref() {
                        "test@pebble.org" => dns_update::DnsUpdater::new_pebble(
                            "http://localhost:8055",
                            server.timeout.into_inner().into(),
                        ),
                        "test@memory.org" => {
                            dns_update::DnsUpdater::new_in_memory(DNS_RECORDS.clone())
                        }
                        _ => dns_update::DnsUpdater::new_cloudflare(
                            server.secret.secret().await?,
                            server.timeout.into_inner().into(),
                        )
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                    }

                    #[cfg(not(feature = "test_mode"))]
                    dns_update::DnsUpdater::new_cloudflare(
                        server.secret.secret().await?,
                        server.timeout.into_inner().into(),
                    )
                    .map_err(|err| format!("Failed to build DNS updater: {}", err))?
                };

                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater,
                })
            }
            DnsServer::DigitalOcean(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_digitalocean(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::DeSEC(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_desec(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Ovh(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_ovh(
                    server.application_key,
                    server.application_secret.secret().await?,
                    server.consumer_key.secret().await?,
                    match server.ovh_endpoint {
                        enums::OvhEndpoint::OvhEu => OvhEndpoint::OvhEu,
                        enums::OvhEndpoint::OvhCa => OvhEndpoint::OvhCa,
                        enums::OvhEndpoint::KimsufiEu => OvhEndpoint::KimsufiEu,
                        enums::OvhEndpoint::KimsufiCa => OvhEndpoint::KimsufiCa,
                        enums::OvhEndpoint::SoyoustartEu => OvhEndpoint::SoyoustartEu,
                        enums::OvhEndpoint::SoyoustartCa => OvhEndpoint::SoyoustartCa,
                    },
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Bunny(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_bunny(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Porkbun(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_porkbun(
                    server.api_key.as_str(),
                    server.secret_api_key.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Dnsimple(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_dnsimple(
                    server.auth_token.secret().await?,
                    server.account_identifier.as_str(),
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Spaceship(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_spaceship(
                    server.api_key.as_str(),
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Route53(server) => {
                let secret_access_key = server.secret_access_key.secret().await?.into_owned();
                let session_token = server.session_token.secret().await?.map(|c| c.into_owned());
                let config = dns_update::providers::route53::Route53Config {
                    access_key_id: server.access_key_id,
                    secret_access_key,
                    session_token,
                    region: Some(server.region),
                    hosted_zone_id: server.hosted_zone_id,
                    private_zone_only: Some(server.private_zone_only),
                    endpoint: None,
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_route53(config)
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::GoogleCloudDns(server) => {
                let service_account_json = server.service_account_json.secret().await?.into_owned();
                let config = dns_update::providers::google_cloud_dns::GoogleCloudDnsConfig {
                    service_account_json,
                    project_id: server.project_id,
                    managed_zone: server.managed_zone,
                    private_zone: server.private_zone,
                    impersonate_service_account: server.impersonate_service_account,
                    request_timeout: Some(server.timeout.into_inner()),
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_google_cloud_dns(config)
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::Alidns(server) => {
                let secret_key = server.secret_key.secret().await?.into_owned();
                let security_token = server
                    .security_token
                    .secret()
                    .await?
                    .map(|c| c.into_owned());
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_alidns(
                        server.access_key.as_str(),
                        secret_key.as_str(),
                        server.region.as_deref(),
                        security_token.as_deref(),
                        server.line.as_deref(),
                        server.timeout.into_inner().into(),
                    )
                    .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::ArvanCloud(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_arvancloud(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Autodns(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_autodns(
                    server.username.as_str(),
                    server.password.secret().await?,
                    server.context.map(|v| v as u32),
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::AzureDns(server) => {
                let client_secret = server.client_secret.secret().await?.into_owned();
                let config = dns_update::providers::azuredns::AzureDnsConfig {
                    tenant_id: server.tenant_id,
                    client_id: server.client_id,
                    client_secret,
                    subscription_id: server.subscription_id,
                    resource_group: server.resource_group,
                    environment: match server.environment {
                        enums::AzureEnvironment::Public => {
                            dns_update::providers::azuredns::AzureEnvironment::Public
                        }
                        enums::AzureEnvironment::China => {
                            dns_update::providers::azuredns::AzureEnvironment::China
                        }
                        enums::AzureEnvironment::UsGovernment => {
                            dns_update::providers::azuredns::AzureEnvironment::UsGovernment
                        }
                    },
                    request_timeout: Some(server.timeout.into_inner()),
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_azuredns(config)
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::BaiduCloud(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_baiducloud(
                    server.access_key.as_str(),
                    server.secret_key.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::BluecatV2(server) => {
                let password = server.password.secret().await?.into_owned();
                let config = dns_update::providers::bluecatv2::BluecatV2Config {
                    server_url: server.base_url,
                    username: server.username,
                    password,
                    config_name: server.config_name,
                    view_name: server.view_name,
                    skip_deploy: server.skip_deploy,
                    request_timeout: Some(server.timeout.into_inner()),
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_bluecatv2(config)
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::ClouDns(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_cloudns(
                    server.auth_id.as_deref(),
                    server.sub_auth_id.as_deref(),
                    server.password.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Constellix(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_constellix(
                    server.api_key.as_str(),
                    server.secret_key.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Cpanel(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_cpanel(
                    server.base_url.as_str(),
                    server.username.as_str(),
                    server.token.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Ddnss(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_ddnss(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::DnsMadeEasy(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_dnsmadeeasy(
                    server.api_key.as_str(),
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Domeneshop(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_domeneshop(
                    server.auth_token.as_str(),
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Dreamhost(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_dreamhost(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::DuckDns(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_duckdns(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Dynu(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_dynu(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::EasyDns(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_easydns(
                    server.token.as_str(),
                    server.key.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::EdgeDns(server) => {
                let client_secret = server.client_secret.secret().await?.into_owned();
                let access_token = server.access_token.secret().await?.into_owned();
                let config = dns_update::providers::edgedns::EdgeDnsConfig {
                    host: server.host,
                    client_token: server.client_token,
                    client_secret,
                    access_token,
                    account_switch_key: server.account_switch_key,
                    request_timeout: Some(server.timeout.into_inner()),
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_edgedns(config)
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::Exoscale(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_exoscale(
                    server.api_key.as_str(),
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::FreeMyIp(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_freemyip(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::GandiV5(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_gandiv5(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Gcore(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_gcore(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Glesys(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_glesys(
                    server.api_user.as_str(),
                    server.api_key.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Godaddy(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_godaddy(
                    server.api_key.as_str(),
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Hetzner(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_hetzner(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::HostingDe(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_hostingde(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Hostinger(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_hostinger(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::HuaweiCloud(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_huaweicloud(
                    server.access_key.as_str(),
                    server.secret_key.secret().await?,
                    server.region.as_str(),
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Hurricane(server) => {
                let mut credentials = std::collections::HashMap::new();
                for cred in server.credentials.0.into_values() {
                    let secret = cred.secret.secret().await?.into_owned();
                    credentials.insert(cred.zone, secret);
                }
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_hurricane(
                        credentials,
                        server.timeout.into_inner().into(),
                    )
                    .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::IbmCloud(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_ibmcloud(
                    server.username.as_str(),
                    server.api_key.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Infoblox(server) => {
                let password = server.password.secret().await?.into_owned();
                let config = dns_update::providers::infoblox::InfobloxConfig {
                    host: server.host,
                    port: server.port,
                    username: server.username,
                    password,
                    wapi_version: server.wapi_version,
                    dns_view: server.dns_view,
                    request_timeout: Some(server.timeout.into_inner()),
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_infoblox(config)
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::Infomaniak(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_infomaniak(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Inwx(server) => {
                let password = server.password.secret().await?.into_owned();
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_inwx(
                        server.username,
                        password,
                        server.sandbox,
                        server.timeout.into_inner().into(),
                    )
                    .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::Ionos(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_ionos(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Ipv64(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_ipv64(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Joker(server) => {
                let auth = match server.auth {
                    registry::schema::structs::JokerAuth::ApiKey(api) => {
                        let key = api.api_key.secret().await?.into_owned();
                        dns_update::providers::joker::JokerAuth::api_key(key)
                    }
                    registry::schema::structs::JokerAuth::UsernamePassword(creds) => {
                        let password = creds.password.secret().await?.into_owned();
                        dns_update::providers::joker::JokerAuth::username_password(
                            creds.username,
                            password,
                        )
                    }
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_joker(
                        auth,
                        server.timeout.into_inner().into(),
                    )
                    .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::Lightsail(server) => {
                let secret_access_key = server.secret_access_key.secret().await?.into_owned();
                let session_token = server.session_token.secret().await?.map(|c| c.into_owned());
                let config = dns_update::providers::lightsail::LightsailConfig {
                    access_key_id: server.access_key_id,
                    secret_access_key,
                    session_token,
                    region: server.region,
                    domain: server.domain,
                    request_timeout: Some(server.timeout.into_inner()),
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_lightsail(config)
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::Linode(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_linode(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::LuaDns(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_luadns(
                    server.username.as_str(),
                    server.auth_token.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::MythicBeasts(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_mythicbeasts(
                    server.username.as_str(),
                    server.password.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Namecheap(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_namecheap(
                    server.api_user.as_str(),
                    server.api_key.secret().await?,
                    server.client_ip.as_str(),
                    server.username.as_deref(),
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::NameDotCom(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_namedotcom(
                    server.username.as_str(),
                    server.auth_token.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::NameSilo(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_namesilo(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Netcup(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_netcup(
                    server.customer_number.as_str(),
                    server.api_key.as_str(),
                    server.password.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Netlify(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_netlify(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Nifcloud(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_nifcloud(
                    server.access_key.as_str(),
                    server.secret_key.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Ns1(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_ns1(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::OracleCloud(server) => {
                let private_key_pem = server.private_key_pem.secret().await?.into_owned();
                let private_key_password = server
                    .private_key_password
                    .secret()
                    .await?
                    .map(|c| c.into_owned());
                let config = dns_update::providers::oraclecloud::OracleCloudConfig {
                    tenancy_ocid: server.tenancy_ocid,
                    user_ocid: server.user_ocid,
                    fingerprint: server.fingerprint,
                    private_key_pem,
                    private_key_password,
                    region: server.region,
                    compartment_ocid: server.compartment_ocid,
                    request_timeout: Some(server.timeout.into_inner()),
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_oraclecloud(config)
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::Plesk(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_plesk(
                    server.base_url.as_str(),
                    server.api_key.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Safedns(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_safedns(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Scaleway(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_scaleway(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::TencentCloud(server) => {
                let secret_key = server.secret_key.secret().await?.into_owned();
                let session_token = server.session_token.secret().await?.map(|c| c.into_owned());
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_tencentcloud(
                        server.secret_id.as_str(),
                        secret_key.as_str(),
                        server.region.as_deref(),
                        session_token.as_deref(),
                        server.timeout.into_inner().into(),
                    )
                    .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::Transip(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_transip(
                    server.username.as_str(),
                    server.private_key_pem.secret().await?,
                    true,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::UltraDns(server) => {
                let password = server.password.secret().await?.into_owned();
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_ultradns(
                        server.username,
                        password,
                        server.endpoint,
                        server.timeout.into_inner().into(),
                    )
                    .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::Vercel(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_vercel(
                    server.auth_token.secret().await?,
                    server.team_id.as_deref(),
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::Volcengine(server) => {
                let secret_key = server.secret_key.secret().await?.into_owned();
                let config = dns_update::providers::volcengine::VolcengineConfig {
                    access_key: server.access_key,
                    secret_key,
                    region: server.region,
                    host: server.host,
                    scheme: server.scheme,
                    request_timeout: Some(server.timeout.into_inner()),
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_volcengine(config)
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::Vultr(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_vultr(
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::WebSupport(server) => Ok(DnsUpdater {
                polling_interval: server.polling_interval.into_inner(),
                propagation_timeout: server.propagation_timeout.into_inner(),
                propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                ttl: server.ttl.into_inner(),
                core,
                updater: dns_update::DnsUpdater::new_websupport(
                    server.api_key.as_str(),
                    server.secret.secret().await?,
                    server.timeout.into_inner().into(),
                )
                .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
            }),
            DnsServer::YandexCloud(server) => {
                let iam_token_b64 = server.api_key.secret().await?.into_owned();
                let config = dns_update::providers::yandexcloud::YandexCloudConfig {
                    iam_token_b64,
                    folder_id: server.folder_id,
                    request_timeout: Some(server.timeout.into_inner()),
                };
                Ok(DnsUpdater {
                    polling_interval: server.polling_interval.into_inner(),
                    propagation_timeout: server.propagation_timeout.into_inner(),
                    propagation_delay: server.propagation_delay.map(|d| d.into_inner()),
                    ttl: server.ttl.into_inner(),
                    core,
                    updater: dns_update::DnsUpdater::new_yandexcloud(config)
                        .map_err(|err| format!("Failed to build DNS updater: {}", err))?,
                })
            }
            DnsServer::Deprecated1 => Err("DNS server type no longer supported".to_string()),
        }
    }

    pub async fn set_rrset(
        &self,
        origin: &str,
        name: &str,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
    ) -> Result<(), String> {
        let record_values = records
            .iter()
            .map(|r| trc::Value::String(r.to_string().into()))
            .collect::<Vec<_>>();

        if let Err(err) = self
            .updater
            .set_rrset(
                name,
                record_type,
                self.ttl.as_secs() as u32,
                records,
                origin,
            )
            .await
        {
            return Err(format!("Failed to set DNS RRSet: {}", err));
        }

        trc::event!(
            Dns(DnsEvent::RecordCreated),
            Hostname = name.to_string(),
            Details = origin.to_string(),
            Type = record_type.as_str(),
            Value = record_values,
        );
        Ok(())
    }

    pub async fn add_to_rrset(
        &self,
        origin: &str,
        name: &str,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
    ) -> Result<(), String> {
        let record_values = records
            .iter()
            .map(|r| trc::Value::String(r.to_string().into()))
            .collect::<Vec<_>>();

        if let Err(err) = self
            .updater
            .add_to_rrset(
                name,
                record_type,
                self.ttl.as_secs() as u32,
                records,
                origin,
            )
            .await
        {
            return Err(format!("Failed to add to DNS RRSet: {}", err));
        }

        trc::event!(
            Dns(DnsEvent::RecordCreated),
            Hostname = name.to_string(),
            Details = origin.to_string(),
            Type = record_type.as_str(),
            Value = record_values,
        );
        Ok(())
    }

    pub async fn list_rrset(
        &self,
        origin: &str,
        name: &str,
        record_type: DnsRecordType,
    ) -> dns_update::Result<Vec<DnsRecord>> {
        self.updater.list_rrset(name, record_type, origin).await
    }

    pub async fn remove_from_rrset(
        &self,
        origin: &str,
        name: &str,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
    ) -> Result<(), String> {
        let record_values = records
            .iter()
            .map(|r| trc::Value::String(r.to_string().into()))
            .collect::<Vec<_>>();

        match self
            .updater
            .remove_from_rrset(name, record_type, records, origin)
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => {
                trc::event!(
                    Dns(DnsEvent::RecordDeletionFailed),
                    Hostname = name.to_string(),
                    Reason = err.to_string(),
                    Details = origin.to_string(),
                    Type = record_type.as_str(),
                    Value = record_values,
                );
                Err(err.to_string())
            }
        }
    }

    pub async fn wait_for_txt_propagation(&self, name: &str, origin: &str, expected: &str) -> bool {
        #[cfg(feature = "test_mode")]
        if matches!(
            self.updater,
            dns_update::DnsUpdater::Pebble(_) | dns_update::DnsUpdater::InMemory(_)
        ) {
            return true;
        }

        if let Some(initial_wait) = self.propagation_delay {
            tokio::time::sleep(initial_wait).await;
        }
        let wait_until = Instant::now() + self.propagation_timeout;
        let mut did_propagate = false;
        while Instant::now() < wait_until {
            match self.core.smtp.resolvers.dns.txt_raw_lookup(&name).await {
                Ok(result) => {
                    let result = std::str::from_utf8(&result).unwrap_or_default();
                    if result.contains(expected) {
                        did_propagate = true;
                        break;
                    } else {
                        trc::event!(
                            Dns(DnsEvent::RecordNotPropagated),
                            Hostname = name.to_string(),
                            Details = origin.to_string(),
                            Result = result.to_string(),
                            Type = DnsRecordType::TXT.as_str(),
                            Value = expected.to_string(),
                        );
                    }
                }
                Err(err) => {
                    trc::event!(
                        Dns(DnsEvent::RecordLookupFailed),
                        Hostname = name.to_string(),
                        Details = origin.to_string(),
                        Reason = err.to_string(),
                        Type = DnsRecordType::TXT.as_str(),
                        Value = expected.to_string(),
                    );
                }
            }

            tokio::time::sleep(self.polling_interval).await;
        }

        if did_propagate {
            trc::event!(
                Dns(DnsEvent::RecordPropagated),
                Hostname = name.to_string(),
                Details = origin.to_string(),
                Type = DnsRecordType::TXT.as_str(),
                Value = expected.to_string(),
            );
        } else {
            trc::event!(
                Dns(DnsEvent::RecordPropagationTimeout),
                Hostname = name.to_string(),
                Details = origin.to_string(),
                Type = DnsRecordType::TXT.as_str(),
                Value = expected.to_string(),
            );
        }
        did_propagate
    }
}

impl Server {
    pub async fn build_dns_updater_for_domain(
        &self,
        domain_id: Id,
    ) -> trc::Result<Result<DnsUpdater, String>> {
        if let Some(domain) = self.registry().object::<Domain>(domain_id).await? {
            match domain.dns_management {
                DnsManagement::Automatic(props) => {
                    self.build_dns_updater(props.dns_server_id).await
                }
                DnsManagement::Manual => Ok(Err(format!(
                    "Domain with ID {} is set to manual DNS management",
                    domain_id
                ))),
            }
        } else {
            Ok(Err(format!("Domain with ID {} not found", domain_id)))
        }
    }

    pub async fn build_dns_updater(
        &self,
        dns_server_id: Id,
    ) -> trc::Result<Result<DnsUpdater, String>> {
        if let Some(settings) = self.registry().object::<DnsServer>(dns_server_id).await? {
            Ok(DnsUpdater::build(settings, self.core.clone()).await)
        } else {
            Ok(Err(format!(
                "DNS server with ID {} not found",
                dns_server_id
            )))
        }
    }
}
