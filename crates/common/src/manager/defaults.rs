/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::auth::permissions::DefaultPermissions;
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};
use registry::{
    schema::{
        enums::*,
        prelude::{ObjectType, SocketAddr},
        structs::*,
    },
    types::{duration::Duration, error::Error, list::List, map::Map},
};
use std::str::FromStr;
use store::{
    rand::{Rng, distr::Alphanumeric, rng},
    registry::{
        bootstrap::Bootstrap,
        write::{RegistryWrite, RegistryWriteResult},
    },
};

pub const ASN_IPV4: &str = "https://cdn.jsdelivr.net/npm/@ip-location-db/asn/asn-ipv4.csv";
pub const ASN_IPV6: &str = "https://cdn.jsdelivr.net/npm/@ip-location-db/asn/asn-ipv6.csv";
pub const GEO_IPV4: &str = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-geo-whois-asn-country/geolite2-geo-whois-asn-country-ipv4.csv";
pub const GEO_IPV6: &str = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-geo-whois-asn-country/geolite2-geo-whois-asn-country-ipv6.csv";

pub trait BootstrapDefaults {
    fn insert_safe_defaults(&mut self) -> impl Future<Output = ()> + Send;
}

impl BootstrapDefaults for Bootstrap {
    async fn insert_safe_defaults(&mut self) {
        if let Err(error) = insert_safe_defaults(self).await {
            self.errors.push(Error::Internal {
                object_id: None,
                error,
            });
        }
    }
}

async fn insert_safe_defaults(bp: &mut Bootstrap) -> trc::Result<()> {
    let is_recovery_mode = bp.registry.is_recovery_mode();
    let is_bootstrap_mode = bp.registry.is_bootstrap_mode();

    #[cfg(not(feature = "test_mode"))]
    if (!is_recovery_mode || is_bootstrap_mode)
        && bp.registry.count_object(ObjectType::Application).await? == 0
    {
        bp.registry
            .write(RegistryWrite::insert(
                &Application {
                    auto_update_frequency: Duration::from_millis(30 * 24 * 60 * 60 * 1000),
                    description: "Stalwart Web Interface".to_string(),
                    enabled: true,
                    #[cfg(not(feature = "dev_mode"))]
                    resource_url:
                        "https://github.com/stalwartlabs/webui/releases/latest/download/webui.zip"
                            .into(),
                    #[cfg(feature = "dev_mode")]
                    resource_url: "file:///Users/me/code/webui/.ignore/webui.zip".into(),
                    unpack_directory: None,
                    url_prefix: Map::new(vec!["/admin".into(), "/account".into()]),
                }
                .into(),
            ))
            .await?;
    }

    if is_bootstrap_mode {
        #[cfg(not(any(feature = "dev_mode", feature = "test_mode")))]
        if bp.registry.count_object(ObjectType::SystemSettings).await? == 0 {
            bp.registry
                .write(RegistryWrite::insert(
                    &SystemSettings {
                        default_hostname: bp.registry.local_hostname().to_string(),
                        ..Default::default()
                    }
                    .into(),
                ))
                .await?;
        }

        return Ok(());
    }

    if is_recovery_mode {
        return Ok(());
    }

    if bp.registry.count_object(ObjectType::MtaQueueQuota).await? == 0 {
        bp.registry
            .write(RegistryWrite::insert(
                &MtaQueueQuota {
                    description: "Global queue quota".to_string().into(),
                    enable: true,
                    messages: 100000.into(),
                    size: 10737418240.into(),
                    ..Default::default()
                }
                .into(),
            ))
            .await?;
    }

    if bp
        .registry
        .count_object(ObjectType::MtaInboundThrottle)
        .await?
        == 0
    {
        for object in [
            MtaInboundThrottle {
                description: "Sender IP throttle".to_string(),
                enable: true,
                key: Map::new(vec![MtaInboundThrottleKey::RemoteIp]),
                rate: Rate {
                    count: 5,
                    period: Duration::from_millis(1000),
                },
                ..Default::default()
            },
            MtaInboundThrottle {
                description: "Sender address to recipient throttle".to_string(),
                enable: true,
                key: Map::new(vec![
                    MtaInboundThrottleKey::SenderDomain,
                    MtaInboundThrottleKey::Rcpt,
                ]),
                rate: Rate {
                    count: 25,
                    period: Duration::from_millis(60 * 60 * 1000),
                },
                ..Default::default()
            },
        ] {
            bp.registry
                .write(RegistryWrite::insert(&object.into()))
                .await?;
        }
    }

    if bp
        .registry
        .count_object(ObjectType::MtaVirtualQueue)
        .await?
        == 0
        && bp
            .registry
            .count_object(ObjectType::MtaDeliverySchedule)
            .await?
            == 0
    {
        for (id, object) in [
            MtaVirtualQueue {
                description: "Local delivery queue".to_string().into(),
                name: "local".into(),
                threads_per_node: 25,
            },
            MtaVirtualQueue {
                description: "Remote delivery queue".to_string().into(),
                name: "remote".into(),
                threads_per_node: 50,
            },
            MtaVirtualQueue {
                description: "Delivery Status Notification delivery queue"
                    .to_string()
                    .into(),
                name: "dsn".into(),
                threads_per_node: 5,
            },
            MtaVirtualQueue {
                description: "DMARC and TLS report delivery queue".to_string().into(),
                name: "report".into(),
                threads_per_node: 5,
            },
        ]
        .into_iter()
        .enumerate()
        {
            bp.registry
                .write(RegistryWrite::insert_with_id(
                    (id as u64).into(),
                    &object.into(),
                ))
                .await?;
        }

        for (id, object) in [
            MtaDeliverySchedule {
                name: "local".into(),
                description: "Local delivery schedule".to_string().into(),
                expiry: MtaDeliveryExpiration::Ttl(MtaDeliveryExpirationTtl {
                    expire: Duration::from_millis(3 * 24 * 60 * 60 * 1000),
                }),
                notify: MtaDeliveryScheduleIntervalsOrDefault::Default,
                retry: MtaDeliveryScheduleIntervalsOrDefault::Default,
                queue_id: 0u64.into(),
            },
            MtaDeliverySchedule {
                name: "remote".into(),
                description: "Remote delivery schedule".to_string().into(),
                expiry: MtaDeliveryExpiration::Ttl(MtaDeliveryExpirationTtl {
                    expire: Duration::from_millis(3 * 24 * 60 * 60 * 1000),
                }),
                notify: MtaDeliveryScheduleIntervalsOrDefault::Default,
                retry: MtaDeliveryScheduleIntervalsOrDefault::Default,
                queue_id: 1u64.into(),
            },
            MtaDeliverySchedule {
                name: "dsn".into(),
                description: "Delivery Status Notification delivery schedule"
                    .to_string()
                    .into(),
                expiry: MtaDeliveryExpiration::Attempts(MtaDeliveryExpirationAttempts {
                    max_attempts: 10,
                }),
                notify: MtaDeliveryScheduleIntervalsOrDefault::Default,
                retry: MtaDeliveryScheduleIntervalsOrDefault::Custom(
                    MtaDeliveryScheduleIntervals {
                        intervals: List::from_iter([
                            MtaDeliveryScheduleInterval {
                                duration: Duration::from_millis(15 * 60 * 1000),
                            },
                            MtaDeliveryScheduleInterval {
                                duration: Duration::from_millis(30 * 60 * 1000),
                            },
                            MtaDeliveryScheduleInterval {
                                duration: Duration::from_millis(60 * 60 * 1000),
                            },
                            MtaDeliveryScheduleInterval {
                                duration: Duration::from_millis(2 * 60 * 60 * 1000),
                            },
                        ]),
                    },
                ),
                queue_id: 2u64.into(),
            },
            MtaDeliverySchedule {
                name: "report".into(),
                description: "DMARC and TLS report delivery schedule".to_string().into(),
                expiry: MtaDeliveryExpiration::Attempts(MtaDeliveryExpirationAttempts {
                    max_attempts: 8,
                }),
                notify: MtaDeliveryScheduleIntervalsOrDefault::Custom(Default::default()),
                retry: MtaDeliveryScheduleIntervalsOrDefault::Custom(
                    MtaDeliveryScheduleIntervals {
                        intervals: List::from_iter([
                            MtaDeliveryScheduleInterval {
                                duration: Duration::from_millis(30 * 60 * 1000),
                            },
                            MtaDeliveryScheduleInterval {
                                duration: Duration::from_millis(60 * 60 * 1000),
                            },
                            MtaDeliveryScheduleInterval {
                                duration: Duration::from_millis(2 * 60 * 60 * 1000),
                            },
                        ]),
                    },
                ),
                queue_id: 3u64.into(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            bp.registry
                .write(RegistryWrite::insert_with_id(
                    (id as u64).into(),
                    &object.into(),
                ))
                .await?;
        }
    }

    if bp.registry.count_object(ObjectType::MtaTlsStrategy).await? == 0 {
        for object in [
            MtaTlsStrategy {
                name: "invalid-tls".into(),
                description: "Allow invalid TLS certificates".to_string().into(),
                allow_invalid_certs: true,
                ..Default::default()
            },
            MtaTlsStrategy {
                name: "default".into(),
                description: "Default TLS settings".to_string().into(),
                allow_invalid_certs: false,
                ..Default::default()
            },
        ] {
            bp.registry
                .write(RegistryWrite::insert(&object.into()))
                .await?;
        }
    }

    if bp.registry.count_object(ObjectType::MtaRoute).await? == 0 {
        for object in [
            MtaRoute::Mx(MtaRouteMx {
                description: "MX delivery route".to_string().into(),
                ip_lookup_strategy: MtaIpStrategy::V4ThenV6,
                max_multihomed: 2,
                max_mx_hosts: 2,
                name: "mx".into(),
            }),
            MtaRoute::Local(MtaRouteCommon {
                description: "Local delivery route".to_string().into(),
                name: "local".into(),
            }),
        ] {
            bp.registry
                .write(RegistryWrite::insert(&object.into()))
                .await?;
        }
    }

    if bp
        .registry
        .count_object(ObjectType::MtaConnectionStrategy)
        .await?
        == 0
    {
        bp.registry
            .write(RegistryWrite::insert(
                &MtaConnectionStrategy {
                    name: "default".into(),
                    description: "Default connection strategy".to_string().into(),
                    ..Default::default()
                }
                .into(),
            ))
            .await?;
    }

    if bp.registry.count_object(ObjectType::OidcProvider).await? == 0 {
        let pkcs8_doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|err| {
                    trc::EventType::Server(trc::ServerEvent::Startup)
                        .into_err()
                        .reason(err)
                        .caused_by(trc::location!())
                })?;
        let signature_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8_doc.as_ref()));

        bp.registry
            .write(RegistryWrite::insert(
                &OidcProvider {
                    encryption_key: SecretKey::Value(SecretKeyValue {
                        secret: rng()
                            .sample_iter(Alphanumeric)
                            .take(64)
                            .map(char::from)
                            .collect::<String>(),
                    }),
                    signature_key: SecretText::Text(SecretTextValue {
                        secret: signature_pem,
                    }),
                    signature_algorithm: JwtSignatureAlgorithm::Es256,
                    ..Default::default()
                }
                .into(),
            ))
            .await?;

        // Generate a Web Push VAPID signing key (RFC 9749)
        if bp.registry.count_object(ObjectType::Jmap).await? == 0 {
            match crate::network::webpush::generate_pkcs8_pem() {
                Ok(web_push_pem) => {
                    bp.registry
                        .write(RegistryWrite::insert(
                            &Jmap {
                                web_push_key: SecretTextOptional::Text(SecretTextValue {
                                    secret: web_push_pem,
                                }),
                                ..Default::default()
                            }
                            .into(),
                        ))
                        .await?;
                }
                Err(err) => {
                    trc::event!(
                        Server(trc::ServerEvent::Startup),
                        Details = "Failed to generate Web Push VAPID key",
                        Reason = err
                    );
                }
            }
        }
    }

    if bp.registry.count_object(ObjectType::Role).await? == 0 {
        let permissions = DefaultPermissions::default();
        let mut role_ids = Vec::with_capacity(4);

        for role in [
            Role {
                description: "User".into(),
                enabled_permissions: Map::new(permissions.user),
                ..Default::default()
            },
            Role {
                description: "Group".into(),
                enabled_permissions: Map::new(permissions.group),
                ..Default::default()
            },
            Role {
                description: "Tenant Administrator".into(),
                enabled_permissions: Map::new(permissions.tenant),
                ..Default::default()
            },
            Role {
                description: "System Administrator".into(),
                enabled_permissions: Map::new(permissions.superuser),
                ..Default::default()
            },
        ] {
            match bp
                .registry
                .write(RegistryWrite::insert(&role.into()))
                .await?
            {
                RegistryWriteResult::Success(id) => role_ids.push(id),
                err => {
                    bp.build_error(
                        ObjectType::Role.singleton(),
                        format!("Failed to insert default role: {err}"),
                    );
                }
            }
        }

        if bp.registry.count_object(ObjectType::Authentication).await? == 0 && role_ids.len() == 4 {
            bp.registry
                .write(RegistryWrite::insert(
                    &Authentication {
                        default_user_role_ids: Map::new(vec![role_ids[0]]),
                        default_group_role_ids: Map::new(vec![role_ids[1]]),
                        default_tenant_role_ids: Map::new(vec![role_ids[2], role_ids[0]]),
                        default_admin_role_ids: Map::new(vec![role_ids[3], role_ids[0]]),
                        ..Default::default()
                    }
                    .into(),
                ))
                .await?;
        }
    }

    if bp
        .registry
        .count_object(ObjectType::NetworkListener)
        .await?
        == 0
    {
        for (protocol, name, port, tls_implicit) in [
            (NetworkListenerProtocol::Smtp, "smtp", 25, false),
            (NetworkListenerProtocol::Smtp, "submissions", 465, true),
            (NetworkListenerProtocol::Imap, "imaps", 993, true),
            (NetworkListenerProtocol::Pop3, "pop3s", 995, true),
            (NetworkListenerProtocol::ManageSieve, "sieve", 4190, false),
            (NetworkListenerProtocol::Http, "https", 443, true),
            (NetworkListenerProtocol::Http, "http", 8080, false),
        ] {
            bp.registry
                .write(RegistryWrite::insert(
                    &NetworkListener {
                        bind: Map::new(vec![
                            SocketAddr::from_str(&format!("[::]:{port}")).unwrap(),
                        ]),
                        name: name.to_string(),
                        protocol,
                        use_tls: true,
                        tls_implicit,
                        ..Default::default()
                    }
                    .into(),
                ))
                .await?;
        }
    }

    #[cfg(not(any(feature = "dev_mode", feature = "test_mode")))]
    if bp.registry.count_object(ObjectType::Asn).await? == 0 {
        bp.registry
            .write(RegistryWrite::insert(
                &Asn::Resource(AsnResource {
                    asn_urls: Map::new(vec![ASN_IPV4.into(), ASN_IPV6.into()]),
                    geo_urls: Map::new(vec![GEO_IPV4.into(), GEO_IPV6.into()]),
                    max_size: 104857600,
                    expires: Duration::from_millis(24 * 60 * 60 * 1000),
                    timeout: Duration::from_millis(5 * 60 * 1000),
                    ..Default::default()
                })
                .into(),
            ))
            .await?;
    }

    #[cfg(not(feature = "test_mode"))]
    if bp.registry.count_object(ObjectType::TracingStore).await? == 0 {
        bp.registry
            .write(RegistryWrite::insert(&TracingStore::Default.into()))
            .await?;
    }

    #[cfg(not(feature = "test_mode"))]
    if bp.registry.count_object(ObjectType::MetricsStore).await? == 0 {
        bp.registry
            .write(RegistryWrite::insert(&MetricsStore::Default.into()))
            .await?;
    }

    if bp.registry.count_object(ObjectType::Tracer).await? == 0 {
        bp.registry
            .write(RegistryWrite::insert(
                &Tracer::Log(TracerLog {
                    enable: true,
                    ansi: false,
                    prefix: "stalwart.log".into(),
                    rotate: LogRotateFrequency::Daily,
                    path: "/var/log/stalwart".into(),
                    ..Default::default()
                })
                .into(),
            ))
            .await?;
    }

    #[cfg(not(feature = "test_mode"))]
    {
        use store::write::BatchBuilder;
        use types::id::Id;

        if bp.registry.count_object(ObjectType::SpamRule).await? == 0
            && bp
                .registry
                .object::<SpamSettings>(Id::singleton())
                .await?
                .is_none_or(|spam| spam.spam_filter_rules_url.is_some())
        {
            let mut batch = BatchBuilder::new();
            batch.schedule_task(Task::SpamFilterMaintenance(TaskSpamFilterMaintenance {
                maintenance_type: TaskSpamFilterMaintenanceType::UpdateRules,
                status: TaskStatus::now(),
            }));
            bp.data_store.write(batch.build_all()).await?;
        }
    }

    Ok(())
}
