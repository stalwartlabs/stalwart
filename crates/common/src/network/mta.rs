/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    config::{
        mailstore::spamfilter::SpamClassifier,
        smtp::{
            auth::DkimSigner,
            queue::{
                ConnectionStrategy, DEFAULT_QUEUE_NAME, MxConfig, QueueExpiry, QueueName,
                QueueStrategy, RequireOptional, RoutingStrategy, TlsStrategy, VirtualQueue,
            },
        },
    },
    manager::SPAM_CLASSIFIER_KEY,
    network::RcptResolution,
};
use mail_auth::IpLookupStrategy;
use sieve::Sieve;
use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};
use store::{
    Deserialize, IterateParams, ValueKey,
    write::{AlignedBytes, Archive, QueueClass, ValueClass},
};
use trc::{AddContext, SpamEvent};

impl Server {
    pub async fn rcpt_resolve(&self, address: &str) -> trc::Result<RcptResolution> {
        let todo = "TODO: RcptResolution implementation";
        todo!()
    }

    pub async fn get_dkim_signers(
        &self,
        domain: &str,
        session_id: u64,
    ) -> trc::Result<Option<Arc<[DkimSigner]>>> {
        if let Some(signers) = self.dkim_signers(domain).await? {
            Ok(Some(signers))
        } else {
            trc::event!(
                Dkim(trc::DkimEvent::SignerNotFound),
                Id = domain.to_string(),
                SpanId = session_id,
            );

            Ok(None)
        }
    }

    pub fn get_trusted_sieve_script(&self, name: &str, session_id: u64) -> Option<&Arc<Sieve>> {
        self.core.sieve.trusted_scripts.get(name).or_else(|| {
            trc::event!(
                Sieve(trc::SieveEvent::ScriptNotFound),
                Id = name.to_string(),
                SpanId = session_id,
            );

            None
        })
    }

    pub fn get_untrusted_sieve_script(&self, name: &str, session_id: u64) -> Option<&Arc<Sieve>> {
        self.core.sieve.untrusted_scripts.get(name).or_else(|| {
            trc::event!(
                Sieve(trc::SieveEvent::ScriptNotFound),
                Id = name.to_string(),
                SpanId = session_id,
            );

            None
        })
    }

    pub fn get_route_or_default(&self, name: &str, session_id: u64) -> &RoutingStrategy {
        static LOCAL_GATEWAY: RoutingStrategy = RoutingStrategy::Local;
        static MX_GATEWAY: RoutingStrategy = RoutingStrategy::Mx(MxConfig {
            max_mx: 5,
            max_multi_homed: 2,
            ip_lookup_strategy: IpLookupStrategy::Ipv4thenIpv6,
        });
        self.core
            .smtp
            .queue
            .routing_strategy
            .get(name)
            .unwrap_or_else(|| match name {
                "local" => &LOCAL_GATEWAY,
                "mx" => &MX_GATEWAY,
                _ => {
                    trc::event!(
                        Smtp(trc::SmtpEvent::IdNotFound),
                        Id = name.to_string(),
                        Details = "Gateway not found",
                        SpanId = session_id,
                    );
                    &MX_GATEWAY
                }
            })
    }

    pub fn get_virtual_queue_or_default(&self, name: &QueueName) -> &VirtualQueue {
        static DEFAULT_QUEUE: VirtualQueue = VirtualQueue { threads: 25 };
        self.core
            .smtp
            .queue
            .virtual_queues
            .get(name)
            .unwrap_or_else(|| {
                if name != &DEFAULT_QUEUE_NAME {
                    trc::event!(
                        Smtp(trc::SmtpEvent::IdNotFound),
                        Id = name.to_string(),
                        Details = "Virtual queue not found",
                    );
                }

                &DEFAULT_QUEUE
            })
    }

    pub fn get_queue_or_default(&self, name: &str, session_id: u64) -> &QueueStrategy {
        static DEFAULT_SCHEDULE: LazyLock<QueueStrategy> = LazyLock::new(|| QueueStrategy {
            retry: vec![
                120,  // 2 minutes
                300,  // 5 minutes
                600,  // 10 minutes
                900,  // 15 minutes
                1800, // 30 minutes
                3600, // 1 hour
                7200, // 2 hours
            ],
            notify: vec![
                86400,  // 1 day
                259200, // 3 days
            ],
            expiry: QueueExpiry::Ttl(432000), // 5 days
            virtual_queue: QueueName::default(),
        });
        self.core
            .smtp
            .queue
            .queue_strategy
            .get(name)
            .unwrap_or_else(|| {
                if name != "default" {
                    trc::event!(
                        Smtp(trc::SmtpEvent::IdNotFound),
                        Id = name.to_string(),
                        Details = "Queue strategy not found",
                        SpanId = session_id,
                    );
                }

                &DEFAULT_SCHEDULE
            })
    }

    pub fn get_tls_or_default(&self, name: &str, session_id: u64) -> &TlsStrategy {
        static DEFAULT_TLS: TlsStrategy = TlsStrategy {
            dane: RequireOptional::Optional,
            mta_sts: RequireOptional::Optional,
            tls: RequireOptional::Optional,
            allow_invalid_certs: false,
            timeout_tls: Duration::from_secs(3 * 60),
            timeout_mta_sts: Duration::from_secs(5 * 60),
        };
        self.core
            .smtp
            .queue
            .tls_strategy
            .get(name)
            .unwrap_or_else(|| {
                if name != "default" {
                    trc::event!(
                        Smtp(trc::SmtpEvent::IdNotFound),
                        Id = name.to_string(),
                        Details = "TLS strategy not found",
                        SpanId = session_id,
                    );
                }

                &DEFAULT_TLS
            })
    }

    pub fn get_connection_or_default(&self, name: &str, session_id: u64) -> &ConnectionStrategy {
        static DEFAULT_CONNECTION: ConnectionStrategy = ConnectionStrategy {
            source_ipv4: Vec::new(),
            source_ipv6: Vec::new(),
            ehlo_hostname: None,
            timeout_connect: Duration::from_secs(5 * 60),
            timeout_greeting: Duration::from_secs(5 * 60),
            timeout_ehlo: Duration::from_secs(5 * 60),
            timeout_mail: Duration::from_secs(5 * 60),
            timeout_rcpt: Duration::from_secs(5 * 60),
            timeout_data: Duration::from_secs(10 * 60),
        };

        self.core
            .smtp
            .queue
            .connection_strategy
            .get(name)
            .unwrap_or_else(|| {
                if name != "default" {
                    trc::event!(
                        Smtp(trc::SmtpEvent::IdNotFound),
                        Id = name.to_string(),
                        Details = "Connection strategy not found",
                        SpanId = session_id,
                    );
                }

                &DEFAULT_CONNECTION
            })
    }

    pub async fn spam_model_reload(&self) -> trc::Result<()> {
        if self.core.spam.classifier.is_some() {
            if let Some(model) = self
                .blob_store()
                .get_blob(SPAM_CLASSIFIER_KEY, 0..usize::MAX)
                .await
                .and_then(|archive| match archive {
                    Some(archive) => <Archive<AlignedBytes> as Deserialize>::deserialize(&archive)
                        .and_then(|archive| archive.deserialize_untrusted::<SpamClassifier>())
                        .map(Some),
                    None => Ok(None),
                })
                .caused_by(trc::location!())?
            {
                self.inner.data.spam_classifier.store(Arc::new(model));
            } else {
                trc::event!(Spam(SpamEvent::ModelNotFound));
            }
        }

        Ok(())
    }

    pub async fn total_queued_messages(&self) -> trc::Result<u64> {
        let mut total = 0;
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::Queue(QueueClass::Message(0))),
                    ValueKey::from(ValueClass::Queue(QueueClass::Message(u64::MAX))),
                )
                .no_values(),
                |_, _| {
                    total += 1;

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| total)
    }
}
