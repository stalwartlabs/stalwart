/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::{DOMAIN_FLAG_RELAY, DOMAIN_FLAG_SUB_ADDRESSING, EmailAddressRef, EmailCache},
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
    expr::{Variable, functions::ResolveVariable},
    manager::SPAM_CLASSIFIER_KEY,
    network::{RcptResolution, masked::MaskedAddress},
};
use directory::Recipient;
use mail_auth::IpLookupStrategy;
use registry::schema::{enums::ExpressionVariable, structs::MaskedEmail};
use sieve::Sieve;
use std::{
    borrow::Cow,
    sync::{Arc, LazyLock},
    time::Duration,
};
use store::{
    Deserialize, IterateParams, ValueKey,
    write::{AlignedBytes, Archive, QueueClass, ValueClass, now},
};
use trc::{AddContext, SpamEvent};
use types::id::Id;

impl Server {
    pub async fn rcpt_resolve(&self, rcpt: &str, session_id: u64) -> trc::Result<RcptResolution> {
        // Obtain domain settings
        let Some((local_part, domain_part)) = rcpt.rsplit_once('@') else {
            return Ok(RcptResolution::UnknownDomain);
        };
        let Some(domain) = self.domain(domain_part).await? else {
            return Ok(RcptResolution::UnknownDomain);
        };

        // Sub-addressing resolution
        let local_part_orig = local_part;
        let mut local_part = Cow::Borrowed(local_part);
        if domain.flags & DOMAIN_FLAG_SUB_ADDRESSING != 0 {
            if let Some(sub_addressing) = &domain.sub_addressing_custom {
                // Custom sub-addressing resolution
                if let Some(result) = self
                    .eval_if::<String, _>(sub_addressing, &Address(local_part.as_ref()), session_id)
                    .await
                {
                    local_part = Cow::Owned(result);
                }
            } else if let Some((new_local_part, _)) = rcpt.split_once('+') {
                local_part = Cow::Borrowed(new_local_part);
            }
        }

        // Masked email resolution
        if let Cow::Borrowed(addr) = &local_part
            && let Some(masked) = MaskedAddress::parse(addr)
        {
            return if !masked.has_expired
                && let Some(masked_entry) = self
                    .registry()
                    .object::<MaskedEmail>(
                        Id::from_parts(masked.account_id, masked.account_id).id(),
                    )
                    .await
                    .caused_by(trc::location!())?
                && masked_entry.enabled
                && masked_entry
                    .expires_at
                    .is_none_or(|at| at.timestamp() > now() as i64)
                && let Some(account) = self
                    .try_account(masked.account_id)
                    .await
                    .caused_by(trc::location!())?
                && account.addresses.iter().any(|addr| {
                    addr.strip_suffix(domain_part)
                        .is_some_and(|a| a.ends_with('@'))
                }) {
                Ok(RcptResolution::Rewrite(account.name().to_string()))
            } else {
                Ok(RcptResolution::UnknownRecipient)
            };
        }

        // Try resolving address from registry
        if let Some(address_type) = self
            .rcpt_id_from_parts(local_part.as_ref(), domain.id)
            .await?
        {
            match address_type {
                EmailCache::Account(id) => {
                    if self.try_account(id).await?.is_some() {
                        return if local_part.as_ref() == local_part_orig {
                            Ok(RcptResolution::Accept)
                        } else {
                            Ok(RcptResolution::Rewrite(format!(
                                "{local_part}@{domain_part}"
                            )))
                        };
                    } else {
                        self.inner
                            .cache
                            .emails
                            .remove(&EmailAddressRef::new(local_part.as_ref(), domain.id));
                    }
                }
                EmailCache::MailingList(id) => {
                    if let Some(list) = self.try_list(id).await? {
                        return Ok(RcptResolution::Expand(list.recipients.clone()));
                    } else {
                        self.inner
                            .cache
                            .emails
                            .remove(&EmailAddressRef::new(local_part.as_ref(), domain.id));
                    }
                }
            }
        }

        // Obtain external directory, if configured
        if let Some(directory) = domain
            .id_directory
            .and_then(|id| self.core.storage.directories.get(&id))
            .or_else(|| self.get_default_directory())
            .filter(|directory| directory.can_lookup_recipients())
        {
            let address = if local_part.as_ref() == local_part_orig {
                Cow::Borrowed(rcpt)
            } else {
                Cow::Owned(format!("{local_part}@{domain_part}"))
            };
            match directory.recipient(address.as_ref()).await? {
                Recipient::Account(account) => {
                    self.synchronize_account(account).await?;
                    return Ok(RcptResolution::Accept);
                }
                Recipient::Group(group) => {
                    self.synchronize_group(group).await?;
                    return Ok(RcptResolution::Accept);
                }
                Recipient::Invalid => {}
            }
        }

        // Catch-all resolution
        if let Some(catch_all) = &domain.catch_all {
            return Ok(RcptResolution::Rewrite(catch_all.to_string()));
        }

        // Verify whether domain relaying is enabled
        if domain.flags & DOMAIN_FLAG_RELAY != 0 {
            Ok(RcptResolution::Accept)
        } else {
            Ok(RcptResolution::UnknownRecipient)
        }
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

struct Address<'x>(&'x str);

impl ResolveVariable for Address<'_> {
    fn resolve_variable(&'_ self, _: ExpressionVariable) -> crate::expr::Variable<'_> {
        Variable::from(self.0)
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}
