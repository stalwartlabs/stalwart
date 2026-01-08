/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Inner, Server,
    auth::{AccessToken, ResourceToken, TenantInfo},
    config::{
        smtp::{
            auth::{ArcSealer, DkimSigner, LazySignature, ResolvedSignature, build_signature},
            queue::{
                ConnectionStrategy, DEFAULT_QUEUE_NAME, MxConfig, QueueExpiry, QueueName,
                QueueStrategy, RequireOptional, RoutingStrategy, TlsStrategy, VirtualQueue,
            },
        },
        spamfilter::SpamClassifier,
    },
    ipc::{BroadcastEvent, PushEvent, PushNotification},
    manager::SPAM_CLASSIFIER_KEY,
};
use directory::{Directory, QueryParams, Type, backend::internal::manage::ManageDirectory};
use mail_auth::IpLookupStrategy;
use sieve::Sieve;
use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};
use store::{
    BlobStore, Deserialize, InMemoryStore, IndexKey, IndexKeyPrefix, IterateParams, Key, LogKey,
    SUBSPACE_LOGS, SearchStore, SerializeInfallible, Store, U32_LEN, U64_LEN, ValueKey,
    dispatch::DocumentSet,
    roaring::RoaringBitmap,
    write::{
        AlignedBytes, AnyClass, Archive, AssignedIds, BatchBuilder, BlobLink, BlobOp,
        DirectoryClass, QueueClass, ValueClass, key::DeserializeBigEndian, now,
    },
};
use trc::{AddContext, SpamEvent};
use types::{
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    field::Field,
    type_state::{DataType, StateChange},
};
use utils::{map::bitmap::Bitmap, snowflake::SnowflakeIdGenerator};

impl Server {
    #[inline(always)]
    pub fn store(&self) -> &Store {
        &self.core.storage.data
    }

    #[inline(always)]
    pub fn blob_store(&self) -> &BlobStore {
        &self.core.storage.blob
    }

    #[inline(always)]
    pub fn search_store(&self) -> &SearchStore {
        &self.core.storage.fts
    }

    #[inline(always)]
    pub fn in_memory_store(&self) -> &InMemoryStore {
        &self.core.storage.lookup
    }

    #[inline(always)]
    pub fn directory(&self) -> &Directory {
        &self.core.storage.directory
    }

    pub fn get_directory(&self, name: &str) -> Option<&Arc<Directory>> {
        self.core.storage.directories.get(name)
    }

    pub fn get_directory_or_default(&self, name: &str, session_id: u64) -> &Arc<Directory> {
        self.core.storage.directories.get(name).unwrap_or_else(|| {
            if !name.is_empty() {
                trc::event!(
                    Eval(trc::EvalEvent::DirectoryNotFound),
                    Id = name.to_string(),
                    SpanId = session_id,
                );
            }

            &self.core.storage.directory
        })
    }

    pub fn get_in_memory_store(&self, name: &str) -> Option<&InMemoryStore> {
        self.core.storage.lookups.get(name)
    }

    pub fn get_in_memory_store_or_default(&self, name: &str, session_id: u64) -> &InMemoryStore {
        self.core.storage.lookups.get(name).unwrap_or_else(|| {
            if !name.is_empty() {
                trc::event!(
                    Eval(trc::EvalEvent::StoreNotFound),
                    Id = name.to_string(),
                    SpanId = session_id,
                );
            }

            &self.core.storage.lookup
        })
    }

    pub fn get_data_store(&self, name: &str, session_id: u64) -> &Store {
        self.core.storage.stores.get(name).unwrap_or_else(|| {
            if !name.is_empty() {
                trc::event!(
                    Eval(trc::EvalEvent::StoreNotFound),
                    Id = name.to_string(),
                    SpanId = session_id,
                );
            }

            &self.core.storage.data
        })
    }

    pub fn get_arc_sealer(&self, name: &str, session_id: u64) -> Option<Arc<ArcSealer>> {
        self.resolve_signature(name).map(|s| s.sealer).or_else(|| {
            trc::event!(
                Arc(trc::ArcEvent::SealerNotFound),
                Id = name.to_string(),
                SpanId = session_id,
            );

            None
        })
    }

    pub fn get_dkim_signer(&self, name: &str, session_id: u64) -> Option<Arc<DkimSigner>> {
        self.resolve_signature(name).map(|s| s.signer).or_else(|| {
            trc::event!(
                Dkim(trc::DkimEvent::SignerNotFound),
                Id = name.to_string(),
                SpanId = session_id,
            );

            None
        })
    }

    fn resolve_signature(&self, name: &str) -> Option<ResolvedSignature> {
        let lazy_resolver_ = self.core.smtp.mail_auth.signatures.get(name)?;
        match lazy_resolver_.load().as_ref() {
            LazySignature::Resolved(resolved_signature) => Some(resolved_signature.clone()),
            LazySignature::Pending(config) => {
                let mut config = config.clone();
                if let Some((signer, sealer)) = build_signature(&mut config, name) {
                    let resolved = ResolvedSignature {
                        signer: Arc::new(signer),
                        sealer: Arc::new(sealer),
                    };
                    lazy_resolver_.store(Arc::new(LazySignature::Resolved(resolved.clone())));
                    Some(resolved)
                } else {
                    config.log_errors();
                    lazy_resolver_.store(Arc::new(LazySignature::Failed));
                    None
                }
            }
            LazySignature::Failed => None,
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

    pub async fn get_used_quota(&self, account_id: u32) -> trc::Result<i64> {
        self.core
            .storage
            .data
            .get_counter(DirectoryClass::UsedQuota(account_id))
            .await
            .add_context(|err| err.caused_by(trc::location!()).account_id(account_id))
    }

    pub async fn has_available_quota(
        &self,
        quotas: &ResourceToken,
        item_size: u64,
    ) -> trc::Result<()> {
        if quotas.quota != 0 {
            let used_quota = self.get_used_quota(quotas.account_id).await? as u64;

            if used_quota + item_size > quotas.quota {
                return Err(trc::LimitEvent::Quota
                    .into_err()
                    .ctx(trc::Key::Limit, quotas.quota)
                    .ctx(trc::Key::Size, used_quota));
            }
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        #[cfg(feature = "enterprise")]
        if self.core.is_enterprise_edition()
            && let Some(tenant) = quotas.tenant.filter(|tenant| tenant.quota != 0)
        {
            let used_quota = self.get_used_quota(tenant.id).await? as u64;

            if used_quota + item_size > tenant.quota {
                return Err(trc::LimitEvent::TenantQuota
                    .into_err()
                    .ctx(trc::Key::Limit, tenant.quota)
                    .ctx(trc::Key::Size, used_quota));
            }
        }

        // SPDX-SnippetEnd

        Ok(())
    }

    pub async fn get_resource_token(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<ResourceToken> {
        Ok(if access_token.primary_id == account_id {
            ResourceToken {
                account_id,
                quota: access_token.quota,
                tenant: access_token.tenant,
            }
        } else {
            let mut quotas = ResourceToken {
                account_id,
                ..Default::default()
            };

            if let Some(principal) = self
                .core
                .storage
                .directory
                .query(QueryParams::id(account_id).with_return_member_of(false))
                .await
                .add_context(|err| err.caused_by(trc::location!()).account_id(account_id))?
            {
                quotas.quota = principal.quota().unwrap_or_default();

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL

                #[cfg(feature = "enterprise")]
                if self.core.is_enterprise_edition()
                    && let Some(tenant_id) = principal.tenant()
                {
                    quotas.tenant = TenantInfo {
                        id: tenant_id,
                        quota: self
                            .core
                            .storage
                            .directory
                            .query(QueryParams::id(tenant_id).with_return_member_of(false))
                            .await
                            .add_context(|err| {
                                err.caused_by(trc::location!()).account_id(tenant_id)
                            })?
                            .and_then(|tenant| tenant.quota())
                            .unwrap_or_default(),
                    }
                    .into();
                }

                // SPDX-SnippetEnd
            }

            quotas
        })
    }

    pub async fn archives<I, CB>(
        &self,
        account_id: u32,
        collection: Collection,
        documents: &I,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        I: DocumentSet + Send + Sync,
        CB: FnMut(u32, Archive<AlignedBytes>) -> trc::Result<bool> + Send + Sync,
    {
        let collection: u8 = collection.into();

        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection,
                        document_id: documents.min(),
                        class: ValueClass::Property(Field::ARCHIVE.into()),
                    },
                    ValueKey {
                        account_id,
                        collection,
                        document_id: documents.max(),
                        class: ValueClass::Property(Field::ARCHIVE.into()),
                    },
                ),
                |key, value| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    if documents.contains(document_id) {
                        <Archive<AlignedBytes> as Deserialize>::deserialize(value)
                            .and_then(|archive| cb(document_id, archive))
                    } else {
                        Ok(true)
                    }
                },
            )
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })
    }

    pub async fn all_archives<CB>(
        &self,
        account_id: u32,
        collection: Collection,
        field: u8,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        CB: FnMut(u32, Archive<AlignedBytes>) -> trc::Result<()> + Send + Sync,
    {
        let collection: u8 = collection.into();

        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection,
                        document_id: 0,
                        class: ValueClass::Property(field),
                    },
                    ValueKey {
                        account_id,
                        collection,
                        document_id: u32::MAX,
                        class: ValueClass::Property(field),
                    },
                ),
                |key, value| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    let archive = <Archive<AlignedBytes> as Deserialize>::deserialize(value)?;
                    cb(document_id, archive)?;

                    Ok(true)
                },
            )
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })
    }

    pub async fn document_ids(
        &self,
        account_id: u32,
        collection: Collection,
        field: impl Into<u8>,
    ) -> trc::Result<RoaringBitmap> {
        let field = field.into();
        let mut results = RoaringBitmap::new();
        self.store()
            .iterate(
                IterateParams::new(
                    IndexKeyPrefix {
                        account_id,
                        collection: collection.into(),
                        field,
                    },
                    IndexKeyPrefix {
                        account_id,
                        collection: collection.into(),
                        field: field + 1,
                    },
                )
                .no_values(),
                |key, _| {
                    results.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| results)
    }

    pub async fn document_exists(
        &self,
        account_id: u32,
        collection: Collection,
        field: impl Into<u8>,
        filter: impl AsRef<[u8]>,
    ) -> trc::Result<bool> {
        let field = field.into();
        let mut exists = false;
        let filter = filter.as_ref();
        let key_len = IndexKeyPrefix::len() + filter.len() + U32_LEN;

        self.store()
            .iterate(
                IterateParams::new(
                    IndexKey {
                        account_id,
                        collection: collection.into(),
                        document_id: 0,
                        field,
                        key: filter,
                    },
                    IndexKey {
                        account_id,
                        collection: collection.into(),
                        document_id: u32::MAX,
                        field,
                        key: filter,
                    },
                )
                .no_values(),
                |key, _| {
                    exists = key.len() == key_len;

                    Ok(!exists)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| exists)
    }

    pub async fn document_ids_matching(
        &self,
        account_id: u32,
        collection: Collection,
        field: impl Into<u8>,
        filter: impl AsRef<[u8]>,
    ) -> trc::Result<RoaringBitmap> {
        let field = field.into();
        let filter = filter.as_ref();
        let key_len = IndexKeyPrefix::len() + filter.len() + U32_LEN;
        let mut results = RoaringBitmap::new();

        self.store()
            .iterate(
                IterateParams::new(
                    IndexKey {
                        account_id,
                        collection: collection.into(),
                        document_id: 0,
                        field,
                        key: filter,
                    },
                    IndexKey {
                        account_id,
                        collection: collection.into(),
                        document_id: u32::MAX,
                        field,
                        key: filter,
                    },
                )
                .no_values(),
                |key, _| {
                    if key.len() == key_len {
                        results.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| results)
    }

    #[inline(always)]
    pub fn notify_task_queue(&self) {
        self.inner.ipc.task_tx.notify_one();
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

    #[inline(always)]
    pub fn generate_snowflake_id(&self) -> u64 {
        self.inner.data.jmap_id_gen.generate()
    }

    pub async fn commit_batch(&self, mut builder: BatchBuilder) -> trc::Result<AssignedIds> {
        let mut assigned_ids = AssignedIds::default();
        let mut commit_points = builder.commit_points();

        for commit_point in commit_points.iter() {
            let batch = builder.build_one(commit_point);
            assigned_ids
                .ids
                .extend(self.store().write(batch).await?.ids);
        }

        if let Some(changes) = builder.changes() {
            for (account_id, changed_collections) in changes {
                let mut state_change = StateChange::new(account_id);
                for changed_collection in changed_collections.changed_containers {
                    if let Some(data_type) = DataType::try_from_sync(changed_collection, true) {
                        state_change.set_change(data_type);
                    }
                }
                for changed_collection in changed_collections.changed_items {
                    if let Some(data_type) = DataType::try_from_sync(changed_collection, false) {
                        state_change.set_change(data_type);
                    }
                }
                if state_change.has_changes() {
                    self.broadcast_push_notification(PushNotification::StateChange(
                        state_change.with_change_id(assigned_ids.last_change_id(account_id)?),
                    ))
                    .await;
                }
                if let Some(change_id) = changed_collections.share_notification_id {
                    self.broadcast_push_notification(PushNotification::StateChange(StateChange {
                        account_id,
                        change_id,
                        types: Bitmap::from_iter([DataType::ShareNotification]),
                    }))
                    .await;
                }
            }
        }

        Ok(assigned_ids)
    }

    pub async fn delete_changes(
        &self,
        account_id: u32,
        max_entries: Option<usize>,
        max_duration: Option<Duration>,
    ) -> trc::Result<()> {
        if let Some(max_entries) = max_entries {
            for sync_collection in [
                SyncCollection::Email,
                SyncCollection::Thread,
                SyncCollection::Identity,
                SyncCollection::EmailSubmission,
                SyncCollection::SieveScript,
                SyncCollection::FileNode,
                SyncCollection::AddressBook,
                SyncCollection::Calendar,
                SyncCollection::CalendarEventNotification,
            ] {
                let collection = sync_collection.into();
                let from_key = LogKey {
                    account_id,
                    collection,
                    change_id: 0,
                };
                let to_key = LogKey {
                    account_id,
                    collection,
                    change_id: u64::MAX,
                };

                let mut first_change_id = 0;
                let mut num_changes = 0;

                self.store()
                    .iterate(
                        IterateParams::new(from_key, to_key)
                            .descending()
                            .no_values(),
                        |key, _| {
                            first_change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
                            num_changes += 1;

                            Ok(num_changes <= max_entries)
                        },
                    )
                    .await
                    .caused_by(trc::location!())?;

                if num_changes > max_entries {
                    self.store()
                        .delete_range(
                            LogKey {
                                account_id,
                                collection,
                                change_id: 0,
                            },
                            LogKey {
                                account_id,
                                collection,
                                change_id: first_change_id,
                            },
                        )
                        .await
                        .caused_by(trc::location!())?;

                    // Delete vanished items
                    if let Some(vanished_collection) =
                        sync_collection.vanished_collection().map(u8::from)
                    {
                        self.store()
                            .delete_range(
                                LogKey {
                                    account_id,
                                    collection: vanished_collection,
                                    change_id: 0,
                                },
                                LogKey {
                                    account_id,
                                    collection: vanished_collection,
                                    change_id: first_change_id,
                                },
                            )
                            .await
                            .caused_by(trc::location!())?;
                    }

                    // Write truncation entry for cache
                    let mut batch = BatchBuilder::new();
                    batch.with_account_id(account_id).set(
                        ValueClass::Any(AnyClass {
                            subspace: SUBSPACE_LOGS,
                            key: LogKey {
                                account_id,
                                collection,
                                change_id: first_change_id,
                            }
                            .serialize(0),
                        }),
                        Vec::new(),
                    );
                    self.store()
                        .write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                }
            }
        }

        if let Some(max_duration) = max_duration {
            self.store()
                .delete_range(
                    LogKey {
                        account_id,
                        collection: SyncCollection::ShareNotification.into(),
                        change_id: 0,
                    },
                    LogKey {
                        account_id,
                        collection: SyncCollection::ShareNotification.into(),
                        change_id: SnowflakeIdGenerator::from_duration(max_duration)
                            .unwrap_or_default(),
                    },
                )
                .await
                .caused_by(trc::location!())?;
        }
        Ok(())
    }

    pub async fn broadcast_push_notification(&self, notification: PushNotification) -> bool {
        match self
            .inner
            .ipc
            .push_tx
            .clone()
            .send(PushEvent::Publish {
                notification,
                broadcast: true,
            })
            .await
        {
            Ok(_) => true,
            Err(_) => {
                trc::event!(
                    Server(trc::ServerEvent::ThreadError),
                    Details = "Error sending state change.",
                    CausedBy = trc::location!()
                );

                false
            }
        }
    }

    pub async fn cluster_broadcast(&self, event: BroadcastEvent) {
        if let Some(broadcast_tx) = &self.inner.ipc.broadcast_tx.clone()
            && broadcast_tx.send(event).await.is_err()
        {
            trc::event!(
                Server(trc::ServerEvent::ThreadError),
                Details = "Error sending broadcast event.",
                CausedBy = trc::location!()
            );
        }
    }

    #[allow(clippy::blocks_in_conditions)]
    pub async fn put_jmap_blob(&self, account_id: u32, data: &[u8]) -> trc::Result<BlobId> {
        // First reserve the hash
        let hash = BlobHash::generate(data);
        let mut batch = BatchBuilder::new();
        let until = now() + self.core.jmap.upload_tmp_ttl;

        batch
            .with_account_id(account_id)
            .set(
                BlobOp::Link {
                    hash: hash.clone(),
                    to: BlobLink::Temporary { until },
                },
                vec![BlobLink::QUOTA_LINK],
            )
            .set(
                BlobOp::Quota {
                    hash: hash.clone(),
                    until,
                },
                (data.len() as u32).serialize(),
            );

        self.core
            .storage
            .data
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        if !self
            .core
            .storage
            .data
            .blob_exists(&hash)
            .await
            .caused_by(trc::location!())?
        {
            // Upload blob to store
            self.core
                .storage
                .blob
                .put_blob(hash.as_ref(), data)
                .await
                .caused_by(trc::location!())?;

            // Commit blob
            let mut batch = BatchBuilder::new();
            batch.set(BlobOp::Commit { hash: hash.clone() }, Vec::new());
            self.core
                .storage
                .data
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
        }

        Ok(BlobId {
            hash,
            class: BlobClass::Reserved {
                account_id,
                expires: until,
            },
            section: None,
        })
    }

    pub async fn put_temporary_blob(
        &self,
        account_id: u32,
        data: &[u8],
        hold_for: u64,
    ) -> trc::Result<(BlobHash, BlobOp)> {
        // First reserve the hash
        let hash = BlobHash::generate(data);
        let mut batch = BatchBuilder::new();
        let until = now() + hold_for;

        batch.with_account_id(account_id).set(
            BlobOp::Link {
                hash: hash.clone(),
                to: BlobLink::Temporary { until },
            },
            vec![],
        );

        self.core
            .storage
            .data
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        if !self
            .core
            .storage
            .data
            .blob_exists(&hash)
            .await
            .caused_by(trc::location!())?
        {
            // Upload blob to store
            self.core
                .storage
                .blob
                .put_blob(hash.as_ref(), data)
                .await
                .caused_by(trc::location!())?;

            // Commit blob
            let mut batch = BatchBuilder::new();
            batch.set(BlobOp::Commit { hash: hash.clone() }, Vec::new());
            self.core
                .storage
                .data
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
        }

        Ok((
            hash.clone(),
            BlobOp::Link {
                hash,
                to: BlobLink::Temporary { until },
            },
        ))
    }

    pub async fn total_accounts(&self) -> trc::Result<u64> {
        self.store()
            .count_principals(None, Type::Individual.into(), None)
            .await
            .caused_by(trc::location!())
    }

    pub async fn total_domains(&self) -> trc::Result<u64> {
        self.store()
            .count_principals(None, Type::Domain.into(), None)
            .await
            .caused_by(trc::location!())
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

    #[cfg(not(feature = "enterprise"))]
    pub async fn logo_resource(
        &self,
        _: &str,
    ) -> trc::Result<Option<crate::manager::webadmin::Resource<Vec<u8>>>> {
        Ok(None)
    }
}

pub trait BuildServer {
    fn build_server(&self) -> Server;
}

impl BuildServer for Arc<Inner> {
    fn build_server(&self) -> Server {
        Server {
            inner: self.clone(),
            core: self.shared_core.load_full(),
        }
    }
}
