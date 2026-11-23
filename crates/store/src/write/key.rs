/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AnyKey, BlobOp, QueueClass, QueueEvent, TaskDue, TaskQueueClass, TelemetryClass, ValueClass,
};
#[cfg(feature = "exchange")]
use crate::write::metadata::ExchangeClass;
use crate::{
    ChangeLogKey, IndexKey, IndexKeyPrefix, Key, LogKey, PrivateLogKey, Subspace, U16_LEN, U32_LEN,
    U64_LEN, ValueKey, WITH_SUBSPACE,
    search::{GLOBAL_BUCKET_SHIFT, SearchField},
    write::{
        BlobLink, IndexPropertyClass, PRIVATE_LOG, QueueDocumentId, RegistryClass, SearchIndex,
        SearchIndexClass, metadata::MetadataClass,
    },
};
use registry::{
    schema::{enums::TaskType, prelude::ObjectType, structs::TaskStatus},
    types::EnumImpl,
};
use std::{borrow::BorrowMut, convert::TryInto, mem};
use types::{
    blob_hash::BLOB_HASH_LEN,
    collection::{Collection, SyncCollection},
    field::{
        CalendarEventField, CalendarNotificationField, ContactField, EmailField, Field,
        MailboxField,
    },
};
use utils::{
    codec::leb128::{Leb128, Leb128Writer},
    hash128::Hash128,
};
pub struct KeySerializer<B = Vec<u8>> {
    buf: B,
}

pub trait KeySerialize {
    fn to_key_bytes(&self) -> impl AsRef<[u8]>;
}

pub trait DeserializeBigEndian {
    fn deserialize_be_u16(&self, index: usize) -> trc::Result<u16>;
    fn deserialize_be_u32(&self, index: usize) -> trc::Result<u32>;
    fn deserialize_be_u64(&self, index: usize) -> trc::Result<u64>;
}

impl KeySerializer<Vec<u8>> {
    #[inline(always)]
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    #[inline(always)]
    pub fn finalize(&mut self) -> Vec<u8> {
        mem::take(&mut self.buf)
    }
}

impl<'x> KeySerializer<&'x mut Vec<u8>> {
    #[inline(always)]
    pub fn borrowed(buf: &'x mut Vec<u8>) -> Self {
        Self { buf }
    }
}

impl<B: BorrowMut<Vec<u8>>> KeySerializer<B> {
    #[inline(always)]
    pub fn write<T: KeySerialize>(&mut self, value: T) -> &mut Self {
        self.buf
            .borrow_mut()
            .extend_from_slice(value.to_key_bytes().as_ref());
        self
    }

    #[inline(always)]
    pub fn write_leb128<T: Leb128>(&mut self, value: T) -> &mut Self {
        self.buf.borrow_mut().push_leb128(value);
        self
    }
}

impl KeySerialize for u8 {
    #[inline(always)]
    fn to_key_bytes(&self) -> impl AsRef<[u8]> {
        [*self]
    }
}

impl KeySerialize for &[u8] {
    #[inline(always)]
    fn to_key_bytes(&self) -> impl AsRef<[u8]> {
        *self
    }
}

impl KeySerialize for &str {
    #[inline(always)]
    fn to_key_bytes(&self) -> impl AsRef<[u8]> {
        self.as_bytes()
    }
}

impl KeySerialize for &String {
    #[inline(always)]
    fn to_key_bytes(&self) -> impl AsRef<[u8]> {
        self.as_bytes()
    }
}

impl KeySerialize for Hash128 {
    #[inline(always)]
    fn to_key_bytes(&self) -> impl AsRef<[u8]> {
        self.as_be_bytes()
    }
}

macro_rules! impl_key_serialize_be {
    ($($ty:ty),+) => {$(
        impl KeySerialize for $ty {
            #[inline(always)]
            fn to_key_bytes(&self) -> impl AsRef<[u8]> {
                self.to_be_bytes()
            }
        }
    )+};
}

impl_key_serialize_be!(u16, u32, u64);

impl DeserializeBigEndian for &[u8] {
    fn deserialize_be_u16(&self, index: usize) -> trc::Result<u16> {
        self.get(index..index + U16_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, *self)
            })
            .map(u16::from_be_bytes)
    }

    fn deserialize_be_u32(&self, index: usize) -> trc::Result<u32> {
        self.get(index..index + U32_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, *self)
            })
            .map(u32::from_be_bytes)
    }

    fn deserialize_be_u64(&self, index: usize) -> trc::Result<u64> {
        self.get(index..index + U64_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, *self)
            })
            .map(u64::from_be_bytes)
    }
}

impl<T: AsRef<ValueClass>> ValueKey<T> {
    pub fn with_document_id(self, document_id: u32) -> Self {
        Self {
            document_id,
            ..self
        }
    }
}

impl ValueKey<ValueClass> {
    pub fn property(
        account_id: u32,
        collection: impl Into<u8>,
        document_id: u32,
        field: impl Into<u8>,
    ) -> ValueKey<ValueClass> {
        ValueKey {
            account_id,
            collection: collection.into(),
            document_id,
            class: ValueClass::Property(field.into()),
        }
    }

    pub fn archive(
        account_id: u32,
        collection: impl Into<u8>,
        document_id: u32,
    ) -> ValueKey<ValueClass> {
        ValueKey {
            account_id,
            collection: collection.into(),
            document_id,
            class: ValueClass::Property(Field::ARCHIVE.into()),
        }
    }

    pub fn immutable(
        account_id: u32,
        collection: impl Into<u8>,
        document_id: u32,
        field: impl Into<u8>,
    ) -> ValueKey<ValueClass> {
        ValueKey {
            account_id,
            collection: collection.into(),
            document_id,
            class: ValueClass::Immutable(field.into()),
        }
    }
}

impl Key for IndexKeyPrefix {
    fn key_len_hint(&self) -> usize {
        IndexKeyPrefix::len()
    }

    fn serialize_into(&self, buf: &mut Vec<u8>, flags: u32) {
        let mut serializer = KeySerializer::borrowed(buf);
        if (flags & WITH_SUBSPACE) != 0 {
            serializer.write(Subspace::Indexes.byte());
        }

        serializer
            .write(self.account_id)
            .write(self.collection)
            .write(self.field);
    }

    fn subspace(&self) -> Subspace {
        Subspace::Indexes
    }
}

impl IndexKeyPrefix {
    pub fn len() -> usize {
        U32_LEN + 2
    }
}

impl Key for LogKey {
    fn subspace(&self) -> Subspace {
        Subspace::Logs
    }

    fn key_len_hint(&self) -> usize {
        U32_LEN + 1 + U64_LEN
    }

    fn serialize_into(&self, buf: &mut Vec<u8>, flags: u32) {
        let mut serializer = KeySerializer::borrowed(buf);
        if (flags & WITH_SUBSPACE) != 0 {
            serializer.write(Subspace::Logs.byte());
        }

        serializer
            .write(self.account_id)
            .write(self.collection)
            .write(self.change_id);
    }
}

impl Key for PrivateLogKey {
    fn subspace(&self) -> Subspace {
        Subspace::Logs
    }

    fn key_len_hint(&self) -> usize {
        U32_LEN + 1 + U32_LEN + U64_LEN
    }

    fn serialize_into(&self, buf: &mut Vec<u8>, flags: u32) {
        let mut serializer = KeySerializer::borrowed(buf);
        if (flags & WITH_SUBSPACE) != 0 {
            serializer.write(Subspace::Logs.byte());
        }

        serializer
            .write(self.account_id)
            .write(PRIVATE_LOG | u8::from(self.collection))
            .write(self.viewer)
            .write(self.change_id);
    }
}

impl Key for ChangeLogKey {
    fn subspace(&self) -> Subspace {
        Subspace::Logs
    }

    fn key_len_hint(&self) -> usize {
        match self {
            ChangeLogKey::Shared(key) => key.key_len_hint(),
            ChangeLogKey::Private(key) => key.key_len_hint(),
        }
    }

    fn serialize_into(&self, buf: &mut Vec<u8>, flags: u32) {
        match self {
            ChangeLogKey::Shared(key) => key.serialize_into(buf, flags),
            ChangeLogKey::Private(key) => key.serialize_into(buf, flags),
        }
    }
}

impl<T: AsRef<ValueClass> + Sync + Send + Clone> Key for ValueKey<T> {
    fn subspace(&self) -> Subspace {
        self.class.as_ref().subspace(self.collection)
    }

    fn key_len_hint(&self) -> usize {
        self.class.as_ref().key_len_hint()
    }

    fn serialize_into(&self, buf: &mut Vec<u8>, flags: u32) {
        self.class.as_ref().serialize_into(
            buf,
            self.account_id,
            self.collection,
            self.document_id,
            flags,
        )
    }
}

impl ValueClass {
    pub fn serialize(
        &self,
        account_id: u32,
        collection: u8,
        document_id: u32,
        flags: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.key_len_hint() + 1);
        self.serialize_into(&mut buf, account_id, collection, document_id, flags);
        buf
    }

    pub fn serialize_into(
        &self,
        buf: &mut Vec<u8>,
        account_id: u32,
        collection: u8,
        document_id: u32,
        flags: u32,
    ) {
        let start = buf.len();
        let with_subspace = (flags & WITH_SUBSPACE) != 0;
        let mut serializer = KeySerializer::borrowed(buf);
        if with_subspace {
            serializer.write(self.subspace(collection).byte());
        }

        let serializer = match self {
            ValueClass::Property(property) => serializer
                .write(account_id)
                .write(collection)
                .write(*property)
                .write(document_id),
            ValueClass::Immutable(property) => serializer
                .write(account_id)
                .write(collection)
                .write(*property)
                .write(document_id),
            ValueClass::MailboxUid => serializer
                .write(CounterKind::MailboxUid.byte())
                .write(account_id)
                .write(document_id),
            ValueClass::IndexProperty(property) => match property {
                IndexPropertyClass::Integer { property, value } => serializer
                    .write(account_id)
                    .write(collection)
                    .write(*property)
                    .write(IndexPropertyClass::KIND_INTEGER)
                    .write(*value)
                    .write(document_id),
                IndexPropertyClass::Hash { property, hash } => serializer
                    .write(account_id)
                    .write(collection)
                    .write(*property)
                    .write(IndexPropertyClass::KIND_HASH)
                    .write(*hash)
                    .write(!document_id),
            },
            ValueClass::Acl(grant_account_id) => serializer
                .write(*grant_account_id)
                .write(account_id)
                .write(collection)
                .write(document_id),
            ValueClass::TaskQueue(task) => match task {
                TaskQueueClass::Task { id } => serializer
                    .write(TaskQueueClass::KIND_TASK)
                    .write(id.resolve(account_id, document_id)),
                TaskQueueClass::Due { id, typ, due } => serializer
                    .write(TaskQueueClass::KIND_DUE)
                    .write(*typ as u16)
                    .write(*due)
                    .write(id.resolve(account_id, document_id)),
            },
            ValueClass::Blob(op) => match op {
                BlobOp::Commit { hash } => serializer.write::<&[u8]>(hash.as_ref()),
                BlobOp::Link { hash, to } => match to {
                    BlobLink::Id { id } => serializer.write::<&[u8]>(hash.as_ref()).write(*id),
                    BlobLink::Document => serializer
                        .write::<&[u8]>(hash.as_ref())
                        .write(account_id)
                        .write(collection)
                        .write(document_id),
                    BlobLink::Temporary { until } => serializer
                        .write::<&[u8]>(hash.as_ref())
                        .write(account_id)
                        .write(*until),
                },
            },
            ValueClass::Registry(registry) => match registry {
                RegistryClass::Item { object_id, item_id } => {
                    serializer.write(*object_id).write(*item_id)
                }
                RegistryClass::IndexId { object_id, item_id } => {
                    serializer.write(u16::MAX).write(*object_id).write(*item_id)
                }
                RegistryClass::Index {
                    index_id,
                    object_id,
                    item_id,
                    key,
                } => serializer
                    .write(*object_id)
                    .write(*index_id)
                    .write(key.as_slice())
                    .write(*item_id),
                RegistryClass::Reference {
                    to_object_id,
                    to_item_id,
                    from_object_id,
                    from_item_id,
                } => serializer
                    .write(RegistryClass::REFERENCE_MARKER)
                    .write(*to_object_id)
                    .write(*to_item_id)
                    .write(*from_object_id)
                    .write(*from_item_id),
                RegistryClass::PrimaryKey {
                    object_id,
                    index_id,
                    key,
                } => serializer
                    .write((*object_id).unwrap_or(u16::MAX))
                    .write(*index_id)
                    .write(key.as_slice()),
                RegistryClass::IdCounter { object_id } => serializer
                    .write(CounterKind::RegistryId.byte())
                    .write(*object_id),
            },
            ValueClass::Queue(queue) => match queue {
                QueueClass::Message(queue_id) => serializer.write(*queue_id),
                QueueClass::MessageEvent(event) => serializer
                    .write(event.queue_name.as_slice())
                    .write(event.due)
                    .write(event.queue_id),
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                QueueClass::TenantMessage {
                    tenant_id,
                    queue_id,
                } => serializer
                    .write(QueueEvent::TENANT_INDEX_QUEUE.as_slice())
                    .write(u64::from(*tenant_id))
                    .write(*queue_id),
                // SPDX-SnippetEnd
                QueueClass::QuotaCount(key) => serializer
                    .write(CounterKind::QueueQuotaCount.byte())
                    .write(*key),
                QueueClass::QuotaSize(key) => serializer
                    .write(CounterKind::QueueQuotaSize.byte())
                    .write(*key),
            },
            ValueClass::Telemetry(telemetry) => match telemetry {
                TelemetryClass::Span(span_id) => serializer.write(*span_id),
                TelemetryClass::Metric(metric_id) => serializer.write(*metric_id),
            },
            ValueClass::DocumentId => serializer
                .write(CounterKind::DocumentId.byte())
                .write(account_id)
                .write(collection),
            ValueClass::ChangeId(group) => serializer
                .write(CounterKind::ChangeId.byte())
                .write(account_id)
                .write(group.to_u8()),
            ValueClass::Quota => serializer
                .write(CounterKind::Quota.byte())
                .write(account_id),
            ValueClass::ObjectCount(object) => serializer
                .write(CounterKind::ObjectCount.byte())
                .write(account_id)
                .write(*object as u8),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ValueClass::TenantQuota(tenant_id) => serializer
                .write(CounterKind::TenantQuota.byte())
                .write(*tenant_id),
            // SPDX-SnippetEnd
            ValueClass::NodeId(node_id) => {
                serializer.write(SystemKind::NodeId as u8).write(*node_id)
            }
            ValueClass::ShareNotification {
                notification_id,
                notify_account_id,
            } => serializer
                .write(*notify_account_id)
                .write(u8::from(SyncCollection::ShareNotification))
                .write(*notification_id),
            ValueClass::SearchIndex(search) => match search {
                SearchIndexClass::Term {
                    index,
                    account_id,
                    field,
                    term,
                    block_id,
                } => serializer
                    .write(index.to_u8())
                    .write(*account_id)
                    .write(index.term_group(*field))
                    .write(term.as_key())
                    .write(term.len() as u8)
                    .write(*field)
                    .write(*block_id),
                SearchIndexClass::Document {
                    index,
                    account_id,
                    document_id,
                } => serializer
                    .write(index.to_u8())
                    .write(*account_id)
                    .write(*document_id),
                SearchIndexClass::GlobalTerm {
                    index,
                    field,
                    term,
                    block_id,
                } => serializer
                    .write(index.to_u8())
                    .write(*field)
                    .write(term.as_key())
                    .write(term.len() as u8)
                    .write(*block_id),
                SearchIndexClass::GlobalDocument { index, document_id } => {
                    serializer.write(index.to_u8()).write(*document_id)
                }
                SearchIndexClass::GlobalDocumentId { index, block_id } => serializer
                    .write(index.to_u8())
                    .write(SearchField::Id.u8_id())
                    .write(*block_id),
                SearchIndexClass::Queue {
                    index,
                    id_prefix,
                    id_suffix,
                    created_at,
                } => serializer
                    .write(index.to_u8())
                    .write(*id_prefix)
                    .write(id_suffix.resolve(document_id))
                    .write(*created_at),
                SearchIndexClass::QueueIndex { index, partition } => serializer
                    .write(SearchIndexClass::QUEUE_CONTROL)
                    .write(index.to_u8())
                    .write(*partition)
                    .write(SearchIndexClass::CONTROL_INDEX),
                SearchIndexClass::QueueStatus { index, partition } => serializer
                    .write(SearchIndexClass::QUEUE_CONTROL)
                    .write(index.to_u8())
                    .write(*partition)
                    .write(SearchIndexClass::CONTROL_STATUS),
            },
            ValueClass::Any(any) => serializer.write(any.key.as_slice()),
            ValueClass::Metadata(class) => {
                let serializer = serializer.write(account_id).write(METADATA_COLLECTION);
                match class {
                    MetadataClass::Shared => serializer
                        .write(MetadataClass::SHARED)
                        .write(collection)
                        .write(document_id),
                    MetadataClass::Private { viewer } => serializer
                        .write(MetadataClass::PRIVATE)
                        .write(*viewer)
                        .write(collection)
                        .write(document_id),
                    MetadataClass::Viewer { viewer } => serializer
                        .write(MetadataClass::VIEWER)
                        .write(collection)
                        .write(*viewer),
                    MetadataClass::Owner { owner } => serializer
                        .write(MetadataClass::OWNER)
                        .write(*owner)
                        .write(collection),
                    #[cfg(feature = "exchange")]
                    MetadataClass::Exchange(class) => {
                        let serializer = serializer
                            .write(MetadataClass::EXCHANGE)
                            .write(class.code());
                        match class {
                            ExchangeClass::Object | ExchangeClass::Alias => {
                                serializer.write(collection).write(document_id)
                            }
                            ExchangeClass::Account
                            | ExchangeClass::NamedProperties
                            | ExchangeClass::Categories
                            | ExchangeClass::TaskList
                            | ExchangeClass::Rules => serializer,
                            ExchangeClass::Device { slot } => serializer.write(*slot),
                            ExchangeClass::DeviceFolder { slot, folder } => {
                                serializer.write(*slot).write(folder.kind).write(folder.id)
                            }
                            ExchangeClass::Fai { folder, id }
                            | ExchangeClass::FaiTombstone { folder, id } => {
                                serializer.write(folder.kind).write(folder.id).write(*id)
                            }
                            ExchangeClass::Folder { id }
                            | ExchangeClass::FolderTombstone { id } => serializer.write(*id),
                            ExchangeClass::OfflineAddressBook { tenant } => {
                                serializer.write(*tenant)
                            }
                            ExchangeClass::SpecialFolder { code } => serializer.write(*code),
                        }
                    }
                }
            }
        };

        debug_assert_eq!(
            serializer.buf.len() - start,
            self.key_len_hint() + usize::from(with_subspace),
            "key length hint disagrees with the serialized key for {self:?}"
        );
    }
}

impl<T: AsRef<[u8]> + Sync + Send + Clone> Key for IndexKey<T> {
    fn subspace(&self) -> Subspace {
        Subspace::Indexes
    }

    fn key_len_hint(&self) -> usize {
        IndexKeyPrefix::len() + self.key.as_ref().len() + U32_LEN
    }

    fn serialize_into(&self, buf: &mut Vec<u8>, flags: u32) {
        let mut serializer = KeySerializer::borrowed(buf);
        if (flags & WITH_SUBSPACE) != 0 {
            serializer.write(Subspace::Indexes.byte());
        }

        serializer
            .write(self.account_id)
            .write(self.collection)
            .write(self.field)
            .write(self.key.as_ref())
            .write(self.document_id);
    }
}

impl<T: AsRef<[u8]> + Sync + Send + Clone> Key for AnyKey<T> {
    fn key_len_hint(&self) -> usize {
        self.key.as_ref().len()
    }

    fn serialize_into(&self, buf: &mut Vec<u8>, flags: u32) {
        let mut serializer = KeySerializer::borrowed(buf);
        if (flags & WITH_SUBSPACE) != 0 {
            serializer.write(self.subspace.byte());
        }

        serializer.write(self.key.as_ref());
    }

    fn subspace(&self) -> Subspace {
        self.subspace
    }
}

const MAILBOX_COLLECTION: u8 = Collection::Mailbox as u8;
const METADATA_COLLECTION: u8 = Collection::Metadata as u8;
const EMAIL_COLLECTION: u8 = Collection::Email as u8;
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
const REG_ARCHIVED_ITEM: u16 = ObjectType::ArchivedItem as u16;
// SPDX-SnippetEnd
const REG_SPAM_SAMPLE: u16 = ObjectType::SpamTrainingSample as u16;
const REG_ACCOUNT: u16 = ObjectType::Account as u16;
const REG_DOMAIN: u16 = ObjectType::Domain as u16;
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
const REG_TENANT: u16 = ObjectType::Tenant as u16;
// SPDX-SnippetEnd
const REG_ROLE: u16 = ObjectType::Role as u16;
const REG_OAUTH_CLIENT: u16 = ObjectType::OAuthClient as u16;
const REG_OAUTH_GRANT: u16 = ObjectType::OAuthGrant as u16;
const REG_MAILING_LIST: u16 = ObjectType::MailingList as u16;
const REG_MASKED_EMAIL: u16 = ObjectType::MaskedEmail as u16;
const REG_PUBLIC_KEY: u16 = ObjectType::PublicKey as u16;
const REG_CALENDAR_SETTINGS: u16 = ObjectType::CalendarSettings as u16;
const REPORT_EXTERNAL_ARF: u16 = ObjectType::ArfExternalReport as u16;
const REPORT_EXTERNAL_DMARC: u16 = ObjectType::DmarcExternalReport as u16;
const REPORT_EXTERNAL_TLS: u16 = ObjectType::TlsExternalReport as u16;
const REPORT_INTERNAL_DMARC: u16 = ObjectType::DmarcInternalReport as u16;
const REPORT_INTERNAL_TLS: u16 = ObjectType::TlsInternalReport as u16;

impl ValueClass {
    pub fn key_len_hint(&self) -> usize {
        match self {
            ValueClass::Property(_) | ValueClass::Immutable(_) => (U32_LEN * 2) + 2,
            ValueClass::MailboxUid => (U32_LEN * 2) + 1,
            ValueClass::IndexProperty(p) => {
                (U32_LEN * 2)
                    + 3
                    + match p {
                        IndexPropertyClass::Hash { .. } => Hash128::LEN,
                        IndexPropertyClass::Integer { .. } => U64_LEN,
                    }
            }
            ValueClass::Acl(_) => (U32_LEN * 3) + 1,
            ValueClass::Registry(registry) => match registry {
                RegistryClass::Item { .. } => U16_LEN + U64_LEN,
                RegistryClass::Reference { .. } => U16_LEN + ((U16_LEN + U64_LEN) * 2),
                RegistryClass::Index { key, .. } => (U16_LEN * 2) + U64_LEN + key.len(),
                RegistryClass::PrimaryKey { key, .. } => (U16_LEN * 2) + key.len(),
                RegistryClass::IndexId { .. } => (U16_LEN * 2) + U64_LEN,
                RegistryClass::IdCounter { .. } => U16_LEN + 1,
            },
            ValueClass::Blob(op) => match op {
                BlobOp::Commit { .. } => BLOB_HASH_LEN,
                BlobOp::Link { to, .. } => {
                    BLOB_HASH_LEN
                        + match to {
                            BlobLink::Id { .. } => U64_LEN,
                            BlobLink::Document => (U32_LEN * 2) + 1,
                            BlobLink::Temporary { .. } => U32_LEN + U64_LEN,
                        }
                }
            },
            ValueClass::TaskQueue(task) => match task {
                TaskQueueClass::Task { .. } => U64_LEN + 1,
                TaskQueueClass::Due { .. } => (U64_LEN * 2) + U16_LEN + 1,
            },
            ValueClass::Queue(q) => match q {
                QueueClass::Message(_) => U64_LEN,
                QueueClass::MessageEvent(_) => QueueEvent::KEY_LEN,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                QueueClass::TenantMessage { .. } => QueueEvent::KEY_LEN,
                // SPDX-SnippetEnd
                QueueClass::QuotaCount(_) | QueueClass::QuotaSize(_) => Hash128::LEN + 1,
            },
            ValueClass::Telemetry(telemetry) => match telemetry {
                TelemetryClass::Span(_) | TelemetryClass::Metric(_) => U64_LEN,
            },
            ValueClass::DocumentId | ValueClass::ChangeId(_) | ValueClass::ObjectCount(_) => {
                U32_LEN + 2
            }
            ValueClass::Quota => U32_LEN + 1,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ValueClass::TenantQuota(_) => U32_LEN + 1,
            // SPDX-SnippetEnd
            ValueClass::ShareNotification { .. } => U32_LEN + U64_LEN + 1,
            ValueClass::NodeId(_) => U16_LEN + 1,
            ValueClass::SearchIndex(v) => match v {
                SearchIndexClass::Term { term, .. } => U32_LEN + term.key_len() + U16_LEN + 4,
                SearchIndexClass::Document { .. } => (U32_LEN * 2) + 1,
                SearchIndexClass::GlobalTerm { term, .. } => term.key_len() + U16_LEN + 3,
                SearchIndexClass::GlobalDocument { .. } => U64_LEN + 1,
                SearchIndexClass::GlobalDocumentId { .. } => U16_LEN + 2,
                SearchIndexClass::Queue { .. } => (U32_LEN * 2) + U64_LEN + 1,
                SearchIndexClass::QueueIndex { .. } | SearchIndexClass::QueueStatus { .. } => {
                    U32_LEN + 3
                }
            },
            ValueClass::Any(v) => v.key.len(),
            ValueClass::Metadata(class) => match class {
                MetadataClass::Private { .. } => (U32_LEN * 3) + 3,
                MetadataClass::Shared
                | MetadataClass::Viewer { .. }
                | MetadataClass::Owner { .. } => (U32_LEN * 2) + 3,
                #[cfg(feature = "exchange")]
                MetadataClass::Exchange(class) => U32_LEN + 3 + class.key_len(),
            },
        }
    }

    pub fn subspace(&self, collection: u8) -> Subspace {
        match self {
            ValueClass::Property(field) => {
                debug_assert!(
                    !(collection == MAILBOX_COLLECTION
                        && *field == u8::from(MailboxField::UidCounter)),
                    "the mailbox UID counter must be written as ValueClass::MailboxUid"
                );
                debug_assert!(
                    !(collection == EMAIL_COLLECTION
                        && (*field == u8::from(EmailField::Metadata)
                            || *field == u8::from(EmailField::SortKeys))),
                    "email field {field} must be written as ValueClass::Immutable"
                );
                Subspace::Property
            }
            ValueClass::Immutable(_) => Subspace::Immutable,
            ValueClass::IndexProperty { .. } => Subspace::IndexProperty,
            ValueClass::MailboxUid => Subspace::Counter,
            ValueClass::Acl(_) => Subspace::Acl,
            ValueClass::TaskQueue { .. } => Subspace::TaskQueue,
            ValueClass::Blob(op) => match op {
                BlobOp::Commit { .. } | BlobOp::Link { .. } => Subspace::BlobLink,
            },
            ValueClass::Registry(registry) => match registry {
                RegistryClass::Item { object_id, .. } => match *object_id {
                    REG_ACCOUNT
                    | REG_DOMAIN
                    | REG_ROLE
                    | REG_OAUTH_CLIENT
                    | REG_MAILING_LIST
                    | REG_PUBLIC_KEY
                    | REG_OAUTH_GRANT
                    | REG_MASKED_EMAIL
                    | REG_CALENDAR_SETTINGS => Subspace::Directory,
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    REG_TENANT => Subspace::Directory,
                    #[cfg(feature = "enterprise")]
                    REG_ARCHIVED_ITEM => Subspace::DeletedItems,
                    // SPDX-SnippetEnd
                    REG_SPAM_SAMPLE => Subspace::SpamSamples,
                    REPORT_EXTERNAL_ARF | REPORT_EXTERNAL_DMARC | REPORT_EXTERNAL_TLS => {
                        Subspace::ReportIn
                    }
                    REPORT_INTERNAL_DMARC | REPORT_INTERNAL_TLS => Subspace::ReportOut,
                    _ => Subspace::Registry,
                },
                RegistryClass::IndexId { .. } | RegistryClass::Index { .. } => {
                    Subspace::RegistryIndex
                }
                RegistryClass::Reference { .. } | RegistryClass::PrimaryKey { .. } => {
                    Subspace::RegistryPrimaryKey
                }
                RegistryClass::IdCounter { .. } => Subspace::Counter,
            },
            ValueClass::NodeId(_) => Subspace::System,
            ValueClass::Queue(queue) => match queue {
                QueueClass::Message(_) => Subspace::QueueMessage,
                QueueClass::MessageEvent(_) => Subspace::QueueEvent,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                QueueClass::TenantMessage { .. } => Subspace::QueueEvent,
                // SPDX-SnippetEnd
                QueueClass::QuotaCount(_) | QueueClass::QuotaSize(_) => Subspace::Counter,
            },
            ValueClass::Telemetry(telemetry) => match telemetry {
                TelemetryClass::Span { .. } => Subspace::TelemetrySpan,
                TelemetryClass::Metric { .. } => Subspace::TelemetryMetric,
            },
            ValueClass::DocumentId
            | ValueClass::ChangeId(_)
            | ValueClass::Quota
            | ValueClass::ObjectCount(_) => Subspace::Counter,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ValueClass::TenantQuota(_) => Subspace::Counter,
            // SPDX-SnippetEnd
            ValueClass::ShareNotification { .. } => Subspace::Logs,
            ValueClass::SearchIndex(search) => match search {
                SearchIndexClass::Term { .. }
                | SearchIndexClass::GlobalTerm { .. }
                | SearchIndexClass::GlobalDocumentId { .. } => Subspace::SearchTerm,
                SearchIndexClass::Document { .. } | SearchIndexClass::GlobalDocument { .. } => {
                    Subspace::SearchDocument
                }
                SearchIndexClass::Queue { .. }
                | SearchIndexClass::QueueIndex { .. }
                | SearchIndexClass::QueueStatus { .. } => Subspace::SearchQueue,
            },
            ValueClass::Any(any) => any.subspace,
            ValueClass::Metadata(_) => Subspace::Property,
        }
    }

    pub fn may_be_chunked(&self) -> bool {
        match self {
            ValueClass::Property(field) => {
                *field == u8::from(Field::ARCHIVE)
                    || *field == ContactField::Content.as_u8()
                    || *field == CalendarEventField::Content.as_u8()
                    || *field == CalendarNotificationField::Content.as_u8()
            }
            ValueClass::Immutable(field) => *field == u8::from(EmailField::Metadata),
            ValueClass::IndexProperty(IndexPropertyClass::Hash { .. })
            | ValueClass::Registry(RegistryClass::Item { .. })
            | ValueClass::Queue(QueueClass::Message(_))
            | ValueClass::TaskQueue(TaskQueueClass::Task { .. })
            | ValueClass::Telemetry(TelemetryClass::Span(_))
            | ValueClass::Metadata(MetadataClass::Shared | MetadataClass::Private { .. }) => true,
            #[cfg(feature = "exchange")]
            ValueClass::Metadata(MetadataClass::Exchange(class)) => class.may_be_chunked(),
            ValueClass::SearchIndex(search) => matches!(
                search,
                SearchIndexClass::Document { .. }
                    | SearchIndexClass::GlobalTerm { .. }
                    | SearchIndexClass::GlobalDocument { .. }
                    | SearchIndexClass::GlobalDocumentId { .. }
            ),
            _ => false,
        }
    }
}

pub fn node_id_from_key(key: &[u8]) -> Option<u16> {
    match key {
        [kind, node_id @ ..] if *kind == SystemKind::NodeId as u8 && node_id.len() == U16_LEN => {
            node_id.try_into().ok().map(u16::from_be_bytes)
        }
        _ => None,
    }
}

pub fn is_node_id_key(key: &[u8]) -> bool {
    node_id_from_key(key).is_some()
}

impl From<ValueClass> for ValueKey<ValueClass> {
    fn from(class: ValueClass) -> Self {
        ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class,
        }
    }
}

impl From<RegistryClass> for ValueKey<ValueClass> {
    fn from(value: RegistryClass) -> Self {
        ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Registry(value),
        }
    }
}

impl From<RegistryClass> for ValueClass {
    fn from(value: RegistryClass) -> Self {
        ValueClass::Registry(value)
    }
}

impl From<BlobOp> for ValueClass {
    fn from(value: BlobOp) -> Self {
        ValueClass::Blob(value)
    }
}

impl RegistryClass {
    pub const REFERENCE_MARKER: u16 = u16::MAX - 1;

    pub fn prefix(object_id: u16, index_id: u16) -> Vec<u8> {
        KeySerializer::new(U16_LEN * 2)
            .write(object_id)
            .write(index_id)
            .finalize()
    }

    pub fn item_range(object_id: u16) -> (AnyKey<Vec<u8>>, AnyKey<Vec<u8>>) {
        let subspace = ValueClass::Registry(RegistryClass::Item {
            object_id,
            item_id: 0,
        })
        .subspace(0);

        (
            AnyKey {
                subspace,
                key: KeySerializer::new(U16_LEN).write(object_id).finalize(),
            },
            AnyKey {
                subspace,
                key: KeySerializer::new(U16_LEN + U64_LEN)
                    .write(object_id)
                    .write(u64::MAX)
                    .finalize(),
            },
        )
    }

    pub fn index_range(
        object_id: u16,
        from: (u16, &[u8], Option<u64>),
        to: (u16, &[u8], Option<u64>),
    ) -> (AnyKey<Vec<u8>>, AnyKey<Vec<u8>>) {
        (
            AnyKey {
                subspace: Subspace::RegistryIndex,
                key: Self::bound(object_id, from),
            },
            AnyKey {
                subspace: Subspace::RegistryIndex,
                key: Self::bound(object_id, to),
            },
        )
    }

    pub fn pk_range(
        object_id: u16,
        from: (u16, &[u8], Option<u64>),
        to: (u16, &[u8], Option<u64>),
    ) -> (AnyKey<Vec<u8>>, AnyKey<Vec<u8>>) {
        (
            AnyKey {
                subspace: Subspace::RegistryPrimaryKey,
                key: Self::bound(object_id, from),
            },
            AnyKey {
                subspace: Subspace::RegistryPrimaryKey,
                key: Self::bound(object_id, to),
            },
        )
    }

    fn bound(object_id: u16, (index_id, value, item_id): (u16, &[u8], Option<u64>)) -> Vec<u8> {
        let mut serializer = KeySerializer::new((U16_LEN * 2) + value.len() + U64_LEN);
        serializer.write(object_id).write(index_id).write(value);
        if let Some(item_id) = item_id {
            serializer.write(item_id);
        }
        serializer.finalize()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CounterKind {
    DocumentId = 0x00,
    ChangeId = 0x01,
    ObjectCount = 0x02,
    Quota = 0x03,
    MailboxUid = 0x04,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    TenantQuota = 0x05,
    // SPDX-SnippetEnd
    RegistryId = 0x06,
    ReportRow = 0x07,
    QueueQuotaCount = 0x08,
    QueueQuotaSize = 0x09,
}

impl CounterKind {
    pub const ACCOUNT_KINDS: [CounterKind; 5] = [
        CounterKind::DocumentId,
        CounterKind::ChangeId,
        CounterKind::ObjectCount,
        CounterKind::Quota,
        CounterKind::MailboxUid,
    ];

    #[inline(always)]
    pub const fn byte(self) -> u8 {
        self as u8
    }
}

#[repr(u8)]
pub enum SystemKind {
    SchemaVersion = 0x00,
    NodeId = 0x01,
}

impl QueueEvent {
    pub const KEY_LEN: usize = U64_LEN * 3;
    pub const TENANT_INDEX_QUEUE: [u8; 8] = [u8::MAX; 8];
    pub const LAST_QUEUE: [u8; 8] = (u64::MAX - 1).to_be_bytes();

    pub fn deserialize(key: &[u8]) -> trc::Result<Self> {
        if let Some((queue_name, rest)) = key.split_first_chunk::<U64_LEN>()
            && let Some((due, rest)) = rest.split_first_chunk::<U64_LEN>()
            && let Some((queue_id, [])) = rest.split_first_chunk::<U64_LEN>()
        {
            Ok(QueueEvent {
                due: u64::from_be_bytes(*due),
                queue_id: u64::from_be_bytes(*queue_id),
                queue_name: *queue_name,
            })
        } else {
            Err(trc::Error::corrupted_key(key, None, trc::location!()))
        }
    }
}

impl TaskQueueClass {
    pub const KIND_TASK: u8 = 0x00;
    pub const KIND_DUE: u8 = 0x01;
    pub const DUE_RETRY: u8 = 0x01;
    pub const DUE_STALLED: u8 = 0x02;

    pub fn due_marker(status: &TaskStatus) -> Option<u8> {
        match status {
            TaskStatus::Retry(_) => Some(Self::DUE_RETRY),
            TaskStatus::Stalled(_) => Some(Self::DUE_STALLED),
            TaskStatus::Pending(_) | TaskStatus::Failed(_) => None,
        }
    }

    #[inline]
    pub fn due_marker_of(value: &[u8]) -> Option<u8> {
        value.first().copied()
    }
}

impl TaskDue {
    pub fn deserialize(key: &[u8]) -> trc::Result<Self> {
        if let Some((&TaskQueueClass::KIND_DUE, rest)) = key.split_first()
            && let Some((typ, rest)) = rest.split_first_chunk::<U16_LEN>()
            && let Some((due, id)) = rest.split_first_chunk::<U64_LEN>()
            && let Ok(id) = <[u8; U64_LEN]>::try_from(id)
            && let Some(typ) = TaskType::from_id(u16::from_be_bytes(*typ))
        {
            Ok(TaskDue {
                typ,
                due: u64::from_be_bytes(*due),
                id: u64::from_be_bytes(id),
            })
        } else {
            Err(trc::Error::corrupted_key(key, None, trc::location!()))
        }
    }
}

impl IndexPropertyClass {
    pub const KIND_INTEGER: u8 = 0x00;
    pub const KIND_HASH: u8 = 0x01;

    pub fn key_len(&self) -> usize {
        IndexKeyPrefix::len()
            + 1
            + match self {
                IndexPropertyClass::Hash { .. } => Hash128::LEN,
                IndexPropertyClass::Integer { .. } => U64_LEN,
            }
            + U32_LEN
    }
}

impl SearchIndexClass {
    pub const QUEUE_CONTROL: u8 = u8::MAX;
    pub const CONTROL_INDEX: u8 = 0x00;
    pub const CONTROL_STATUS: u8 = 0x01;

    pub fn control_range(
        from: (SearchIndex, u32),
        to: Option<(SearchIndex, u32)>,
    ) -> (AnyKey<Vec<u8>>, AnyKey<Vec<u8>>) {
        let begin = KeySerializer::new(U32_LEN + 3)
            .write(Self::QUEUE_CONTROL)
            .write(from.0.to_u8())
            .write(from.1)
            .write(Self::CONTROL_INDEX)
            .finalize();
        let end = match to {
            Some((index, partition)) => KeySerializer::new(U32_LEN + 3)
                .write(Self::QUEUE_CONTROL)
                .write(index.to_u8())
                .write(partition)
                .write(u8::MAX)
                .finalize(),
            None => KeySerializer::new(2)
                .write(Self::QUEUE_CONTROL)
                .write(u8::MAX)
                .finalize(),
        };

        (
            AnyKey {
                subspace: Subspace::SearchQueue,
                key: begin,
            },
            AnyKey {
                subspace: Subspace::SearchQueue,
                key: end,
            },
        )
    }

    pub fn queue_range(index: SearchIndex, partition: u32) -> (Self, Self) {
        let (from_prefix, to_prefix) = if matches!(index, SearchIndex::Tracing) {
            let bucket = partition << (GLOBAL_BUCKET_SHIFT - 32);
            (bucket, bucket | ((1 << (GLOBAL_BUCKET_SHIFT - 32)) - 1))
        } else {
            (partition, partition)
        };

        (
            SearchIndexClass::Queue {
                index,
                id_prefix: from_prefix,
                id_suffix: QueueDocumentId::Assigned(0),
                created_at: 0,
            },
            SearchIndexClass::Queue {
                index,
                id_prefix: to_prefix,
                id_suffix: QueueDocumentId::Assigned(u32::MAX),
                created_at: u64::MAX,
            },
        )
    }

    pub fn queue_partition(index: SearchIndex, id_prefix: u32) -> u32 {
        if matches!(index, SearchIndex::Tracing) {
            id_prefix >> (GLOBAL_BUCKET_SHIFT - 32)
        } else {
            id_prefix
        }
    }
}

impl From<SearchIndexClass> for ValueClass {
    fn from(value: SearchIndexClass) -> Self {
        ValueClass::SearchIndex(value)
    }
}

impl From<SearchIndexClass> for ValueKey<ValueClass> {
    fn from(value: SearchIndexClass) -> Self {
        ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::SearchIndex(value),
        }
    }
}

impl SearchIndex {
    pub fn to_u8(&self) -> u8 {
        match self {
            SearchIndex::Email => 0,
            SearchIndex::Calendar => 1,
            SearchIndex::Contacts => 2,
            SearchIndex::File => 3,
            SearchIndex::Tracing => 4,
            SearchIndex::InMemory => unreachable!(),
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(SearchIndex::Email),
            1 => Some(SearchIndex::Calendar),
            2 => Some(SearchIndex::Contacts),
            3 => Some(SearchIndex::File),
            4 => Some(SearchIndex::Tracing),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            SearchIndex::Email => "email",
            SearchIndex::Calendar => "calendar",
            SearchIndex::Contacts => "contacts",
            SearchIndex::File => "file",
            SearchIndex::Tracing => "tracing",
            SearchIndex::InMemory => "in_memory",
        }
    }

    pub fn try_from_str(value: &str) -> Option<Self> {
        match value {
            "email" => Some(SearchIndex::Email),
            "calendar" => Some(SearchIndex::Calendar),
            "contacts" => Some(SearchIndex::Contacts),
            "file" => Some(SearchIndex::File),
            "tracing" => Some(SearchIndex::Tracing),
            _ => None,
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/store/src/write/key/tests.rs"]
mod tests;
