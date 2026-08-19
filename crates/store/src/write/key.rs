/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AnyKey, BlobOp, InMemoryClass, QueueClass, TaskQueueClass, TelemetryClass, ValueClass,
};
use crate::{
    IndexKey, IndexKeyPrefix, Key, LogKey, Subspace, U16_LEN, U32_LEN, U64_LEN, U128_LEN, ValueKey,
    WITH_SUBSPACE,
    search::{GLOBAL_BUCKET_SHIFT, SearchField},
    write::{BlobLink, IndexPropertyClass, RegistryClass, SearchIndex, SearchIndexClass},
};
use registry::schema::prelude::ObjectType;
use std::{borrow::BorrowMut, convert::TryInto};
use types::{
    blob_hash::BLOB_HASH_LEN,
    collection::{Collection, SyncCollection},
    field::{EmailField, Field, MailboxField},
};
use utils::codec::leb128::Leb128_;

pub struct KeySerializer<B = Vec<u8>> {
    pub buf: B,
}

pub trait KeySerialize {
    fn serialize(&self, buf: &mut Vec<u8>);
}

pub trait DeserializeBigEndian {
    fn deserialize_be_u16(&self, index: usize) -> trc::Result<u16>;
    fn deserialize_be_u32(&self, index: usize) -> trc::Result<u32>;
    fn deserialize_be_u64(&self, index: usize) -> trc::Result<u64>;
}

impl KeySerializer<Vec<u8>> {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        self.buf
    }
}

impl<'x> KeySerializer<&'x mut Vec<u8>> {
    pub fn borrowed(buf: &'x mut Vec<u8>) -> Self {
        Self { buf }
    }
}

impl<B: BorrowMut<Vec<u8>>> KeySerializer<B> {
    pub fn write<T: KeySerialize>(mut self, value: T) -> Self {
        value.serialize(self.buf.borrow_mut());
        self
    }

    pub fn write_leb128<T: Leb128_>(mut self, value: T) -> Self {
        T::to_leb128_bytes(value, self.buf.borrow_mut());
        self
    }
}

impl KeySerialize for u8 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.push(*self);
    }
}

impl KeySerialize for &str {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl KeySerialize for &String {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl KeySerialize for &[u8] {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self);
    }
}

impl KeySerialize for u32 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl KeySerialize for u16 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl KeySerialize for u64 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl KeySerialize for u128 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

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
        let serializer = if (flags & WITH_SUBSPACE) != 0 {
            KeySerializer::borrowed(buf).write(Subspace::Indexes.byte())
        } else {
            KeySerializer::borrowed(buf)
        };

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
        let serializer = if (flags & WITH_SUBSPACE) != 0 {
            KeySerializer::borrowed(buf).write(Subspace::Logs.byte())
        } else {
            KeySerializer::borrowed(buf)
        };

        serializer
            .write(self.account_id)
            .write(self.collection)
            .write(self.change_id);
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
        let serializer = if with_subspace {
            KeySerializer::borrowed(buf).write(self.subspace(collection).byte())
        } else {
            KeySerializer::borrowed(buf)
        };

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
                .write(account_id)
                .write(MAILBOX_COLLECTION)
                .write(u8::from(MailboxField::UidCounter))
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
                    .write(document_id),
            },
            ValueClass::Acl(grant_account_id) => serializer
                .write(*grant_account_id)
                .write(account_id)
                .write(collection)
                .write(document_id),
            ValueClass::TaskQueue(task) => match task {
                TaskQueueClass::Task { id } => serializer.write(0u64).write(*id),
                TaskQueueClass::Due { id, due } => serializer.write(*due).write(*id),
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
            ValueClass::InMemory(lookup) => match lookup {
                InMemoryClass::Key(key) => serializer.write(key.as_slice()),
                InMemoryClass::Counter(key) => serializer.write(key.as_slice()),
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
                    .write(GlobalCounterKind::RegistryId as u8)
                    .write(*object_id),
            },
            ValueClass::Queue(queue) => match queue {
                QueueClass::Message(queue_id) => serializer.write(*queue_id),
                QueueClass::MessageEvent(event) => serializer
                    .write(event.due)
                    .write(event.queue_id)
                    .write(event.queue_name.as_slice()),
                QueueClass::QuotaCount(key) => serializer.write(0u8).write(key.as_slice()),
                QueueClass::QuotaSize(key) => serializer.write(1u8).write(key.as_slice()),
            },
            ValueClass::Telemetry(telemetry) => match telemetry {
                TelemetryClass::Span(span_id) => serializer.write(*span_id),
                TelemetryClass::Metric(metric_id) => serializer.write(*metric_id),
            },
            ValueClass::DocumentId => serializer.write(account_id).write(collection),
            ValueClass::ChangeId => serializer.write(account_id),
            ValueClass::Quota => serializer.write(account_id).write(u8::MAX),
            ValueClass::TenantQuota(tenant_id) => serializer
                .write(GlobalCounterKind::TenantQuota as u8)
                .write(*tenant_id),
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
                    .write(*field)
                    .write(term.as_key())
                    .write(term.len() as u8)
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
                    .write(*id_suffix)
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
        let serializer = if (flags & WITH_SUBSPACE) != 0 {
            KeySerializer::borrowed(buf).write(Subspace::Indexes.byte())
        } else {
            KeySerializer::borrowed(buf)
        };

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
        let serializer = if (flags & WITH_SUBSPACE) != 0 {
            KeySerializer::borrowed(buf).write(self.subspace.byte())
        } else {
            KeySerializer::borrowed(buf)
        };

        serializer.write(self.key.as_ref());
    }

    fn subspace(&self) -> Subspace {
        self.subspace
    }
}

const MAILBOX_COLLECTION: u8 = Collection::Mailbox as u8;
const EMAIL_COLLECTION: u8 = Collection::Email as u8;
const REG_ARCHIVED_ITEM: u16 = ObjectType::ArchivedItem as u16;
const REG_SPAM_SAMPLE: u16 = ObjectType::SpamTrainingSample as u16;
const REG_ACCOUNT: u16 = ObjectType::Account as u16;
const REG_DOMAIN: u16 = ObjectType::Domain as u16;
const REG_TENANT: u16 = ObjectType::Tenant as u16;
const REG_ROLE: u16 = ObjectType::Role as u16;
const REG_OAUTH_CLIENT: u16 = ObjectType::OAuthClient as u16;
const REG_MAILING_LIST: u16 = ObjectType::MailingList as u16;
const REG_MASKED_EMAIL: u16 = ObjectType::MaskedEmail as u16;
const REG_PUBLIC_KEY: u16 = ObjectType::PublicKey as u16;
const REG_TRACE: u16 = ObjectType::Trace as u16;
const REG_METRIC: u16 = ObjectType::Metric as u16;
const REPORT_EXTERNAL_ARF: u16 = ObjectType::ArfExternalReport as u16;
const REPORT_EXTERNAL_DMARC: u16 = ObjectType::DmarcExternalReport as u16;
const REPORT_EXTERNAL_TLS: u16 = ObjectType::TlsExternalReport as u16;
const REPORT_INTERNAL_DMARC: u16 = ObjectType::DmarcInternalReport as u16;
const REPORT_INTERNAL_TLS: u16 = ObjectType::TlsInternalReport as u16;

impl ValueClass {
    pub fn key_len_hint(&self) -> usize {
        match self {
            ValueClass::Property(_) | ValueClass::Immutable(_) | ValueClass::MailboxUid => {
                (U32_LEN * 2) + 2
            }
            ValueClass::IndexProperty(p) => {
                (U32_LEN * 2)
                    + 3
                    + match p {
                        IndexPropertyClass::Hash { .. } => U128_LEN,
                        IndexPropertyClass::Integer { .. } => U64_LEN,
                    }
            }
            ValueClass::Acl(_) => (U32_LEN * 3) + 1,
            ValueClass::InMemory(InMemoryClass::Counter(v) | InMemoryClass::Key(v)) => v.len(),
            ValueClass::Registry(registry) => match registry {
                RegistryClass::Item { .. } => U16_LEN + U64_LEN,
                RegistryClass::Reference { .. } => (U16_LEN + U64_LEN) * 2,
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
            ValueClass::TaskQueue(_) => U64_LEN * 2,
            ValueClass::Queue(q) => match q {
                QueueClass::Message(_) => U64_LEN,
                QueueClass::MessageEvent(_) => U64_LEN * 3,
                QueueClass::QuotaCount(v) | QueueClass::QuotaSize(v) => v.len() + 1,
            },
            ValueClass::Telemetry(telemetry) => match telemetry {
                TelemetryClass::Span(_) | TelemetryClass::Metric(_) => U64_LEN,
            },
            ValueClass::DocumentId | ValueClass::Quota | ValueClass::TenantQuota(_) => U32_LEN + 1,
            ValueClass::ChangeId => U32_LEN,
            ValueClass::ShareNotification { .. } => U32_LEN + U64_LEN + 1,
            ValueClass::NodeId(_) => U16_LEN + 1,
            ValueClass::SearchIndex(v) => match v {
                SearchIndexClass::Term { term, .. } => U32_LEN + term.key_len() + U16_LEN + 3,
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
                    REG_ACCOUNT | REG_DOMAIN | REG_TENANT | REG_ROLE | REG_OAUTH_CLIENT
                    | REG_MAILING_LIST | REG_MASKED_EMAIL | REG_PUBLIC_KEY => Subspace::Directory,
                    REG_ARCHIVED_ITEM => Subspace::DeletedItems,
                    REG_SPAM_SAMPLE => Subspace::SpamSamples,
                    REG_TRACE => Subspace::TelemetrySpan,
                    REG_METRIC => Subspace::TelemetryMetric,
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
                RegistryClass::IdCounter { .. } => Subspace::GlobalCounter,
            },
            ValueClass::NodeId(_) => Subspace::System,
            ValueClass::InMemory(lookup) => match lookup {
                InMemoryClass::Key(_) => Subspace::InMemoryValue,
                InMemoryClass::Counter(_) => Subspace::InMemoryCounter,
            },
            ValueClass::Queue(queue) => match queue {
                QueueClass::Message(_) => Subspace::QueueMessage,
                QueueClass::MessageEvent(_) => Subspace::QueueEvent,
                QueueClass::QuotaCount(_) | QueueClass::QuotaSize(_) => Subspace::Quota,
            },
            ValueClass::Telemetry(telemetry) => match telemetry {
                TelemetryClass::Span { .. } => Subspace::TelemetrySpan,
                TelemetryClass::Metric { .. } => Subspace::TelemetryMetric,
            },
            ValueClass::DocumentId | ValueClass::ChangeId | ValueClass::Quota => Subspace::Counter,
            ValueClass::TenantQuota(_) => Subspace::GlobalCounter,
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
        }
    }
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
        let serializer = KeySerializer::new((U16_LEN * 2) + value.len() + U64_LEN)
            .write(object_id)
            .write(index_id)
            .write(value);

        match item_id {
            Some(item_id) => serializer.write(item_id),
            None => serializer,
        }
        .finalize()
    }
}

#[repr(u8)]
pub enum GlobalCounterKind {
    TenantQuota = 0x00,
    RegistryId = 0x01,
}

#[repr(u8)]
pub enum SystemKind {
    SchemaVersion = 0x00,
    NodeId = 0x01,
}

impl IndexPropertyClass {
    pub const KIND_INTEGER: u8 = 0x00;
    pub const KIND_HASH: u8 = 0x01;

    pub fn key_len(&self) -> usize {
        IndexKeyPrefix::len()
            + 1
            + match self {
                IndexPropertyClass::Hash { .. } => U128_LEN,
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
                id_suffix: 0,
                created_at: 0,
            },
            SearchIndexClass::Queue {
                index,
                id_prefix: to_prefix,
                id_suffix: u32::MAX,
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
