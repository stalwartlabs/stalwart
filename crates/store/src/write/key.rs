/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AnyKey, BlobOp, InMemoryClass, QueueClass, TaskQueueClass, TelemetryClass, ValueClass,
};
use crate::{
    IndexKey, IndexKeyPrefix, Key, LogKey, SUBSPACE_ACL, SUBSPACE_BLOB_LINK, SUBSPACE_COUNTER,
    SUBSPACE_DELETED_ITEMS, SUBSPACE_DIRECTORY, SUBSPACE_IN_MEMORY_COUNTER,
    SUBSPACE_IN_MEMORY_VALUE, SUBSPACE_INDEXES, SUBSPACE_LOGS, SUBSPACE_PROPERTY,
    SUBSPACE_QUEUE_EVENT, SUBSPACE_QUEUE_MESSAGE, SUBSPACE_QUOTA, SUBSPACE_REGISTRY,
    SUBSPACE_REGISTRY_IDX, SUBSPACE_REGISTRY_PK, SUBSPACE_REPORT_IN, SUBSPACE_REPORT_OUT,
    SUBSPACE_SEARCH_INDEX, SUBSPACE_SPAM_SAMPLES, SUBSPACE_TASK_QUEUE, SUBSPACE_TELEMETRY_METRIC,
    SUBSPACE_TELEMETRY_SPAN, U16_LEN, U32_LEN, U64_LEN, ValueKey, WITH_SUBSPACE,
    write::{
        BlobLink, IndexPropertyClass, RegistryClass, SearchIndex, SearchIndexId, SearchIndexType,
    },
};
use registry::schema::prelude::ObjectType;
use std::convert::TryInto;
use types::{
    blob_hash::BLOB_HASH_LEN,
    collection::{Collection, SyncCollection},
    field::{Field, MailboxField},
};
use utils::codec::leb128::Leb128_;

pub struct KeySerializer {
    pub buf: Vec<u8>,
}

pub trait KeySerialize {
    fn serialize(&self, buf: &mut Vec<u8>);
}

pub trait DeserializeBigEndian {
    fn deserialize_be_u16(&self, index: usize) -> trc::Result<u16>;
    fn deserialize_be_u32(&self, index: usize) -> trc::Result<u32>;
    fn deserialize_be_u64(&self, index: usize) -> trc::Result<u64>;
}

impl KeySerializer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    pub fn write<T: KeySerialize>(mut self, value: T) -> Self {
        value.serialize(&mut self.buf);
        self
    }

    pub fn write_leb128<T: Leb128_>(mut self, value: T) -> Self {
        T::to_leb128_bytes(value, &mut self.buf);
        self
    }

    pub fn finalize(self) -> Vec<u8> {
        self.buf
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
}

impl Key for IndexKeyPrefix {
    fn serialize(&self, flags: u32) -> Vec<u8> {
        {
            if (flags & WITH_SUBSPACE) != 0 {
                KeySerializer::new(std::mem::size_of::<IndexKeyPrefix>() + 1)
                    .write(crate::SUBSPACE_INDEXES)
            } else {
                KeySerializer::new(std::mem::size_of::<IndexKeyPrefix>())
            }
        }
        .write(self.account_id)
        .write(self.collection)
        .write(self.field)
        .finalize()
    }

    fn subspace(&self) -> u8 {
        SUBSPACE_INDEXES
    }
}

impl IndexKeyPrefix {
    pub fn len() -> usize {
        U32_LEN + 2
    }
}

impl Key for LogKey {
    fn subspace(&self) -> u8 {
        SUBSPACE_LOGS
    }

    fn serialize(&self, flags: u32) -> Vec<u8> {
        {
            if (flags & WITH_SUBSPACE) != 0 {
                KeySerializer::new(std::mem::size_of::<LogKey>() + 1).write(crate::SUBSPACE_LOGS)
            } else {
                KeySerializer::new(std::mem::size_of::<LogKey>())
            }
        }
        .write(self.account_id)
        .write(self.collection)
        .write(self.change_id)
        .finalize()
    }
}

impl<T: AsRef<ValueClass> + Sync + Send + Clone> Key for ValueKey<T> {
    fn subspace(&self) -> u8 {
        self.class.as_ref().subspace(self.collection)
    }

    fn serialize(&self, flags: u32) -> Vec<u8> {
        self.class
            .as_ref()
            .serialize(self.account_id, self.collection, self.document_id, flags)
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
        let serializer = if (flags & WITH_SUBSPACE) != 0 {
            KeySerializer::new(self.serialized_size() + 2).write(self.subspace(collection))
        } else {
            KeySerializer::new(self.serialized_size() + 1)
        };

        match self {
            ValueClass::Property(property) => serializer
                .write(account_id)
                .write(collection)
                .write(*property)
                .write(document_id),
            ValueClass::IndexProperty(property) => match property {
                IndexPropertyClass::Hash { property, hash } => serializer
                    .write(account_id)
                    .write(collection)
                    .write(*property)
                    .write(hash.as_bytes())
                    .write(document_id),
                IndexPropertyClass::Integer { property, value } => serializer
                    .write(account_id)
                    .write(collection)
                    .write(*property)
                    .write(*value)
                    .write(document_id),
            },
            ValueClass::Acl(grant_account_id) => serializer
                .write(*grant_account_id)
                .write(account_id)
                .write(collection)
                .write(document_id),
            ValueClass::TaskQueue(task) => match task {
                TaskQueueClass::Task { id } => serializer.write(*id),
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
                    serializer.write(*object_id).write_leb128(*item_id)
                }
                RegistryClass::Id { object_id, item_id } => {
                    serializer.write(*object_id).write(*item_id)
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
                RegistryClass::IdCounter { object_id } => serializer.write(*object_id),
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
            ValueClass::TenantQuota(tenant_id) => serializer.write(*tenant_id).write(u8::MAX - 1),
            ValueClass::ShareNotification {
                notification_id,
                notify_account_id,
            } => serializer
                .write(*notify_account_id)
                .write(u8::from(SyncCollection::ShareNotification))
                .write(*notification_id),
            ValueClass::SearchIndex(index) => match &index.typ {
                SearchIndexType::Term { field, hash } => {
                    let class = index.index.as_u8();
                    match &index.id {
                        SearchIndexId::Account {
                            account_id,
                            document_id,
                        } => serializer
                            .write(class)
                            .write(*account_id)
                            .write(hash.payload())
                            .write(hash.payload_len())
                            .write(*field)
                            .write(*document_id),
                        SearchIndexId::Global { id } => serializer
                            .write(class)
                            .write(hash.payload())
                            .write(hash.payload_len())
                            .write(*field)
                            .write(*id),
                    }
                }
                SearchIndexType::Index { field } => {
                    let class = index.index.as_u8() | 1 << 6;
                    match &index.id {
                        SearchIndexId::Account {
                            account_id,
                            document_id,
                        } => serializer
                            .write(class)
                            .write(*account_id)
                            .write(field.field_id)
                            .write(field.data.as_slice())
                            .write(*document_id),
                        SearchIndexId::Global { id } => serializer
                            .write(class)
                            .write(field.field_id)
                            .write(field.data.as_slice())
                            .write(*id),
                    }
                }
                SearchIndexType::Document => {
                    let class = index.index.as_u8() | 2 << 6;
                    match &index.id {
                        SearchIndexId::Account {
                            account_id,
                            document_id,
                        } => serializer
                            .write(class)
                            .write(*account_id)
                            .write(*document_id),
                        SearchIndexId::Global { id } => serializer.write(class).write(*id),
                    }
                }
            },
            ValueClass::Any(any) => serializer.write(any.key.as_slice()),
        }
        .finalize()
    }
}

impl<T: AsRef<[u8]> + Sync + Send + Clone> Key for IndexKey<T> {
    fn subspace(&self) -> u8 {
        SUBSPACE_INDEXES
    }

    fn serialize(&self, flags: u32) -> Vec<u8> {
        let key = self.key.as_ref();
        {
            if (flags & WITH_SUBSPACE) != 0 {
                KeySerializer::new(std::mem::size_of::<IndexKey<T>>() + key.len() + 1)
                    .write(crate::SUBSPACE_INDEXES)
            } else {
                KeySerializer::new(std::mem::size_of::<IndexKey<T>>() + key.len())
            }
        }
        .write(self.account_id)
        .write(self.collection)
        .write(self.field)
        .write(key)
        .write(self.document_id)
        .finalize()
    }
}

impl<T: AsRef<[u8]> + Sync + Send + Clone> Key for AnyKey<T> {
    fn serialize(&self, flags: u32) -> Vec<u8> {
        let key = self.key.as_ref();
        if (flags & WITH_SUBSPACE) != 0 {
            KeySerializer::new(key.len() + 1).write(self.subspace)
        } else {
            KeySerializer::new(key.len())
        }
        .write(key)
        .finalize()
    }

    fn subspace(&self) -> u8 {
        self.subspace
    }
}

const MAILBOX_COLLECTION: u8 = Collection::Mailbox as u8;
const MAILBOX_COUNTER_FIELD: u8 = MailboxField::UidCounter as u8;
const REG_DELETED_ITEM: u16 = ObjectType::DeletedItem as u16;
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
    pub fn serialized_size(&self) -> usize {
        match self {
            ValueClass::Property(_) => U32_LEN * 2 + 3,
            ValueClass::IndexProperty(p) => match p {
                IndexPropertyClass::Hash { hash, .. } => U32_LEN * 2 + 3 + hash.len(),
                IndexPropertyClass::Integer { .. } => U32_LEN * 2 + 3 + U64_LEN,
            },
            ValueClass::Acl(_) => U32_LEN * 3 + 2,
            ValueClass::InMemory(InMemoryClass::Counter(v) | InMemoryClass::Key(v)) => v.len(),
            ValueClass::Registry(registry) => match registry {
                RegistryClass::Item { .. } => U16_LEN + U64_LEN + 1,
                RegistryClass::Reference { .. } => ((U16_LEN + U64_LEN) * 2) + 1,
                RegistryClass::Index { key, .. } => (U16_LEN * 2) + U64_LEN + key.len() + 1,
                RegistryClass::PrimaryKey { key, .. } => (U16_LEN * 2) + key.len() + 1,
                RegistryClass::Id { .. } => U16_LEN + U64_LEN + 1,
                RegistryClass::IdCounter { .. } => U16_LEN + 1,
            },
            ValueClass::Blob(op) => match op {
                BlobOp::Commit { .. } => BLOB_HASH_LEN,
                BlobOp::Link { to, .. } => {
                    BLOB_HASH_LEN
                        + match to {
                            BlobLink::Id { .. } => U64_LEN,
                            BlobLink::Document => U32_LEN * 2 + 1,
                            BlobLink::Temporary { .. } => U32_LEN + U64_LEN,
                        }
                }
            },
            ValueClass::TaskQueue(e) => match e {
                TaskQueueClass::Task { .. } => U64_LEN + 1,
                TaskQueueClass::Due { .. } => (U64_LEN * 2) + 1,
            },
            ValueClass::Queue(q) => match q {
                QueueClass::Message(_) => U64_LEN,
                QueueClass::MessageEvent(_) => U64_LEN * 3,
                QueueClass::QuotaCount(v) | QueueClass::QuotaSize(v) => v.len(),
            },
            ValueClass::Telemetry(telemetry) => match telemetry {
                TelemetryClass::Span(_) | TelemetryClass::Metric(_) => U64_LEN + 1,
            },
            ValueClass::DocumentId | ValueClass::Quota | ValueClass::TenantQuota(_) => U32_LEN + 1,
            ValueClass::ChangeId => U32_LEN,
            ValueClass::ShareNotification { .. } => U32_LEN + U64_LEN + 1,
            ValueClass::SearchIndex(v) => match &v.typ {
                SearchIndexType::Term { hash, .. } => U64_LEN + hash.len() + 2,
                SearchIndexType::Index { field, .. } => 1 + field.data.len() + U64_LEN,
                SearchIndexType::Document => match &v.id {
                    SearchIndexId::Account { .. } => 1 + U32_LEN * 2,
                    SearchIndexId::Global { .. } => 1 + U64_LEN,
                },
            },
            ValueClass::Any(v) => v.key.len(),
        }
    }

    pub fn subspace(&self, collection: u8) -> u8 {
        match self {
            ValueClass::Property(field) => {
                if collection == MAILBOX_COLLECTION && *field == MAILBOX_COUNTER_FIELD {
                    SUBSPACE_COUNTER
                } else {
                    SUBSPACE_PROPERTY
                }
            }
            ValueClass::IndexProperty { .. } => SUBSPACE_PROPERTY,
            ValueClass::Acl(_) => SUBSPACE_ACL,
            ValueClass::TaskQueue { .. } => SUBSPACE_TASK_QUEUE,
            ValueClass::Blob(op) => match op {
                BlobOp::Commit { .. } | BlobOp::Link { .. } => SUBSPACE_BLOB_LINK,
            },
            ValueClass::Registry(registry) => match registry {
                RegistryClass::Item { object_id, .. } => match *object_id {
                    REG_ACCOUNT | REG_DOMAIN | REG_TENANT | REG_ROLE | REG_OAUTH_CLIENT
                    | REG_MAILING_LIST | REG_MASKED_EMAIL | REG_PUBLIC_KEY => SUBSPACE_DIRECTORY,
                    REG_DELETED_ITEM => SUBSPACE_DELETED_ITEMS,
                    REG_SPAM_SAMPLE => SUBSPACE_SPAM_SAMPLES,
                    REG_TRACE => SUBSPACE_TELEMETRY_SPAN,
                    REG_METRIC => SUBSPACE_TELEMETRY_METRIC,
                    REPORT_EXTERNAL_ARF | REPORT_EXTERNAL_DMARC | REPORT_EXTERNAL_TLS => {
                        SUBSPACE_REPORT_IN
                    }
                    REPORT_INTERNAL_DMARC | REPORT_INTERNAL_TLS => SUBSPACE_REPORT_OUT,
                    _ => SUBSPACE_REGISTRY,
                },
                RegistryClass::Id { .. } | RegistryClass::Index { .. } => SUBSPACE_REGISTRY_IDX,
                RegistryClass::Reference { .. } | RegistryClass::PrimaryKey { .. } => {
                    SUBSPACE_REGISTRY_PK
                }
                RegistryClass::IdCounter { .. } => SUBSPACE_COUNTER,
            },
            ValueClass::InMemory(lookup) => match lookup {
                InMemoryClass::Key(_) => SUBSPACE_IN_MEMORY_VALUE,
                InMemoryClass::Counter(_) => SUBSPACE_IN_MEMORY_COUNTER,
            },
            ValueClass::Queue(queue) => match queue {
                QueueClass::Message(_) => SUBSPACE_QUEUE_MESSAGE,
                QueueClass::MessageEvent(_) => SUBSPACE_QUEUE_EVENT,
                QueueClass::QuotaCount(_) | QueueClass::QuotaSize(_) => SUBSPACE_QUOTA,
            },
            ValueClass::Telemetry(telemetry) => match telemetry {
                TelemetryClass::Span { .. } => SUBSPACE_TELEMETRY_SPAN,
                TelemetryClass::Metric { .. } => SUBSPACE_TELEMETRY_METRIC,
            },
            ValueClass::DocumentId
            | ValueClass::ChangeId
            | ValueClass::Quota
            | ValueClass::TenantQuota(_) => SUBSPACE_COUNTER,
            ValueClass::ShareNotification { .. } => SUBSPACE_LOGS,
            ValueClass::SearchIndex(_) => SUBSPACE_SEARCH_INDEX,
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
