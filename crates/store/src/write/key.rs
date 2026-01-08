/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AnyKey, BlobOp, DirectoryClass, InMemoryClass, QueueClass, ReportClass, ReportEvent,
    TaskQueueClass, TelemetryClass, ValueClass,
};
use crate::{
    Deserialize, IndexKey, IndexKeyPrefix, Key, LogKey, SUBSPACE_ACL, SUBSPACE_BLOB_EXTRA,
    SUBSPACE_BLOB_LINK, SUBSPACE_COUNTER, SUBSPACE_DIRECTORY, SUBSPACE_IN_MEMORY_COUNTER,
    SUBSPACE_IN_MEMORY_VALUE, SUBSPACE_INDEXES, SUBSPACE_LOGS, SUBSPACE_PROPERTY,
    SUBSPACE_QUEUE_EVENT, SUBSPACE_QUEUE_MESSAGE, SUBSPACE_QUOTA, SUBSPACE_REPORT_IN,
    SUBSPACE_REPORT_OUT, SUBSPACE_SEARCH_INDEX, SUBSPACE_SETTINGS, SUBSPACE_TASK_QUEUE,
    SUBSPACE_TELEMETRY_METRIC, SUBSPACE_TELEMETRY_SPAN, U16_LEN, U32_LEN, U64_LEN, ValueKey,
    WITH_SUBSPACE,
    write::{BlobLink, IndexPropertyClass, SearchIndex, SearchIndexId, SearchIndexType},
};
use std::convert::TryInto;
use types::{blob_hash::BLOB_HASH_LEN, collection::SyncCollection, field::Field};
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
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, *self)
            })
            .and_then(|bytes| {
                bytes.try_into().map_err(|_| {
                    trc::StoreEvent::DataCorruption
                        .caused_by(trc::location!())
                        .ctx(trc::Key::Value, *self)
                })
            })
            .map(u16::from_be_bytes)
    }

    fn deserialize_be_u32(&self, index: usize) -> trc::Result<u32> {
        self.get(index..index + U32_LEN)
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, *self)
            })
            .and_then(|bytes| {
                bytes.try_into().map_err(|_| {
                    trc::StoreEvent::DataCorruption
                        .caused_by(trc::location!())
                        .ctx(trc::Key::Value, *self)
                })
            })
            .map(u32::from_be_bytes)
    }

    fn deserialize_be_u64(&self, index: usize) -> trc::Result<u64> {
        self.get(index..index + U64_LEN)
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, *self)
            })
            .and_then(|bytes| {
                bytes.try_into().map_err(|_| {
                    trc::StoreEvent::DataCorruption
                        .caused_by(trc::location!())
                        .ctx(trc::Key::Value, *self)
                })
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

    pub fn is_counter(&self) -> bool {
        self.class.as_ref().is_counter(self.collection)
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
                TaskQueueClass::UpdateIndex {
                    index,
                    is_insert,
                    due,
                } => serializer
                    .write(due.inner())
                    .write(account_id)
                    .write(if *is_insert { 7u8 } else { 8u8 })
                    .write(document_id)
                    .write(index.to_u8()),
                TaskQueueClass::SendAlarm {
                    due,
                    event_id,
                    alarm_id,
                    is_email_alert,
                } => serializer
                    .write(due.inner())
                    .write(account_id)
                    .write(if *is_email_alert { 3u8 } else { 6u8 })
                    .write(document_id)
                    .write(*event_id)
                    .write(*alarm_id),
                TaskQueueClass::SendImip { due, is_payload } => {
                    if !*is_payload {
                        serializer
                            .write(due.inner())
                            .write(account_id)
                            .write(4u8)
                            .write(document_id)
                    } else {
                        serializer
                            .write(u64::MAX)
                            .write(account_id)
                            .write(5u8)
                            .write(document_id)
                            .write(due.inner())
                    }
                }
                TaskQueueClass::MergeThreads { due } => serializer
                    .write(due.inner())
                    .write(account_id)
                    .write(9u8)
                    .write(document_id),
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
                BlobOp::Quota { hash, until } => serializer
                    .write(BlobLink::QUOTA_LINK)
                    .write(account_id)
                    .write::<&[u8]>(hash.as_ref())
                    .write(*until),
                BlobOp::Undelete { hash, until } => serializer
                    .write(BlobLink::UNDELETE_LINK)
                    .write(account_id)
                    .write::<&[u8]>(hash.as_ref())
                    .write(*until),
                BlobOp::SpamSample { hash, until } => serializer
                    .write(BlobLink::SPAM_SAMPLE_LINK)
                    .write(*until)
                    .write(account_id)
                    .write::<&[u8]>(hash.as_ref()),
            },
            ValueClass::Config(key) => serializer.write(key.as_slice()),
            ValueClass::InMemory(lookup) => match lookup {
                InMemoryClass::Key(key) => serializer.write(key.as_slice()),
                InMemoryClass::Counter(key) => serializer.write(key.as_slice()),
            },
            ValueClass::Directory(directory) => match directory {
                DirectoryClass::NameToId(name) => serializer.write(0u8).write(name.as_slice()),
                DirectoryClass::EmailToId(email) => serializer.write(1u8).write(email.as_slice()),
                DirectoryClass::Principal(uid) => serializer.write(2u8).write_leb128(*uid),
                DirectoryClass::UsedQuota(uid) => serializer.write(4u8).write_leb128(*uid),
                DirectoryClass::MemberOf {
                    principal_id,
                    member_of,
                } => serializer.write(5u8).write(*principal_id).write(*member_of),
                DirectoryClass::Members {
                    principal_id,
                    has_member,
                } => serializer
                    .write(6u8)
                    .write(*principal_id)
                    .write(*has_member),
                DirectoryClass::Index { word, principal_id } => serializer
                    .write(7u8)
                    .write(word.as_slice())
                    .write(*principal_id),
            },
            ValueClass::Queue(queue) => match queue {
                QueueClass::Message(queue_id) => serializer.write(*queue_id),
                QueueClass::MessageEvent(event) => serializer
                    .write(event.due)
                    .write(event.queue_id)
                    .write(event.queue_name.as_slice()),
                QueueClass::DmarcReportHeader(event) => serializer
                    .write(0u8)
                    .write(event.due)
                    .write(event.domain.as_bytes())
                    .write(event.policy_hash)
                    .write(event.seq_id)
                    .write(0u8),
                QueueClass::TlsReportHeader(event) => serializer
                    .write(0u8)
                    .write(event.due)
                    .write(event.domain.as_bytes())
                    .write(event.policy_hash)
                    .write(event.seq_id)
                    .write(1u8),
                QueueClass::DmarcReportEvent(event) => serializer
                    .write(1u8)
                    .write(event.due)
                    .write(event.domain.as_bytes())
                    .write(event.policy_hash)
                    .write(event.seq_id),
                QueueClass::TlsReportEvent(event) => serializer
                    .write(2u8)
                    .write(event.due)
                    .write(event.domain.as_bytes())
                    .write(event.policy_hash)
                    .write(event.seq_id),
                QueueClass::QuotaCount(key) => serializer.write(0u8).write(key.as_slice()),
                QueueClass::QuotaSize(key) => serializer.write(1u8).write(key.as_slice()),
            },
            ValueClass::Report(report) => match report {
                ReportClass::Tls { id, expires } => {
                    serializer.write(0u8).write(*expires).write(*id)
                }
                ReportClass::Dmarc { id, expires } => {
                    serializer.write(1u8).write(*expires).write(*id)
                }
                ReportClass::Arf { id, expires } => {
                    serializer.write(2u8).write(*expires).write(*id)
                }
            },
            ValueClass::Telemetry(telemetry) => match telemetry {
                TelemetryClass::Span { span_id } => serializer.write(*span_id),
                TelemetryClass::Metric {
                    timestamp,
                    metric_id,
                    node_id,
                } => serializer
                    .write(*timestamp)
                    .write_leb128(*metric_id)
                    .write_leb128(*node_id),
            },
            ValueClass::DocumentId => serializer.write(account_id).write(collection),
            ValueClass::ChangeId => serializer.write(account_id),
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

impl BlobLink {
    pub const QUOTA_LINK: u8 = 0;
    pub const UNDELETE_LINK: u8 = 1;
    pub const SPAM_SAMPLE_LINK: u8 = 2;
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

impl ValueClass {
    pub fn serialized_size(&self) -> usize {
        match self {
            ValueClass::Property(_) => U32_LEN * 2 + 3,
            ValueClass::IndexProperty(p) => match p {
                IndexPropertyClass::Hash { hash, .. } => U32_LEN * 2 + 3 + hash.len(),
                IndexPropertyClass::Integer { .. } => U32_LEN * 2 + 3 + U64_LEN,
            },
            ValueClass::Acl(_) => U32_LEN * 3 + 2,
            ValueClass::InMemory(InMemoryClass::Counter(v) | InMemoryClass::Key(v))
            | ValueClass::Config(v) => v.len(),
            ValueClass::Directory(d) => match d {
                DirectoryClass::NameToId(v) | DirectoryClass::EmailToId(v) => v.len(),
                DirectoryClass::Principal(_) | DirectoryClass::UsedQuota(_) => U32_LEN,
                DirectoryClass::Members { .. } | DirectoryClass::MemberOf { .. } => U32_LEN * 2,
                DirectoryClass::Index { word, .. } => word.len() + U32_LEN,
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
                BlobOp::Quota { .. } | BlobOp::Undelete { .. } => {
                    BLOB_HASH_LEN + U32_LEN + U64_LEN + 1
                }
                BlobOp::SpamSample { .. } => BLOB_HASH_LEN + U32_LEN + 2,
            },
            ValueClass::TaskQueue(e) => match e {
                TaskQueueClass::UpdateIndex { .. } => (U64_LEN * 2) + 2,
                TaskQueueClass::SendAlarm { .. } | TaskQueueClass::MergeThreads { .. } => {
                    U64_LEN + (U32_LEN * 3) + 1
                }
                TaskQueueClass::SendImip { is_payload, .. } => {
                    if *is_payload {
                        (U64_LEN * 2) + (U32_LEN * 2) + 1
                    } else {
                        U64_LEN + (U32_LEN * 2) + 1
                    }
                }
            },
            ValueClass::Queue(q) => match q {
                QueueClass::Message(_) => U64_LEN,
                QueueClass::MessageEvent(_) => U64_LEN * 3,
                QueueClass::DmarcReportEvent(event) | QueueClass::TlsReportEvent(event) => {
                    event.domain.len() + U64_LEN * 3
                }
                QueueClass::DmarcReportHeader(event) | QueueClass::TlsReportHeader(event) => {
                    event.domain.len() + (U64_LEN * 3) + 1
                }
                QueueClass::QuotaCount(v) | QueueClass::QuotaSize(v) => v.len(),
            },
            ValueClass::Report(_) => U64_LEN * 2 + 1,
            ValueClass::Telemetry(telemetry) => match telemetry {
                TelemetryClass::Span { .. } => U64_LEN + 1,
                TelemetryClass::Metric { .. } => U64_LEN * 2 + 1,
            },
            ValueClass::DocumentId => U32_LEN + 1,
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
                if *field == 84 && collection == 1 {
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
                BlobOp::Quota { .. } | BlobOp::Undelete { .. } | BlobOp::SpamSample { .. } => {
                    SUBSPACE_BLOB_EXTRA
                }
            },
            ValueClass::Config(_) => SUBSPACE_SETTINGS,
            ValueClass::InMemory(lookup) => match lookup {
                InMemoryClass::Key(_) => SUBSPACE_IN_MEMORY_VALUE,
                InMemoryClass::Counter(_) => SUBSPACE_IN_MEMORY_COUNTER,
            },
            ValueClass::Directory(directory) => match directory {
                DirectoryClass::UsedQuota(_) => SUBSPACE_QUOTA,
                _ => SUBSPACE_DIRECTORY,
            },
            ValueClass::Queue(queue) => match queue {
                QueueClass::Message(_) => SUBSPACE_QUEUE_MESSAGE,
                QueueClass::MessageEvent(_) => SUBSPACE_QUEUE_EVENT,
                QueueClass::DmarcReportHeader(_)
                | QueueClass::TlsReportHeader(_)
                | QueueClass::DmarcReportEvent(_)
                | QueueClass::TlsReportEvent(_) => SUBSPACE_REPORT_OUT,
                QueueClass::QuotaCount(_) | QueueClass::QuotaSize(_) => SUBSPACE_QUOTA,
            },
            ValueClass::Report(_) => SUBSPACE_REPORT_IN,
            ValueClass::Telemetry(telemetry) => match telemetry {
                TelemetryClass::Span { .. } => SUBSPACE_TELEMETRY_SPAN,
                TelemetryClass::Metric { .. } => SUBSPACE_TELEMETRY_METRIC,
            },
            ValueClass::DocumentId | ValueClass::ChangeId => SUBSPACE_COUNTER,
            ValueClass::ShareNotification { .. } => SUBSPACE_LOGS,
            ValueClass::SearchIndex(_) => SUBSPACE_SEARCH_INDEX,
            ValueClass::Any(any) => any.subspace,
        }
    }

    pub fn is_counter(&self, collection: u8) -> bool {
        match self {
            ValueClass::Directory(DirectoryClass::UsedQuota(_))
            | ValueClass::InMemory(InMemoryClass::Counter(_))
            | ValueClass::Queue(QueueClass::QuotaCount(_) | QueueClass::QuotaSize(_))
            | ValueClass::DocumentId
            | ValueClass::ChangeId => true,
            ValueClass::Property(84) if collection == 1 => true, // TODO: Find a more elegant way to do this
            _ => false,
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

impl From<DirectoryClass> for ValueKey<ValueClass> {
    fn from(value: DirectoryClass) -> Self {
        ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Directory(value),
        }
    }
}

impl From<DirectoryClass> for ValueClass {
    fn from(value: DirectoryClass) -> Self {
        ValueClass::Directory(value)
    }
}

impl From<BlobOp> for ValueClass {
    fn from(value: BlobOp) -> Self {
        ValueClass::Blob(value)
    }
}

impl Deserialize for ReportEvent {
    fn deserialize(key: &[u8]) -> trc::Result<Self> {
        Ok(ReportEvent {
            due: key.deserialize_be_u64(1)?,
            policy_hash: key.deserialize_be_u64(key.len() - (U64_LEN * 2 + 1))?,
            seq_id: key.deserialize_be_u64(key.len() - (U64_LEN + 1))?,
            domain: key
                .get(U64_LEN + 1..key.len() - (U64_LEN * 2 + 1))
                .and_then(|domain| std::str::from_utf8(domain).ok())
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    trc::StoreEvent::DataCorruption
                        .caused_by(trc::location!())
                        .ctx(trc::Key::Key, key)
                })?,
        })
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
