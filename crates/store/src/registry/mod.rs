/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod bootstrap;
pub mod get;
pub mod local;
pub mod query;
pub mod write;

use crate::{
    Deserialize, SerializeInfallible, U16_LEN, U32_LEN, U64_LEN,
    write::key::{DeserializeBigEndian, KeySerializer},
};
use registry::{
    pickle::{Pickle, PickledStream},
    schema::{
        prelude::{Object, ObjectInner, ObjectType, Property},
        structs::{
            DeletedItem, DmarcInternalReport, SpamTrainingSample, Task, TlsInternalReport, Trace,
        },
    },
    types::{EnumImpl, ObjectImpl, id::ObjectId},
};
use types::id::Id;

pub struct RegistryObject<T: ObjectImpl> {
    pub id: ObjectId,
    pub object: T,
    pub revision: u64,
}

pub struct RegistryQuery {
    pub object_type: ObjectType,
    pub filters: Vec<RegistryFilter>,
}

pub struct RegistryFilter {
    pub property: Property,
    pub op: RegistryFilterOp,
    pub value: RegistryFilterValue,
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub struct ObjectIdVersioned {
    pub object_id: ObjectId,
    pub version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryFilterOp {
    Equal,
    GreaterThan,
    GreaterEqualThan,
    LowerThan,
    LowerEqualThan,
    TextMatch,
}

pub enum RegistryFilterValue {
    String(String),
    U64(u64),
    U16(u16),
    Boolean(bool),
}

impl Deserialize for Object {
    fn deserialize_with_key(key: &[u8], bytes: &[u8]) -> trc::Result<Self> {
        let revision = xxhash_rust::xxh3::xxh3_64(bytes);
        ObjectType::from_id(key.deserialize_be_u16(0)?)
            .and_then(|object_id| ObjectInner::unpickle(object_id, &mut PickledStream::new(bytes)))
            .map(|inner| Object { revision, inner })
            .ok_or_else(|| {
                trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                    .into_err()
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, bytes)
            })
    }

    fn deserialize(_: &[u8]) -> trc::Result<Self> {
        unreachable!("Object deserialization requires the object type from the key")
    }
}

impl Deserialize for Task {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let mut stream = PickledStream::new(bytes);
        Task::unpickle(&mut stream).ok_or_else(|| {
            trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })
    }
}

impl Deserialize for SpamTrainingSample {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let mut stream = PickledStream::new(bytes);
        SpamTrainingSample::unpickle(&mut stream).ok_or_else(|| {
            trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })
    }
}

impl Deserialize for DeletedItem {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let mut stream = PickledStream::new(bytes);
        DeletedItem::unpickle(&mut stream).ok_or_else(|| {
            trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })
    }
}

impl Deserialize for TlsInternalReport {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let mut stream = PickledStream::new(bytes);
        TlsInternalReport::unpickle(&mut stream).ok_or_else(|| {
            trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })
    }
}

impl Deserialize for DmarcInternalReport {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let mut stream = PickledStream::new(bytes);
        DmarcInternalReport::unpickle(&mut stream).ok_or_else(|| {
            trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })
    }
}

impl SerializeInfallible for ObjectId {
    fn serialize(&self) -> Vec<u8> {
        KeySerializer::new(U16_LEN + U64_LEN)
            .write(self.object().to_id())
            .write(self.id().id())
            .finalize()
    }
}

impl Deserialize for ObjectId {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let object_id = bytes.deserialize_be_u16(0)?;
        let item_id = bytes.deserialize_be_u64(U16_LEN)?;
        Ok(ObjectId::new(
            ObjectType::from_id(object_id).ok_or_else(|| {
                trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                    .into_err()
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, bytes)
            })?,
            Id::new(item_id),
        ))
    }
}

impl SerializeInfallible for ObjectIdVersioned {
    fn serialize(&self) -> Vec<u8> {
        KeySerializer::new(U16_LEN + U64_LEN + U32_LEN)
            .write(self.object_id.object().to_id())
            .write(self.object_id.id().id())
            .write(self.version)
            .finalize()
    }
}

impl Deserialize for ObjectIdVersioned {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let object_id = ObjectId::deserialize(bytes)?;
        let version = bytes.deserialize_be_u32(U16_LEN + U64_LEN)?;
        Ok(Self { object_id, version })
    }
}

impl Deserialize for Trace {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let mut stream = PickledStream::new(bytes);
        Trace::unpickle(&mut stream).ok_or_else(|| {
            trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })
    }
}
