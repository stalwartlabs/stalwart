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
    Deserialize, SerializeInfallible, U16_LEN, U64_LEN,
    write::key::{DeserializeBigEndian, KeySerializer},
};
use registry::{
    pickle::{Pickle, PickledStream},
    schema::{
        prelude::{Object, ObjectType, Property},
        structs::{DeletedItem, SpamTrainingSample, Task},
    },
    types::{EnumImpl, ObjectImpl, id::ObjectId},
};
use types::id::Id;

pub struct RegistryObject<T: ObjectImpl> {
    pub id: ObjectId,
    pub object: T,
    pub revision: u32,
}

pub struct RegistryQuery {
    pub object_type: ObjectType,
    pub filters: Vec<RegistryFilter>,
    pub account_id: Option<u32>,
    pub tenant_id: Option<u32>,
}

pub struct RegistryFilter {
    pub property: Property,
    pub op: RegistryFilterOp,
    pub value: RegistryFilterValue,
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
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let mut stream = PickledStream::new(bytes);
        Object::unpickle(&mut stream).ok_or_else(|| {
            trc::EventType::Registry(trc::RegistryEvent::DeserializationError)
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })
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
