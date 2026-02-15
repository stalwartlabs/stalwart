/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{RegistryStore, registry::RegistryObject};
use registry::{
    schema::prelude::Object,
    types::{ObjectType, id::ObjectId},
};
use types::id::Id;

impl RegistryStore {
    pub async fn object<T: ObjectType>(&self, id: impl Into<u64>) -> trc::Result<Option<T>> {
        todo!()
    }

    pub async fn singleton<T: ObjectType>(&self) -> trc::Result<Option<T>> {
        todo!()
    }

    pub async fn insert<T: ObjectType>(&self, object: &T) -> trc::Result<Id> {
        todo!()
    }

    pub async fn update<T: ObjectType>(&self, id: Id, object: &T) -> trc::Result<bool> {
        todo!()
    }

    pub async fn list<T: ObjectType>(&self) -> trc::Result<Vec<RegistryObject<T>>> {
        todo!()
    }

    pub async fn delete(&self, id: ObjectId) -> trc::Result<()> {
        todo!()
    }

    pub async fn count(&self, typ: Object) -> trc::Result<u64> {
        todo!()
    }
}
