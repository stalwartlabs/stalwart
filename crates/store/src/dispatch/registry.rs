/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{RegistryStore, registry::RegistryObject};
use registry::types::{ObjectType, id::Id};

impl RegistryStore {
    pub async fn get<T: ObjectType>(&self, id: Id) -> trc::Result<Option<T>> {
        todo!()
    }

    pub async fn list<T: ObjectType>(&self) -> trc::Result<Vec<RegistryObject<T>>> {
        todo!()
    }

    pub async fn delete(&self, id: Id) -> trc::Result<()> {
        todo!()
    }
}
