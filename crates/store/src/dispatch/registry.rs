/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::{schema::prelude::Registry, types::id::Id};

use crate::RegistryStore;

impl RegistryStore {
    pub async fn get(&self, id: Id) -> trc::Result<Option<Registry>> {
        todo!()
    }

    pub async fn get_or_default(&self, id: Id) -> trc::Result<Registry> {
        todo!()
    }

    pub async fn delete(&self, id: Id) -> trc::Result<()> {
        todo!()
    }
}
