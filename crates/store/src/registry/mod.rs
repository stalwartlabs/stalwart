/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::types::{ObjectType, id::Id};

pub struct RegistryObject<T: ObjectType> {
    pub id: Id,
    pub object: T,
}
