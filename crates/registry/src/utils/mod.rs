/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::schema::prelude::Roles;
use types::id::Id;

pub mod account;
pub mod cron;
pub mod http;
pub mod report;
pub mod secret;
pub mod task;

impl Roles {
    pub fn role_ids(&self) -> Option<&[Id]> {
        match self {
            Roles::Default => None,
            Roles::Custom(custom_roles) => Some(&custom_roles.role_ids),
        }
    }
}
