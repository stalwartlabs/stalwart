/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;
use registry::schema::structs::Account;

pub(crate) struct AccountWithId {
    pub id: u32,
    pub account: Account,
}

impl Server {
    pub(crate) async fn synchronize_account(
        &self,
        account: directory::Account,
    ) -> trc::Result<AccountWithId> {
        todo!()
    }

    pub(crate) async fn synchronize_group(
        &self,
        group: directory::Group,
    ) -> trc::Result<AccountWithId> {
        todo!()
    }
}
