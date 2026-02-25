/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::schema::prelude::{Account, GroupAccount, UserAccount};

impl Account {
    pub fn into_user(self) -> Option<UserAccount> {
        if let Account::User(user) = self {
            Some(user)
        } else {
            None
        }
    }

    pub fn into_group(self) -> Option<GroupAccount> {
        if let Account::Group(group) = self {
            Some(group)
        } else {
            None
        }
    }
}
