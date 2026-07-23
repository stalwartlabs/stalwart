/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::Store;

pub mod config;
pub mod lookup;

pub struct SqlDirectory {
    sql_store: Store,
    mappings: SqlMappings,
}

#[derive(Debug, Default)]
pub(crate) struct SqlMappings {
    query_login: String,
    query_recipient: String,
    query_member_of: Option<String>,
    query_email_aliases: Option<String>,
    column_email: String,
    column_secret: String,
    column_type: Option<String>,
    column_description: Option<String>,
}
