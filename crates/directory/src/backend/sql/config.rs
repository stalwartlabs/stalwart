/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqlDirectory, SqlMappings};
use crate::Directory;
use registry::schema::structs;
use store::Store;

#[allow(unreachable_patterns)]
impl SqlDirectory {
    pub async fn open(
        config: structs::SqlDirectory,
        data_store: &Store,
    ) -> Result<Directory, String> {
        let sql_store = match config.store {
            #[cfg(feature = "postgres")]
            structs::SqlAuthStore::PostgreSql(store) => {
                store::backend::postgres::PostgresStore::open(store).await?
            }
            #[cfg(feature = "mysql")]
            structs::SqlAuthStore::MySql(store) => {
                store::backend::mysql::MysqlStore::open(store).await?
            }
            #[cfg(feature = "sqlite")]
            structs::SqlAuthStore::Sqlite(store) => {
                store::backend::sqlite::SqliteStore::open(store)?
            }
            structs::SqlAuthStore::Default => {
                if data_store.is_sql() {
                    data_store.clone()
                } else {
                    return Err(concat!(
                        "This directory is set to store accounts in the main data store, ",
                        "but the configured data store is not an SQL database. ",
                        "Either select an SQL data store or configure a separate SQL ",
                        "database for this directory."
                    )
                    .to_string());
                }
            }
            _ => {
                return Err(
                    "Binary not compiled with support for the selected SQL directory backend."
                        .to_string(),
                );
            }
        };

        let mappings = SqlMappings {
            query_login: config.query_login,
            query_recipient: config.query_recipient,
            query_member_of: config.query_member_of,
            query_email_aliases: config.query_email_aliases,
            column_email: config.column_email,
            column_secret: config.column_secret,
            column_type: config.column_class,
            column_description: config.column_description,
        };

        Ok(Directory::Sql(SqlDirectory {
            sql_store,
            mappings,
        }))
    }
}
