/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PostgresStore, into_error};
use crate::{
    backend::postgres::{PsqlSearchField, into_pool_error, tls::MakeRustlsConnect},
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, SearchableField,
        TracingSearchField,
    },
    *,
};
use deadpool::managed::Object;
use deadpool_postgres::{Config, Manager, ManagerConfig, PoolConfig, RecyclingMethod, Runtime};
use nlp::language::Language;
use std::time::Duration;
use tokio_postgres::NoTls;
use utils::{config::utils::AsKey, rustls_client_config};

impl PostgresStore {
    pub async fn open(
        config: &mut utils::config::Config,
        prefix: impl AsKey,
        create_store_tables: bool,
        create_search_tables: bool,
    ) -> Option<Self> {
        let prefix = prefix.as_key();
        let mut cfg = Config::new();
        cfg.dbname = config
            .value_require((&prefix, "database"))?
            .to_string()
            .into();
        cfg.host = config.value((&prefix, "host")).map(|s| s.to_string());
        cfg.user = config.value((&prefix, "user")).map(|s| s.to_string());
        cfg.password = config.value((&prefix, "password")).map(|s| s.to_string());
        cfg.port = config.property((&prefix, "port"));
        cfg.connect_timeout = config
            .property::<Option<Duration>>((&prefix, "timeout"))
            .unwrap_or_default();
        cfg.options = config.value((&prefix, "options")).map(|s| s.to_string());
        cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });
        if let Some(max_conn) = config.property::<usize>((&prefix, "pool.max-connections")) {
            cfg.pool = PoolConfig::new(max_conn).into();
        }
        let mut db = Self {
            conn_pool: if config
                .property_or_default::<bool>((&prefix, "tls.enable"), "false")
                .unwrap_or_default()
            {
                cfg.create_pool(
                    Some(Runtime::Tokio1),
                    MakeRustlsConnect::new(rustls_client_config(
                        config
                            .property_or_default((&prefix, "tls.allow-invalid-certs"), "false")
                            .unwrap_or_default(),
                    )),
                )
            } else {
                cfg.create_pool(Some(Runtime::Tokio1), NoTls)
            }
            .map_err(|e| {
                config.new_build_error(
                    prefix.as_str(),
                    format!("Failed to create connection pool: {e}"),
                )
            })
            .ok()?,
            languages: config
                .properties::<Language>((&prefix, "languages"))
                .into_iter()
                .map(|(_, v)| v)
                .collect(),
        };

        if db.languages.is_empty() {
            db.languages.insert(Language::English);
        }

        if create_store_tables && let Err(err) = db.create_storage_tables().await {
            config.new_build_error(prefix.as_str(), format!("Failed to create tables: {err}"));
        }

        if create_search_tables && let Err(err) = db.create_search_tables().await {
            config.new_build_warning(
                prefix.as_str(),
                format!("Failed to create search tables: {err}"),
            );
        }

        Some(db)
    }

    pub(crate) async fn create_storage_tables(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;

        for table in [
            SUBSPACE_ACL,
            SUBSPACE_DIRECTORY,
            SUBSPACE_TASK_QUEUE,
            SUBSPACE_BLOB_EXTRA,
            SUBSPACE_BLOB_LINK,
            SUBSPACE_IN_MEMORY_VALUE,
            SUBSPACE_PROPERTY,
            SUBSPACE_SETTINGS,
            SUBSPACE_QUEUE_MESSAGE,
            SUBSPACE_QUEUE_EVENT,
            SUBSPACE_REPORT_OUT,
            SUBSPACE_REPORT_IN,
            SUBSPACE_LOGS,
            SUBSPACE_BLOBS,
            SUBSPACE_TELEMETRY_SPAN,
            SUBSPACE_TELEMETRY_METRIC,
        ] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BYTEA PRIMARY KEY,
                        v BYTEA NOT NULL
                    )"
                ),
                &[],
            )
            .await
            .map_err(into_error)?;
        }

        for table in [SUBSPACE_INDEXES] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BYTEA PRIMARY KEY
                    )"
                ),
                &[],
            )
            .await
            .map_err(into_error)?;
        }

        for table in [SUBSPACE_COUNTER, SUBSPACE_QUOTA, SUBSPACE_IN_MEMORY_COUNTER] {
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {} (
                    k BYTEA PRIMARY KEY,
                    v BIGINT NOT NULL DEFAULT 0
                )",
                    char::from(table)
                ),
                &[],
            )
            .await
            .map_err(into_error)?;
        }

        Ok(())
    }

    pub(crate) async fn create_search_tables(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;

        create_search_tables::<EmailSearchField>(&conn).await?;
        create_search_tables::<CalendarSearchField>(&conn).await?;
        create_search_tables::<ContactSearchField>(&conn).await?;
        //create_search_tables::<FileSearchField>(&conn).await?;
        create_search_tables::<TracingSearchField>(&conn).await?;

        Ok(())
    }
}

async fn create_search_tables<T: SearchableField + PsqlSearchField + 'static>(
    conn: &Object<Manager>,
) -> trc::Result<()> {
    let table_name = T::index().psql_table();
    let mut query = format!("CREATE TABLE IF NOT EXISTS {} (", table_name);

    // Add primary key columns
    let pkeys = T::primary_keys();
    for pkey in pkeys {
        query.push_str(&format!("{} {}, ", pkey.column(), pkey.column_type()));
    }

    // Add other columns
    for field in T::all_fields() {
        query.push_str(&format!("{} {}", field.column(), field.column_type()));
        if let Some(sort_type) = field.sort_column_type() {
            query.push_str(&format!(", {} {}", field.sort_column().unwrap(), sort_type));
        }
        query.push_str(", ");
    }

    // Add primary key constraint
    query.push_str("PRIMARY KEY (");
    for (i, pkey) in pkeys.iter().enumerate() {
        if i > 0 {
            query.push_str(", ");
        }
        query.push_str(pkey.column());
    }
    query.push_str("))");

    conn.execute(&query, &[]).await.map_err(into_error)?;

    // Create indexes
    for field in T::all_fields() {
        if field.is_text() || field.is_json() {
            let column_name = field.column();
            let create_index_query = format!(
                "CREATE INDEX IF NOT EXISTS gin_{table_name}_{column_name} ON {table_name} USING GIN({column_name})",
            );
            conn.execute(&create_index_query, &[])
                .await
                .map_err(into_error)?;
        }

        if field.is_indexed() {
            let column_name = field.sort_column().unwrap_or(field.column());
            let create_index_query = format!(
                "CREATE INDEX IF NOT EXISTS idx_{table_name}_{column_name} ON {table_name}({column_name})",
            );
            conn.execute(&create_index_query, &[])
                .await
                .map_err(into_error)?;
        }
    }

    Ok(())
}
