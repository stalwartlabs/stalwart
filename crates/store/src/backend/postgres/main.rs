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
use ::registry::schema::{enums::PostgreSqlRecyclingMethod, structs};
use deadpool::managed::Object;
use deadpool_postgres::{Config, Manager, ManagerConfig, PoolConfig, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;
use utils::rustls_client_config;

impl PostgresStore {
    pub async fn open(config: structs::PostgreSqlStore) -> Result<Store, String> {
        let mut cfg = Config::new();
        cfg.dbname = config.database.into();
        cfg.host = config.host.into();
        cfg.user = config.auth_username;
        cfg.password = config.auth_secret.secret().await?.map(|v| v.into_owned());
        cfg.port = (config.port as u16).into();
        cfg.connect_timeout = config.timeout.map(|t| t.into_inner());
        cfg.options = config.options;
        cfg.manager = Some(ManagerConfig {
            recycling_method: match config.pool_recycling_method {
                PostgreSqlRecyclingMethod::Fast => RecyclingMethod::Fast,
                PostgreSqlRecyclingMethod::Verified => RecyclingMethod::Verified,
                PostgreSqlRecyclingMethod::Clean => RecyclingMethod::Clean,
            },
        });
        if let Some(max_conn) = config.pool_max_connections {
            cfg.pool = PoolConfig::new(max_conn as usize).into();
        }
        let todo = "implement disabled languages properly";

        let mut replicas = vec![];
        for replica in config.read_replicas {
            let mut cfg = cfg.clone();
            cfg.dbname = replica.database.into();
            cfg.host = replica.host.into();
            cfg.user = replica.auth_username;
            cfg.password = replica.auth_secret.secret().await?.map(|v| v.into_owned());
            cfg.port = (replica.port as u16).into();
            cfg.options = replica.options;
            replicas.push(Store::PostgreSQL(Arc::new(PostgresStore {
                conn_pool: if config.use_tls {
                    cfg.create_pool(
                        Some(Runtime::Tokio1),
                        MakeRustlsConnect::new(rustls_client_config(config.allow_invalid_certs)),
                    )
                } else {
                    cfg.create_pool(Some(Runtime::Tokio1), NoTls)
                }
                .map_err(|e| format!("Failed to create connection pool: {e}"))?,
            })));
        }

        let primary = Store::PostgreSQL(Arc::new(PostgresStore {
            conn_pool: if config.use_tls {
                cfg.create_pool(
                    Some(Runtime::Tokio1),
                    MakeRustlsConnect::new(rustls_client_config(config.allow_invalid_certs)),
                )
            } else {
                cfg.create_pool(Some(Runtime::Tokio1), NoTls)
            }
            .map_err(|e| format!("Failed to create connection pool: {e}"))?,
        }));

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if !replicas.is_empty() {
            return backend::composite::read_replica::SQLReadReplica::open(primary, replicas);
        }
        // SPDX-SnippetEnd

        Ok(primary)
    }

    pub(crate) async fn create_storage_tables(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;

        for table in [
            SUBSPACE_ACL,
            SUBSPACE_TASK_QUEUE,
            SUBSPACE_DELETED_ITEMS,
            SUBSPACE_SPAM_SAMPLES,
            SUBSPACE_BLOB_LINK,
            SUBSPACE_IN_MEMORY_VALUE,
            SUBSPACE_PROPERTY,
            SUBSPACE_REGISTRY,
            SUBSPACE_REGISTRY_PK,
            SUBSPACE_QUEUE_MESSAGE,
            SUBSPACE_QUEUE_EVENT,
            SUBSPACE_REPORT_OUT,
            SUBSPACE_REPORT_IN,
            SUBSPACE_LOGS,
            SUBSPACE_BLOBS,
            SUBSPACE_DIRECTORY,
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

        for table in [SUBSPACE_INDEXES, SUBSPACE_REGISTRY_IDX] {
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
