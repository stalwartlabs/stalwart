/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MysqlStore, into_error};
use crate::{
    backend::mysql::{MysqlSearchField, sql::SqlStatements},
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, FileSearchField,
        SearchableField, TracingSearchField,
    },
    *,
};
use ::registry::schema::structs;
use mysql_async::{
    Conn, OptsBuilder, Pool, PoolConstraints, PoolOpts, SslOpts, prelude::Queryable,
};

const STMT_CACHE_SIZE: usize = 64;
const SESSION_SETUP: &str =
    "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED; SET SESSION autocommit = 1";

impl MysqlStore {
    pub async fn open(config: structs::MySqlStore) -> Result<Store, String> {
        let mut opts = OptsBuilder::default()
            .ip_or_hostname(config.host)
            .user(config.auth_username)
            .pass(config.auth_secret.secret().await?.map(|v| v.into_owned()))
            .db_name(Some(config.database))
            .max_allowed_packet(config.max_allowed_packet.map(|v| v as usize))
            .wait_timeout(config.idle_timeout.map(|t| t.as_secs() as usize))
            .stmt_cache_size(STMT_CACHE_SIZE)
            .client_found_rows(true)
            .setup(vec![SESSION_SETUP])
            .prefer_socket(false)
            .tcp_port(config.port as u16);

        if config.use_tls {
            opts = opts.ssl_opts(Some(
                SslOpts::default()
                    .with_danger_accept_invalid_certs(config.allow_invalid_certs)
                    .with_danger_skip_domain_validation(config.allow_invalid_certs),
            ));
        }

        opts = opts.pool_opts(
            PoolOpts::default()
                .with_constraints(pool_constraints(
                    config.pool_max_connections,
                    config.pool_min_connections,
                    backend::default_pool_max_connections,
                )?)
                .with_reset_connection(false),
        );

        let sql = Arc::new(SqlStatements::new());
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let mut replicas = vec![];
        #[cfg(feature = "enterprise")]
        for replica in config.read_replicas {
            replicas.push(Store::MySQL(Arc::new(MysqlStore {
                conn_pool: Pool::new(
                    opts.clone()
                        .ip_or_hostname(replica.host)
                        .user(replica.auth_username)
                        .pass(replica.auth_secret.secret().await?.map(|v| v.into_owned()))
                        .db_name(Some(replica.database))
                        .tcp_port(replica.port as u16),
                ),
                sql: sql.clone(),
            })))
        }
        // SPDX-SnippetEnd

        let primary = Store::MySQL(Arc::new(MysqlStore {
            conn_pool: Pool::new(opts),
            sql,
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
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        check_prepared_statement_budget(&mut conn).await;

        for subspace in Subspace::ALL
            .iter()
            .copied()
            .filter(|subspace| !subspace.is_internal_fts())
        {
            let table = subspace.name();
            let columns = match subspace.shape() {
                Shape::Value => {
                    let value_type = match subspace {
                        Subspace::Blobs | Subspace::Immutable => "LONGBLOB",
                        _ => "MEDIUMBLOB",
                    };
                    format!("k VARBINARY(255) NOT NULL, v {value_type} NOT NULL, PRIMARY KEY (k)")
                }
                Shape::Presence => "k VARBINARY(767) NOT NULL, PRIMARY KEY (k)".to_string(),
                Shape::Counter => {
                    "k VARBINARY(255) NOT NULL, v BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (k)"
                        .to_string()
                }
            };

            conn.query_drop(format!(
                "CREATE TABLE IF NOT EXISTS {table} ({columns}) ENGINE=InnoDB"
            ))
            .await
            .map_err(into_error)?;
        }

        Ok(())
    }

    pub(crate) async fn create_search_tables(&self) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;

        create_search_tables::<EmailSearchField>(&mut conn).await?;
        create_search_tables::<CalendarSearchField>(&mut conn).await?;
        create_search_tables::<ContactSearchField>(&mut conn).await?;
        create_search_tables::<FileSearchField>(&mut conn).await?;
        create_search_tables::<TracingSearchField>(&mut conn).await?;

        Ok(())
    }
}

fn pool_constraints(
    max: Option<u64>,
    min: Option<u64>,
    default_max: impl FnOnce() -> usize,
) -> Result<PoolConstraints, String> {
    let min = min.map_or_else(|| PoolConstraints::default().min(), |min| min as usize);
    let max = max.map_or_else(|| default_max().max(min), |max| max as usize);
    PoolConstraints::new(min.min(max), max)
        .ok_or_else(|| format!("Invalid MySQL poolMaxConnections {max}: must be at least 1"))
}

async fn check_prepared_statement_budget(conn: &mut Conn) {
    let opts = conn.opts();
    let statements = opts
        .pool_opts()
        .constraints()
        .max()
        .saturating_mul(opts.stmt_cache_size()) as u64;
    if let Ok(Some(limit)) = conn
        .query_first::<u64, _>("SELECT @@GLOBAL.max_prepared_stmt_count")
        .await
        && statements > limit
    {
        trc::event!(
            Registry(trc::RegistryEvent::BuildWarning),
            Property = "poolMaxConnections",
            Reason = "Prepared statements cached by this node can exceed the server's max_prepared_stmt_count",
            Total = statements,
            Limit = limit,
        );
    }
}

async fn create_search_tables<T: SearchableField + MysqlSearchField + 'static>(
    conn: &mut Conn,
) -> trc::Result<()> {
    let table_name = T::index().mysql_table();
    let mut query = format!("CREATE TABLE IF NOT EXISTS {} (", table_name);

    // Add primary key columns
    let pkeys = T::primary_keys();
    for pkey in pkeys {
        query.push_str(&format!("{} {}, ", pkey.column(), pkey.column_type()));
    }

    // Add other columns
    for field in T::all_fields() {
        query.push_str(&format!("{} {}, ", field.column(), field.column_type()));
    }

    // Add primary key constraint
    query.push_str("PRIMARY KEY (");
    for (i, pkey) in pkeys.iter().enumerate() {
        if i > 0 {
            query.push_str(", ");
        }
        query.push_str(pkey.column());
    }
    query.push_str(")) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    conn.query_drop(&query).await.map_err(into_error)?;

    // Create indexes
    for field in T::all_fields() {
        if field.is_text() {
            let column_name = field.column();
            let create_index_query = format!(
                "CREATE FULLTEXT INDEX fts_{table_name}_{column_name} ON {table_name}({column_name})",
            );

            let _ = conn.query_drop(&create_index_query).await;
        }

        if field.is_indexed() {
            let column_name = field.column();
            let create_index_query = format!(
                "CREATE INDEX idx_{table_name}_{column_name} ON {table_name}({column_name})",
            );
            let _ = conn.query_drop(&create_index_query).await;
        }
    }

    Ok(())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/mysql/main/tests.rs"]
mod tests;
