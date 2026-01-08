/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use mysql_async::{
    Conn, OptsBuilder, Pool, PoolConstraints, PoolOpts, SslOpts, prelude::Queryable,
};
use utils::config::{Config, utils::AsKey};

use crate::{
    backend::mysql::MysqlSearchField,
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, SearchableField,
        TracingSearchField,
    },
    *,
};

use super::{MysqlStore, into_error};

impl MysqlStore {
    pub async fn open(
        config: &mut Config,
        prefix: impl AsKey,
        create_store_tables: bool,
        create_search_tables: bool,
    ) -> Option<Self> {
        let prefix = prefix.as_key();
        let mut opts = OptsBuilder::default()
            .ip_or_hostname(config.value_require((&prefix, "host"))?.to_string())
            .user(config.value((&prefix, "user")).map(|s| s.to_string()))
            .pass(config.value((&prefix, "password")).map(|s| s.to_string()))
            .db_name(
                config
                    .value_require((&prefix, "database"))?
                    .to_string()
                    .into(),
            )
            .max_allowed_packet(config.property((&prefix, "max-allowed-packet")))
            .wait_timeout(
                config
                    .property::<Option<Duration>>((&prefix, "timeout"))
                    .unwrap_or_default()
                    .map(|t| t.as_secs() as usize),
            )
            .client_found_rows(true);
        if let Some(port) = config.property((&prefix, "port")) {
            opts = opts.tcp_port(port);
        }

        if config
            .property_or_default::<bool>((&prefix, "tls.enable"), "false")
            .unwrap_or_default()
        {
            let allow_invalid = config
                .property_or_default::<bool>((&prefix, "tls.allow-invalid-certs"), "false")
                .unwrap_or_default();
            opts = opts.ssl_opts(Some(
                SslOpts::default()
                    .with_danger_accept_invalid_certs(allow_invalid)
                    .with_danger_skip_domain_validation(allow_invalid),
            ));
        }

        // Configure connection pool
        let mut pool_min = PoolConstraints::default().min();
        let mut pool_max = PoolConstraints::default().max();
        if let Some(n_size) = config
            .property::<usize>((&prefix, "pool.min-connections"))
            .filter(|&n| n > 0)
        {
            pool_min = n_size;
        }
        if let Some(n_size) = config
            .property::<usize>((&prefix, "pool.max-connections"))
            .filter(|&n| n > 0)
        {
            pool_max = n_size;
        }
        opts = opts.pool_opts(
            PoolOpts::default().with_constraints(PoolConstraints::new(pool_min, pool_max).unwrap()),
        );

        let db = Self {
            conn_pool: Pool::new(opts),
        };

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
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;

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
            SUBSPACE_TELEMETRY_SPAN,
            SUBSPACE_TELEMETRY_METRIC,
        ] {
            let table = char::from(table);
            conn.query_drop(format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                    k TINYBLOB,
                    v MEDIUMBLOB NOT NULL,
                    PRIMARY KEY (k(255))
                ) ENGINE=InnoDB"
            ))
            .await
            .map_err(into_error)?;
        }

        conn.query_drop(format!(
            "CREATE TABLE IF NOT EXISTS {} (
                k TINYBLOB,
                v LONGBLOB NOT NULL,
                PRIMARY KEY (k(255))
            ) ENGINE=InnoDB",
            char::from(SUBSPACE_BLOBS),
        ))
        .await
        .map_err(into_error)?;

        for table in [SUBSPACE_INDEXES] {
            let table = char::from(table);
            conn.query_drop(format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                    k BLOB,
                    PRIMARY KEY (k(400))
                ) ENGINE=InnoDB"
            ))
            .await
            .map_err(into_error)?;
        }

        for table in [SUBSPACE_COUNTER, SUBSPACE_QUOTA, SUBSPACE_IN_MEMORY_COUNTER] {
            conn.query_drop(format!(
                "CREATE TABLE IF NOT EXISTS {} (
                k TINYBLOB,
                v BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (k(255))
            ) ENGINE=InnoDB",
                char::from(table)
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
        //create_search_tables::<FileSearchField>(&mut conn).await?;
        create_search_tables::<TracingSearchField>(&mut conn).await?;

        Ok(())
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
