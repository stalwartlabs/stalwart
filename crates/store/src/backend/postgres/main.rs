/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PostgresStore, into_error};
use crate::{
    backend::postgres::{
        PsqlSearchField,
        connect::PgConnect,
        into_pool_error,
        pool::{PgManager, PgObject, PgPool},
        search::{PG_FALLBACK_LANG, PG_LANGS, PG_UNSTEMMED_LANG},
        sql::SqlStatements,
        tls::MakeRustlsConnect,
    },
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, FileSearchField,
        SearchableField, TracingSearchField,
    },
    *,
};
use ::registry::schema::{enums::PostgreSqlRecyclingMethod, structs};
use ahash::AHashSet;
use compact_str::ToCompactString;
use deadpool_postgres::{Config, Manager, ManagerConfig, PoolConfig, RecyclingMethod, Runtime};
use std::time::Duration;
use tokio_postgres::NoTls;
use utils::tls::rustls_client_config;

impl PostgresStore {
    pub async fn open(config: structs::PostgreSqlStore) -> Result<Store, String> {
        let mut cfg = Config::new();
        cfg.dbname = config.database.into();
        cfg.host = config.host.into();
        cfg.user = config.auth_username;
        cfg.password = config.auth_secret.secret().await?.map(|v| v.into_owned());
        cfg.port = (config.port as u16).into();
        cfg.connect_timeout = config.connect_timeout.map(|t| t.into_inner());
        cfg.options = config.options;
        cfg.manager = Some(ManagerConfig {
            recycling_method: match config.pool_recycling_method {
                PostgreSqlRecyclingMethod::Fast => RecyclingMethod::Fast,
                PostgreSqlRecyclingMethod::Verified => RecyclingMethod::Verified,
                PostgreSqlRecyclingMethod::Clean => RecyclingMethod::Clean,
            },
        });
        cfg.pool = PoolConfig::new(
            config
                .pool_max_connections
                .map_or_else(backend::default_pool_max_connections, |max| max as usize),
        )
        .into();

        let response_timeout = config.response_timeout.map(|t| t.into_inner());
        let primary_pool = create_pool(
            &cfg,
            config.use_tls,
            config.allow_invalid_certs,
            response_timeout,
        )?;
        let ts_configs = discover_ts_configs(&primary_pool).await;
        let sql = Arc::new(SqlStatements::new());

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let mut replicas = vec![];
        #[cfg(feature = "enterprise")]
        for replica in config.read_replicas {
            let mut cfg = cfg.clone();
            cfg.dbname = replica.database.into();
            cfg.host = replica.host.into();
            cfg.user = replica.auth_username;
            cfg.password = replica.auth_secret.secret().await?.map(|v| v.into_owned());
            cfg.port = (replica.port as u16).into();
            cfg.options = replica.options;
            replicas.push(Store::PostgreSQL(Arc::new(PostgresStore {
                conn_pool: create_pool(
                    &cfg,
                    config.use_tls,
                    config.allow_invalid_certs,
                    response_timeout,
                )?,
                ts_configs: ts_configs.clone(),
                sql: sql.clone(),
            })));
        }
        // SPDX-SnippetEnd

        let primary = Store::PostgreSQL(Arc::new(PostgresStore {
            conn_pool: primary_pool,
            ts_configs,
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
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;

        for subspace in Subspace::ALL
            .iter()
            .copied()
            .filter(|subspace| !subspace.is_internal_fts())
        {
            let table = subspace.name();
            let (columns, storage) = match subspace.shape() {
                Shape::Value => (
                    "k BYTEA PRIMARY KEY, v BYTEA NOT NULL",
                    " WITH (fillfactor = 85)",
                ),
                Shape::Presence => ("k BYTEA PRIMARY KEY", ""),
                Shape::Counter => (
                    "k BYTEA PRIMARY KEY, v BIGINT NOT NULL DEFAULT 0",
                    " WITH (fillfactor = 60)",
                ),
            };

            conn.execute(
                &format!("CREATE TABLE IF NOT EXISTS {table} ({columns}){storage}"),
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
        create_search_tables::<FileSearchField>(&conn).await?;
        create_search_tables::<TracingSearchField>(&conn).await?;

        Ok(())
    }
}

async fn create_search_tables<T: SearchableField + PsqlSearchField + 'static>(
    conn: &PgObject,
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
            let column_name = field.column();
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

fn create_pool(
    cfg: &Config,
    use_tls: bool,
    allow_invalid_certs: bool,
    response_timeout: Option<Duration>,
) -> Result<PgPool, String> {
    let pg_config = cfg
        .get_pg_config()
        .map_err(|e| format!("Failed to create connection pool: {e}"))?;
    let connect = PgConnect {
        config: pg_config.clone(),
        tls: use_tls
            .then(|| rustls_client_config(allow_invalid_certs).map(MakeRustlsConnect::new))
            .transpose()?,
        connect_timeout: cfg.connect_timeout,
        response_timeout,
        unresponsive: Default::default(),
    };
    let manager = Manager::from_config(pg_config, NoTls, cfg.get_manager_config());
    PgPool::builder(PgManager::new(manager, connect))
        .config(cfg.get_pool_config())
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|e| format!("Failed to create connection pool: {e}"))
}

async fn discover_ts_configs(pool: &PgPool) -> AHashSet<&'static str> {
    let mut ts_configs = AHashSet::from_iter([PG_FALLBACK_LANG, PG_UNSTEMMED_LANG]);

    match probe_ts_configs(pool).await {
        Ok(available) => {
            for name in available {
                if let Some(config) = PG_LANGS.iter().copied().find(|config| *config == name) {
                    ts_configs.insert(config);
                }
            }
        }
        Err(err) => {
            trc::event!(
                Store(trc::StoreEvent::PostgresqlError),
                Details = "Failed to query pg_ts_config, assuming english only",
                Reason = err.to_compact_string(),
            );
        }
    }

    ts_configs
}

async fn probe_ts_configs(pool: &PgPool) -> trc::Result<Vec<String>> {
    let conn = pool.get().await.map_err(into_pool_error)?;

    conn.query("SELECT cfgname::text FROM pg_ts_config", &[])
        .await
        .map_err(into_error)?
        .into_iter()
        .map(|row| row.try_get::<_, String>(0).map_err(into_error))
        .collect()
}
