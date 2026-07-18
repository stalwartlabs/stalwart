/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::cleanup::{search_store_destroy, store_assert_is_empty};
use crate::utils::registry::UnwrapRegistryId;
use common::Server;
use registry::schema::structs::{Task, TaskStatus};
use registry::{
    schema::{
        enums::{BlobStoreType, DataStoreType, InMemoryStoreType, SearchStoreType},
        prelude::Object,
        structs::{
            BlobStore, DataStore, ElasticSearchStore, FileSystemStore, FoundationDbStore, HttpAuth,
            HttpAuthBasic, HttpAuthBearer, InMemoryStore, MeilisearchStore, MySqlStore,
            PostgreSqlStore, RedisStore, RocksDbStore, S3Store, S3StoreCustomRegion, S3StoreRegion,
            SearchStore, SecretKey, SecretKeyOptional, SecretKeyValue, SqliteStore,
        },
    },
    types::{EnumImpl, duration::Duration},
};
use store::write::now;
use store::{
    Deserialize, IterateParams, ValueKey,
    write::{TaskQueueClass, ValueClass},
};
use store::{RegistryStore, registry::write::RegistryWrite};

pub trait RegistryEnvStores {
    fn insert_stores_from_env(&self) -> impl Future<Output = ()>;
}

impl RegistryEnvStores for RegistryStore {
    async fn insert_stores_from_env(&self) {
        let path = self.path().as_os_str().to_str().unwrap();
        let mut search_store = None;
        if let Ok(store) = std::env::var("SEARCH_STORE") {
            let store = SearchStoreType::parse(&store).expect("Invalid store type");
            search_store = Some(Object::from(build_search_store(store, path).await));
        }
        let mut blob_store = None;
        if let Ok(store) = std::env::var("BLOB_STORE") {
            let store = BlobStoreType::parse(&store).expect("Invalid store type");
            blob_store = Some(Object::from(build_blob_store(store, path).await));
        }
        let mut in_memory = None;
        if let Ok(store) = std::env::var("MEMORY_STORE") {
            let store = InMemoryStoreType::parse(&store).expect("Invalid store type");
            in_memory = Some(Object::from(build_in_memory_store(store, path).await));
        }

        for store in [search_store, blob_store, in_memory].into_iter().flatten() {
            self.write(RegistryWrite::insert(&store))
                .await
                .expect("Failed to insert store into registry")
                .unwrap_id(trc::location!());
        }
    }
}

pub async fn build_data_store(typ: DataStoreType, path: &str) -> DataStore {
    match typ {
        DataStoreType::RocksDb => DataStore::RocksDb(RocksDbStore {
            path: format!("{path}/rocks.db"),
            ..Default::default()
        }),
        DataStoreType::Sqlite => DataStore::Sqlite(SqliteStore {
            path: format!("{path}/sqlite.db"),
            ..Default::default()
        }),
        DataStoreType::FoundationDb => {
            crate::utils::containers::ensure_foundationdb().await;
            DataStore::FoundationDb(FoundationDbStore::default())
        }
        DataStoreType::PostgreSql => {
            crate::utils::containers::ensure_postgres().await;
            DataStore::PostgreSql(PostgreSqlStore {
                host: "localhost".into(),
                port: 5432,
                auth_username: "stalwart".to_string().into(),
                auth_secret: SecretKeyOptional::Value(SecretKeyValue {
                    secret: "stalwart".into(),
                }),
                database: "stalwart".into(),
                use_tls: false,
                allow_invalid_certs: true,
                ..Default::default()
            })
        }
        DataStoreType::MySql => {
            crate::utils::containers::ensure_mysql().await;
            DataStore::MySql(MySqlStore {
                host: "localhost".into(),
                port: 3307,
                auth_username: "root".to_string().into(),
                auth_secret: SecretKeyOptional::Value(SecretKeyValue {
                    secret: "password".into(),
                }),
                database: "stalwart".into(),
                use_tls: false,
                allow_invalid_certs: true,
                ..Default::default()
            })
        }
    }
}

async fn build_blob_store(typ: BlobStoreType, path: &str) -> BlobStore {
    match typ {
        BlobStoreType::S3 => {
            crate::utils::containers::ensure_minio().await;
            BlobStore::S3(S3Store {
                access_key: "minioadmin".to_string().into(),
                bucket: "stalwart".into(),
                region: S3StoreRegion::Custom(S3StoreCustomRegion {
                    custom_endpoint: "http://localhost:9000".into(),
                    custom_region: "eu-central-1".into(),
                }),
                secret_key: SecretKeyOptional::Value(SecretKeyValue {
                    secret: "minioadmin".into(),
                }),
                allow_invalid_certs: true,
                ..Default::default()
            })
        }
        BlobStoreType::FileSystem => BlobStore::FileSystem(FileSystemStore {
            path: path.to_string(),
            ..Default::default()
        }),
        _ => unreachable!(),
    }
}

async fn build_in_memory_store(typ: InMemoryStoreType, _path: &str) -> InMemoryStore {
    match typ {
        InMemoryStoreType::Redis => {
            crate::utils::containers::ensure_redis().await;
            InMemoryStore::Redis(RedisStore {
                url: "redis://127.0.0.1".into(),
                ..Default::default()
            })
        }
        _ => unreachable!(),
    }
}

async fn build_search_store(typ: SearchStoreType, _path: &str) -> SearchStore {
    match typ {
        SearchStoreType::ElasticSearch => {
            crate::utils::containers::ensure_opensearch().await;
            SearchStore::ElasticSearch(ElasticSearchStore {
                url: "http://localhost:9200".into(),
                allow_invalid_certs: true,
                http_auth: HttpAuth::Basic(HttpAuthBasic {
                    username: "elastic".into(),
                    secret: SecretKey::Value(SecretKeyValue {
                        secret: "changeme".into(),
                    }),
                }),
                ..Default::default()
            })
        }
        SearchStoreType::Meilisearch => {
            crate::utils::containers::ensure_meilisearch().await;
            SearchStore::Meilisearch(MeilisearchStore {
                url: "http://localhost:7700".into(),
                allow_invalid_certs: true,
                poll_interval: Duration::from_millis(100),
                http_auth: HttpAuth::Bearer(HttpAuthBearer {
                    bearer_token: SecretKey::Value(SecretKeyValue {
                        secret: "stalwart-master-key".into(),
                    }),
                }),
                ..Default::default()
            })
        }
        SearchStoreType::PostgreSql => {
            crate::utils::containers::ensure_postgres().await;
            SearchStore::PostgreSql(PostgreSqlStore {
                host: "localhost".into(),
                port: 5432,
                auth_username: "stalwart".to_string().into(),
                auth_secret: SecretKeyOptional::Value(SecretKeyValue {
                    secret: "stalwart".into(),
                }),
                database: "stalwart".into(),
                use_tls: false,
                allow_invalid_certs: true,
                ..Default::default()
            })
        }
        SearchStoreType::MySql => {
            crate::utils::containers::ensure_mysql().await;
            SearchStore::MySql(MySqlStore {
                host: "localhost".into(),
                port: 3307,
                auth_username: "root".to_string().into(),
                auth_secret: SecretKeyOptional::Value(SecretKeyValue {
                    secret: "password".into(),
                }),
                database: "stalwart".into(),
                use_tls: false,
                allow_invalid_certs: true,
                ..Default::default()
            })
        }
        _ => unreachable!(),
    }
}

pub async fn wait_for_tasks(server: &Server, skip_not_due: bool, skip_permanent_failures: bool) {
    let mut count = 0;
    loop {
        let mut has_index_tasks = None;
        server
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task { id: 0 })),
                    ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task { id: u64::MAX })),
                )
                .ascending(),
                |_, value| {
                    let task = Task::deserialize(value)?;
                    if (skip_permanent_failures && matches!(task.status(), TaskStatus::Failed(_)))
                        || (skip_not_due && task.due_timestamp() > now())
                    {
                        Ok(true)
                    } else {
                        has_index_tasks = Some(task);

                        Ok(false)
                    }
                },
            )
            .await
            .unwrap();

        if let Some(task) = has_index_tasks {
            count += 1;
            if count % 10 == 0 {
                println!("Waiting for pending task {:?}...", task);
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        } else {
            break;
        }
    }
}

pub async fn assert_is_empty(server: &Server, include_registry: bool) {
    // Wait for pending index tasks
    wait_for_tasks(server, false, false).await;

    // Assert is empty
    store_assert_is_empty(
        server.store(),
        server.core.storage.blob.clone(),
        include_registry,
    )
    .await;
    search_store_destroy(server.search_store()).await;

    // Clean caches
    for cache in [
        &server.inner.cache.events,
        &server.inner.cache.contacts,
        &server.inner.cache.files,
        &server.inner.cache.scheduling,
    ] {
        cache.clear();
    }
    server.inner.cache.messages.clear();
}
