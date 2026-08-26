/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{server::TestServer, storage::build_data_store};
use futures::FutureExt;
use registry::schema::structs::DataStore;
use std::{panic::AssertUnwindSafe, time::Duration};
use store::{
    IterateParams, Key, Rows, Store, Subspace, U32_LEN, Value, ValueKey,
    write::ValueClass,
};
use types::collection::Collection;

const ACCOUNT_ID: u32 = 90210;
const NUM_KEYS: u32 = 300000;
const VALUE_SIZE: usize = 64;
const PROPERTY: u8 = 128;
const STATEMENT_TIMEOUT: Duration = Duration::from_millis(10);

#[derive(Clone, Copy)]
enum Backend {
    #[cfg(feature = "postgres")]
    Postgres,
    #[cfg(feature = "mysql")]
    MariaDb,
}

pub async fn test(test: &TestServer) {
    let Some(backend) = Backend::detect(test.server.store()) else {
        return;
    };

    println!("Running SQL statement timeout tests...");

    let admin = Store::build(backend.data_store(false).await)
        .await
        .expect("Failed to connect to the statement timeout store");
    admin.create_tables().await.unwrap();
    admin.delete_range(key(0), key(u32::MAX)).await.unwrap();
    for query in [backend.populate_query(), backend.populate_counters_query()] {
        admin
            .sql_query::<usize>(&query, vec![])
            .await
            .expect("Failed to populate the statement timeout store");
    }
    backend.set_timeout(&admin, true).await;

    let slow = Store::build(backend.data_store(true).await)
        .await
        .expect("Failed to open the statement timeout connection pool");
    let result = AssertUnwindSafe(scenarios(&slow, backend))
        .catch_unwind()
        .await;

    backend.set_timeout(&admin, false).await;

    let mut remaining = 0;
    let mut counters = String::new();
    if result.is_ok() {
        admin
            .iterate(
                IterateParams::new(key(0), key(u32::MAX)).no_values(),
                |_, _| {
                    remaining += 1;
                    Ok(true)
                },
            )
            .await
            .expect("Failed to count remaining keys");
        counters = admin
            .sql_query::<Rows>(&backend.count_counters_query(), range_params())
            .await
            .expect("Failed to count remaining counters")
            .rows
            .into_iter()
            .next()
            .and_then(|row| row.values.into_iter().next())
            .map(|value| value.to_str().into_owned())
            .unwrap_or_default();
    }

    admin.delete_range(key(0), key(u32::MAX)).await.unwrap();
    admin
        .sql_query::<usize>(&backend.purge_query(), vec![])
        .await
        .unwrap();

    if let Err(err) = result {
        std::panic::resume_unwind(err);
    }

    assert_eq!(remaining, 0, "Keys left behind by delete_range");
    assert_eq!(counters, "0", "Counters left behind by purge_store");
}

async fn scenarios(db: &Store, backend: Backend) {
    match db
        .sql_query::<Rows>(&backend.scan_query(), range_params())
        .await
    {
        Ok(rows) => panic!(
            "Unable to reproduce a statement timeout: scanning {} keys completed within a \
             {STATEMENT_TIMEOUT:?} statement timeout",
            rows.rows.len()
        ),
        Err(err) => backend.assert_timeout(&err),
    }

    let mut ids = Vec::with_capacity(NUM_KEYS as usize);
    db.iterate(IterateParams::new(key(0), key(u32::MAX)), |key, value| {
        let document_id = document_id(key);
        assert_eq!(value.len(), VALUE_SIZE, "document {document_id}");
        assert_eq!(
            value.get(..U32_LEN),
            Some(document_id.to_be_bytes().as_slice()),
            "document {document_id}"
        );
        ids.push(document_id);
        Ok(true)
    })
    .await
    .expect("Failed to iterate in ascending order");
    assert_ids(&ids, 0..NUM_KEYS);

    ids.clear();
    db.iterate(
        IterateParams::new(key(0), key(u32::MAX)).descending(),
        |key, _| {
            ids.push(document_id(key));
            Ok(true)
        },
    )
    .await
    .expect("Failed to iterate in descending order");
    assert_ids(&ids, (0..NUM_KEYS).rev());

    ids.clear();
    db.iterate(
        IterateParams::new(key(0), key(u32::MAX)).no_values(),
        |key, value| {
            assert!(value.is_empty());
            ids.push(document_id(key));
            Ok(true)
        },
    )
    .await
    .expect("Failed to iterate over keys");
    assert_ids(&ids, 0..NUM_KEYS);

    ids.clear();
    db.iterate(IterateParams::new(key(0), key(u32::MAX)), |key, _| {
        ids.push(document_id(key));
        Ok(ids.len() < 10)
    })
    .await
    .expect("Failed to stop iterating");
    assert_ids(&ids, 0..10);

    match db
        .sql_query::<usize>(&backend.delete_query(), range_params())
        .await
    {
        Ok(deleted) => panic!(
            "Unable to reproduce a statement timeout: deleting {deleted} keys completed within \
             a {STATEMENT_TIMEOUT:?} statement timeout"
        ),
        Err(err) => backend.assert_timeout(&err),
    }

    db.delete_range(key(0), key(u32::MAX))
        .await
        .expect("Failed to delete range");

    match db.sql_query::<usize>(&backend.purge_query(), vec![]).await {
        Ok(deleted) => panic!(
            "Unable to reproduce a statement timeout: purging {deleted} counters completed \
             within a {STATEMENT_TIMEOUT:?} statement timeout"
        ),
        Err(err) => backend.assert_timeout(&err),
    }

    db.purge_store().await.expect("Failed to purge store");
}

fn assert_ids(ids: &[u32], expected: impl ExactSizeIterator<Item = u32>) {
    assert_eq!(ids.len(), expected.len(), "Unexpected number of keys");

    for (position, (id, expected)) in ids.iter().zip(expected).enumerate() {
        assert_eq!(*id, expected, "Unexpected key at position {position}");
    }
}

fn key(document_id: u32) -> ValueKey<ValueClass> {
    ValueKey {
        account_id: ACCOUNT_ID,
        collection: Collection::Email.into(),
        document_id,
        class: ValueClass::Property(PROPERTY),
    }
}

fn document_id(key: &[u8]) -> u32 {
    u32::from_be_bytes(key[key.len() - U32_LEN..].try_into().unwrap())
}

fn key_prefix() -> String {
    let key = key(0).serialize(0);
    key[..key.len() - U32_LEN]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn range_params() -> Vec<Value<'static>> {
    vec![
        Value::Blob(key(0).serialize(0).into()),
        Value::Blob(key(u32::MAX).serialize(0).into()),
    ]
}

impl Backend {
    fn detect(db: &Store) -> Option<Self> {
        match db {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(_) => Some(Backend::Postgres),
            #[cfg(feature = "mysql")]
            Store::MySQL(_) => Some(Backend::MariaDb),
            _ => None,
        }
    }

    async fn data_store(&self, slow: bool) -> DataStore {
        let mut config = build_data_store(
            match self {
                #[cfg(feature = "postgres")]
                Backend::Postgres => "PostgreSql",
                #[cfg(feature = "mysql")]
                Backend::MariaDb => "MariaDb",
            },
            "",
        )
        .await;

        if slow {
            match &mut config {
                DataStore::PostgreSql(config) => {
                    config.options = Some(format!(
                        "-c statement_timeout={}ms",
                        STATEMENT_TIMEOUT.as_millis()
                    ));
                }
                DataStore::MySql(_) => (),
                _ => unreachable!(),
            }
        }

        config
    }

    async fn set_timeout(&self, _admin: &Store, _enable: bool) {
        match self {
            #[cfg(feature = "postgres")]
            Backend::Postgres => (),
            #[cfg(feature = "mysql")]
            Backend::MariaDb => {
                let timeout = if _enable {
                    STATEMENT_TIMEOUT.as_secs_f64()
                } else {
                    0.0
                };

                _admin
                    .sql_query::<usize>(
                        &format!("SET GLOBAL max_statement_time = {timeout}"),
                        vec![],
                    )
                    .await
                    .unwrap();
            }
        }
    }

    fn populate_query(&self) -> String {
        let table = Subspace::Property.name();
        let prefix = key_prefix();
        let padding = VALUE_SIZE - U32_LEN;
        let last = NUM_KEYS - 1;

        match self {
            #[cfg(feature = "postgres")]
            Backend::Postgres => format!(
                "INSERT INTO {table} (k, v) SELECT \
                 decode('{prefix}' || lpad(to_hex(id), 8, '0'), 'hex'), \
                 decode(lpad(to_hex(id), 8, '0') || repeat('76', {padding}), 'hex') \
                 FROM generate_series(0, {last}) id"
            ),
            #[cfg(feature = "mysql")]
            Backend::MariaDb => format!(
                "INSERT INTO {table} (k, v) SELECT \
                 UNHEX(CONCAT('{prefix}', LPAD(HEX(seq), 8, '0'))), \
                 UNHEX(CONCAT(LPAD(HEX(seq), 8, '0'), REPEAT('76', {padding}))) \
                 FROM seq_0_to_{last}"
            ),
        }
    }

    fn populate_counters_query(&self) -> String {
        let table = Subspace::Counter.name();
        let prefix = key_prefix();
        let last = NUM_KEYS - 1;

        match self {
            #[cfg(feature = "postgres")]
            Backend::Postgres => format!(
                "INSERT INTO {table} (k, v) SELECT \
                 decode('{prefix}' || lpad(to_hex(id), 8, '0'), 'hex'), 0 \
                 FROM generate_series(0, {last}) id"
            ),
            #[cfg(feature = "mysql")]
            Backend::MariaDb => format!(
                "INSERT INTO {table} (k, v) SELECT \
                 UNHEX(CONCAT('{prefix}', LPAD(HEX(seq), 8, '0'))), 0 FROM seq_0_to_{last}"
            ),
        }
    }

    fn purge_query(&self) -> String {
        format!("DELETE FROM {} WHERE v = 0", Subspace::Counter.name())
    }

    fn count_counters_query(&self) -> String {
        let table = Subspace::Counter.name();
        match self {
            #[cfg(feature = "postgres")]
            Backend::Postgres => format!("SELECT COUNT(*) FROM {table} WHERE k >= $1 AND k <= $2"),
            #[cfg(feature = "mysql")]
            Backend::MariaDb => format!("SELECT COUNT(*) FROM {table} WHERE k >= ? AND k <= ?"),
        }
    }

    fn scan_query(&self) -> String {
        let table = Subspace::Property.name();
        match self {
            #[cfg(feature = "postgres")]
            Backend::Postgres => {
                format!("SELECT k, v FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k ASC")
            }
            #[cfg(feature = "mysql")]
            Backend::MariaDb => {
                format!("SELECT k, v FROM {table} WHERE k >= ? AND k <= ? ORDER BY k ASC")
            }
        }
    }

    fn delete_query(&self) -> String {
        let table = Subspace::Property.name();
        match self {
            #[cfg(feature = "postgres")]
            Backend::Postgres => format!("DELETE FROM {table} WHERE k >= $1 AND k <= $2"),
            #[cfg(feature = "mysql")]
            Backend::MariaDb => format!("DELETE FROM {table} WHERE k >= ? AND k <= ?"),
        }
    }

    fn assert_timeout(&self, err: &trc::Error) {
        let (event_type, marker) = match self {
            #[cfg(feature = "postgres")]
            Backend::Postgres => (trc::StoreEvent::PostgresqlError, "57014"),
            #[cfg(feature = "mysql")]
            Backend::MariaDb => (
                trc::StoreEvent::MysqlError,
                "Query execution was interrupted",
            ),
        };
        let details = format!("{err:?}");

        assert!(
            err.matches(trc::EventType::Store(event_type)) && details.contains(marker),
            "Expected a statement timeout, got: {details}"
        );
    }
}
