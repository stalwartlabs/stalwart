/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod blob;
pub mod cleanup;
pub mod import_export;
pub mod lookup;
pub mod ops;
pub mod query;

use crate::{
    AssertConfig,
    store::cleanup::{search_store_destroy, store_destroy},
};
use std::io::Read;
use store::Stores;
use utils::config::Config;

pub struct TempDir {
    pub path: std::path::PathBuf,
}

#[tokio::test(flavor = "multi_thread")]
pub async fn store_tests() {
    let insert = true;
    let temp_dir = TempDir::new("store_tests", insert);
    let mut config = Config::new(build_store_config(&temp_dir.path.to_string_lossy()))
        .unwrap()
        .assert_no_errors();
    let stores = Stores::parse_all(&mut config, false).await;

    let store_id = std::env::var("STORE")
        .expect("Missing store type. Try running `STORE=<store_type> cargo test`");
    let store = stores
        .stores
        .get(&store_id)
        .expect("Store not found")
        .clone();

    println!("Testing store {}...", store_id);
    if insert {
        store_destroy(&store).await;
    }

    import_export::test(store.clone()).await;
    ops::test(store.clone()).await;

    if insert {
        temp_dir.delete();
    }
}

#[tokio::test(flavor = "multi_thread")]
pub async fn search_tests() {
    let insert = std::env::var("NO_INSERT").is_err();
    let temp_dir = TempDir::new("search_store_tests", insert);
    let mut config = Config::new(build_store_config(&temp_dir.path.to_string_lossy()))
        .unwrap()
        .assert_no_errors();
    let stores = Stores::parse_all(&mut config, false).await;

    let store_id = std::env::var("SEARCH_STORE")
        .expect("Missing store type. Try running `SEARCH_STORE=<store_type> cargo test`");
    let store = stores
        .search_stores
        .get(&store_id)
        .expect("Store not found")
        .clone();

    println!("Testing store {}...", store_id);
    if insert {
        search_store_destroy(&store).await;
    }

    query::test(store, insert).await;

    if insert {
        temp_dir.delete();
    }
}

pub fn deflate_test_resource(name: &str) -> Vec<u8> {
    let mut csv_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    csv_path.push("resources");
    csv_path.push(name);

    let mut decoder = flate2::bufread::GzDecoder::new(std::io::BufReader::new(
        std::fs::File::open(csv_path).unwrap(),
    ));
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).unwrap();
    result
}

impl TempDir {
    pub fn new(name: &str, delete_if_exists: bool) -> Self {
        let mut path = std::env::temp_dir();
        path.push(name);
        if delete_if_exists && path.exists() {
            std::fs::remove_dir_all(&path).unwrap();
        }
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub fn delete(&self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

pub fn build_store_config(temp_dir: &str) -> String {
    let store = std::env::var("STORE")
        .expect("Missing store type. Try running `STORE=<store_type> cargo test`");
    let fts_store = std::env::var("SEARCH_STORE").unwrap_or_else(|_| store.clone());
    let blob_store = std::env::var("BLOB_STORE").unwrap_or_else(|_| store.clone());
    let lookup_store = std::env::var("LOOKUP_STORE").unwrap_or_else(|_| store.clone());

    CONFIG
        .replace("{STORE}", &store)
        .replace("{SEARCH_STORE}", &fts_store)
        .replace("{BLOB_STORE}", &blob_store)
        .replace("{LOOKUP_STORE}", &lookup_store)
        .replace("{TMP}", temp_dir)
        .replace(
            "{ELASTIC_ENABLED}",
            if fts_store != "elastic" {
                "true"
            } else {
                "false"
            },
        )
        .replace(
            "{MEILI_ENABLED}",
            if fts_store != "meili" {
                "true"
            } else {
                "false"
            },
        )
}

const CONFIG: &str = r#"
[store."sqlite"]
type = "sqlite"
path = "{TMP}/sqlite.db"

[store."rocksdb"]
type = "rocksdb"
path = "{TMP}/rocks.db"

[store."foundationdb"]
type = "foundationdb"

[store."postgresql"]
type = "postgresql"
host = "localhost"
port = 5432
database = "stalwart"
user = "postgres"
password = "mysecretpassword"

[store."mysql"]
type = "mysql"
host = "localhost"
port = 3307
database = "stalwart"
user = "root"
password = "password"

[store."elastic"]
type = "elasticsearch"
url = "https://localhost:9200"
tls.allow-invalid-certs = true
disable = {ELASTIC_ENABLED}
[store."elastic".auth]
username = "elastic"
secret = "changeme"

[store."meili"]
type = "meilisearch"
url = "http://localhost:7700"
tls.allow-invalid-certs = true
disable = {MEILI_ENABLED}
[store."meili".task]
poll-interval = "100ms"
#[store."meili".auth]
#username = "meili"
#secret = "changeme"

#[store."s3"]
#type = "s3"
#access-key = "minioadmin"
#secret-key = "minioadmin"
#region = "eu-central-1"
#endpoint = "http://localhost:9000"
#bucket = "tmp"

[store."fs"]
type = "fs"
path = "{TMP}"

[store."redis"]
type = "redis"
urls = "redis://127.0.0.1"
redis-type = "single"

#[store."psql-replica"]
#type = "sql-read-replica"
#primary = "postgresql"
#replicas = "postgresql"

[storage]
data = "{STORE}"
fts = "{SEARCH_STORE}"
blob = "{BLOB_STORE}"
lookup = "{LOOKUP_STORE}"
directory = "{STORE}"

[directory."{STORE}"]
type = "internal"
store = "{STORE}"

[session.rcpt]
directory = "'{STORE}'"

[session.auth]
directory = "'{STORE}'"

"#;
