/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{BlobStore, backend::fs::FsStore, registry::bootstrap::Bootstrap};
use registry::schema::{prelude::ObjectType, structs};

#[allow(unreachable_patterns)]
impl BlobStore {
    pub async fn build(bp: &mut Bootstrap) -> Option<Self> {
        let result = match bp.setting_infallible::<structs::BlobStore>().await {
            structs::BlobStore::Default => return Some(BlobStore::Store(bp.data_store.clone())),
            #[cfg(feature = "foundation")]
            structs::BlobStore::FoundationDb(foundation_db_store) => {
                crate::backend::foundationdb::FdbStore::open(foundation_db_store)
                    .await
                    .map(BlobStore::Store)
            }
            #[cfg(feature = "postgres")]
            structs::BlobStore::PostgreSql(postgre_sql_store) => {
                crate::backend::postgres::PostgresStore::open(postgre_sql_store)
                    .await
                    .map(BlobStore::Store)
            }
            #[cfg(feature = "mysql")]
            structs::BlobStore::MySql(my_sql_store) => {
                crate::backend::mysql::MysqlStore::open(my_sql_store)
                    .await
                    .map(BlobStore::Store)
            }
            #[cfg(feature = "s3")]
            structs::BlobStore::S3(s3_store) => crate::backend::s3::S3Store::open(s3_store).await,
            #[cfg(feature = "azure")]
            structs::BlobStore::Azure(azure_store) => {
                crate::backend::azure::AzureStore::open(azure_store).await
            }
            structs::BlobStore::FileSystem(file_system_store) => {
                FsStore::open(file_system_store).await
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            structs::BlobStore::Sharded(store) => {
                crate::backend::composite::sharded_blob::ShardedBlob::open(store).await
            } // SPDX-SnippetEnd
            _ => Err("Binary was not compiled with the selected blob store backend".to_string()),
        };

        match result {
            Ok(store) => Some(store),
            Err(err) => {
                bp.build_error(ObjectType::BlobStore.singleton(), err);
                None
            }
        }
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn downgrade_store(self) -> BlobStore {
        match self {
            BlobStore::Sharded(_) => BlobStore::default(),
            other => other,
        }
    }

    #[cfg(feature = "enterprise")]
    pub fn is_enterprise(&self) -> bool {
        matches!(self, BlobStore::Sharded(_))
    }
    // SPDX-SnippetEnd
}
