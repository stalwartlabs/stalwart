/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::{
    IndexKey, IndexKeyPrefix, IterateParams, U32_LEN, roaring::RoaringBitmap,
    write::key::DeserializeBigEndian,
};
use trc::AddContext;
use types::collection::Collection;

use crate::Server;

impl Server {
    pub async fn document_ids(
        &self,
        account_id: u32,
        collection: Collection,
        field: impl Into<u8>,
    ) -> trc::Result<RoaringBitmap> {
        let field = field.into();
        let mut results = RoaringBitmap::new();
        self.store()
            .iterate(
                IterateParams::new(
                    IndexKeyPrefix {
                        account_id,
                        collection: collection.into(),
                        field,
                    },
                    IndexKeyPrefix {
                        account_id,
                        collection: collection.into(),
                        field: field + 1,
                    },
                )
                .no_values(),
                |key, _| {
                    results.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| results)
    }

    pub async fn document_exists(
        &self,
        account_id: u32,
        collection: Collection,
        field: impl Into<u8>,
        filter: impl AsRef<[u8]>,
    ) -> trc::Result<bool> {
        let field = field.into();
        let mut exists = false;
        let filter = filter.as_ref();
        let key_len = IndexKeyPrefix::len() + filter.len() + U32_LEN;

        self.store()
            .iterate(
                IterateParams::new(
                    IndexKey {
                        account_id,
                        collection: collection.into(),
                        document_id: 0,
                        field,
                        key: filter,
                    },
                    IndexKey {
                        account_id,
                        collection: collection.into(),
                        document_id: u32::MAX,
                        field,
                        key: filter,
                    },
                )
                .no_values(),
                |key, _| {
                    exists = key.len() == key_len;

                    Ok(!exists)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| exists)
    }

    pub async fn document_ids_matching(
        &self,
        account_id: u32,
        collection: Collection,
        field: impl Into<u8>,
        filter: impl AsRef<[u8]>,
    ) -> trc::Result<RoaringBitmap> {
        let field = field.into();
        let filter = filter.as_ref();
        let key_len = IndexKeyPrefix::len() + filter.len() + U32_LEN;
        let mut results = RoaringBitmap::new();

        self.store()
            .iterate(
                IterateParams::new(
                    IndexKey {
                        account_id,
                        collection: collection.into(),
                        document_id: 0,
                        field,
                        key: filter,
                    },
                    IndexKey {
                        account_id,
                        collection: collection.into(),
                        document_id: u32::MAX,
                        field,
                        key: filter,
                    },
                )
                .no_values(),
                |key, _| {
                    if key.len() == key_len {
                        results.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| results)
    }
}
