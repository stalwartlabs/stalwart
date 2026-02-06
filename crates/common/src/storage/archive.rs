/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;
use store::{
    Deserialize, IterateParams, U32_LEN, ValueKey,
    dispatch::DocumentSet,
    write::{AlignedBytes, Archive, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{collection::Collection, field::Field};

impl Server {
    pub async fn archives<I, CB>(
        &self,
        account_id: u32,
        collection: Collection,
        documents: &I,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        I: DocumentSet + Send + Sync,
        CB: FnMut(u32, Archive<AlignedBytes>) -> trc::Result<bool> + Send + Sync,
    {
        let collection: u8 = collection.into();

        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection,
                        document_id: documents.min(),
                        class: ValueClass::Property(Field::ARCHIVE.into()),
                    },
                    ValueKey {
                        account_id,
                        collection,
                        document_id: documents.max(),
                        class: ValueClass::Property(Field::ARCHIVE.into()),
                    },
                ),
                |key, value| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    if documents.contains(document_id) {
                        <Archive<AlignedBytes> as Deserialize>::deserialize(value)
                            .and_then(|archive| cb(document_id, archive))
                    } else {
                        Ok(true)
                    }
                },
            )
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })
    }

    pub async fn all_archives<CB>(
        &self,
        account_id: u32,
        collection: Collection,
        field: u8,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        CB: FnMut(u32, Archive<AlignedBytes>) -> trc::Result<()> + Send + Sync,
    {
        let collection: u8 = collection.into();

        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection,
                        document_id: 0,
                        class: ValueClass::Property(field),
                    },
                    ValueKey {
                        account_id,
                        collection,
                        document_id: u32::MAX,
                        class: ValueClass::Property(field),
                    },
                ),
                |key, value| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    let archive = <Archive<AlignedBytes> as Deserialize>::deserialize(value)?;
                    cb(document_id, archive)?;

                    Ok(true)
                },
            )
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })
    }
}
