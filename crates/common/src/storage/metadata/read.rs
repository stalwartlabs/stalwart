/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{StoredContainer, metadata_key, viewer::parse_owner_key};
use crate::Server;
use store::{
    Deserialize, IterateParams, U32_LEN,
    dispatch::DocumentSet,
    write::{
        key::DeserializeBigEndian,
        metadata::{MetadataBuf, MetadataClass, StoredMetadata, ViewerState},
    },
};
use trc::AddContext;
use types::{collection::Collection, metadata::MetadataView};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataViewerEntry {
    pub collection: Collection,
    pub viewer_id: u32,
    pub state: ViewerState,
}

impl Server {
    pub async fn metadata_containers<I, CB>(
        &self,
        account_id: u32,
        collection: Collection,
        documents: &I,
        cb: CB,
    ) -> trc::Result<()>
    where
        I: DocumentSet + Send + Sync,
        CB: for<'x> FnMut(u32, MetadataView<'x>, StoredContainer) -> trc::Result<bool>
            + Send
            + Sync,
    {
        self.containers_of(account_id, collection, MetadataClass::Shared, documents, cb)
            .await
    }

    pub async fn private_metadata_containers<I, CB>(
        &self,
        owner_id: u32,
        viewer_id: u32,
        collection: Collection,
        documents: &I,
        cb: CB,
    ) -> trc::Result<()>
    where
        I: DocumentSet + Send + Sync,
        CB: for<'x> FnMut(u32, MetadataView<'x>, StoredContainer) -> trc::Result<bool>
            + Send
            + Sync,
    {
        self.containers_of(
            owner_id,
            collection,
            MetadataClass::Private { viewer: viewer_id },
            documents,
            cb,
        )
        .await
    }

    pub async fn all_metadata_containers<CB>(
        &self,
        account_id: u32,
        collection: Collection,
        cb: CB,
    ) -> trc::Result<()>
    where
        CB: for<'x> FnMut(u32, MetadataView<'x>, StoredContainer) -> trc::Result<bool>
            + Send
            + Sync,
    {
        self.all_containers_of(account_id, collection, MetadataClass::Shared, cb)
            .await
    }

    pub async fn all_private_metadata_containers<CB>(
        &self,
        owner_id: u32,
        viewer_id: u32,
        collection: Collection,
        cb: CB,
    ) -> trc::Result<()>
    where
        CB: for<'x> FnMut(u32, MetadataView<'x>, StoredContainer) -> trc::Result<bool>
            + Send
            + Sync,
    {
        self.all_containers_of(
            owner_id,
            collection,
            MetadataClass::Private { viewer: viewer_id },
            cb,
        )
        .await
    }

    pub async fn metadata_container(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
    ) -> trc::Result<Option<MetadataBuf>> {
        self.core
            .storage
            .data
            .get_value(metadata_key(
                account_id,
                collection.into(),
                document_id,
                MetadataClass::Shared,
            ))
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .document_id(document_id)
            })
    }

    pub async fn private_metadata_container(
        &self,
        owner_id: u32,
        viewer_id: u32,
        collection: Collection,
        document_id: u32,
    ) -> trc::Result<Option<MetadataBuf>> {
        self.core
            .storage
            .data
            .get_value(metadata_key(
                owner_id,
                collection.into(),
                document_id,
                MetadataClass::Private { viewer: viewer_id },
            ))
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(owner_id)
                    .document_id(document_id)
            })
    }

    pub async fn all_metadata_viewers(
        &self,
        owner_id: u32,
    ) -> trc::Result<Vec<MetadataViewerEntry>> {
        let mut viewers = Vec::new();
        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    metadata_key(owner_id, 0, 0, MetadataClass::Viewer { viewer: 0 }),
                    metadata_key(
                        owner_id,
                        u8::MAX,
                        0,
                        MetadataClass::Viewer { viewer: u32::MAX },
                    ),
                ),
                |key, value| {
                    let (collection, viewer_id) = key
                        .len()
                        .checked_sub(U32_LEN + 1)
                        .and_then(|offset| key.get(offset..))
                        .and_then(|suffix| suffix.split_first())
                        .and_then(|(collection, viewer)| {
                            Some((*collection, u32::from_be_bytes(viewer.try_into().ok()?)))
                        })
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                    viewers.push(MetadataViewerEntry {
                        collection: Collection::from(collection),
                        viewer_id,
                        state: ViewerState::deserialize(value)?,
                    });
                    Ok(true)
                },
            )
            .await
            .add_context(|err| err.caused_by(trc::location!()).account_id(owner_id))?;
        Ok(viewers)
    }

    pub async fn metadata_owners(&self, viewer_id: u32) -> trc::Result<Vec<(u32, Collection)>> {
        let mut owners = Vec::new();
        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    metadata_key(viewer_id, 0, 0, MetadataClass::Owner { owner: 0 }),
                    metadata_key(
                        viewer_id,
                        u8::MAX,
                        0,
                        MetadataClass::Owner { owner: u32::MAX },
                    ),
                )
                .no_values(),
                |key, _| {
                    let (owner, collection) = parse_owner_key(key)?;
                    owners.push((owner, Collection::from(collection)));
                    Ok(true)
                },
            )
            .await
            .add_context(|err| err.caused_by(trc::location!()).account_id(viewer_id))?;
        Ok(owners)
    }

    async fn containers_of<I, CB>(
        &self,
        account_id: u32,
        collection: Collection,
        class: MetadataClass,
        documents: &I,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        I: DocumentSet + Send + Sync,
        CB: for<'x> FnMut(u32, MetadataView<'x>, StoredContainer) -> trc::Result<bool>
            + Send
            + Sync,
    {
        let collection = u8::from(collection);
        let mut scratch = Vec::new();
        let mut collect = |key: &[u8], value: &[u8]| {
            let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
            if documents.contains(document_id) {
                let view = StoredMetadata::view(value, &mut scratch)?;
                let stored = StoredContainer::new(&view, value)?;
                cb(document_id, view, stored)
            } else {
                Ok(true)
            }
        };
        self.iterate_documents(account_id, collection, class, documents, &mut collect)
            .await
    }

    async fn all_containers_of<CB>(
        &self,
        account_id: u32,
        collection: Collection,
        class: MetadataClass,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        CB: for<'x> FnMut(u32, MetadataView<'x>, StoredContainer) -> trc::Result<bool>
            + Send
            + Sync,
    {
        let collection = u8::from(collection);
        let mut scratch = Vec::new();
        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    metadata_key(account_id, collection, 0, class),
                    metadata_key(account_id, collection, u32::MAX, class),
                ),
                |key, value| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    let view = StoredMetadata::view(value, &mut scratch)?;
                    let stored = StoredContainer::new(&view, value)?;
                    cb(document_id, view, stored)
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
