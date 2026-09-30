/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, storage::metadata::StoredContainer};
use store::{roaring::RoaringBitmap, write::metadata::MetadataBuf};
use types::{collection::Collection, metadata::MetadataView};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MetadataContainers {
    containers: Vec<(u32, MetadataBuf)>,
}

impl MetadataContainers {
    pub async fn load(
        server: &Server,
        account_id: u32,
        collection: Collection,
        documents: &RoaringBitmap,
    ) -> trc::Result<Self> {
        let mut containers = Vec::new();
        if !documents.is_empty() {
            server
                .metadata_containers(account_id, collection, documents, collect(&mut containers))
                .await?;
        }
        Ok(MetadataContainers::new(containers))
    }

    pub async fn load_private(
        server: &Server,
        owner_id: u32,
        private_viewer: Option<u32>,
        collection: Collection,
        documents: &RoaringBitmap,
    ) -> trc::Result<Self> {
        let mut containers = Vec::new();
        if let Some(viewer_id) = private_viewer
            && !documents.is_empty()
        {
            server
                .private_metadata_containers(
                    owner_id,
                    viewer_id,
                    collection,
                    documents,
                    collect(&mut containers),
                )
                .await?;
        }
        Ok(MetadataContainers::new(containers))
    }

    pub fn new(mut containers: Vec<(u32, MetadataBuf)>) -> Self {
        if !containers.is_sorted_by_key(|(document_id, _)| *document_id) {
            containers.sort_unstable_by_key(|(document_id, _)| *document_id);
        }
        MetadataContainers { containers }
    }

    pub fn get(&self, document_id: u32) -> Option<&MetadataBuf> {
        self.containers
            .binary_search_by_key(&document_id, |(document_id, _)| *document_id)
            .ok()
            .and_then(|position| self.containers.get(position))
            .map(|(_, container)| container)
    }

    pub fn is_empty(&self) -> bool {
        self.containers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.containers.len()
    }
}

fn collect(
    containers: &mut Vec<(u32, MetadataBuf)>,
) -> impl for<'x> FnMut(u32, MetadataView<'x>, StoredContainer) -> trc::Result<bool> + Send + Sync + '_
{
    |document_id, view, stored| {
        containers.push((
            document_id,
            MetadataBuf::from_view(&view, stored.size, stored.hash),
        ));
        Ok(true)
    }
}
