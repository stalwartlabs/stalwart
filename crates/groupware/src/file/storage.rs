/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedFileNode, FileNode};
use crate::DestroyArchive;
use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use store::{
    ValueKey,
    write::{AlignedBytes, Archive, BatchBuilder, now},
};
use trc::AddContext;
use types::collection::{Collection, VanishedCollection};

impl FileNode {
    pub fn insert<'x>(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build node
        let mut node = self;
        let now = now() as i64;
        node.modified = now;
        node.created = now;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::FileNode)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(node)
                    .with_access_token(access_token),
            )
            .map(|b| b.commit_point())
    }
    pub fn update<'x>(
        self,
        access_token: &AccessToken,
        node: Archive<&ArchivedFileNode>,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build node
        let mut new_node = self;
        new_node.modified = now() as i64;
        batch
            .with_account_id(account_id)
            .with_collection(Collection::FileNode)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(node)
                    .with_changes(new_node)
                    .with_access_token(access_token),
            )
            .map(|b| b.commit_point())
    }
}

impl DestroyArchive<Archive<&ArchivedFileNode>> {
    pub fn delete(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
        path: String,
    ) -> trc::Result<()> {
        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::FileNode)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::<_, ()>::new()
                    .with_current(self.0)
                    .with_access_token(access_token),
            )?
            .log_vanished_item(VanishedCollection::FileNode, path)
            .commit_point();
        Ok(())
    }
}

impl DestroyArchive<Vec<u32>> {
    pub async fn delete(
        self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
        delete_path: Option<String>,
    ) -> trc::Result<()> {
        // Process deletions
        let mut batch = BatchBuilder::new();
        self.delete_batch(server, access_token, account_id, delete_path, &mut batch)
            .await?;
        // Write changes
        if !batch.is_empty() {
            server
                .commit_batch(batch)
                .await
                .caused_by(trc::location!())?;
        }

        Ok(())
    }

    pub async fn delete_batch(
        self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
        delete_path: Option<String>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        // Process deletions
        batch
            .with_account_id(account_id)
            .with_collection(Collection::FileNode);
        for document_id in self.0 {
            if let Some(node) = server
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::FileNode,
                    document_id,
                ))
                .await?
            {
                // Delete record
                batch
                    .with_document(document_id)
                    .custom(
                        ObjectIndexBuilder::<_, ()>::new()
                            .with_access_token(access_token)
                            .with_current(
                                node.to_unarchived::<FileNode>()
                                    .caused_by(trc::location!())?,
                            ),
                    )
                    .caused_by(trc::location!())?
                    .commit_point();
            }
        }

        if !batch.is_empty()
            && let Some(delete_path) = delete_path
        {
            batch.log_vanished_item(VanishedCollection::FileNode, delete_path);
        }

        Ok(())
    }
}
