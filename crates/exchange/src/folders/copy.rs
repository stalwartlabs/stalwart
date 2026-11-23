/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FolderContents, FolderCreate, FolderEntry, FolderNode, FolderTree, FolderWriteError,
    FolderWrites, FolderWritten, WritableFolder, access::ViewRights,
};
use crate::{
    cache::ExchangeCacheFetch,
    mail::{CommitOutcome, CopyOutcome, MailEdits},
    store::{
        FolderKind, FolderRef, QuotaOwner,
        account::{ExchangeAccountStore, ExchangeCounter},
        folder::{FaiFolder, FaiMessage, FaiNext, FaiWrite, FolderStore},
        object::ObjectVersion,
    },
};
use common::{Server, auth::AccessToken};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    mailbox::JUNK_ID,
};
use store::write::{BatchBuilder, serialize::rkyv_deserialize};
use trc::AddContext;

const MAX_FAI_ATTEMPTS: usize = 3;
const MAX_EDIT_ATTEMPTS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FolderCopyError {
    Folder(FolderWriteError),
    MailboxLimit,
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyDepth {
    Folder,
    Subtree,
}

#[derive(Clone, Copy)]
pub(crate) enum CopyScope<'x> {
    Everything,
    Readable(&'x ViewRights),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyCompletion {
    Full,
    Partial,
}

pub(crate) struct FolderCopy<'x> {
    pub server: &'x Server,
    pub access_token: &'x AccessToken,
    pub session_id: u64,
    pub account_id: u32,
    pub scope: CopyScope<'x>,
}

impl CopyScope<'_> {
    fn copies(self, node: FolderNode) -> bool {
        match self {
            CopyScope::Everything => true,
            CopyScope::Readable(rights) => rights.of(node).reads_items(),
        }
    }
}

pub(crate) fn copy_source(node: FolderNode) -> Option<u32> {
    match node {
        FolderNode::Stored(FolderRef {
            kind: FolderKind::Mailbox,
            id,
        }) if id != JUNK_ID => Some(id),
        _ => None,
    }
}

impl FolderCopy<'_> {
    pub(crate) async fn copy(
        &self,
        tree: &FolderTree,
        entry: &FolderEntry,
        from: u32,
        to: FolderNode,
        name: &str,
        depth: CopyDepth,
    ) -> trc::Result<Result<(FolderWritten, CopyCompletion), FolderCopyError>> {
        let root = match self.create(entry, name, to).await? {
            Ok(root) => root,
            Err(err) => return Ok(Err(FolderCopyError::Folder(err))),
        };
        let filled = self.fill(tree, entry, (from, root.folder), depth).await;
        if !matches!(filled, Ok(Ok(_))) {
            self.discard(root.folder).await;
        }
        Ok(filled?.map(|completion| (root, completion)))
    }

    async fn fill(
        &self,
        tree: &FolderTree,
        entry: &FolderEntry,
        root: (u32, FolderRef),
        depth: CopyDepth,
    ) -> trc::Result<Result<CopyCompletion, FolderCopyError>> {
        let mut copies = vec![root];
        let mut completion = CopyCompletion::Full;
        if depth == CopyDepth::Subtree {
            let mut ancestors = vec![(entry.node, Some(FolderNode::Stored(root.1)))];
            for child in tree.descendants(entry.node) {
                while ancestors
                    .last()
                    .is_some_and(|(node, _)| Some(*node) != child.parent)
                {
                    ancestors.pop();
                }
                let parent = ancestors.last().and_then(|(_, copy)| *copy);
                let copy = match (parent, copy_source(child.node)) {
                    (Some(parent), Some(from)) if self.scope.copies(child.node) => {
                        match self.create(child, &child.name, parent).await? {
                            Ok(written) => {
                                copies.push((from, written.folder));
                                Some(FolderNode::Stored(written.folder))
                            }
                            Err(err) => return Ok(Err(FolderCopyError::Folder(err))),
                        }
                    }
                    (Some(_), Some(_)) => {
                        completion = CopyCompletion::Partial;
                        None
                    }
                    _ => None,
                };
                ancestors.push((child.node, copy));
            }
        }

        let owner = self
            .server
            .exchange_quota_owner(self.access_token, self.account_id)
            .await?;
        for (from, to) in copies {
            if let Err(err) = self.copy_messages(from, to.id).await? {
                return Ok(Err(err));
            }
            if !copy_fai(self.server, owner, from, to).await? {
                return Ok(Err(FolderCopyError::Folder(FolderWriteError::Conflict)));
            }
        }
        Ok(Ok(completion))
    }

    async fn create(
        &self,
        entry: &FolderEntry,
        name: &str,
        parent: FolderNode,
    ) -> trc::Result<Result<FolderWritten, FolderWriteError>> {
        self.server
            .folder_create(
                self.access_token,
                self.account_id,
                FolderCreate {
                    kind: WritableFolder::Mailbox,
                    parent,
                    name,
                    class: Some(entry.class.as_str()),
                    search: None,
                    client_key: None,
                },
            )
            .await
    }

    async fn copy_messages(&self, from: u32, to: u32) -> trc::Result<Result<(), FolderCopyError>> {
        let limits = &self.server.core.email.limits;
        let mut cache = self.server.get_cached_messages(self.account_id).await?;
        for _ in 0..MAX_EDIT_ATTEMPTS {
            if cache.in_mailbox(from).any(|message| {
                if message.has_mailbox_id(to) {
                    return false;
                }
                let count = message.mailboxes().len();
                limits
                    .validate_mailbox_change(count, count.saturating_add(1))
                    .is_err()
            }) {
                return Ok(Err(FolderCopyError::MailboxLimit));
            }
            let mut edits = MailEdits::new(self.account_id);
            for message in cache.in_mailbox(from) {
                let document_id = message.document_id();
                let Some(data) = cache.message_data(document_id) else {
                    continue;
                };
                if let CopyOutcome::MailboxLimit =
                    edits.copy_to(limits, document_id, data, from, to)?
                {
                    return Ok(Err(FolderCopyError::MailboxLimit));
                }
            }
            match edits
                .commit(self.server, self.access_token, self.session_id)
                .await?
            {
                CommitOutcome::Committed(_) => return Ok(Ok(())),
                CommitOutcome::Conflict => {
                    cache = self.server.get_cached_messages(self.account_id).await?;
                }
            }
        }
        Ok(Err(FolderCopyError::Conflict))
    }

    async fn discard(&self, root: FolderRef) {
        if let Err(err) = self
            .server
            .folder_destroy(
                self.access_token,
                self.account_id,
                FolderNode::Stored(root),
                FolderContents::Remove,
            )
            .await
        {
            trc::error!(err.caused_by(trc::location!()));
        }
    }
}

async fn copy_fai(
    server: &Server,
    owner: QuotaOwner,
    from: u32,
    to: FolderRef,
) -> trc::Result<bool> {
    let account_id = owner.account_id;
    let source = FaiFolder::from(FolderRef {
        kind: FolderKind::Mailbox,
        id: from,
    });
    let target = FaiFolder::from(to);
    let max_size = server.core.exchange.max_object_size;
    let mut messages = Vec::new();
    for _ in 0..MAX_FAI_ATTEMPTS {
        messages.clear();
        server
            .fai_messages(account_id, source, |_, message| {
                messages.push(rkyv_deserialize::<_, FaiMessage>(message)?);
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
        if messages.is_empty() {
            return Ok(true);
        }
        let count = u32::try_from(messages.len()).map_err(|_| fai_exhausted())?;
        let reservation = server
            .reserve_exchange_ids(
                account_id,
                [
                    (ExchangeCounter::Fai, count),
                    (ExchangeCounter::Change, count),
                ],
            )
            .await?;
        let [first_id, first_change] = reservation.ids();
        let mut batch = BatchBuilder::new();
        reservation.seal(&mut batch);
        for ((mut message, id), change) in messages.drain(..).zip(first_id..).zip(first_change..) {
            let id = u32::try_from(id).map_err(|_| fai_exhausted())?;
            message.change = change;
            FaiWrite {
                owner,
                folder: target,
                id,
                version: ObjectVersion::Server,
                previous: None,
                next: FaiNext::Live(message),
                max_size,
            }
            .build(&mut batch)?;
            batch.commit_point();
        }
        match server.commit_batch(batch).await {
            Ok(_) => {
                server.mark_exchange_stale(account_id);
                return Ok(true);
            }
            Err(err) if err.is_assertion_failure() => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
    Ok(false)
}

#[cold]
fn fai_exhausted() -> trc::Error {
    trc::StoreEvent::UnexpectedError
        .into_err()
        .details("FAI id space exhausted.")
        .caused_by(trc::location!())
}
