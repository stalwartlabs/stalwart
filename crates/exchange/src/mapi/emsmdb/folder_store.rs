/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    execute::{RopContext, RopError},
    folder_write::OpenFolder,
    message::object_row::decode_property,
    props::PropBag,
};
use crate::{
    cache::ExchangeCacheFetch,
    folders::{FolderNode, FolderWrites, SpecialFolder},
    store::{
        FolderKind, FolderRef,
        account::ExchangeAccountStore,
        account_key,
        folder::{SpecialFolderWrite, VirtualFolder, special_folder_class},
        named::AccountNamedProps,
        object::{
            ExchangeObject, ExchangeObjectStore, ExchangeObjectWrite, ObjectVersion, OwnerStamp,
        },
    },
};
use exchange_proto::mapi::{
    ErrorCode,
    prop::{NamedPropMap, PropKeyRef, PropTag, tags},
};
use store::write::{Archive, ArchiveBytes, BatchBuilder, PendingId, metadata::ExchangeClass};
use trc::{AddContext, EventType, LimitEvent};
use types::collection::{Collection, SyncCollection};

const MAX_ATTEMPTS: usize = 3;

pub(super) const FOLDER_COMPUTED: [PropTag; 22] = [
    tags::OBJECT_TYPE,
    tags::FOLDER_ID,
    tags::PARENT_FOLDER_ID,
    tags::ENTRY_ID,
    tags::PARENT_ENTRY_ID,
    tags::RECORD_KEY,
    tags::INSTANCE_KEY,
    tags::SOURCE_KEY,
    tags::PARENT_SOURCE_KEY,
    tags::CHANGE_KEY,
    tags::PREDECESSOR_CHANGE_LIST,
    tags::CHANGE_NUMBER,
    tags::FOLDER_TYPE,
    tags::SUBFOLDERS,
    tags::CONTENT_COUNT,
    tags::CONTENT_UNREAD_COUNT,
    tags::ASSOC_CONTENT_COUNT,
    tags::ACCESS,
    tags::ACCESS_LEVEL,
    tags::RIGHTS,
    tags::DELETED_COUNT_TOTAL,
    tags::HAS_RULES,
];

pub(super) enum RowEdit {
    Set(Vec<u8>, Vec<u8>),
    SetIfAbsent(Vec<u8>, Vec<u8>),
    Remove(Vec<u8>),
}

pub(super) fn is_folder_computed(tag: PropTag) -> bool {
    FOLDER_COMPUTED
        .iter()
        .any(|computed| computed.id() == tag.id())
}

#[derive(Clone, Copy)]
pub(super) enum RowTarget {
    Object(Collection, u32),
    Special(SpecialFolder),
}

#[derive(Clone, Copy)]
pub(super) enum PropTarget {
    Row(RowTarget),
    Virtual(u32),
}

impl PropTarget {
    pub(super) fn of(node: FolderNode) -> Option<Self> {
        match node {
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Virtual,
                id,
            }) => Some(PropTarget::Virtual(id)),
            node => RowTarget::of(node).map(PropTarget::Row),
        }
    }
}

impl RowTarget {
    pub(super) fn of(node: FolderNode) -> Option<Self> {
        match node {
            FolderNode::Special(special) => {
                special.is_fixed().then_some(RowTarget::Special(special))
            }
            node => folder_collection(node)
                .map(|(collection, document_id)| RowTarget::Object(collection, document_id)),
        }
    }
}

fn folder_collection(node: FolderNode) -> Option<(Collection, u32)> {
    match node {
        FolderNode::Stored(folder) => match folder.collection()? {
            Collection::FileNode => None,
            collection => Some((collection, folder.id)),
        },
        FolderNode::Special(_) => None,
    }
}

impl RopContext<'_, '_> {
    pub(super) async fn folder_row(
        &mut self,
        mailbox_id: u32,
        node: FolderNode,
    ) -> Result<Option<Archive<ArchiveBytes>>, RopError> {
        let server = self.request.server;
        match RowTarget::of(node) {
            Some(RowTarget::Object(collection, document_id)) => {
                if !self
                    .mailbox(mailbox_id)
                    .await?
                    .exchange
                    .has_object(collection, document_id)
                {
                    return Ok(None);
                }
                server
                    .exchange_object(mailbox_id, collection, document_id)
                    .await
            }
            Some(RowTarget::Special(folder)) => {
                server
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(account_key(
                        mailbox_id,
                        special_folder_class(folder),
                    ))
                    .await
            }
            None => return Ok(None),
        }
        .caused_by(trc::location!())
        .map_err(Into::into)
    }

    pub(super) async fn push_folder_row(
        &mut self,
        mailbox_id: u32,
        node: FolderNode,
        bag: &mut PropBag,
    ) -> Result<(), RopError> {
        let target = PropTarget::of(node);
        let row = match target {
            Some(PropTarget::Virtual(id)) => self
                .request
                .server
                .store()
                .get_value::<Archive<ArchiveBytes>>(account_key(
                    mailbox_id,
                    ExchangeClass::Folder { id },
                ))
                .await
                .caused_by(trc::location!())?,
            _ => self.folder_row(mailbox_id, node).await?,
        };
        let Some(row) = row else {
            return Ok(());
        };
        let exchange = self.mailbox(mailbox_id).await?.exchange;
        let named = AccountNamedProps::new(&exchange);
        let properties = match target {
            Some(PropTarget::Virtual(_)) => &row.unarchive::<VirtualFolder>()?.properties,
            _ => &row.unarchive::<ExchangeObject>()?.properties,
        };
        for property in properties.iter() {
            let Some((key, value)) =
                decode_property(property.key.as_slice(), property.value.as_slice())
            else {
                continue;
            };
            let id = match key.as_ref() {
                PropKeyRef::Tag(id) => Some(id),
                key => named.id(key),
            };
            if let Some(id) = id {
                let tag = PropTag::new(id, value.ptype());
                if !bag.contains(tag) && !is_folder_computed(tag) {
                    bag.push_owned(tag, &value);
                }
            }
        }
        Ok(())
    }

    pub(super) async fn edit_folder_row(
        &mut self,
        folder: OpenFolder,
        edits: &[RowEdit],
    ) -> Result<(), RopError> {
        let mailbox_id = folder.mailbox_id;
        let server = self.request.server;
        let target = match PropTarget::of(folder.node).ok_or(ErrorCode::NOT_SUPPORTED)? {
            PropTarget::Row(target) => target,
            PropTarget::Virtual(_) => {
                let written = server
                    .folder_edit_properties(
                        self.request.access_token,
                        mailbox_id,
                        folder.node,
                        |object| apply_edits(object, edits),
                    )
                    .await?;
                return match written {
                    Ok(written) => {
                        if written.change_id.is_some() {
                            self.invalidate_mailbox();
                        }
                        Ok(())
                    }
                    Err(err) => Err(RopError::Code(err.into())),
                };
            }
        };
        let owner = server
            .exchange_quota_owner(self.request.access_token, mailbox_id)
            .await?;
        for _ in 0..MAX_ATTEMPTS {
            let previous = self.folder_row(mailbox_id, folder.node).await?;
            let mut next = previous
                .as_ref()
                .map(|previous| previous.deserialize::<ExchangeObject>())
                .transpose()?
                .unwrap_or_default();
            if !apply_edits(&mut next, edits) {
                return Ok(());
            }
            let mut batch = BatchBuilder::new();
            let max_size = server.core.exchange.max_object_size;
            let written = match target {
                RowTarget::Object(collection, document_id) => ExchangeObjectWrite {
                    owner,
                    collection,
                    document_id: PendingId::Assigned(document_id),
                    stamp: OwnerStamp::Logged,
                    version: ObjectVersion::Server,
                    previous: previous.as_ref(),
                    next: Some(next),
                    max_size,
                }
                .build(&mut batch),
                RowTarget::Special(special) => SpecialFolderWrite {
                    owner,
                    folder: special,
                    previous: previous.as_ref(),
                    next: (!next.is_empty()).then_some(next),
                    max_size,
                }
                .build(&mut batch),
            };
            match written {
                Ok(()) => {}
                Err(err) if err.matches(EventType::Limit(LimitEvent::SizeRequest)) => {
                    return Err(RopError::Code(ErrorCode::QUOTA_EXCEEDED));
                }
                Err(err) => return Err(err.into()),
            }
            if let RowTarget::Object(collection, document_id) = target {
                batch
                    .with_account_id(mailbox_id)
                    .with_collection(collection)
                    .with_document(document_id)
                    .log_container_update(SyncCollection::from(collection));
            }
            let committed = server.commit_batch(batch).await;
            if let RowTarget::Object(..) = target {
                server.mark_exchange_stale(mailbox_id);
                self.invalidate_mailbox();
            }
            match committed {
                Ok(_) => return Ok(()),
                Err(err) if err.is_assertion_failure() => continue,
                Err(err) => return Err(err.caused_by(trc::location!()).into()),
            }
        }
        Err(RopError::Code(ErrorCode::OBJECT_MODIFIED))
    }
}

fn apply_edits(object: &mut ExchangeObject, edits: &[RowEdit]) -> bool {
    let mut changed = false;
    for edit in edits {
        match edit {
            RowEdit::Set(key, value) => {
                if object.property(key) != Some(value.as_slice()) {
                    object.set_property(key.clone(), value.clone());
                    changed = true;
                }
            }
            RowEdit::SetIfAbsent(key, value) => {
                if object.property(key).is_none() {
                    object.set_property(key.clone(), value.clone());
                    changed = true;
                }
            }
            RowEdit::Remove(key) => changed |= object.remove_property(key).is_some(),
        }
    }
    changed
}
