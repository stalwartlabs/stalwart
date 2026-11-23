/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    fai::{FaiRowFilter, holds_normal_fai_rows},
    groupware_move::{GroupwareMove, GroupwareRoute},
    save::MailContainer,
};
use crate::{
    eas::folder_sync::MAX_STATE_ATTEMPTS,
    folders::{FolderContents, FolderNode, FolderWrites, SpecialFolder, access::ViewRights},
    groupware_write::{WriteFailure, card_failure, event_failure},
    mail::{AccountCategories, CommitOutcome, MailEdits},
    mail_copy::{Copied, CopyOrigin, MailCopier},
    mapi::{
        emsmdb::{
            access::ItemWrite,
            execute::{RopContext, RopError, RopResult},
            folder::folder_data_type,
            state::{ServerObject, mail_container},
        },
        ids::{IdSpace, MapiId},
    },
    store::{FolderKind, FolderRef, folder::FaiClientKey, object::ObjectVersion},
};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess};
use exchange_proto::{
    ids::Eid,
    mapi::{
        ErrorCode,
        rop::{
            DecodedRop,
            requests::MoveCopyMessages,
            responses::{
                DeleteMessagesResponse, EmptyFolderResponse,
                HardDeleteMessagesAndSubfoldersResponse, HardDeleteMessagesResponse,
                MoveCopyMessagesResponse,
            },
            views::EidArray,
        },
    },
};
use groupware::{
    cache::GroupwareCache,
    calendar::write::{EventWriter, ItipMode},
    contact::write::CardWriter,
};
use smallvec::SmallVec;
use std::mem;
use trc::{AddContext, EventType};
use types::{collection::SyncCollection, type_state::DataType};

const MAX_EDIT_BATCH: usize = 512;

#[derive(Clone, Copy)]
enum MailOp {
    Remove { from: u32 },
    Move { from: u32, to: u32 },
}

impl MailOp {
    fn from(self) -> u32 {
        match self {
            MailOp::Remove { from } | MailOp::Move { from, .. } => from,
        }
    }

    fn done(self, mailboxes: Option<(bool, bool)>) -> bool {
        match (self, mailboxes) {
            (MailOp::Remove { .. }, None) => true,
            (MailOp::Remove { .. }, Some((in_from, _))) => !in_from,
            (MailOp::Move { .. }, Some((in_from, in_to))) => in_to && !in_from,
            (_, None) => false,
        }
    }

    fn to(self) -> Option<u32> {
        match self {
            MailOp::Remove { .. } => None,
            MailOp::Move { to, .. } => Some(to),
        }
    }
}

#[derive(Default)]
struct CopyTally {
    partial: bool,
    over_quota: bool,
    failure: Option<trc::Error>,
}

impl CopyTally {
    fn count(&mut self, copies: impl Iterator<Item = (usize, Copied)>, session_id: u64) {
        for (_, copied) in copies {
            match copied {
                Copied::Created { .. } => {}
                Copied::NotFound | Copied::CommitFailed => self.partial = true,
                Copied::OverQuota => {
                    self.partial = true;
                    self.over_quota = true;
                }
                Copied::Rejected(err) => {
                    if !matches!(
                        err.as_ref(),
                        EventType::Limit(_) | EventType::MessageIngest(_)
                    ) {
                        trc::error!(err.span_id(session_id));
                    }
                    self.partial = true;
                }
                Copied::Failed(err) => match &self.failure {
                    Some(_) => {
                        trc::error!(err.span_id(session_id));
                    }
                    None => self.failure = Some(err),
                },
            }
        }
    }

    fn stopped(&self) -> bool {
        self.over_quota || self.failure.is_some()
    }
}

#[derive(Clone, Copy)]
pub(in crate::mapi::emsmdb) enum GroupwareContainer {
    Calendar(u32),
    AddressBook(u32),
}

impl GroupwareContainer {
    pub(in crate::mapi::emsmdb) fn of(folder: u64) -> Option<Self> {
        match MapiId::from_counter(folder).and_then(MapiId::to_node) {
            Some(FolderNode::Stored(FolderRef {
                kind: FolderKind::Calendar,
                id,
            })) => Some(GroupwareContainer::Calendar(id)),
            Some(FolderNode::Stored(FolderRef {
                kind: FolderKind::AddressBook,
                id,
            })) => Some(GroupwareContainer::AddressBook(id)),
            _ => None,
        }
    }

    fn space(self) -> IdSpace {
        match self {
            GroupwareContainer::Calendar(_) => IdSpace::Event,
            GroupwareContainer::AddressBook(_) => IdSpace::Contact,
        }
    }

    fn data_type(self) -> DataType {
        match self {
            GroupwareContainer::Calendar(_) => DataType::CalendarEvent,
            GroupwareContainer::AddressBook(_) => DataType::ContactCard,
        }
    }
}

#[derive(Clone, Copy)]
struct SourceFolder {
    mailbox_id: u32,
    counter: u64,
}

#[derive(Default)]
struct Selection {
    emails: Vec<u32>,
    fai: Vec<u32>,
    normal_fai: Vec<u32>,
    groupware: Vec<u32>,
    partial: bool,
}

impl RopContext<'_, '_> {
    pub async fn delete_messages(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        message_ids: &EidArray<'_>,
    ) -> RopResult {
        let partial_completion = self.remove_messages(rop, message_ids).await?;
        self.respond(rop, index, &DeleteMessagesResponse { partial_completion })
    }

    pub async fn hard_delete_messages(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        message_ids: &EidArray<'_>,
    ) -> RopResult {
        let partial_completion = self.remove_messages(rop, message_ids).await?;
        self.respond(
            rop,
            index,
            &HardDeleteMessagesResponse { partial_completion },
        )
    }

    pub async fn empty_folder(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        associated: bool,
    ) -> RopResult {
        let partial_completion = self.clear_folder(rop, associated).await?;
        self.respond(rop, index, &EmptyFolderResponse { partial_completion })
    }

    pub async fn hard_delete_messages_and_subfolders(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        associated: bool,
    ) -> RopResult {
        let partial_completion = self.clear_folder(rop, associated).await?;
        self.respond(
            rop,
            index,
            &HardDeleteMessagesAndSubfoldersResponse { partial_completion },
        )
    }

    pub async fn move_copy_messages(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &MoveCopyMessages<'_>,
    ) -> RopResult {
        let source = self.source_folder(rop.header.input_handle)?;
        let dest_handle = self
            .input(request.dest_handle_index)
            .map_err(|_| ErrorCode::DST_NULL_OBJECT)?;
        let dest = match self.state.get(dest_handle) {
            Some(ServerObject::Folder(folder)) if folder.mailbox_id == source.mailbox_id => {
                folder.counter
            }
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::DST_NULL_OBJECT)),
        };
        let Some(to) = mail_container(dest) else {
            if let Some(route) = GroupwareContainer::of(source.counter)
                .zip(GroupwareContainer::of(dest))
                .and_then(|(from, to)| GroupwareRoute::between(from, to))
                .filter(|_| !request.want_copy)
            {
                return self
                    .move_groupware_messages(rop, index, source, route, request)
                    .await;
            }
            return Err(RopError::Code(
                match MapiId::from_counter(dest).and_then(MapiId::to_node) {
                    Some(FolderNode::Stored(FolderRef {
                        kind: FolderKind::Virtual,
                        ..
                    })) => ErrorCode::SEARCH_FOLDER,
                    _ => ErrorCode::NOT_SUPPORTED,
                },
            ));
        };
        let mut selection = self.select(source, request.message_ids.iter()).await?;
        let mut partial = selection.partial || !selection.fai.is_empty();
        match mail_container(source.counter) {
            Some(from) if from == to && !request.want_copy => {}
            Some(from) => {
                let source_allowed = if request.want_copy {
                    self.items_readable(source).await?
                } else {
                    self.write_allowed(source.mailbox_id, source.counter, ItemWrite::Delete)
                        .await?
                };
                let allowed = source_allowed
                    && self
                        .write_allowed(source.mailbox_id, dest, ItemWrite::Create)
                        .await?;
                if allowed && request.want_copy {
                    partial |= self
                        .copy_mail(source.mailbox_id, &mut selection.emails, from, to)
                        .await?;
                } else if allowed {
                    partial |= self
                        .apply_mail_op(
                            source.mailbox_id,
                            &mut selection.emails,
                            MailOp::Move { from, to },
                        )
                        .await?;
                } else {
                    partial |= !selection.emails.is_empty();
                }
            }
            None => partial |= !selection.emails.is_empty(),
        }
        let in_place = !request.want_copy && mail_container(source.counter) == Some(to);
        if !selection.normal_fai.is_empty() && !in_place {
            let allowed = self.types.contains(DataType::Email)
                && self
                    .write_allowed(source.mailbox_id, dest, ItemWrite::Create)
                    .await?
                && if request.want_copy {
                    self.items_readable(source).await?
                } else {
                    self.write_allowed(source.mailbox_id, source.counter, ItemWrite::Associated)
                        .await?
                };
            if allowed {
                let filed = self
                    .file_normal_fai(source, to, &mut selection.normal_fai)
                    .await;
                if !request.want_copy {
                    partial |= match self.remove_fai(source, &mut selection.normal_fai).await {
                        Err(RopError::Code(_)) => true,
                        removed => removed?,
                    };
                }
                partial |= filed?;
            } else {
                partial = true;
            }
        }
        if !selection.groupware.is_empty() {
            partial |=
                if !request.want_copy && self.in_deleted_items(source.mailbox_id, dest).await? {
                    self.destroy_groupware(source, &mut selection.groupware)
                        .await?
                } else {
                    true
                };
        }
        self.respond(
            rop,
            index,
            &MoveCopyMessagesResponse {
                partial_completion: partial,
            },
        )
    }

    async fn move_groupware_messages(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        source: SourceFolder,
        route: GroupwareRoute,
        request: &MoveCopyMessages<'_>,
    ) -> RopResult {
        let mut selection = self.select(source, request.message_ids.iter()).await?;
        selection.groupware.sort_unstable();
        selection.groupware.dedup();
        let refused = self
            .move_groupware(source.mailbox_id, route, &selection.groupware)
            .await?
            .iter()
            .any(|moved| matches!(moved, GroupwareMove::Refused(_)));
        let partial = refused
            || selection.partial
            || !selection.fai.is_empty()
            || !selection.normal_fai.is_empty()
            || !selection.emails.is_empty();
        self.respond(
            rop,
            index,
            &MoveCopyMessagesResponse {
                partial_completion: partial,
            },
        )
    }

    async fn remove_messages(
        &mut self,
        rop: &DecodedRop<'_>,
        message_ids: &EidArray<'_>,
    ) -> Result<bool, RopError> {
        let source = self.source_folder(rop.header.input_handle)?;
        self.remove_selected(source, message_ids.iter()).await
    }

    pub(in crate::mapi::emsmdb) async fn remove_message_ids(
        &mut self,
        mailbox_id: u32,
        counter: u64,
        message_ids: &[Eid],
    ) -> Result<bool, RopError> {
        self.remove_selected(
            SourceFolder {
                mailbox_id,
                counter,
            },
            message_ids.iter().copied(),
        )
        .await
    }

    async fn remove_selected(
        &mut self,
        source: SourceFolder,
        message_ids: impl Iterator<Item = Eid>,
    ) -> Result<bool, RopError> {
        let mut selection = self.select(source, message_ids).await?;
        let mut partial = selection.partial;
        if !selection.emails.is_empty() {
            match mail_container(source.counter) {
                Some(from)
                    if self
                        .write_allowed(source.mailbox_id, source.counter, ItemWrite::Delete)
                        .await? =>
                {
                    partial |= self
                        .apply_mail_op(
                            source.mailbox_id,
                            &mut selection.emails,
                            MailOp::Remove { from },
                        )
                        .await?;
                }
                Some(_) => partial = true,
                None => partial = true,
            }
        }
        if !selection.groupware.is_empty() {
            partial |= self
                .destroy_groupware(source, &mut selection.groupware)
                .await?;
        }
        selection.fai.append(&mut selection.normal_fai);
        partial |= self.remove_fai(source, &mut selection.fai).await?;
        Ok(partial)
    }

    async fn file_normal_fai(
        &mut self,
        source: SourceFolder,
        to: u32,
        ids: &mut Vec<u32>,
    ) -> Result<bool, RopError> {
        let folder = self.fai_target(source.mailbox_id, source.counter).await?;
        let mut exchange = self.mailbox(source.mailbox_id).await?.exchange;
        let mut pending = mem::take(ids);
        pending.sort_unstable();
        pending.dedup();
        let mut partial = false;
        for id in pending {
            let Some(content) = self
                .normal_fai_content(source.mailbox_id, folder, id)
                .await?
            else {
                partial = true;
                continue;
            };
            let created = match self
                .create_mail_content(
                    &content,
                    MailContainer {
                        mailbox_id: source.mailbox_id,
                        container: to,
                        store_instance: exchange.store_instance,
                    },
                    AccountCategories::new(&exchange),
                    ObjectVersion::Server,
                    None,
                )
                .await
            {
                Ok(created) => created,
                Err(RopError::Code(_)) => {
                    partial = true;
                    continue;
                }
                Err(err) => return Err(err),
            };
            ids.push(id);
            if created.respelled {
                self.invalidate_mailbox();
                exchange = self.mailbox(source.mailbox_id).await?.exchange;
            }
        }
        if !ids.is_empty() {
            self.invalidate_mailbox();
        }
        Ok(partial)
    }

    async fn items_readable(&mut self, source: SourceFolder) -> Result<bool, RopError> {
        match self
            .require_folder_items(source.mailbox_id, source.counter)
            .await
        {
            Ok(()) => Ok(true),
            Err(RopError::Code(ErrorCode::ACCESS_DENIED)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    async fn remove_fai(
        &mut self,
        source: SourceFolder,
        ids: &mut Vec<u32>,
    ) -> Result<bool, RopError> {
        if ids.is_empty() {
            return Ok(false);
        }
        if !self
            .write_allowed(source.mailbox_id, source.counter, ItemWrite::Associated)
            .await?
        {
            return Ok(true);
        }
        match self
            .delete_fai_ids(source.mailbox_id, source.counter, ids)
            .await
        {
            Err(RopError::Code(ErrorCode::NOT_FOUND)) => Ok(true),
            result => result,
        }
    }

    async fn clear_folder(
        &mut self,
        rop: &DecodedRop<'_>,
        associated: bool,
    ) -> Result<bool, RopError> {
        let source = self.source_folder(rop.header.input_handle)?;
        let node = MapiId::from_counter(source.counter)
            .and_then(MapiId::to_node)
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let subfolders = match node {
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                ..
            }) => true,
            FolderNode::Special(
                SpecialFolder::Root | SpecialFolder::IpmSubtree | SpecialFolder::Finder,
            )
            | FolderNode::Stored(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            FolderNode::Special(_) => false,
        };
        let container = mail_container(source.counter);
        if container.is_some() && !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let tree = self.folder_tree(source.mailbox_id).await?;
        let entry = tree.get(node).ok_or(ErrorCode::OBJECT_DELETED)?;
        let fai_rows = if associated {
            Some(FaiRowFilter::All)
        } else if holds_normal_fai_rows(entry) {
            Some(FaiRowFilter::Normal)
        } else {
            None
        };
        let mut partial = false;
        let mut granted = [false; 2];
        for ((needed, write), allowed) in [
            (container.is_some(), ItemWrite::Delete),
            (fai_rows.is_some(), ItemWrite::Associated),
        ]
        .into_iter()
        .zip(granted.iter_mut())
        {
            if needed {
                match self
                    .require_node_write(source.mailbox_id, node, write)
                    .await
                {
                    Err(RopError::Code(ErrorCode::ACCESS_DENIED)) => partial = true,
                    result => {
                        result?;
                        *allowed = true;
                    }
                }
            }
        }
        let [delete_allowed, associated_allowed] = granted;
        let container = container.filter(|_| delete_allowed);
        if partial && container.is_none() && !associated_allowed {
            return Ok(true);
        }
        let mut children = SmallVec::<[FolderNode; 8]>::new();
        if subfolders && delete_allowed {
            for entry in tree.children(node) {
                if entry.special.is_none()
                    && folder_data_type(entry.node)
                        .is_some_and(|data_type| self.types.contains(data_type))
                {
                    children.push(entry.node);
                } else {
                    partial = true;
                }
            }
        }
        if let Some(from) = container {
            let mut emails = self
                .request
                .server
                .get_cached_messages(source.mailbox_id)
                .await
                .caused_by(trc::location!())?
                .in_mailbox(from)
                .map(|message| message.document_id())
                .collect::<Vec<_>>();
            partial |= self
                .apply_mail_op(source.mailbox_id, &mut emails, MailOp::Remove { from })
                .await?;
        }
        if let Some(filter) = fai_rows.filter(|_| associated_allowed) {
            partial |= match self
                .clear_fai(source.mailbox_id, source.counter, filter)
                .await
            {
                Err(RopError::Code(ErrorCode::NOT_FOUND)) => false,
                result => result?,
            };
        }
        let request = self.request;
        for child in children {
            let result = request
                .server
                .folder_destroy(
                    request.access_token,
                    source.mailbox_id,
                    child,
                    FolderContents::Remove,
                )
                .await;
            match result {
                Ok(result) => partial |= result.is_err(),
                Err(err) => {
                    self.invalidate_mailbox();
                    return Err(err.into());
                }
            }
        }
        self.invalidate_mailbox();
        Ok(partial)
    }

    fn source_folder(&self, input_handle: u8) -> Result<SourceFolder, RopError> {
        let handle = self.input(input_handle)?;
        let folder = match self.state.get(handle) {
            Some(ServerObject::Folder(folder)) => SourceFolder {
                mailbox_id: folder.mailbox_id,
                counter: folder.counter,
            },
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        Ok(folder)
    }

    async fn select(
        &mut self,
        source: SourceFolder,
        message_ids: impl Iterator<Item = Eid>,
    ) -> Result<Selection, RopError> {
        let mut selection = Selection::default();
        let mail = self.types.contains(DataType::Email);
        let container = mail_container(source.counter);
        let groupware = GroupwareContainer::of(source.counter)
            .filter(|groupware| self.types.contains(groupware.data_type()));
        let view = match (container, groupware) {
            (Some(_), _) if mail => Some(self.mailbox(source.mailbox_id).await?),
            (None, Some(_)) => Some(self.mailbox(source.mailbox_id).await?),
            _ => None,
        };
        for eid in message_ids {
            match MapiId::from_eid(eid) {
                Some(id) if id.space == IdSpace::Fai => selection.fai.push(id.id),
                Some(id) if groupware.is_some_and(|groupware| groupware.space() == id.space) => {
                    selection.groupware.push(id.id);
                }
                Some(id) if id.space == IdSpace::Email && groupware.is_some() => {
                    match (
                        view.as_ref()
                            .and_then(|view| view.stored_item(source.counter, id)),
                        FaiClientKey::new(id.id),
                    ) {
                        (Some(stored), _) => selection.groupware.push(stored.id),
                        (None, Some(key)) => selection.normal_fai.push(key.id()),
                        (None, None) => selection.partial = true,
                    }
                }
                Some(id) if id.space == IdSpace::Email => {
                    let document = view.as_ref().zip(container).and_then(|(view, container)| {
                        let document = view.email_document(container, id.id);
                        view.messages
                            .as_ref()
                            .and_then(|messages| messages.email_by_id(&document))
                            .is_some_and(|item| item.has_mailbox_id(container))
                            .then_some(document)
                    });
                    match (document, FaiClientKey::new(id.id)) {
                        (Some(document), _) => selection.emails.push(document),
                        (None, Some(key)) if container.is_none() || view.is_some() => {
                            selection.normal_fai.push(key.id());
                        }
                        _ => selection.partial = true,
                    }
                }
                _ => selection.partial = true,
            }
        }
        Ok(selection)
    }

    pub(in crate::mapi::emsmdb) async fn in_deleted_items(
        &mut self,
        mailbox_id: u32,
        folder: u64,
    ) -> Result<bool, RopError> {
        let Some(node) = MapiId::from_counter(folder).and_then(MapiId::to_node) else {
            return Ok(false);
        };
        let tree = self.folder_tree(mailbox_id).await?;
        Ok(tree
            .special(SpecialFolder::DeletedItems)
            .is_some_and(|trash| tree.in_subtree(trash.node, node)))
    }

    pub(in crate::mapi::emsmdb) async fn destroy_groupware_item(
        &mut self,
        mailbox_id: u32,
        folder: u64,
        document_id: u32,
    ) -> Result<bool, RopError> {
        self.destroy_groupware(
            SourceFolder {
                mailbox_id,
                counter: folder,
            },
            &mut vec![document_id],
        )
        .await
    }

    async fn destroy_groupware(
        &mut self,
        source: SourceFolder,
        documents: &mut Vec<u32>,
    ) -> Result<bool, RopError> {
        let Some(container) = GroupwareContainer::of(source.counter) else {
            return Ok(true);
        };
        documents.sort_unstable();
        documents.dedup();
        let before = documents.len();
        let server = self.request.server;
        let access_token = self.request.access_token;
        let account_id = source.mailbox_id;
        let mut partial = false;
        match container {
            GroupwareContainer::AddressBook(address_book) => {
                let resources = server
                    .fetch_groupware_resources(account_id, account_id, SyncCollection::AddressBook)
                    .await
                    .caused_by(trc::location!())?;
                let writer = CardWriter {
                    server,
                    access_token,
                    account_id,
                    resources: &resources,
                };
                for &document_id in documents.iter() {
                    let Some(path) =
                        resources.format_resource_path_by_parent(document_id, address_book)
                    else {
                        partial = true;
                        continue;
                    };
                    let mut done = false;
                    for _ in 0..MAX_STATE_ATTEMPTS {
                        let deleted = match writer.prepare_delete(address_book, document_id).await {
                            Ok(deletion) => writer.delete(deletion, Some(path.clone())).await,
                            Err(err) => Err(err),
                        };
                        let failure = match deleted {
                            Ok(()) => {
                                done = true;
                                break;
                            }
                            Err(err) => card_failure(err)?,
                        };
                        if failure != WriteFailure::Conflict {
                            break;
                        }
                    }
                    partial |= !done;
                }
            }
            GroupwareContainer::Calendar(calendar) => {
                let resources = server
                    .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
                    .await
                    .caused_by(trc::location!())?;
                let rights = self.view_rights(account_id).await?;
                documents.retain(|document_id| !rights.hides(&resources, *document_id));
                partial |= documents.len() < before;
                let account_info = server
                    .account_info(account_id)
                    .await
                    .caused_by(trc::location!())?;
                let writer = EventWriter {
                    server,
                    access_token,
                    account_id,
                    resources: &resources,
                    account_info: &account_info,
                };
                let sees_all = matches!(rights, ViewRights::Owner | ViewRights::Member);
                for &document_id in documents.iter() {
                    let Some(path) =
                        resources.format_resource_path_by_parent(document_id, calendar)
                    else {
                        partial |= !sees_all || resources.item_by_id(document_id).is_some();
                        continue;
                    };
                    let mut done = false;
                    for _ in 0..MAX_STATE_ATTEMPTS {
                        let deleted = match writer.prepare_delete(calendar, document_id).await {
                            Ok(deletion) => {
                                writer
                                    .delete(deletion, None, ItipMode::Suppress, Some(path.clone()))
                                    .await
                            }
                            Err(err) => Err(err),
                        };
                        let failure = match deleted {
                            Ok(()) => {
                                done = true;
                                break;
                            }
                            Err(err) => event_failure(err)?,
                        };
                        if failure != WriteFailure::Conflict {
                            break;
                        }
                    }
                    partial |= !done;
                }
            }
        }
        self.invalidate_mailbox();
        Ok(partial)
    }

    async fn copy_mail(
        &mut self,
        account_id: u32,
        documents: &mut Vec<u32>,
        from: u32,
        to: u32,
    ) -> Result<bool, RopError> {
        let server = self.request.server;
        let cache = server
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        if !cache.has_mailbox_id(&to) {
            return Err(RopError::Code(ErrorCode::OBJECT_DELETED));
        }
        documents.sort_unstable();
        documents.dedup();
        let mut copier = MailCopier::new(
            server,
            self.request.access_token,
            account_id,
            self.session_id(),
        )
        .await?;
        let session_id = self.session_id();
        let mut tally = CopyTally::default();
        for (slot, &document_id) in documents.iter().enumerate() {
            let origin = CopyOrigin { document_id, from };
            copier.copy(&cache, origin, to, slot).await;
            tally.count(copier.settled(), session_id);
            if tally.stopped() {
                break;
            }
        }
        copier.finish(&cache).await;
        tally.count(copier.settled(), session_id);
        self.invalidate_mailbox();
        match tally.failure {
            Some(err) => Err(err.into()),
            None => Ok(tally.partial),
        }
    }

    async fn apply_mail_op(
        &mut self,
        mailbox_id: u32,
        documents: &mut Vec<u32>,
        op: MailOp,
    ) -> Result<bool, RopError> {
        let server = self.request.server;
        let access_token = self.request.access_token;
        let session_id = self.session_id();
        let from = op.from();
        let mut cache = server
            .get_cached_messages(mailbox_id)
            .await
            .caused_by(trc::location!())?;
        if op.to().is_some_and(|to| !cache.has_mailbox_id(&to)) {
            return Err(RopError::Code(ErrorCode::OBJECT_DELETED));
        }
        documents.sort_unstable();
        documents.dedup();
        let before = documents.len();
        documents.retain(|document_id| {
            cache
                .email_by_id(document_id)
                .is_some_and(|item| item.has_mailbox_id(from))
        });
        let mut partial = documents.len() != before;
        for chunk in documents.chunks(MAX_EDIT_BATCH) {
            let mut done = false;
            for _ in 0..MAX_STATE_ATTEMPTS {
                if op.to().is_some_and(|to| !cache.has_mailbox_id(&to)) {
                    break;
                }
                let mut edits = MailEdits::new(mailbox_id);
                let mut failed = false;
                for &document_id in chunk {
                    let mailboxes = cache.email_by_id(&document_id).map(|item| {
                        (
                            item.has_mailbox_id(from),
                            op.to().is_some_and(|to| item.has_mailbox_id(to)),
                        )
                    });
                    let data = cache
                        .message_data(document_id)
                        .filter(|_| mailboxes.is_some_and(|(in_from, _)| in_from));
                    let Some(data) = data.filter(|_| !op.done(mailboxes)) else {
                        failed |= !op.done(mailboxes);
                        continue;
                    };
                    failed |= match op {
                        MailOp::Remove { from } => !edits.remove_from(document_id, data, from)?,
                        MailOp::Move { from, to } => !edits.move_to(document_id, data, from, to)?,
                    };
                }
                match edits.commit(server, access_token, session_id).await? {
                    CommitOutcome::Committed(_) => {
                        self.invalidate_mailbox();
                        partial |= failed;
                        done = true;
                        break;
                    }
                    CommitOutcome::Conflict => {
                        cache = server
                            .get_cached_messages(mailbox_id)
                            .await
                            .caused_by(trc::location!())?;
                    }
                }
            }
            partial |= !done;
        }
        Ok(partial)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/message/edit/tests.rs"]
mod tests;
