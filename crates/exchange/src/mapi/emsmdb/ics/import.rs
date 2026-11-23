/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::stream::Versions;
use crate::{
    eas::folder_sync::MAX_STATE_ATTEMPTS,
    folders::FolderNode,
    mail::{CommitOutcome, MailEdits},
    mapi::{
        emsmdb::{
            access::ItemWrite,
            execute::{MailboxView, RopContext, RopError, RopResult},
            message::{fai::holds_normal_fai_rows, load::ClientVersion},
            staged::{ImportResolution, MessageImport, StagedMessage, StagedObject},
            state::{
                FolderObject, MessageObject, RecipientColumns, ServerObject, UNSAVED,
                mail_container,
            },
            store::StoreGuids,
        },
        ids::{ChangeNumber, ChangeSpace, IdSpace, MapiId},
    },
    store::{
        FolderKind, FolderRef,
        folder::FaiKind,
        object::{ConflictState, ObjectVersion, StoredPlacement},
    },
};
use common::cache::exchange::Placement;
use email::cache::{email::MessageCacheAccess, mailbox::MailboxCacheAccess};
use exchange_proto::{
    convert::{model::MessageContent, tags::message_flags},
    ics::{Pcl, PclOrder, SyncKind, flags::ImportFlags},
    ids::{Gid, ReplGuid, Xid},
    mapi::{
        ErrorCode,
        prop::{OwnedPropValue, PropKey, PropValue, tags},
        rop::{
            DecodedRop,
            requests::{SynchronizationImportMessageChange, SynchronizationImportMessageMove},
            responses::{
                SynchronizationImportMessageChangeResponse,
                SynchronizationImportMessageMoveResponse,
            },
        },
    },
};
use std::sync::Arc;
use types::type_state::DataType;

const KNOWN_IMPORT_FLAGS: u8 = ImportFlags::ASSOCIATED | ImportFlags::FAIL_ON_CONFLICT;

pub(super) struct ImportHeader<'x> {
    pub(super) source_key: &'x [u8],
    change_key: &'x [u8],
    pcl: Pcl,
}

#[derive(Clone, Copy)]
pub(super) enum MoveOrder {
    Same,
    ClientNewer,
    ServerNewer,
}

pub(in crate::mapi::emsmdb) enum MoveVersion {
    Kept(ConflictState),
    Successor(Pcl),
}

impl MoveVersion {
    pub(in crate::mapi::emsmdb) fn stamped(
        &self,
        change: Option<ChangeNumber>,
        replica: ReplGuid,
    ) -> Option<ConflictState> {
        match self {
            MoveVersion::Kept(conflict) => Some(conflict.clone()),
            MoveVersion::Successor(pcl) => {
                change.map(|change| Versions::merged(change.xid(replica), pcl.clone()).conflict())
            }
        }
    }

    pub(super) fn is_successor(&self) -> bool {
        matches!(self, MoveVersion::Successor(_))
    }
}

impl MoveOrder {
    pub(super) fn of(pcl: &Pcl, server: &Pcl) -> Self {
        match pcl.compare(server) {
            PclOrder::OlderOrEqual if pcl.includes(server) => MoveOrder::Same,
            PclOrder::Newer => MoveOrder::ClientNewer,
            PclOrder::OlderOrEqual | PclOrder::Conflict => MoveOrder::ServerNewer,
        }
    }

    pub(super) fn resolved(
        self,
        mut pcl: Pcl,
        (change_number, change_key): (&Xid, &[u8]),
        (server, server_pcl): (&Versions, &Pcl),
    ) -> MoveVersion {
        pcl.merge(change_number);
        match self {
            MoveOrder::ClientNewer => MoveVersion::Kept(server.conflict()),
            MoveOrder::ServerNewer => {
                pcl.merge_pcl(server_pcl);
                MoveVersion::Successor(pcl)
            }
            MoveOrder::Same => {
                let mut encoded = Vec::with_capacity(pcl.encoded_len());
                pcl.encode(&mut encoded);
                MoveVersion::Kept(ConflictState {
                    change_key: change_key.to_vec(),
                    pcl: encoded,
                })
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ImportTarget {
    Existing { item: u32, document_id: u32 },
    New { item: Option<u32> },
}

impl<'x> ImportHeader<'x> {
    fn parse(request: &SynchronizationImportMessageChange<'x>) -> Option<Self> {
        let mut values = request.property_values.iter();
        let (
            Some((source_tag, PropValue::Binary(source_key))),
            Some((time_tag, PropValue::Time(_))),
            Some((key_tag, PropValue::Binary(change_key))),
            Some((pcl_tag, PropValue::Binary(pcl))),
            None,
        ) = (
            values.next(),
            values.next(),
            values.next(),
            values.next(),
            values.next(),
        )
        else {
            return None;
        };
        if source_tag.id() != tags::SOURCE_KEY.id()
            || time_tag.id() != tags::LAST_MODIFICATION_TIME.id()
            || key_tag.id() != tags::CHANGE_KEY.id()
            || pcl_tag.id() != tags::PREDECESSOR_CHANGE_LIST.id()
        {
            return None;
        }
        let change = Xid::decode(change_key)?;
        Gid::from_wire(source_key)?;
        let mut pcl = Pcl::decode(pcl).ok().filter(|pcl| !pcl.is_empty())?;
        pcl.merge(&change);
        Some(ImportHeader {
            source_key,
            change_key,
            pcl,
        })
    }

    pub(super) fn has_server_change(&self, guids: &StoreGuids) -> bool {
        self.pcl
            .xids()
            .iter()
            .any(|xid| xid.namespace == guids.replica.0)
    }

    pub(super) fn resolve(
        self,
        server: Option<&Pcl>,
        flags: ImportFlags,
    ) -> Result<(ConflictState, ImportResolution), RopError> {
        let (pcl, resolution) = match server.map(|server| (self.pcl.compare(server), server)) {
            None | Some((PclOrder::Newer, _)) => (self.pcl, ImportResolution::Newer),
            Some((PclOrder::OlderOrEqual, _)) => {
                return Err(RopError::Code(ErrorCode::SYNC_IGNORE));
            }
            Some((PclOrder::Conflict, _)) if flags.contains(ImportFlags::FAIL_ON_CONFLICT) => {
                return Err(RopError::Code(ErrorCode::SYNC_CONFLICT));
            }
            Some((PclOrder::Conflict, server)) => {
                let mut merged = self.pcl;
                merged.merge_pcl(server);
                (merged, ImportResolution::Merged)
            }
        };
        let mut encoded = Vec::with_capacity(pcl.encoded_len());
        pcl.encode(&mut encoded);
        Ok((
            ConflictState {
                change_key: self.change_key.to_vec(),
                pcl: encoded,
            },
            resolution,
        ))
    }
}

impl RopContext<'_, '_> {
    pub async fn synchronization_import_message_change(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &SynchronizationImportMessageChange<'_>,
    ) -> RopResult {
        let (collector, folder) = self.collector(rop, SyncKind::Contents)?;
        let flags = request.import_flag;
        if flags.0 & !KNOWN_IMPORT_FLAGS != 0 {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        let header = ImportHeader::parse(request).ok_or(ErrorCode::INVALID_PARAM)?;
        let index = request.output_handle_index;
        if flags.contains(ImportFlags::ASSOCIATED) {
            return self
                .import_fai_change(
                    rop,
                    index,
                    (collector, folder),
                    (header, flags),
                    FaiKind::Associated,
                )
                .await;
        }
        let Some(container) = mail_container(folder.counter) else {
            return if self
                .holds_normal_fai(folder.mailbox_id, folder.counter)
                .await?
            {
                self.import_fai_change(
                    rop,
                    index,
                    (collector, folder),
                    (header, flags),
                    FaiKind::Normal,
                )
                .await
            } else {
                self.import_groupware_change(rop, index, (collector, folder), header, flags)
                    .await
            };
        };
        if !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let account_id = folder.mailbox_id;
        let view = self.mailbox(account_id).await?;
        let guids = StoreGuids::new(view.exchange.store_instance, account_id);
        let target = match guids.local_id(header.source_key) {
            Some(id) if id.space == IdSpace::Email => {
                let live = view
                    .client_document(container, id.id)
                    .zip(view.messages.as_ref())
                    .and_then(|(document_id, messages)| {
                        messages
                            .email_by_id(&document_id)
                            .map(|item| (document_id, item))
                    });
                match live {
                    Some((document_id, item)) if item.has_mailbox_id(container) => {
                        ImportTarget::Existing {
                            item: id.id,
                            document_id,
                        }
                    }
                    Some(_) => return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED)),
                    None if header.has_server_change(&guids) => {
                        return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED));
                    }
                    None if self
                        .free_client_item(collector, &view, container, id.id)
                        .await? =>
                    {
                        ImportTarget::New { item: Some(id.id) }
                    }
                    None => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
                }
            }
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => ImportTarget::New { item: None },
        };
        let (version, resolution) = match target {
            ImportTarget::Existing { document_id, .. } => {
                let server = self.server_version(&view, document_id, &guids).await?.pcl();
                header.resolve(Some(&server), flags)?
            }
            ImportTarget::New { item: Some(_) } => header.resolve(None, flags)?,
            ImportTarget::New { item: None } => {
                (header.resolve(None, flags)?.0, ImportResolution::ForeignKey)
            }
        };
        let (base, item, message) = match target {
            ImportTarget::Existing { item, .. } => {
                let id = MapiId::new(IdSpace::Email, item);
                (Some(id), None, id.counter())
            }
            ImportTarget::New { item } => (None, item, UNSAVED),
        };
        let mut content = MessageContent::default();
        if base.is_none() {
            content.props.set(
                PropKey::tag(tags::MESSAGE_FLAGS.id()),
                OwnedPropValue::I32(message_flags::READ),
            );
        }
        let mut staged = StagedMessage::new(Arc::new(content), base, false);
        staged.import = Some(Box::new(MessageImport {
            collector,
            version,
            item,
            resolution,
            stored_change: None,
        }));
        self.stage_import(rop, index, folder, message, staged)
    }

    pub(super) fn stage_import(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        folder: FolderObject,
        message: u64,
        staged: StagedMessage,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let (logon_id, _) = self
            .state
            .logon_of(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        let staged_id = self.state.allocate_staged();
        self.staged()
            .insert(staged_id, StagedObject::Message(Box::new(staged)), 0)?;
        let handle = self.state.insert(
            logon_id,
            ServerObject::Message(Box::new(MessageObject {
                mailbox_id: folder.mailbox_id,
                folder: folder.counter,
                message,
                code_page: self.code_page().0,
                path: Vec::new(),
                staged: Some(staged_id),
                recipient_columns: RecipientColumns::Unannounced,
            })),
        )?;
        self.set_output(index, handle)?;
        self.respond(rop, index, &SynchronizationImportMessageChangeResponse)
    }
}

pub(super) fn move_versions(
    request: &SynchronizationImportMessageMove<'_>,
) -> Result<(Pcl, Xid), RopError> {
    let change_number = Xid::decode(request.change_number).ok_or(ErrorCode::INVALID_PARAM)?;
    let pcl = Pcl::decode(request.predecessor_change_list)
        .ok()
        .filter(|pcl| !pcl.is_empty())
        .ok_or(ErrorCode::INVALID_PARAM)?;
    Gid::from_wire(request.destination_message_id).ok_or(ErrorCode::INVALID_PARAM)?;
    Ok((pcl, change_number))
}

impl RopContext<'_, '_> {
    async fn holds_normal_fai(&mut self, mailbox_id: u32, folder: u64) -> Result<bool, RopError> {
        match MapiId::from_counter(folder).and_then(MapiId::to_node) {
            Some(
                node @ (FolderNode::Special(_)
                | FolderNode::Stored(FolderRef {
                    kind: FolderKind::Virtual,
                    ..
                })),
            ) => Ok(self
                .folder_tree(mailbox_id)
                .await?
                .get(node)
                .is_some_and(holds_normal_fai_rows)),
            _ => Ok(false),
        }
    }

    pub async fn synchronization_import_message_move(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SynchronizationImportMessageMove<'_>,
    ) -> RopResult {
        let (collector, folder) = self.collector(rop, SyncKind::Contents)?;
        let account_id = folder.mailbox_id;
        let view = self.mailbox(account_id).await?;
        let guids = StoreGuids::new(view.exchange.store_instance, account_id);
        let source_folder = guids
            .folder_node(&view.exchange, request.source_folder_id)
            .map(|node| MapiId::from_node(node).counter())
            .ok_or(ErrorCode::NOT_FOUND)?;
        let outbox_mirror = match (
            MapiId::from_counter(source_folder),
            guids.local_id(request.source_message_id),
        ) {
            (Some(outbox), Some(source)) => self.outbox_mirror(account_id, outbox, source).await?,
            _ => None,
        };
        if mail_container(source_folder).is_none() && outbox_mirror.is_none() {
            if self.holds_normal_fai(account_id, source_folder).await?
                && self.holds_normal_fai(account_id, folder.counter).await?
            {
                let versions = move_versions(request)?;
                let source = guids
                    .local_id(request.source_message_id)
                    .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
                return self
                    .import_fai_move(
                        rop,
                        index,
                        (collector, folder),
                        (source_folder, source),
                        request,
                        versions,
                    )
                    .await;
            }
            return self
                .import_groupware_move(rop, index, (collector, folder), source_folder, request)
                .await;
        }
        let to = mail_container(folder.counter).ok_or(ErrorCode::NOT_SUPPORTED)?;
        if !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let (pcl, change_number) = move_versions(request)?;
        let from = match outbox_mirror {
            Some(mirror) => mirror,
            None => mail_container(source_folder).ok_or(ErrorCode::NOT_FOUND)?,
        };
        let source = guids
            .local_id(request.source_message_id)
            .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
        let email = Some(source)
            .filter(|id| id.space == IdSpace::Email)
            .and_then(|id| view.client_document(from, id.id))
            .zip(view.messages.as_ref())
            .and_then(|(document_id, messages)| {
                messages
                    .email_by_id(&document_id)
                    .map(|item| (document_id, item))
            });
        let document_id = match email {
            Some((document_id, item)) if item.has_mailbox_id(from) => document_id,
            Some(_) => {
                self.require_node_write(
                    account_id,
                    FolderNode::Stored(FolderRef {
                        kind: FolderKind::Mailbox,
                        id: from,
                    }),
                    ItemWrite::Delete,
                )
                .await?;
                return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED));
            }
            None => {
                return self
                    .import_fai_move(
                        rop,
                        index,
                        (collector, folder),
                        (source_folder, source),
                        request,
                        (pcl, change_number),
                    )
                    .await;
            }
        };
        let realias = outbox_mirror.is_some() && from == to;
        if from == to && !realias {
            return self.respond(rop, index, &SynchronizationImportMessageMoveResponse);
        }
        let server = self.server_version(&view, document_id, &guids).await?;
        let server_pcl = server.pcl();
        let order = MoveOrder::of(&pcl, &server_pcl);
        let alias = match guids
            .local_id(request.destination_message_id)
            .filter(|id| id.space == IdSpace::Email)
        {
            Some(id) if outbox_mirror.is_some() && id.id == source.id => Some(id.id),
            Some(id) if self.free_client_item(collector, &view, to, id.id).await? => Some(id.id),
            Some(_) => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
            None => None,
        };
        let (document_id, item, moved) = if realias {
            let moved = match alias.filter(|item| *item != source.id) {
                Some(item) => {
                    self.alias_imported(
                        account_id,
                        document_id,
                        StoredPlacement {
                            container: to,
                            item,
                        },
                    )
                    .await?
                }
                None => None,
            };
            (document_id, alias.unwrap_or(source.id), moved)
        } else {
            let (document_id, moved) = self
                .move_imported(account_id, (from, source.id), to, alias)
                .await?;
            (document_id, alias.unwrap_or(document_id), moved)
        };
        let item = Some(MapiId::new(IdSpace::Email, item));
        let version = order.resolved(
            pcl,
            (&change_number, request.change_number),
            (&server, &server_pcl),
        );
        let change = match version.stamped(
            moved.and_then(|change| ChangeSpace::Email.cn(change)),
            guids.replica,
        ) {
            Some(conflict) => Some(
                self.write_import_row(
                    account_id,
                    document_id,
                    ObjectVersion::Client(conflict),
                    None,
                )
                .await?,
            ),
            None => None,
        };
        self.record_import_change(
            collector,
            change.filter(|_| !version.is_successor()),
            item,
            (guids.replica, ChangeSpace::Email),
        )?;
        if matches!(order, MoveOrder::ClientNewer) {
            return Err(RopError::Code(ErrorCode::SYNC_CLIENT_CHANGE_NEWER));
        }
        self.respond(rop, index, &SynchronizationImportMessageMoveResponse)
    }

    async fn move_imported(
        &mut self,
        account_id: u32,
        (from, item): (u32, u32),
        to: u32,
        alias: Option<u32>,
    ) -> Result<(u32, Option<u64>), RopError> {
        for (folder, write) in [(from, ItemWrite::Delete), (to, ItemWrite::Create)] {
            self.require_node_write(
                account_id,
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Mailbox,
                    id: folder,
                }),
                write,
            )
            .await?;
        }
        let server = self.request.server;
        let access_token = self.request.access_token;
        for _ in 0..MAX_STATE_ATTEMPTS {
            let view = self.mailbox(account_id).await?;
            let messages = view.messages.as_ref().ok_or(ErrorCode::ACCESS_DENIED)?;
            if !messages.has_mailbox_id(&to) {
                return Err(RopError::Code(ErrorCode::OBJECT_DELETED));
            }
            let document_id = view.email_document(from, item);
            let data = messages
                .email_by_id(&document_id)
                .filter(|item| item.has_mailbox_id(from))
                .and_then(|_| messages.message_data(document_id))
                .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
            let mut edits = MailEdits::new(account_id);
            let moved = match alias {
                Some(alias) => edits.move_to_alias(document_id, data, from, to, alias)?,
                None => edits.move_to(document_id, data, from, to)?,
            };
            if !moved {
                return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED));
            }
            match edits
                .commit(server, access_token, self.session_id())
                .await?
            {
                CommitOutcome::Committed(change) => {
                    self.invalidate_mailbox();
                    return Ok((document_id, change));
                }
                CommitOutcome::Conflict => self.invalidate_mailbox(),
            }
        }
        Err(RopError::Code(ErrorCode::OBJECT_MODIFIED))
    }

    async fn alias_imported(
        &mut self,
        account_id: u32,
        document_id: u32,
        alias: StoredPlacement,
    ) -> Result<Option<u64>, RopError> {
        self.require_node_write(
            account_id,
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                id: alias.container,
            }),
            ItemWrite::Create,
        )
        .await?;
        for _ in 0..MAX_STATE_ATTEMPTS {
            let view = self.mailbox(account_id).await?;
            let data = view
                .messages
                .as_ref()
                .and_then(|messages| messages.message_data(document_id))
                .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
            let mut edits = MailEdits::new(account_id);
            if !edits.alias_in(document_id, &data, alias)? {
                return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED));
            }
            let outcome = edits
                .commit(
                    self.request.server,
                    self.request.access_token,
                    self.session_id(),
                )
                .await?;
            self.invalidate_mailbox();
            if let CommitOutcome::Committed(change) = outcome {
                return Ok(change);
            }
        }
        Err(RopError::Code(ErrorCode::OBJECT_MODIFIED))
    }

    pub(super) async fn server_version(
        &mut self,
        view: &MailboxView,
        document_id: u32,
        guids: &StoreGuids,
    ) -> Result<Versions, RopError> {
        let change_id = view
            .messages
            .as_ref()
            .and_then(|messages| messages.email_by_id(&document_id))
            .map(|item| item.change_id())
            .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
        let cn = ChangeSpace::Email
            .cn(change_id)
            .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
        let client = match self.object_row(view.id, document_id).await? {
            Some(archive) => ClientVersion::read(&archive, change_id)?,
            None => None,
        };
        Ok(Versions::of(client.as_ref(), cn, guids.replica))
    }

    pub(super) async fn free_client_key(
        &mut self,
        collector: u32,
        view: &MailboxView,
        key: u32,
    ) -> Result<bool, RopError> {
        let live = view
            .messages
            .as_ref()
            .is_some_and(|messages| messages.email_by_id(&key).is_some());
        if live
            || view.exchange.alias_of(key).is_some()
            || view.exchange.resolve_folder_key(key).is_some()
            || view
                .exchange
                .aliased
                .keys()
                .any(|placement| placement.item == key)
        {
            return Ok(false);
        }
        self.below_id_counter(collector, view.id, key).await
    }

    async fn free_client_item(
        &mut self,
        collector: u32,
        view: &MailboxView,
        container: u32,
        item: u32,
    ) -> Result<bool, RopError> {
        let live = view
            .client_document(container, item)
            .zip(view.messages.as_ref())
            .is_some_and(|(document_id, messages)| messages.email_by_id(&document_id).is_some());
        if live
            || view
                .exchange
                .resolve_alias(Placement { container, item })
                .is_some()
            || view.exchange.resolve_folder_key(item).is_some()
        {
            return Ok(false);
        }
        self.below_id_counter(collector, view.id, item).await
    }
}
