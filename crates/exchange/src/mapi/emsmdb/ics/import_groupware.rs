/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    import::{ImportHeader, MoveOrder, move_versions},
    stream::Versions,
};
use crate::{
    ews::groupware::change_id_of,
    folders::FolderNode,
    groupware_write::WriteFailure,
    mapi::{
        emsmdb::{
            execute::{MailboxView, RopContext, RopError, RopResult},
            message::{
                edit::GroupwareContainer,
                groupware_import::PinnedRow,
                groupware_move::{GroupwareMove, GroupwareRoute},
            },
            staged::{ImportResolution, MessageImport, StagedMessage},
            state::{FolderObject, UNSAVED},
            store::StoreGuids,
        },
        ids::{ChangeSpace, IdSpace, MapiId},
    },
    store::{
        FolderRef,
        alias::{GroupwareAlias, GroupwareKind, set_groupware_alias},
    },
};
use common::cache::exchange::GroupwarePlacement;
use exchange_proto::{
    convert::model::MessageContent,
    ics::flags::ImportFlags,
    mapi::{
        ErrorCode,
        rop::{
            DecodedRop, requests::SynchronizationImportMessageMove,
            responses::SynchronizationImportMessageMoveResponse,
        },
    },
};
use std::sync::Arc;
use trc::AddContext;
use types::{field::Field, type_state::DataType};

#[derive(Clone, Copy)]
enum GroupwareImportTarget {
    Existing { document_id: u32, item: Option<u32> },
    New { item: Option<u32> },
}

impl RopContext<'_, '_> {
    pub(super) async fn import_groupware_change(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        (collector, folder): (u32, FolderObject),
        header: ImportHeader<'_>,
        flags: ImportFlags,
    ) -> RopResult {
        let folder_id = MapiId::from_counter(folder.counter).ok_or(ErrorCode::NOT_SUPPORTED)?;
        let Some(FolderNode::Stored(FolderRef {
            kind,
            id: container,
        })) = folder_id.to_node()
        else {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        };
        let groupware = GroupwareKind::from_folder(kind).ok_or(ErrorCode::NOT_SUPPORTED)?;
        let (data_type, change_space) = match groupware {
            GroupwareKind::Event => (DataType::CalendarEvent, ChangeSpace::Calendar),
            GroupwareKind::Contact => (DataType::ContactCard, ChangeSpace::AddressBook),
        };
        if !self.types.contains(data_type) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let space = IdSpace::of_groupware(groupware);
        let account_id = folder.mailbox_id;
        let view = self.mailbox(account_id).await?;
        let guids = StoreGuids::new(view.exchange.store_instance, account_id);
        let local = guids.local_id(header.source_key);
        let streamed = match local {
            Some(id) if id.space == IdSpace::Email => self
                .stream_aliases(collector)?
                .document(GroupwarePlacement {
                    folder: groupware.folder(container),
                    item: id.id,
                })
                .map(|document_id| MapiId::new(space, document_id)),
            _ => None,
        };
        let target = match local {
            Some(id) if id.space == space => {
                if !self.message_in_folder(account_id, folder_id, id).await? {
                    return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED));
                }
                GroupwareImportTarget::Existing {
                    document_id: id.id,
                    item: None,
                }
            }
            Some(id) if id.space == IdSpace::Email => {
                match streamed.or_else(|| view.stored_item(folder.counter, id)) {
                    Some(stored)
                        if self
                            .message_in_folder(account_id, folder_id, stored)
                            .await? =>
                    {
                        GroupwareImportTarget::Existing {
                            document_id: stored.id,
                            item: Some(id.id),
                        }
                    }
                    Some(_) => return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED)),
                    None if header.has_server_change(&guids) => {
                        return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED));
                    }
                    None if self.free_client_key(collector, &view, id.id).await? => {
                        GroupwareImportTarget::New { item: Some(id.id) }
                    }
                    None => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
                }
            }
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => GroupwareImportTarget::New { item: None },
        };
        let (version, resolution, stored_change) = match target {
            GroupwareImportTarget::Existing { document_id, .. } => {
                let (change_id, server) = self
                    .stored_versions(&view, (groupware, document_id), change_space, &guids)
                    .await?;
                let (version, resolution) = header.resolve(Some(&server.pcl()), flags)?;
                (version, resolution, Some(change_id))
            }
            GroupwareImportTarget::New { item: Some(_) } => {
                let (version, resolution) = header.resolve(None, flags)?;
                (version, resolution, None)
            }
            GroupwareImportTarget::New { item: None } => (
                header.resolve(None, flags)?.0,
                ImportResolution::ForeignKey,
                None,
            ),
        };
        let (base, item, message) = match target {
            GroupwareImportTarget::Existing { document_id, item } => {
                let stored = MapiId::new(space, document_id);
                let client = item.map_or(stored, |item| MapiId::new(IdSpace::Email, item));
                (Some(stored), None, client.counter())
            }
            GroupwareImportTarget::New { item } => (None, item, UNSAVED),
        };
        let mut staged = StagedMessage::new(Arc::new(MessageContent::default()), base, false);
        staged.import = Some(Box::new(MessageImport {
            collector,
            version,
            item,
            resolution,
            stored_change,
        }));
        self.stage_import(rop, index, folder, message, staged)
    }

    pub(super) async fn import_groupware_move(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        (collector, folder): (u32, FolderObject),
        source_folder: u64,
        request: &SynchronizationImportMessageMove<'_>,
    ) -> RopResult {
        let Some(FolderNode::Stored(FolderRef { kind, .. })) =
            MapiId::from_counter(source_folder).and_then(MapiId::to_node)
        else {
            return Err(RopError::Code(ErrorCode::NOT_FOUND));
        };
        let groupware = GroupwareKind::from_folder(kind).ok_or(ErrorCode::NOT_FOUND)?;
        let (data_type, change_space) = match groupware {
            GroupwareKind::Event => (DataType::CalendarEvent, ChangeSpace::Calendar),
            GroupwareKind::Contact => (DataType::ContactCard, ChangeSpace::AddressBook),
        };
        if !self.types.contains(data_type) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let (pcl, change_number) = move_versions(request)?;
        let account_id = folder.mailbox_id;
        let route = if self.in_deleted_items(account_id, folder.counter).await? {
            None
        } else {
            Some(
                GroupwareContainer::of(source_folder)
                    .zip(GroupwareContainer::of(folder.counter))
                    .and_then(|(from, to)| GroupwareRoute::between(from, to))
                    .ok_or(ErrorCode::NOT_SUPPORTED)?,
            )
        };
        let view = self.mailbox(account_id).await?;
        let guids = StoreGuids::new(view.exchange.store_instance, account_id);
        let space = IdSpace::of_groupware(groupware);
        let source = guids
            .local_id(request.source_message_id)
            .and_then(|id| view.stored_item(source_folder, id))
            .filter(|id| id.space == space)
            .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
        let given = guids
            .local_id(request.destination_message_id)
            .filter(|id| id.space == IdSpace::Email);
        let Some(route) = route else {
            if self
                .destroy_groupware_item(account_id, source_folder, source.id)
                .await?
            {
                return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED));
            }
            self.record_import_change(collector, None, given, (guids.replica, ChangeSpace::Email))?;
            return self.respond(rop, index, &SynchronizationImportMessageMoveResponse);
        };
        let target = given.ok_or(ErrorCode::INVALID_PARAM)?;
        let container = route.target();
        let placement = GroupwarePlacement {
            folder: groupware.folder(container),
            item: target.id,
        };
        if self
            .stream_aliases(collector)?
            .document(placement)
            .is_some()
            || !self.free_client_key(collector, &view, target.id).await?
        {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        let (_, server) = self
            .stored_versions(&view, (groupware, source.id), change_space, &guids)
            .await?;
        let server_pcl = server.pcl();
        let order = MoveOrder::of(&pcl, &server_pcl);
        let change_id = match self
            .move_groupware(account_id, route, &[source.id])
            .await?
            .first()
        {
            Some(GroupwareMove::Moved { change_id }) => *change_id,
            Some(GroupwareMove::Refused(failure)) => {
                return Err(RopError::Code(match failure {
                    WriteFailure::NotFound => ErrorCode::SYNC_OBJECT_DELETED,
                    WriteFailure::Forbidden => ErrorCode::ACCESS_DENIED,
                    WriteFailure::Conflict => ErrorCode::SYNC_CONFLICT,
                    WriteFailure::Invalid => ErrorCode::NOT_SUPPORTED,
                    WriteFailure::UidConflict => ErrorCode::DUPLICATE_NAME,
                    WriteFailure::Quota => ErrorCode::QUOTA_EXCEEDED,
                }));
            }
            None => return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED)),
        };
        set_groupware_alias(
            self.request.server,
            account_id,
            GroupwareAlias {
                kind: groupware,
                container,
                document_id: source.id,
                item: target.id,
            },
        )
        .await
        .caused_by(trc::location!())?;
        self.record_stream_alias(collector, source.id, placement)?;
        let version = order.resolved(
            pcl,
            (&change_number, request.change_number),
            (&server, &server_pcl),
        );
        if let Some(conflict) = version.stamped(
            change_id.and_then(|change_id| change_space.cn(change_id)),
            guids.replica,
        ) {
            self.pin_groupware_version(
                account_id,
                (groupware, source.id),
                change_id,
                (conflict, PinnedRow::Existing),
            )
            .await;
        }
        self.record_import_change(
            collector,
            change_id.filter(|_| !version.is_successor()),
            Some(target),
            (guids.replica, change_space),
        )?;
        self.respond(rop, index, &SynchronizationImportMessageMoveResponse)
    }

    async fn stored_versions(
        &self,
        view: &MailboxView,
        (groupware, document_id): (GroupwareKind, u32),
        change_space: ChangeSpace,
        guids: &StoreGuids,
    ) -> Result<(u64, Versions), RopError> {
        let mut change_id = None;
        self.request
            .server
            .archives(
                view.id,
                groupware.collection(),
                Field::ARCHIVE,
                &document_id,
                |_, archive| {
                    change_id = Some(change_id_of(archive.version));
                    Ok(false)
                },
            )
            .await
            .caused_by(trc::location!())?;
        let change_id = change_id.ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
        let cn = change_space
            .cn(change_id.max(1))
            .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
        let client = self
            .groupware_client(view, (groupware, document_id), change_id)
            .await?;
        Ok((change_id, Versions::of(client.as_ref(), cn, guids.replica)))
    }
}
