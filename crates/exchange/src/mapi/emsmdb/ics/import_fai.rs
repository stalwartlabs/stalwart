/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    import::{ImportHeader, MoveOrder},
    stream::Versions,
};
use crate::{
    mapi::{
        emsmdb::{
            access::ItemWrite,
            execute::{RopContext, RopError, RopResult},
            message::fai::fai_client,
            staged::{ImportResolution, MessageImport, StagedMessage},
            state::{FolderObject, UNSAVED},
            store::StoreGuids,
        },
        ids::{ChangeSpace, IdSpace, MapiId},
    },
    store::{
        folder::{ArchivedFaiMessage, FaiClientKey, FaiKind, FaiMessage, FolderStore},
        object::ConflictState,
    },
};
use exchange_proto::{
    convert::model::MessageContent,
    ics::{Pcl, flags::ImportFlags},
    ids::{ReplGuid, Xid},
    mapi::{
        ErrorCode,
        rop::{
            DecodedRop, requests::SynchronizationImportMessageMove,
            responses::SynchronizationImportMessageMoveResponse,
        },
    },
};
use std::sync::Arc;

#[derive(Clone, Copy)]
enum FaiImportTarget {
    Existing(u32),
    New(Option<u32>),
}

fn fai_versions(fai: &ArchivedFaiMessage, replica: ReplGuid) -> Result<Versions, RopError> {
    let cn = ChangeSpace::Exchange
        .cn(fai.change.to_native())
        .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
    Ok(Versions::of(fai_client(fai).as_ref(), cn, replica))
}

impl RopContext<'_, '_> {
    pub(super) async fn import_fai_change(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        (collector, folder): (u32, FolderObject),
        (header, flags): (ImportHeader<'_>, ImportFlags),
        kind: FaiKind,
    ) -> RopResult {
        let account_id = folder.mailbox_id;
        self.require_write(account_id, folder.counter, ItemWrite::Associated)
            .await?;
        let fai_folder = self.fai_target(account_id, folder.counter).await?;
        let view = self.mailbox(account_id).await?;
        let guids = StoreGuids::new(view.exchange.store_instance, account_id);
        let (id, key) = match guids.local_id(header.source_key) {
            Some(id) if id.space == IdSpace::Fai => (id.id, None),
            Some(id) if id.space == IdSpace::Email => {
                let key = FaiClientKey::new(id.id).ok_or(ErrorCode::INVALID_PARAM)?;
                (key.id(), Some(id.id))
            }
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => {
                let (version, _) = header.resolve(None, flags)?;
                return self.stage_fai_import(
                    rop,
                    index,
                    (collector, folder),
                    (FaiImportTarget::New(None), kind),
                    (version, ImportResolution::ForeignKey),
                );
            }
        };
        let server = self.request.server;
        let row = server.fai_message(account_id, fai_folder, id).await?;
        let (target, server_pcl) = match (&row, key) {
            (Some(row), _) => {
                let pcl = fai_versions(row.unarchive::<FaiMessage>()?, guids.replica)?.pcl();
                (FaiImportTarget::Existing(id), Some(pcl))
            }
            (None, None) => return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED)),
            (None, Some(_)) if header.has_server_change(&guids) => {
                return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED));
            }
            (None, Some(key)) if self.free_client_key(collector, &view, key).await? => {
                (FaiImportTarget::New(Some(key)), None)
            }
            (None, Some(_)) => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
        };
        let resolved = header.resolve(server_pcl.as_ref(), flags)?;
        self.stage_fai_import(rop, index, (collector, folder), (target, kind), resolved)
    }

    pub(super) async fn import_fai_move(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        (collector, folder): (u32, FolderObject),
        (source_folder, source): (u64, MapiId),
        request: &SynchronizationImportMessageMove<'_>,
        (pcl, change_number): (Pcl, Xid),
    ) -> RopResult {
        let id = source
            .from_client_fai()
            .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?
            .id;
        let account_id = folder.mailbox_id;
        if !self
            .write_allowed(account_id, source_folder, ItemWrite::Associated)
            .await?
        {
            return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED));
        }
        let from = self.fai_target(account_id, source_folder).await?;
        let row = self
            .request
            .server
            .fai_message(account_id, from, id)
            .await?
            .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
        self.require_write(account_id, folder.counter, ItemWrite::Associated)
            .await?;
        let to = self.fai_target(account_id, folder.counter).await?;
        let view = self.mailbox(account_id).await?;
        let guids = StoreGuids::new(view.exchange.store_instance, account_id);
        let server = fai_versions(row.unarchive::<FaiMessage>()?, guids.replica)?;
        let server_pcl = server.pcl();
        let order = MoveOrder::of(&pcl, &server_pcl);
        let key = match guids
            .local_id(request.destination_message_id)
            .filter(|id| id.space == IdSpace::Email)
        {
            Some(id) if self.free_client_key(collector, &view, id.id).await? => {
                Some(FaiClientKey::new(id.id).ok_or(ErrorCode::INVALID_PARAM)?)
            }
            Some(_) => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
            None => None,
        };
        let version = order.resolved(
            pcl,
            (&change_number, request.change_number),
            (&server, &server_pcl),
        );
        let (moved, change) = self
            .move_fai(
                account_id,
                (from, id),
                to,
                key,
                row,
                (&version, guids.replica),
            )
            .await?;
        self.record_fai_import_change(
            collector,
            (!version.is_successor()).then_some(change),
            key.map(|_| MapiId::new(IdSpace::Fai, moved)),
            guids.replica,
        )?;
        if matches!(order, MoveOrder::ClientNewer) {
            return Err(RopError::Code(ErrorCode::SYNC_CLIENT_CHANGE_NEWER));
        }
        self.respond(rop, index, &SynchronizationImportMessageMoveResponse)
    }

    fn stage_fai_import(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        (collector, folder): (u32, FolderObject),
        (target, kind): (FaiImportTarget, FaiKind),
        (version, resolution): (ConflictState, ImportResolution),
    ) -> RopResult {
        let (base, item, message) = match target {
            FaiImportTarget::Existing(id) => {
                let id = MapiId::new(IdSpace::Fai, id);
                (Some(id), None, id.counter())
            }
            FaiImportTarget::New(key) => (None, key, UNSAVED),
        };
        let mut staged = StagedMessage::new(
            Arc::new(MessageContent::default()),
            base,
            kind == FaiKind::Associated,
        );
        staged.import = Some(Box::new(MessageImport {
            collector,
            version,
            item,
            resolution,
            stored_change: None,
        }));
        self.stage_import(rop, index, folder, message, staged)
    }
}
