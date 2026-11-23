/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    RANGE_CHARGE, SyncConfig, SyncContext, SyncPhase, TagFilter, TransferContext, state_charge,
};
use crate::{
    folders::{FolderContents, FolderNode, FolderWriteError, FolderWrites},
    mapi::{
        emsmdb::{
            access::ViewRights,
            execute::{RopContext, RopError, RopResult},
            read_flags::{ReadChange, ReadScope, ReadTargets},
            state::{FolderObject, ServerObject, TransferKind, mail_container},
            store::StoreGuids,
        },
        ids::{ChangeNumber, ChangeSpace, IdSpace, MapiId},
    },
};
use common::cache::exchange::{ExchangeAccountCache, GroupwareAliases, GroupwarePlacement};
use email::cache::email::MessageCacheAccess;
use exchange_proto::{
    ics::{IcsLimits, IcsState, IdSet, ReplKey, StateUpload, SyncKind, fx::StringMode},
    ids::{Eid, Gid, ReplGuid, ReplId},
    mapi::{
        ErrorCode,
        prop::{MvType, PropValue},
        rop::{
            DecodedRop,
            requests::{
                GetLocalReplicaIds, SynchronizationImportDeletes,
                SynchronizationImportReadStateChanges, SynchronizationOpenCollector,
            },
            responses::GetLocalReplicaIdsResponse,
        },
    },
};
use smallvec::SmallVec;
use store::{
    ValueKey,
    write::{BatchBuilder, ValueClass},
};
use trc::AddContext;
use types::{collection::Collection, type_state::DataType};

const MAX_LOCAL_REPLICA_IDS: u32 = 0x10000;
const MAX_DOCUMENT_ID: i64 = 1 << 31;
const DELEGATE_DOCUMENT_ID_LIMIT: i64 = MAX_DOCUMENT_ID / 2;
const IMPORT_HIERARCHY: u8 = 0x01;
const IMPORT_HARD_DELETE: u8 = 0x02;
const ALIAS_CHARGE: u64 = 64;

#[derive(Debug, Default)]
pub struct Imported {
    seen: IdSet,
    seen_fai: IdSet,
    given: IdSet,
    deleted: IdSet,
    aliases: GroupwareAliases,
    id_counter: i64,
}

impl Imported {
    pub fn merged(&self, uploaded: &IcsState) -> IcsState {
        let mut state = uploaded.clone();
        state.seen.union_with(&self.seen);
        state.seen_fai.union_with(&self.seen_fai);
        state.given.union_with(&self.given);
        state.given.difference_with(&self.deleted);
        state
    }

    pub fn charge(&self) -> u64 {
        let ranges = self
            .seen
            .total_ranges()
            .saturating_add(self.seen_fai.total_ranges())
            .saturating_add(self.given.total_ranges())
            .saturating_add(self.deleted.total_ranges());
        u64::try_from(ranges)
            .unwrap_or(u64::MAX)
            .saturating_mul(RANGE_CHARGE)
            .saturating_add(
                u64::try_from(self.aliases.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(ALIAS_CHARGE),
            )
    }
}

impl SyncConfig {
    fn collector(kind: SyncKind) -> Self {
        SyncConfig {
            kind,
            flags: Default::default(),
            extra: Default::default(),
            mode: StringMode::Unicode,
            tags: TagFilter::Exclude(Box::default()),
            restriction: Box::default(),
        }
    }
}

impl StoreGuids {
    pub fn local_id(&self, source_key: &[u8]) -> Option<MapiId> {
        Gid::from_wire(source_key).and_then(|gid| self.local_gid(gid))
    }

    pub fn local_gid(&self, gid: Gid) -> Option<MapiId> {
        if gid.guid != self.replica {
            return None;
        }
        MapiId::from_eid(Eid::new(ReplId::LOCAL, gid.counter))
    }

    pub fn folder_gid(&self, exchange: &ExchangeAccountCache, node: FolderNode) -> Gid {
        self.gid(MapiId::from_folder(exchange, node))
    }

    pub fn folder_node(
        &self,
        exchange: &ExchangeAccountCache,
        source_key: &[u8],
    ) -> Option<FolderNode> {
        self.local_id(source_key)?.to_folder(exchange)
    }
}

impl RopContext<'_, '_> {
    pub fn synchronization_open_collector(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &SynchronizationOpenCollector,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let folder = match self.state.get(parent) {
            Some(ServerObject::Folder(folder)) => *folder,
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        let (kind, transfer_kind) = if request.is_contents_collector {
            (SyncKind::Contents, TransferKind::ContentsCollector)
        } else {
            (SyncKind::Hierarchy, TransferKind::HierarchyCollector)
        };
        let context = TransferContext::Sync(Box::new(SyncContext {
            config: SyncConfig::collector(kind),
            upload: StateUpload::new(&IcsLimits::DEFAULT),
            phase: SyncPhase::Collecting(Box::default()),
        }));
        self.open_transfer(
            rop,
            parent,
            request.output_handle_index,
            folder,
            transfer_kind,
            context,
        )
    }

    pub async fn get_local_replica_ids(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &GetLocalReplicaIds,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let account_id = match self.state.get(handle) {
            Some(ServerObject::Logon(logon)) => logon.mailbox_id,
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        let count = request.id_count;
        if count == 0 || count > MAX_LOCAL_REPLICA_IDS {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        if !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let limit = match self.view_rights(account_id).await? {
            ViewRights::Owner | ViewRights::Member => MAX_DOCUMENT_ID,
            ViewRights::Delegate(rights) if rights.creates_mail() => DELEGATE_DOCUMENT_ID_LIMIT,
            ViewRights::Delegate(_) | ViewRights::Revoked => {
                return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
            }
        };
        if self
            .email_id_counter(account_id)
            .await?
            .saturating_add(i64::from(count))
            > limit
        {
            return Err(RopError::Code(ErrorCode::ERROR));
        }
        let mut batch = BatchBuilder::new();
        let range = batch.reserve_document_ids(account_id, Collection::Email, count);
        let first = self
            .request
            .server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?
            .slot(range.first());
        if i64::from(first).saturating_add(i64::from(count)) > limit {
            return Err(RopError::Code(ErrorCode::ERROR));
        }
        let guids = self.store_guids(account_id).await?;
        self.respond(
            rop,
            index,
            &GetLocalReplicaIdsResponse {
                repl_guid: guids.replica.0,
                global_count: MapiId::new(IdSpace::Email, first).to_eid().counter,
            },
        )
    }

    pub async fn synchronization_import_read_state_changes(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SynchronizationImportReadStateChanges<'_>,
    ) -> RopResult {
        let (staged, folder) = self.collector(rop, SyncKind::Contents)?;
        if !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let Some(container) = mail_container(folder.counter) else {
            return self.respond_empty(rop, index);
        };
        let view = self.mailbox(folder.mailbox_id).await?;
        let guids = StoreGuids::new(view.exchange.store_instance, folder.mailbox_id);
        let key = ReplKey::Guid(guids.replica);
        let mut read: SmallVec<[u32; 16]> = SmallVec::new();
        let mut unread: SmallVec<[u32; 16]> = SmallVec::new();
        for state in request.message_read_states.iter() {
            let Some(document_id) = guids
                .local_id(state.message_id)
                .filter(|id| id.space == IdSpace::Email)
                .and_then(|id| view.client_document(container, id.id))
            else {
                continue;
            };
            let target = if state.mark_as_read {
                &mut read
            } else {
                &mut unread
            };
            target.push(document_id);
        }
        for (mut ids, mark) in [(read, true), (unread, false)] {
            if ids.is_empty() {
                continue;
            }
            ids.sort_unstable();
            ids.dedup();
            let scope = if ids.len() == 1 {
                ReadScope::PerMessage
            } else {
                ReadScope::Bulk
            };
            let Some((change_id, cache)) = self
                .mark_read(
                    folder.mailbox_id,
                    folder.counter,
                    ReadTargets::Listed {
                        container: Some(container),
                        ids: &ids,
                    },
                    ReadChange::imported(mark, scope),
                )
                .await?
                .committed
            else {
                continue;
            };
            let contiguous = cache.last_change_id.checked_add(1) == Some(change_id);
            let seen = contiguous && {
                let context = self.sync_context(staged)?;
                ids.iter().all(|document_id| {
                    cache
                        .email_by_id(document_id)
                        .and_then(|item| ChangeSpace::Email.cn(item.change_id()))
                        .is_none_or(|cn| collector_seen(context, key, cn))
                })
            };
            if seen {
                self.record_import_change(
                    staged,
                    Some(change_id),
                    None,
                    (guids.replica, ChangeSpace::Email),
                )?;
            }
        }
        self.respond_empty(rop, index)
    }

    pub async fn synchronization_import_deletes(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SynchronizationImportDeletes<'_>,
    ) -> RopResult {
        if request.import_delete_flags & !(IMPORT_HIERARCHY | IMPORT_HARD_DELETE) != 0 {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        let hierarchy = request.import_delete_flags & IMPORT_HIERARCHY != 0;
        let kind = if hierarchy {
            SyncKind::Hierarchy
        } else {
            SyncKind::Contents
        };
        let (staged, folder) = self.collector(rop, kind)?;
        let view = self.mailbox(folder.mailbox_id).await?;
        let guids = StoreGuids::new(view.exchange.store_instance, folder.mailbox_id);
        let mut ids = SmallVec::<[Eid; 16]>::new();
        let mut nodes = SmallVec::<[FolderNode; 16]>::new();
        for (_, value) in request.property_values.iter() {
            let PropValue::Mv(keys) = value else {
                return Err(RopError::Code(ErrorCode::INVALID_PARAM));
            };
            if keys.mv_type() != MvType::Binary {
                return Err(RopError::Code(ErrorCode::INVALID_PARAM));
            }
            let keys = keys.iter().filter_map(|key| match key {
                PropValue::Binary(key) => Some(key),
                _ => None,
            });
            if hierarchy {
                for node in keys.filter_map(|key| guids.folder_node(&view.exchange, key)) {
                    ids.push(MapiId::from_folder(&view.exchange, node).to_eid());
                    nodes.push(node);
                }
            } else {
                ids.extend(
                    keys.filter_map(|key| guids.local_id(key))
                        .map(MapiId::to_eid),
                );
            }
        }
        if ids.is_empty() {
            return self.respond_empty(rop, index);
        }
        if hierarchy {
            self.destroy_folders(folder.mailbox_id, &nodes).await?;
        } else {
            self.remove_message_ids(folder.mailbox_id, folder.counter, &ids)
                .await?;
        }
        self.record_import(staged, |imported| {
            let deleted = imported.deleted.get_mut(ReplKey::Guid(guids.replica));
            for eid in &ids {
                deleted.insert(eid.counter);
            }
        })?;
        self.respond_empty(rop, index)
    }

    async fn destroy_folders(
        &mut self,
        account_id: u32,
        nodes: &[FolderNode],
    ) -> Result<(), RopError> {
        let server = self.request.server;
        let access_token = self.request.access_token;
        let tree = self.folder_tree(account_id).await?;
        for &node in nodes {
            self.check_folder_type(node)?;
            if tree.get(node).is_some_and(|entry| entry.special.is_some())
                || tree.descendants(node).any(|entry| entry.special.is_some())
            {
                return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
            }
        }
        for &node in nodes {
            let result = server
                .folder_destroy(access_token, account_id, node, FolderContents::Remove)
                .await?;
            self.invalidate_mailbox();
            match result {
                Ok(_) | Err(FolderWriteError::NotFound) => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    pub(super) fn record_folder_change(
        &mut self,
        collector: u32,
        folder: Option<MapiId>,
        cn: Option<ChangeNumber>,
        guid: ReplGuid,
    ) -> Result<(), RopError> {
        self.record_import(collector, |imported| {
            if let Some(cn) = cn {
                imported
                    .seen
                    .get_mut(ReplKey::Guid(guid))
                    .insert(cn.globcnt());
            }
            if let Some(folder) = folder {
                imported
                    .given
                    .get_mut(ReplKey::Guid(guid))
                    .insert(folder.to_eid().counter);
            }
        })
    }

    pub(super) fn collector_seen(
        &mut self,
        collector: u32,
        guid: ReplGuid,
        cn: ChangeNumber,
    ) -> Result<bool, RopError> {
        let context = self.sync_context(collector)?;
        Ok(collector_seen(context, ReplKey::Guid(guid), cn))
    }

    pub(super) async fn below_id_counter(
        &mut self,
        collector: u32,
        account_id: u32,
        item: u32,
    ) -> Result<bool, RopError> {
        let item = i64::from(item);
        if let SyncPhase::Collecting(imported) = &self.sync_context(collector)?.phase
            && item < imported.id_counter
        {
            return Ok(true);
        }
        let bound = self.email_id_counter(account_id).await?.saturating_add(1);
        if let SyncPhase::Collecting(imported) = &mut self.sync_context(collector)?.phase {
            imported.id_counter = bound;
        }
        Ok(item < bound)
    }

    pub(in crate::mapi::emsmdb) async fn email_id_counter(
        &self,
        account_id: u32,
    ) -> trc::Result<i64> {
        self.request
            .server
            .core
            .storage
            .data
            .get_counter(ValueKey {
                account_id,
                collection: u8::from(Collection::Email),
                document_id: 0,
                class: ValueClass::DocumentId,
            })
            .await
            .caused_by(trc::location!())
    }

    pub(in crate::mapi::emsmdb) fn record_import_change(
        &mut self,
        collector: u32,
        change_id: Option<u64>,
        item: Option<MapiId>,
        (guid, space): (ReplGuid, ChangeSpace),
    ) -> Result<(), RopError> {
        let cn = change_id.and_then(|change_id| space.cn(change_id));
        if cn.is_none() && item.is_none() {
            return Ok(());
        }
        self.record_import(collector, |imported| {
            if let Some(cn) = cn {
                imported
                    .seen
                    .get_mut(ReplKey::Guid(guid))
                    .insert(cn.globcnt());
            }
            if let Some(item) = item {
                imported
                    .given
                    .get_mut(ReplKey::Guid(guid))
                    .insert(item.to_eid().counter);
            }
        })
    }

    pub(in crate::mapi::emsmdb) fn stream_aliases(
        &mut self,
        collector: u32,
    ) -> Result<&GroupwareAliases, RopError> {
        match &self.sync_context(collector)?.phase {
            SyncPhase::Collecting(imported) => Ok(&imported.aliases),
            _ => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
        }
    }

    pub(in crate::mapi::emsmdb) fn record_stream_alias(
        &mut self,
        collector: u32,
        document_id: u32,
        placement: GroupwarePlacement,
    ) -> Result<(), RopError> {
        self.record_import(collector, |imported| {
            imported.aliases.insert(document_id, placement)
        })
    }

    pub(in crate::mapi::emsmdb) fn record_fai_import_change(
        &mut self,
        collector: u32,
        change: Option<u64>,
        item: Option<MapiId>,
        guid: ReplGuid,
    ) -> Result<(), RopError> {
        let cn = change.and_then(|change| ChangeSpace::Exchange.cn(change));
        if cn.is_none() && item.is_none() {
            return Ok(());
        }
        self.record_import(collector, |imported| {
            if let Some(cn) = cn {
                imported
                    .seen_fai
                    .get_mut(ReplKey::Guid(guid))
                    .insert(cn.globcnt());
            }
            if let Some(item) = item {
                imported
                    .given
                    .get_mut(ReplKey::Guid(guid))
                    .insert(item.to_client_message().to_eid().counter);
            }
        })
    }

    pub(super) fn collector(
        &mut self,
        rop: &DecodedRop<'_>,
        kind: SyncKind,
    ) -> Result<(u32, FolderObject), RopError> {
        let transfer = self.transfer_object(rop)?;
        let expected = match kind {
            SyncKind::Contents => TransferKind::ContentsCollector,
            SyncKind::Hierarchy => TransferKind::HierarchyCollector,
        };
        if transfer.kind != expected {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        if self.sync_context(transfer.staged)?.upload.is_streaming() {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        Ok((transfer.staged, transfer.folder))
    }

    fn record_import(
        &mut self,
        staged: u32,
        record: impl FnOnce(&mut Imported),
    ) -> Result<(), RopError> {
        let context = self.sync_context(staged)?;
        let SyncPhase::Collecting(imported) = &mut context.phase else {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        };
        record(imported);
        let charge = state_charge(context.upload.state()).saturating_add(imported.charge());
        self.staged().set_charge(staged, charge)?;
        Ok(())
    }

    pub(in crate::mapi::emsmdb) async fn store_guids(
        &mut self,
        account_id: u32,
    ) -> Result<StoreGuids, RopError> {
        let view = self.mailbox(account_id).await?;
        Ok(StoreGuids::new(view.exchange.store_instance, account_id))
    }
}

fn collector_seen(context: &SyncContext, key: ReplKey, cn: ChangeNumber) -> bool {
    let cn = cn.globcnt();
    context.upload.state().seen.contains(key, cn)
        || matches!(&context.phase, SyncPhase::Collecting(imported) if imported.seen.contains(key, cn))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/ics/upload/tests.rs"]
mod tests;
