/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Download, SyncConfig, SyncContext, SyncPhase, TailStep, TransferContext,
    plan::{
        self, DownloadPlan, ItemKind, ItemVersion, PlanEntry, PlanInput, PlanOrder, ScopeItem,
        SpaceHead, Unreported,
    },
    state_charge,
};
use crate::{
    folders::{FolderEntry, FolderNode, FolderTree, SpecialFolder},
    mapi::{
        emsmdb::{
            access::ViewRights,
            execute::{RopContext, RopError},
            folder::{REN_FOLDERS, change_time, folder_bag, push_inbox_ren_entry_ids},
            message::{
                load::ClientVersion,
                object_row::{decode_property, encode_key},
            },
            props::{PropBag, PropOut},
            state::{FolderObject, TransferObject},
            store::StoreGuids,
        },
        ids::{ChangeNumber, ChangeSpace, MapiId},
    },
    store::{
        FolderKind, FolderRef,
        named::AccountNamedProps,
        object::{ConflictState, ExchangeObject},
    },
};
use common::cache::exchange::ExchangeAccountCache;
use exchange_proto::{
    common::{FileTime, UtcSeconds},
    ics::{
        FxError, GlobSet, IcsState, Pcl, SyncKind,
        flags::{SynchronizationExtraFlags, SynchronizationFlags},
        fx::{FxEncoder, Marker},
    },
    ids::{ReplGuid, Xid},
    mapi::{
        ErrorCode,
        prop::{NamedPropMap, PropKeyRef, PropTag, PropValue, tags},
        rop::requests::FastTransferSourceGetBuffer,
    },
};
use smallvec::SmallVec;
use std::time::{SystemTime, UNIX_EPOCH};

const GET_BUFFER_OVERHEAD: usize = 15;
pub(super) const TRANSFER_BUFFER_MAX: usize = 0xFFFF;
const MIN_DOWNLOAD_HEADROOM: u64 = TRANSFER_BUFFER_MAX as u64;
const CHANGE_KEY_LEN: usize = 22;
const PCL_LEN: usize = 23;

pub struct Fill {
    pub finished: bool,
    pub in_progress: u16,
    pub total: u16,
}

pub fn buffer_budget(
    remaining: usize,
    request: &FastTransferSourceGetBuffer,
) -> Result<usize, RopError> {
    let residual = remaining
        .saturating_sub(GET_BUFFER_OVERHEAD)
        .min(TRANSFER_BUFFER_MAX);
    let requested = usize::from(request.buffer_size);
    match request.maximum_buffer_size {
        Some(max) => Ok(residual.min(usize::from(max))),
        None if requested <= residual => Ok(requested),
        None => Err(RopError::Overflow),
    }
}

pub fn encoder_charge(encoder: &FxEncoder) -> u64 {
    u64::try_from(encoder.buffered()).unwrap_or(u64::MAX)
}

pub fn folder_space(entry: &FolderEntry) -> ChangeSpace {
    match entry.node {
        FolderNode::Stored(FolderRef { kind, .. }) => match kind {
            FolderKind::Mailbox => ChangeSpace::Email,
            FolderKind::Calendar => ChangeSpace::Calendar,
            FolderKind::AddressBook => ChangeSpace::AddressBook,
            FolderKind::FileNode => ChangeSpace::FileNode,
            FolderKind::Virtual => ChangeSpace::Exchange,
        },
        FolderNode::Special(
            SpecialFolder::Calendar | SpecialFolder::Tasks | SpecialFolder::Journal,
        ) => ChangeSpace::Calendar,
        FolderNode::Special(_) => ChangeSpace::Email,
    }
}

pub fn folder_cn(tree: &FolderTree, entry: &FolderEntry) -> Option<ChangeNumber> {
    let change_id = match entry.special {
        Some(SpecialFolder::Inbox) => REN_FOLDERS
            .into_iter()
            .filter_map(|folder| tree.special(folder))
            .fold(entry.change_id, |cn, ren| cn.max(ren.change_id)),
        _ => entry.change_id,
    };
    folder_space(entry).cn(change_id.max(1))
}

pub(super) fn cache_heads(change_ids: &[u64]) -> impl Iterator<Item = SpaceHead> + '_ {
    change_ids.iter().enumerate().filter_map(|(index, &head)| {
        Some(SpaceHead {
            space: ChangeSpace::from_cache_group(index)?,
            head,
        })
    })
}

pub(super) fn sync_time() -> FileTime {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        });
    FileTime::from_utc(UtcSeconds(seconds), 0)
}

pub(crate) struct Versions {
    pub(crate) change_key: SmallVec<[u8; CHANGE_KEY_LEN]>,
    pub(crate) pcl: SmallVec<[u8; PCL_LEN]>,
}

impl Versions {
    pub(crate) fn server(cn: ChangeNumber, guid: ReplGuid) -> Self {
        Self::merged(cn.xid(guid), Pcl::new())
    }

    pub(super) fn of(client: Option<&ClientVersion>, cn: ChangeNumber, guid: ReplGuid) -> Self {
        match client {
            Some(client) if client.current => Versions {
                change_key: SmallVec::from_slice(&client.change_key),
                pcl: SmallVec::from_slice(&client.pcl),
            },
            Some(client) => {
                Self::merged(cn.xid(guid), Pcl::decode(&client.pcl).unwrap_or_default())
            }
            None => Self::server(cn, guid),
        }
    }

    pub(super) fn pcl(&self) -> Pcl {
        Pcl::decode(&self.pcl).unwrap_or_default()
    }

    pub(crate) fn conflict(&self) -> ConflictState {
        ConflictState {
            change_key: self.change_key.to_vec(),
            pcl: self.pcl.to_vec(),
        }
    }

    pub(crate) fn merged(xid: Xid, mut pcl: Pcl) -> Self {
        pcl.merge(&xid);
        let mut versions = Versions {
            change_key: SmallVec::new(),
            pcl: SmallVec::with_capacity(pcl.encoded_len()),
        };
        xid.encode(&mut versions.change_key);
        pcl.encode(&mut versions.pcl);
        versions
    }
}

impl RopContext<'_, '_> {
    pub(super) async fn produce(
        &mut self,
        transfer: &TransferObject,
        context: &mut TransferContext,
        budget: usize,
    ) -> Result<Fill, RopError> {
        match context {
            TransferContext::Upload(_) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            TransferContext::Copy(source) => {
                let result = self.produce_copy(source, budget).await;
                if let Err(err) = &result {
                    source.fail(match err {
                        RopError::Code(code) => *code,
                        _ => ErrorCode::ERROR,
                    });
                }
                result
            }
            TransferContext::Buffer(_) => Ok(Fill {
                finished: true,
                in_progress: 0,
                total: 0,
            }),
            TransferContext::Sync(sync) => {
                let result = self.produce_sync(transfer.folder, sync, budget).await;
                if let Err(err) = &result
                    && !matches!(sync.phase, SyncPhase::Collecting(_))
                {
                    sync.phase = SyncPhase::Failed(match err {
                        RopError::Code(code) => *code,
                        _ => ErrorCode::ERROR,
                    });
                }
                result
            }
        }
    }

    async fn produce_sync(
        &mut self,
        folder: FolderObject,
        sync: &mut SyncContext,
        budget: usize,
    ) -> Result<Fill, RopError> {
        if sync.upload.is_streaming() {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        let SyncContext {
            config,
            upload,
            phase,
        } = sync;
        match phase {
            SyncPhase::Failed(code) => return Err(RopError::Code(*code)),
            SyncPhase::Collecting(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            SyncPhase::Done(_) => {
                return Ok(Fill {
                    finished: true,
                    in_progress: 0,
                    total: 0,
                });
            }
            SyncPhase::Configured => {
                let plan = self.build_plan(folder, config, upload.state()).await?;
                let mut encoder = FxEncoder::new(config.mode);
                if config.kind == SyncKind::Contents
                    && config.flags.contains(SynchronizationFlags::PROGRESS)
                {
                    encoder.progress_total(&plan.progress()).map_err(fx)?;
                }
                *phase = SyncPhase::Streaming(Box::new(Download {
                    plan,
                    cursor: 0,
                    encoder,
                    tail: TailStep::Changes,
                }));
            }
            SyncPhase::Streaming(_) => {}
        }
        let SyncPhase::Streaming(download) = phase else {
            return Err(RopError::Code(ErrorCode::ERROR));
        };
        let held = state_charge(upload.state()).saturating_add(download.plan.footprint());
        let limit = self.staged().headroom().saturating_sub(held);
        if config.kind == SyncKind::Contents
            && download.tail == TailStep::Changes
            && download.cursor < download.plan.changes.len()
            && limit < MIN_DOWNLOAD_HEADROOM
        {
            return Err(RopError::Code(ErrorCode::NOT_ENOUGH_MEMORY));
        }
        while download.encoder.buffered() < budget && download.tail == TailStep::Changes {
            match download.plan.changes.get(download.cursor).copied() {
                Some(entry) => {
                    self.write_change(folder, config, upload.state(), download, entry, limit)
                        .await?;
                    download.cursor = download.cursor.saturating_add(1);
                }
                None => {
                    let guid = self.store_guids(folder.mailbox_id).await?.replica;
                    write_tail(config, download, guid)?;
                    download.tail = TailStep::Written;
                }
            }
        }
        Ok(Fill {
            finished: download.tail == TailStep::Written,
            in_progress: u16::try_from(download.cursor).unwrap_or(u16::MAX),
            total: u16::try_from(download.plan.changes.len()).unwrap_or(u16::MAX),
        })
    }

    async fn build_plan(
        &mut self,
        folder: FolderObject,
        config: &SyncConfig,
        uploaded: &IcsState,
    ) -> Result<DownloadPlan, RopError> {
        match config.kind {
            SyncKind::Hierarchy => self.hierarchy_plan(folder, uploaded).await,
            SyncKind::Contents => self.contents_plan(folder, config, uploaded).await,
        }
    }

    async fn hierarchy_plan(
        &mut self,
        folder: FolderObject,
        uploaded: &IcsState,
    ) -> Result<DownloadPlan, RopError> {
        let mailbox_id = folder.mailbox_id;
        let root = folder
            .id()
            .and_then(MapiId::to_node)
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let mailbox = self.mailbox(mailbox_id).await?;
        let guid = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id).replica;
        let heads: Vec<SpaceHead> = cache_heads(&mailbox.exchange.change_ids).collect();
        let tree = self.folder_tree(mailbox_id).await?;
        if tree.get(root).is_none() {
            return Err(RopError::Code(ErrorCode::OBJECT_DELETED));
        }
        let rights = self.view_rights(mailbox_id).await?;
        let items = tree
            .descendants(root)
            .filter(|entry| rights.of(entry.node).is_visible())
            .enumerate()
            .map(|(position, entry)| ScopeItem {
                id: MapiId::from_folder(&mailbox.exchange, entry.node)
                    .to_eid()
                    .counter,
                version: folder_cn(&tree, entry).map_or(ItemVersion::Unknown, ItemVersion::Known),
                kind: ItemKind::Normal,
                size: 0,
                order: u64::try_from(position).unwrap_or(u64::MAX),
            })
            .collect();
        Ok(plan::plan(
            &PlanInput {
                guid,
                uploaded,
                heads: &heads,
                fai_heads: &[],
                outside: &GlobSet::new(),
                order: PlanOrder::Input,
                replicas: &mailbox.exchange.replicas,
            },
            items,
        ))
    }

    async fn write_change(
        &mut self,
        folder: FolderObject,
        config: &SyncConfig,
        uploaded: &IcsState,
        download: &mut Download,
        entry: PlanEntry,
        limit: u64,
    ) -> Result<(), RopError> {
        match config.kind {
            SyncKind::Hierarchy => {
                self.write_folder_change(folder, config, download, entry)
                    .await
            }
            SyncKind::Contents => {
                self.write_message_change(folder, (config, uploaded), download, entry, limit)
                    .await
            }
        }
    }

    async fn write_folder_change(
        &mut self,
        folder: FolderObject,
        config: &SyncConfig,
        download: &mut Download,
        entry: PlanEntry,
    ) -> Result<(), RopError> {
        let mailbox_id = folder.mailbox_id;
        let mailbox = self.mailbox(mailbox_id).await?;
        let guids = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id);
        let tree = self.folder_tree(mailbox_id).await?;
        let rights = self.view_rights(mailbox_id).await?;
        let node =
            MapiId::from_counter(entry.id.get()).and_then(|id| id.to_folder(&mailbox.exchange));
        let Some((current, cn)) = node
            .filter(|node| rights.of(*node).is_visible())
            .and_then(|node| tree.get(node))
            .and_then(|current| Some((current, folder_cn(&tree, current)?)))
        else {
            download.plan.skip(&entry, guids.replica);
            return Ok(());
        };
        let root = folder.id().and_then(MapiId::to_node);
        let mut stored = PropBag::default();
        if current.special == Some(SpecialFolder::Inbox)
            && config.tags.allows(tags::ADDITIONAL_REN_ENTRY_IDS)
        {
            if let Some(row) = self.folder_row(mailbox_id, current.node).await? {
                let key = encode_key(PropKeyRef::Tag(tags::ADDITIONAL_REN_ENTRY_IDS.id()));
                if let Some((_, value)) = row
                    .unarchive::<ExchangeObject>()?
                    .property(&key)
                    .and_then(|value| decode_property(&key, value))
                {
                    stored.push_owned(
                        PropTag::new(tags::ADDITIONAL_REN_ENTRY_IDS.id(), value.ptype()),
                        &value,
                    );
                }
            }
            push_inbox_ren_entry_ids(
                &mut stored,
                &tree,
                current,
                &guids,
                &mailbox.exchange,
                &rights,
            );
        }
        let names = AccountNamedProps::new(&mailbox.exchange);
        write_folder(
            &mut download.encoder,
            FolderWrite {
                tree: &tree,
                exchange: &mailbox.exchange,
                entry: current,
                root,
                guids: &guids,
                cn,
                config,
                rights: &rights,
                stored: &stored,
            },
            &names,
        )?;
        download.plan.record_sent(&entry, cn, guids.replica);
        Ok(())
    }
}

struct FolderWrite<'x> {
    tree: &'x FolderTree,
    exchange: &'x ExchangeAccountCache,
    entry: &'x FolderEntry,
    root: Option<FolderNode>,
    guids: &'x StoreGuids,
    cn: ChangeNumber,
    config: &'x SyncConfig,
    rights: &'x ViewRights,
    stored: &'x PropBag,
}

const FOLDER_HEADER_TAGS: [PropTag; 11] = [
    tags::PARENT_SOURCE_KEY,
    tags::SOURCE_KEY,
    tags::LAST_MODIFICATION_TIME,
    tags::CHANGE_KEY,
    tags::PREDECESSOR_CHANGE_LIST,
    tags::DISPLAY_NAME,
    tags::FOLDER_ID,
    tags::PARENT_FOLDER_ID,
    tags::OBJECT_TYPE,
    tags::ENTRY_ID,
    tags::PARENT_ENTRY_ID,
];

fn write_folder(
    encoder: &mut FxEncoder,
    folder: FolderWrite<'_>,
    names: &dyn NamedPropMap,
) -> Result<(), RopError> {
    let FolderWrite {
        tree,
        exchange,
        entry,
        root,
        guids,
        cn,
        config,
        rights,
        stored,
    } = folder;
    let id = MapiId::from_folder(exchange, entry.node);
    let source_key = guids.gid(id).to_wire();
    let parent_key = match entry.parent {
        Some(parent) if Some(parent) != root => Some(guids.folder_gid(exchange, parent).to_wire()),
        _ => None,
    };
    let versions = Versions::server(cn, guids.replica);
    encoder.marker(Marker::IncrSyncChg).map_err(fx)?;
    encoder
        .prop(
            tags::PARENT_SOURCE_KEY,
            &PropValue::Binary(parent_key.as_ref().map_or(&[][..], |key| &key[..])),
            names,
        )
        .map_err(fx)?;
    encoder
        .prop(tags::SOURCE_KEY, &PropValue::Binary(&source_key), names)
        .map_err(fx)?;
    encoder
        .prop(
            tags::LAST_MODIFICATION_TIME,
            &PropValue::Time(change_time(entry.change_id)),
            names,
        )
        .map_err(fx)?;
    encoder
        .prop(
            tags::CHANGE_KEY,
            &PropValue::Binary(&versions.change_key),
            names,
        )
        .map_err(fx)?;
    encoder
        .prop(
            tags::PREDECESSOR_CHANGE_LIST,
            &PropValue::Binary(&versions.pcl),
            names,
        )
        .map_err(fx)?;
    encoder
        .prop_text(tags::DISPLAY_NAME, &entry.name, names)
        .map_err(fx)?;
    let eid = config.extra.contains(SynchronizationExtraFlags::EID);
    if eid {
        let fid = id.to_eid();
        encoder
            .prop(
                tags::FOLDER_ID,
                &PropValue::I64(i64::from_le_bytes(fid.to_wire())),
                names,
            )
            .map_err(fx)?;
    }
    if (eid
        || config
            .flags
            .contains(SynchronizationFlags::NO_FOREIGN_IDENTIFIERS))
        && let Some(parent) = entry.parent
    {
        let parent = MapiId::from_folder(exchange, parent).to_eid();
        encoder
            .prop(
                tags::PARENT_FOLDER_ID,
                &PropValue::I64(i64::from_le_bytes(parent.to_wire())),
                names,
            )
            .map_err(fx)?;
    }
    let bag: PropBag = folder_bag(tree, entry, guids, exchange, None, rights);
    for (tag, value) in bag.all() {
        if FOLDER_HEADER_TAGS
            .iter()
            .any(|header| header.id() == tag.id())
            || !config.tags.allows(tag)
        {
            continue;
        }
        match value {
            PropOut::Value(value) => encoder.prop(tag, &value, names),
            PropOut::Text(text) => encoder.prop_text(tag, text, names),
        }
        .map_err(fx)?;
    }
    if let Some(PropOut::Value(ids)) = stored.get(tags::ADDITIONAL_REN_ENTRY_IDS) {
        encoder
            .prop(tags::ADDITIONAL_REN_ENTRY_IDS, &ids, names)
            .map_err(fx)?;
    }
    Ok(())
}

pub(super) fn fx(err: FxError) -> RopError {
    RopError::Code(err.error_code())
}

fn write_tail(
    config: &SyncConfig,
    download: &mut Download,
    guid: ReplGuid,
) -> Result<(), RopError> {
    if config.reports_deletions() {
        let ignores_scope = config
            .flags
            .contains(SynchronizationFlags::IGNORE_NO_LONGER_IN_SCOPE);
        let no_longer_in_scope = (!ignores_scope).then_some(&download.plan.no_longer_in_scope);
        download
            .encoder
            .deletions(&download.plan.deleted, no_longer_in_scope)
            .map_err(fx)?;
        if ignores_scope {
            download.plan.keep_unreported(guid, Unreported::OutOfScope);
        }
    } else {
        download.plan.keep_unreported(guid, Unreported::Deletions);
    }
    download
        .encoder
        .state(&download.plan.next, config.kind)
        .map_err(fx)?;
    download.encoder.end().map_err(fx)
}
