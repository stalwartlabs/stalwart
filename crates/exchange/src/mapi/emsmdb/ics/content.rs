/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Download, SyncConfig, TagFilter,
    plan::{
        self, DownloadPlan, ItemKind, ItemVersion, PlanEntry, PlanInput, PlanOrder, ScopeItem,
        SegmentWalk, SpaceHead,
    },
    stream::{Versions, encoder_charge, fx, sync_time},
};
use crate::{
    folders::FolderNode,
    mapi::{
        emsmdb::{
            execute::{MailboxView, RopContext, RopError},
            message::{
                CategorySource, ContentScope, MAX_EMBED_DEPTH, MessageParent, derived_attach_size,
                fai::{fai_props, holds_normal_fai_rows},
                load::LoadDepth,
                message_bag, numbered_attachments, push_message_ids, push_scoped_content,
            },
            props::{PropBag, PropOut},
            staged::content_size,
            state::{
                FolderObject, MessageObject, RecipientColumns, TableKind, TableObject,
                mail_container,
            },
            store::StoreGuids,
            table::{
                TableRow,
                contents::{RowFill, push_row_instance},
                decode_restriction,
                filter::RowFilter,
            },
        },
        ids::{ChangeNumber, ChangeSpace, IdSpace, MapiId},
    },
    store::{
        FolderKind, FolderRef,
        alias::GroupwareKind,
        folder::{FaiKind, FolderStore},
        named::AccountNamedProps,
    },
};
use email::cache::email::MessageCacheAccess;
use exchange_proto::{
    convert::{
        model::{AttachData, Attachment, MessageContent, PropBag as ContentBag},
        tags::native_body,
    },
    ics::{
        GlobSet, IcsState, IdSet, ReplKey,
        flags::{SynchronizationExtraFlags, SynchronizationFlags},
        fx::{FxEncoder, Marker, MessageChangeHeader, tags as subobject},
    },
    ids::{Globcnt, ReplGuid},
    mapi::{
        ErrorCode,
        prop::{NamedPropMap, PropId, PropKeyRef, PropTag, PropType, PropValue, tags},
    },
};
use groupware::cache::GroupwareCache;
use std::{ops::RangeInclusive, sync::Arc};
use store::{
    query::log::{Change, Changes, Query},
    roaring::RoaringBitmap,
};
use trc::AddContext;
use types::{collection::SyncCollection, type_state::DataType};

const PROVIDER_INTERNAL: RangeInclusive<u16> = 0x6600..=0x67FF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaiRows {
    Associated,
    Normal,
    Both,
}

impl FaiRows {
    fn new(associated: bool, normal: bool) -> Option<Self> {
        match (associated, normal) {
            (true, true) => Some(FaiRows::Both),
            (true, false) => Some(FaiRows::Associated),
            (false, true) => Some(FaiRows::Normal),
            (false, false) => None,
        }
    }

    fn select(self, kind: FaiKind) -> Option<ItemKind> {
        match (self, kind) {
            (FaiRows::Associated | FaiRows::Both, FaiKind::Associated) => {
                Some(ItemKind::Associated)
            }
            (FaiRows::Normal | FaiRows::Both, FaiKind::Normal) => Some(ItemKind::NormalFai),
            _ => None,
        }
    }
}

const MESSAGE_SKIP_TAGS: [PropTag; 16] = [
    tags::SOURCE_KEY,
    tags::LAST_MODIFICATION_TIME,
    tags::CHANGE_KEY,
    tags::PREDECESSOR_CHANGE_LIST,
    tags::ASSOCIATED,
    tags::MID,
    tags::MESSAGE_SIZE,
    tags::CHANGE_NUMBER,
    tags::FOLDER_ID,
    tags::PARENT_FOLDER_ID,
    tags::PARENT_SOURCE_KEY,
    tags::ENTRY_ID,
    tags::PARENT_ENTRY_ID,
    tags::INSTANCE_KEY,
    tags::INST_ID,
    tags::INSTANCE_NUM,
];

#[derive(Default)]
struct Scope {
    items: Vec<ScopeItem>,
    outside: GlobSet,
    heads: Vec<SpaceHead>,
    fai_cns: Vec<Globcnt>,
}

struct Restricted<'x> {
    filter: RowFilter<'x>,
    table: TableObject,
    fill: RowFill,
    uploaded: &'x IcsState,
    guid: ReplGuid,
}

struct MessageWrite<'x> {
    bag: &'x PropBag,
    content: &'x MessageContent,
    entry: &'x PlanEntry,
    id: MapiId,
    cn: ChangeNumber,
    versions: &'x Versions,
    guids: &'x StoreGuids,
    config: &'x SyncConfig,
}

impl RopContext<'_, '_> {
    pub(super) async fn contents_plan(
        &mut self,
        folder: FolderObject,
        config: &SyncConfig,
        uploaded: &IcsState,
    ) -> Result<DownloadPlan, RopError> {
        let mailbox_id = folder.mailbox_id;
        let node = folder
            .id()
            .and_then(MapiId::to_node)
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let normal_fai = holds_normal_fai_rows(
            self.folder_tree(mailbox_id)
                .await?
                .get(node)
                .ok_or(ErrorCode::OBJECT_DELETED)?,
        );
        self.require_folder_items(mailbox_id, folder.counter)
            .await?;
        let mailbox = self.mailbox(mailbox_id).await?;
        let guid = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id).replica;
        let restriction = decode_restriction(&config.restriction)?;
        let restricted = match &restriction {
            Some(decoded) => {
                let mut table =
                    TableObject::new(folder, TableKind::Contents { associated: false }, true);
                table.restriction = config.restriction.to_vec();
                let fill = if mail_container(folder.counter).is_none()
                    || table.envelope_in_order(Some(decoded))
                {
                    RowFill::Envelope
                } else {
                    RowFill::State
                };
                Some(Restricted {
                    filter: RowFilter::new(decoded, self.code_page())
                        .ok_or(RopError::Code(ErrorCode::TOO_COMPLEX))?,
                    table,
                    fill,
                    uploaded,
                    guid,
                })
            }
            None => None,
        };
        let mut scope = Scope::default();
        let fai_rows = FaiRows::new(config.wants_fai(), config.wants_normal() && normal_fai);
        if let Some(rows) = fai_rows {
            self.fai_scope(folder, node, rows, restricted.as_ref(), &mut scope)
                .await?;
        }
        if config.wants_normal()
            && let FolderNode::Stored(stored) = node
        {
            self.normal_scope(folder, stored, uploaded, &mailbox, &mut scope)
                .await?;
            if let Some(restricted) = &restricted {
                self.restrict_normal(restricted, &mut scope).await?;
            }
        }
        let order = if config
            .extra
            .contains(SynchronizationExtraFlags::ORDER_BY_DELIVERY_TIME)
        {
            PlanOrder::NewestFirst
        } else {
            PlanOrder::ChangeNumber
        };
        let fai_cns = std::mem::take(&mut scope.fai_cns);
        let mut planned = plan::plan(
            &PlanInput {
                guid,
                uploaded,
                heads: &scope.heads,
                fai_heads: &[],
                outside: &scope.outside,
                order,
                replicas: &mailbox.exchange.replicas,
            },
            scope.items,
        );
        if fai_rows.is_some() {
            *planned.next.seen_fai.get_mut(ReplKey::Guid(guid)) = cn_set(fai_cns);
        }
        if config.flags.contains(SynchronizationFlags::READ_STATE)
            && let FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                ..
            }) = node
            && let Some(messages) = mailbox.messages.as_ref()
        {
            plan::collapse(
                &mut planned.next.read,
                ReplKey::Guid(guid),
                &[SpaceHead {
                    space: ChangeSpace::Email,
                    head: messages.last_change_id,
                }],
            );
        }
        if planned.footprint() > self.staged().headroom() {
            return Err(RopError::Code(ErrorCode::NOT_ENOUGH_MEMORY));
        }
        Ok(planned)
    }

    async fn fai_scope(
        &mut self,
        folder: FolderObject,
        node: FolderNode,
        rows: FaiRows,
        restricted: Option<&Restricted<'_>>,
        scope: &mut Scope,
    ) -> Result<(), RopError> {
        let mailbox_id = folder.mailbox_id;
        let Ok(fai_folder) = self.fai_folder(mailbox_id, node) else {
            return Ok(());
        };
        let folder_id = folder.id().ok_or(ErrorCode::OBJECT_DELETED)?;
        let mailbox = self.mailbox(mailbox_id).await?;
        let guids = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id);
        let parent_ids = MessageParent::new(&guids, &mailbox.exchange, folder_id);
        let named = AccountNamedProps::new(&mailbox.exchange);
        self.request
            .server
            .fai_messages(mailbox_id, fai_folder, |id, fai| {
                let Some(kind) = rows.select(FaiKind::from(&fai.kind)) else {
                    return Ok(true);
                };
                let change = fai.change.to_native();
                let cn = ChangeSpace::Exchange.cn(change);
                let id = MapiId::new(IdSpace::Fai, id);
                let item = ScopeItem {
                    id: id.to_client_message().to_eid().counter,
                    version: cn.map_or(ItemVersion::Unknown, ItemVersion::Known),
                    kind,
                    size: 0,
                    order: change,
                };
                scope.fai_cns.extend(cn.map(ChangeNumber::globcnt));
                if let Some(restricted) = restricted {
                    let mut bag = PropBag::default();
                    push_message_ids(&mut bag, &guids, &parent_ids, id);
                    push_row_instance(&mut bag, id);
                    push_scoped_content(&mut bag, &fai_props(fai).props, &named, ContentScope::Row);
                    if !restricted.filter.matches(&|tag| bag.get(tag)) {
                        scope.outside.insert(item.id);
                        return Ok(true);
                    }
                }
                scope.items.push(item);
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
        Ok(())
    }

    async fn restrict_normal(
        &mut self,
        restricted: &Restricted<'_>,
        scope: &mut Scope,
    ) -> Result<(), RopError> {
        let mut rows = scope
            .items
            .iter()
            .filter(|item| {
                !item.kind.fai_row()
                    && (restricted.fill == RowFill::State
                        || plan::is_candidate(restricted.uploaded, restricted.guid, item))
            })
            .map(|item| TableRow {
                key: item.id.get(),
                bag: PropBag::default(),
            })
            .collect::<Vec<_>>();
        if rows.is_empty() {
            return Ok(());
        }
        self.complete_rows(&restricted.table, &mut rows, restricted.fill)
            .await?;
        let mut rejected = rows
            .iter()
            .filter(|row| !restricted.filter.matches(&|tag| row.get(tag)))
            .map(|row| row.key)
            .collect::<Vec<_>>();
        if rejected.is_empty() {
            return Ok(());
        }
        rejected.sort_unstable();
        let outside = &mut scope.outside;
        scope.items.retain(|item| {
            let excluded = !item.kind.fai_row() && rejected.binary_search(&item.id.get()).is_ok();
            if excluded {
                outside.insert(item.id);
            }
            !excluded
        });
        Ok(())
    }

    async fn normal_scope(
        &mut self,
        folder: FolderObject,
        stored: FolderRef,
        uploaded: &IcsState,
        mailbox: &MailboxView,
        scope: &mut Scope,
    ) -> Result<(), RopError> {
        let FolderRef {
            kind,
            id: container,
        } = stored;
        let (space, collection, data_type) = match kind {
            FolderKind::Mailbox => {
                let Some(messages) = mailbox.messages.as_ref() else {
                    return Ok(());
                };
                scope.heads.push(SpaceHead {
                    space: ChangeSpace::Email,
                    head: messages.last_change_id,
                });
                for item in messages.in_mailbox(container) {
                    let id = MapiId::new(
                        IdSpace::Email,
                        mailbox.email_item(container, item.document_id()),
                    );
                    scope.items.push(ScopeItem {
                        id: id.to_eid().counter,
                        version: ChangeSpace::Email
                            .cn(item.change_id())
                            .map_or(ItemVersion::Unknown, ItemVersion::Known),
                        kind: ItemKind::Normal,
                        size: item.size(),
                        order: item.received_at(),
                    });
                }
                return Ok(());
            }
            FolderKind::Calendar => (
                ChangeSpace::Calendar,
                SyncCollection::Calendar,
                DataType::CalendarEvent,
            ),
            FolderKind::AddressBook => (
                ChangeSpace::AddressBook,
                SyncCollection::AddressBook,
                DataType::ContactCard,
            ),
            FolderKind::FileNode | FolderKind::Virtual => return Ok(()),
        };
        if !self.types.contains(data_type) {
            return Ok(());
        }
        let mailbox_id = folder.mailbox_id;
        let guid = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id).replica;
        let head = self
            .request
            .server
            .store()
            .get_last_change_id(mailbox_id, collection.into())
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default();
        scope.heads.push(SpaceHead { space, head });
        let resources = self
            .request
            .server
            .fetch_groupware_resources(mailbox_id, mailbox_id, collection)
            .await
            .caused_by(trc::location!())?;
        let window = self
            .unseen_changes(
                mailbox_id,
                collection,
                (&uploaded.seen, guid, space),
                (head, resources.children_ids(container)),
            )
            .await?;
        let rights = self.view_rights(mailbox_id).await?;
        for document_id in resources.children_ids(container) {
            if rights.hides(&resources, document_id) {
                continue;
            }
            let version = match &window {
                Some(changed) if !changed.contains(document_id) => ItemVersion::Unchanged,
                _ => ItemVersion::Unknown,
            };
            scope.items.push(ScopeItem {
                id: mailbox.client_item(stored, document_id).to_eid().counter,
                version,
                kind: ItemKind::Normal,
                size: 0,
                order: u64::from(document_id),
            });
        }
        Ok(())
    }

    async fn changed_since(
        &self,
        account_id: u32,
        collection: SyncCollection,
        since: u64,
    ) -> Result<Option<RoaringBitmap>, RopError> {
        if since == 0 {
            return Ok(None);
        }
        let changes = self
            .request
            .server
            .store()
            .changes(account_id, collection.into(), Query::Since(since))
            .await
            .caused_by(trc::location!())?;
        if changes.needs_full_rebuild(since) {
            return Ok(None);
        }
        Ok(Some(changed_items(&changes)))
    }

    async fn unseen_changes(
        &self,
        account_id: u32,
        collection: SyncCollection,
        (seen, guid, space): (&IdSet, ReplGuid, ChangeSpace),
        (head, children): (u64, impl Iterator<Item = u32> + Send),
    ) -> Result<Option<RoaringBitmap>, RopError> {
        let since = plan::seen_run_end(seen, guid, space);
        let Some(changed) = self.changed_since(account_id, collection, since).await? else {
            return Ok(None);
        };
        if changed.is_empty() {
            return Ok(Some(changed));
        }
        let Some(segments) = plan::seen_segments(seen, guid, space, (since, head)) else {
            return Ok(Some(changed));
        };
        let mut walk = SegmentWalk::new(children.filter(|id| changed.contains(*id)).collect());
        for segment in segments.into_iter().rev() {
            if walk.is_done() {
                break;
            }
            let (from, to) = segment.range();
            let changes = self
                .request
                .server
                .store()
                .changes(
                    account_id,
                    collection.into(),
                    Query::RangeInclusive(from, to),
                )
                .await
                .caused_by(trc::location!())?;
            if changes.is_truncated {
                return Ok(Some(walk.truncated()));
            }
            walk.attribute(segment, changed_items(&changes));
        }
        Ok(Some(walk.pending()))
    }

    pub(super) async fn write_message_change(
        &mut self,
        folder: FolderObject,
        (config, uploaded): (&SyncConfig, &IcsState),
        download: &mut Download,
        entry: PlanEntry,
        limit: u64,
    ) -> Result<(), RopError> {
        let mailbox_id = folder.mailbox_id;
        self.require_folder_items(mailbox_id, folder.counter)
            .await?;
        let mailbox = self.mailbox(mailbox_id).await?;
        let guids = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id);
        let Some(id) = MapiId::from_counter(entry.id.get()).and_then(|id| {
            if entry.fai_row() {
                id.from_client_fai()
            } else {
                Some(id)
            }
        }) else {
            download.plan.skip(&entry, guids.replica);
            return Ok(());
        };
        let message = MessageObject {
            mailbox_id,
            folder: folder.counter,
            message: id.counter(),
            code_page: self.code_page().0,
            path: Vec::new(),
            staged: None,
            recipient_columns: RecipientColumns::Unannounced,
        };
        let Some(stored) = mailbox.stored_item(folder.counter, id) else {
            download.plan.skip(&entry, guids.replica);
            return Ok(());
        };
        let loaded = match stored.space {
            IdSpace::Event | IdSpace::Contact => {
                let (space, kind) = if stored.space == IdSpace::Event {
                    (ChangeSpace::Calendar, GroupwareKind::Event)
                } else {
                    (ChangeSpace::AddressBook, GroupwareKind::Contact)
                };
                match self
                    .load_versioned(mailbox_id, stored, LoadDepth::Full)
                    .await
                {
                    Ok((content, change)) => {
                        let cn = space.cn(change.max(1));
                        if cn.is_some_and(|cn| entry.echoes(uploaded, guids.replica, cn)) {
                            return Ok(());
                        }
                        self.groupware_client(&mailbox, (kind, stored.id), change)
                            .await
                            .map(|client| (Arc::new(content), cn, client))
                    }
                    Err(err) => Err(err),
                }
            }
            IdSpace::Email | IdSpace::Fai => {
                let cn = if stored.space == IdSpace::Email {
                    mailbox
                        .messages
                        .as_ref()
                        .and_then(|messages| messages.email_by_id(&stored.id))
                        .and_then(|item| ChangeSpace::Email.cn(item.change_id()))
                } else {
                    entry.cn()
                };
                self.message_root(&message).await.map(|content| {
                    let client = self
                        .loaded_for(&message)
                        .and_then(|loaded| loaded.client.clone());
                    (content, cn, client)
                })
            }
            _ => self
                .message_root(&message)
                .await
                .map(|content| (content, entry.cn(), None)),
        };
        let (content, cn, client) = match loaded {
            Ok((content, Some(cn), client)) => (content, cn, client),
            Ok((_, None, _)) | Err(RopError::Code(_)) => {
                download.plan.skip(&entry, guids.replica);
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        if entry.echoes(uploaded, guids.replica, cn) {
            return Ok(());
        }
        if encoder_charge(&download.encoder).saturating_add(content_size(&content)) > limit {
            download.plan.skip(&entry, guids.replica);
            return Ok(());
        }
        let names = AccountNamedProps::new(&mailbox.exchange);
        let bag = message_bag(&message, &content, &mailbox, CategorySource::Stored);
        let checkpoint = download.encoder.checkpoint();
        let written = write_message(
            &mut download.encoder,
            MessageWrite {
                bag: &bag,
                content: &content,
                entry: &entry,
                id: id.to_client_message(),
                cn,
                versions: &Versions::of(client.as_ref(), cn, guids.replica),
                guids: &guids,
                config,
            },
            &names,
        );
        match written {
            Ok(()) if encoder_charge(&download.encoder) <= limit => {
                download.plan.record_sent(&entry, cn, guids.replica);
                Ok(())
            }
            Ok(()) | Err(RopError::Code(_)) => {
                if !download.encoder.rollback(checkpoint) {
                    return Err(RopError::Code(ErrorCode::ERROR));
                }
                download.plan.skip(&entry, guids.replica);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

fn changed_items(changes: &Changes) -> RoaringBitmap {
    changes
        .changes
        .iter()
        .filter_map(|change| match change {
            Change::UpdateItem(id) | Change::UpdateItemMetadata(id) | Change::InsertItem(id) => {
                u32::try_from(*id).ok()
            }
            _ => None,
        })
        .collect()
}

fn cn_set(mut cns: Vec<Globcnt>) -> GlobSet {
    cns.sort_unstable();
    cns.dedup();
    let mut set = GlobSet::new();
    for cn in cns {
        set.push_ascending(cn, cn);
    }
    set
}

fn write_message(
    encoder: &mut FxEncoder,
    message: MessageWrite<'_>,
    names: &dyn NamedPropMap,
) -> Result<(), RopError> {
    let MessageWrite {
        bag,
        content,
        entry,
        id,
        cn,
        versions,
        guids,
        config,
    } = message;
    let source_key = guids.gid(id).to_wire();
    let last_modified = match bag.get(tags::LAST_MODIFICATION_TIME) {
        Some(PropOut::Value(PropValue::Time(time))) => time,
        _ => sync_time(),
    };
    let size = match bag.get(tags::MESSAGE_SIZE) {
        Some(PropOut::Value(PropValue::I32(size))) => u32::try_from(size).unwrap_or(entry.size),
        _ => entry.size,
    };
    if config.flags.contains(SynchronizationFlags::PROGRESS) {
        encoder
            .progress_per_message(entry.size, entry.associated())
            .map_err(fx)?;
    }
    encoder
        .message_change_begin(&MessageChangeHeader {
            source_key: &source_key,
            last_modified,
            change_key: &versions.change_key,
            pcl: &versions.pcl,
            associated: entry.associated(),
            mid: config
                .extra
                .contains(SynchronizationExtraFlags::EID)
                .then(|| id.to_eid()),
            size: config
                .extra
                .contains(SynchronizationExtraFlags::MESSAGE_SIZE)
                .then_some(size),
            cn: config
                .extra
                .contains(SynchronizationExtraFlags::CN)
                .then(|| cn.to_eid()),
        })
        .map_err(fx)?;
    let filter = (!(entry.associated()
        && config
            .flags
            .contains(SynchronizationFlags::IGNORE_SPECIFIED_ON_FAI)))
    .then_some(&config.tags);
    let native = config
        .flags
        .contains(SynchronizationFlags::BEST_BODY)
        .then(|| native_body_id(bag))
        .flatten();
    write_message_props(encoder, bag, filter, native, names)?;
    write_children(encoder, content, filter, names, 0)
}

fn native_body_id(bag: &PropBag) -> Option<PropId> {
    match bag.get(tags::NATIVE_BODY) {
        Some(PropOut::Value(PropValue::I32(native_body::PLAIN))) => Some(tags::BODY.id()),
        Some(PropOut::Value(PropValue::I32(native_body::RTF))) => Some(tags::RTF_COMPRESSED.id()),
        Some(PropOut::Value(PropValue::I32(native_body::HTML))) => Some(tags::HTML.id()),
        _ => (carries_value(bag, tags::BODY)
            && !carries_value(bag, tags::HTML)
            && !carries_value(bag, tags::RTF_COMPRESSED))
        .then(|| tags::BODY.id()),
    }
}

fn carries_value(bag: &PropBag, tag: PropTag) -> bool {
    bag.get(tag)
        .is_some_and(|value| !matches!(value, PropOut::Value(PropValue::Error(_))))
}

pub(super) fn write_message_props(
    encoder: &mut FxEncoder,
    bag: &PropBag,
    filter: Option<&TagFilter>,
    native: Option<PropId>,
    names: &dyn NamedPropMap,
) -> Result<(), RopError> {
    for (tag, value) in bag.all() {
        if tag.ptype() == PropType::Error
            || PROVIDER_INTERNAL.contains(&tag.id().0)
            || MESSAGE_SKIP_TAGS.iter().any(|skip| skip.id() == tag.id())
            || filter.is_some_and(|filter| !filter.allows_body(tag, native))
        {
            continue;
        }
        match value {
            PropOut::Value(value) => encoder.prop(tag, &value, names),
            PropOut::Text(text) => encoder.prop_text(tag, text, names),
        }
        .map_err(fx)?;
    }
    Ok(())
}

pub(super) fn write_children(
    encoder: &mut FxEncoder,
    content: &MessageContent,
    filter: Option<&TagFilter>,
    names: &dyn NamedPropMap,
    depth: usize,
) -> Result<(), RopError> {
    if filter.is_none_or(|filter| filter.allows(subobject::MESSAGE_RECIPIENTS)) {
        if depth == 0 {
            encoder
                .fx_del_prop(subobject::MESSAGE_RECIPIENTS)
                .map_err(fx)?;
        }
        for (row, recipient) in content.recipients.iter().enumerate() {
            encoder.marker(Marker::StartRecip).map_err(fx)?;
            if recipient
                .get_any(PropKeyRef::Tag(tags::ROWID.id()))
                .is_none()
            {
                encoder
                    .prop(
                        tags::ROWID,
                        &PropValue::I32(i32::try_from(row).unwrap_or(i32::MAX)),
                        names,
                    )
                    .map_err(fx)?;
            }
            write_content_props(encoder, recipient, None, names)?;
            encoder.marker(Marker::EndToRecip).map_err(fx)?;
        }
    }
    if filter.is_none_or(|filter| filter.allows(subobject::MESSAGE_ATTACHMENTS)) {
        if depth == 0 {
            encoder
                .fx_del_prop(subobject::MESSAGE_ATTACHMENTS)
                .map_err(fx)?;
        }
        for (number, attachment) in numbered_attachments(content) {
            encoder.marker(Marker::NewAttach).map_err(fx)?;
            encoder
                .prop(
                    tags::ATTACH_NUMBER,
                    &PropValue::I32(i32::try_from(number).unwrap_or(i32::MAX)),
                    names,
                )
                .map_err(fx)?;
            write_attachment_content(encoder, attachment, None, names, depth)?;
            encoder.marker(Marker::EndAttach).map_err(fx)?;
        }
    }
    Ok(())
}

const ATTACH_METHOD_BY_VALUE: i32 = 1;
const ATTACH_METHOD_EMBEDDED: i32 = 5;
const EMBEDDED_MESSAGE_ID: i64 = 0;

pub(super) fn write_attachment_content(
    encoder: &mut FxEncoder,
    attachment: &Attachment,
    filter: Option<&TagFilter>,
    names: &dyn NamedPropMap,
    depth: usize,
) -> Result<(), RopError> {
    let allows = |tag: PropTag| filter.is_none_or(|filter| filter.allows(tag));
    write_content_props(encoder, &attachment.props, filter, names)?;
    if allows(tags::ATTACH_METHOD)
        && attachment
            .props
            .get_any(PropKeyRef::Tag(tags::ATTACH_METHOD.id()))
            .is_none()
    {
        let method = match attachment.data {
            AttachData::Embedded(_) => ATTACH_METHOD_EMBEDDED,
            _ => ATTACH_METHOD_BY_VALUE,
        };
        encoder
            .prop(tags::ATTACH_METHOD, &PropValue::I32(method), names)
            .map_err(fx)?;
    }
    if allows(tags::ATTACH_SIZE)
        && let Some(size) = derived_attach_size(attachment)
    {
        encoder
            .prop(tags::ATTACH_SIZE, &PropValue::I32(size), names)
            .map_err(fx)?;
    }
    match &attachment.data {
        AttachData::Bytes(bytes) if allows(tags::ATTACH_DATA_BINARY) => {
            encoder
                .prop(tags::ATTACH_DATA_BINARY, &PropValue::Binary(bytes), names)
                .map_err(fx)?;
        }
        AttachData::Embedded(embedded)
            if depth < MAX_EMBED_DEPTH && allows(tags::ATTACH_DATA_OBJECT) =>
        {
            encoder.marker(Marker::StartEmbed).map_err(fx)?;
            encoder
                .prop(tags::MID, &PropValue::I64(EMBEDDED_MESSAGE_ID), names)
                .map_err(fx)?;
            write_content_props(encoder, &embedded.props, None, names)?;
            write_children(encoder, embedded, None, names, depth.saturating_add(1))?;
            encoder.marker(Marker::EndEmbed).map_err(fx)?;
        }
        AttachData::Bytes(_)
        | AttachData::Embedded(_)
        | AttachData::None
        | AttachData::Deferred(_) => {}
    }
    Ok(())
}

fn write_content_props(
    encoder: &mut FxEncoder,
    props: &ContentBag,
    filter: Option<&TagFilter>,
    names: &dyn NamedPropMap,
) -> Result<(), RopError> {
    for (key, value) in props.iter() {
        let key = key.as_ref();
        if let PropKeyRef::Tag(id) = key
            && (PROVIDER_INTERNAL.contains(&id.0) || id == tags::ATTACH_NUMBER.id())
        {
            continue;
        }
        if let Some(filter) = filter {
            let allowed = match key {
                PropKeyRef::Tag(id) => filter.allows_id(id),
                PropKeyRef::Lid { .. } | PropKeyRef::Name { .. } => {
                    names.id(key).is_some_and(|id| filter.allows_id(id))
                }
            };
            if !allowed {
                continue;
            }
        }
        encoder.prop_owned(key, value, names).map_err(fx)?;
    }
    Ok(())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/ics/content/tests.rs"]
mod tests;
