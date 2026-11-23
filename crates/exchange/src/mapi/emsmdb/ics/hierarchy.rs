/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::stream::folder_cn;
use crate::{
    folders::{
        ContainerClass, FolderCreate, FolderNode, FolderTree, FolderUpdate, FolderWriteError,
        FolderWrites,
    },
    mapi::{
        emsmdb::{
            execute::{RopContext, RopError, RopResult},
            folder_write::child_kind,
            store::StoreGuids,
        },
        ids::{IdSpace, MapiId},
        text::decode_text,
    },
};
use exchange_proto::{
    ics::{Pcl, PclOrder, SyncKind},
    ids::{Gid, Xid},
    mapi::{
        ErrorCode,
        prop::{PropValue, TaggedValues, tags},
        rop::{
            DecodedRop, requests::SynchronizationImportHierarchyChange,
            responses::SynchronizationImportHierarchyChangeResponse,
        },
    },
};
use std::fmt::Write;

const MAX_NAME_SUFFIX: u32 = 99;
const MAX_SUFFIX_LEN: usize = 5;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Placement {
    AsNamed,
    Renamed,
}

struct HierarchyHeader<'x> {
    parent_key: &'x [u8],
    source_key: &'x [u8],
    name: PropValue<'x>,
    pcl: Pcl,
}

impl<'x> HierarchyHeader<'x> {
    fn parse(values: &TaggedValues<'x>) -> Option<Self> {
        let mut values = values.iter();
        let (
            Some((parent_tag, PropValue::Binary(parent_key))),
            Some((source_tag, PropValue::Binary(source_key))),
            Some((time_tag, PropValue::Time(_))),
            Some((key_tag, PropValue::Binary(change_key))),
            Some((pcl_tag, PropValue::Binary(pcl))),
            Some((name_tag, name @ (PropValue::Unicode(_) | PropValue::String8(_)))),
            None,
        ) = (
            values.next(),
            values.next(),
            values.next(),
            values.next(),
            values.next(),
            values.next(),
            values.next(),
        )
        else {
            return None;
        };
        if parent_tag.id() != tags::PARENT_SOURCE_KEY.id()
            || source_tag.id() != tags::SOURCE_KEY.id()
            || time_tag.id() != tags::LAST_MODIFICATION_TIME.id()
            || key_tag.id() != tags::CHANGE_KEY.id()
            || pcl_tag.id() != tags::PREDECESSOR_CHANGE_LIST.id()
            || name_tag.id() != tags::DISPLAY_NAME.id()
        {
            return None;
        }
        Xid::decode(change_key)?;
        Gid::from_wire(source_key)?;
        if !parent_key.is_empty() {
            Gid::from_wire(parent_key)?;
        }
        let pcl = Pcl::decode(pcl).ok().filter(|pcl| !pcl.is_empty())?;
        Some(HierarchyHeader {
            parent_key,
            source_key,
            name,
            pcl,
        })
    }
}

impl RopContext<'_, '_> {
    pub async fn synchronization_import_hierarchy_change(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SynchronizationImportHierarchyChange<'_>,
    ) -> RopResult {
        let (collector, root) = self.collector(rop, SyncKind::Hierarchy)?;
        let header =
            HierarchyHeader::parse(&request.hierarchy_values).ok_or(ErrorCode::INVALID_PARAM)?;
        let code_page = self.code_page();
        let mut name = String::new();
        decode_text(&header.name, code_page, &mut name);
        if name.is_empty() {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        let mut class = String::new();
        if let Some((_, value)) = request
            .property_values
            .iter()
            .find(|(tag, _)| tag.id() == tags::CONTAINER_CLASS.id())
        {
            decode_text(&ContainerClass::wire_value(value), code_page, &mut class);
        }
        let account_id = root.mailbox_id;
        let view = self.mailbox(account_id).await?;
        let guids = StoreGuids::new(view.exchange.store_instance, account_id);
        let root_node = root
            .id()
            .and_then(MapiId::to_node)
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let parent = if header.parent_key.is_empty() {
            root_node
        } else {
            guids
                .folder_node(&view.exchange, header.parent_key)
                .ok_or(ErrorCode::SYNC_NO_PARENT)?
        };
        let tree = self.folder_tree(account_id).await?;
        let parent_entry = tree.get(parent).ok_or(ErrorCode::SYNC_NO_PARENT)?;
        let server = self.request.server;
        let access_token = self.request.access_token;
        let local = guids.local_id(header.source_key);
        let mut order = PclOrder::Newer;
        let mut placement = Placement::AsNamed;
        let given;
        let node = match guids.folder_node(&view.exchange, header.source_key) {
            Some(node) => {
                given = Some(MapiId::from_folder(&view.exchange, node));
                let entry = tree.get(node).ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
                self.check_folder_type(node)?;
                if let Some(cn) = folder_cn(&tree, entry)
                    && !self.collector_seen(collector, guids.replica, cn)?
                {
                    let mut server = Pcl::new();
                    server.merge(&cn.xid(guids.replica));
                    order = header.pcl.compare(&server);
                }
                let update = FolderUpdate {
                    name: (entry.special.is_none() && *entry.name != *name)
                        .then_some(name.as_str()),
                    parent: (entry.parent != Some(parent)).then_some(parent),
                };
                if order != PclOrder::OlderOrEqual
                    && (update.name.is_some() || update.parent.is_some())
                {
                    let mut result = server
                        .folder_update(access_token, account_id, node, update)
                        .await?;
                    if let Err(clash @ FolderWriteError::AlreadyExists(_)) = result
                        && entry.special.is_none()
                        && let Some(free) = free_sibling_name(&tree, parent, &name)
                    {
                        placement = Placement::Renamed;
                        result = server
                            .folder_update(
                                access_token,
                                account_id,
                                node,
                                FolderUpdate {
                                    name: Some(free.as_str()),
                                    ..update
                                },
                            )
                            .await?
                            .map_err(|_| clash);
                    }
                    self.invalidate_mailbox();
                    result?;
                }
                node
            }
            None if local.is_some_and(|id| id.space.is_folder()) => {
                return Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED));
            }
            None => {
                let container_class = (!class.is_empty()).then(|| ContainerClass::parse(&class));
                let (kind, child_class) =
                    child_kind(parent, parent_entry, container_class.as_ref())
                        .ok_or(ErrorCode::NOT_SUPPORTED)?;
                self.check_writable(kind)?;
                let client_key = match local.filter(|id| id.space == IdSpace::Email) {
                    Some(id) if self.free_client_key(collector, &view, id.id).await? => Some(id.id),
                    Some(_) => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
                    None => None,
                };
                given = client_key.map(|key| MapiId::new(IdSpace::Email, key));
                let create = FolderCreate {
                    kind,
                    parent,
                    name: &name,
                    class: child_class.map(ContainerClass::as_str),
                    search: None,
                    client_key,
                };
                let mut result = server
                    .folder_create(access_token, account_id, create)
                    .await?;
                if let Err(clash @ FolderWriteError::AlreadyExists(_)) = result
                    && let Some(free) = free_sibling_name(&tree, parent, &name)
                {
                    placement = Placement::Renamed;
                    result = server
                        .folder_create(
                            access_token,
                            account_id,
                            FolderCreate {
                                name: &free,
                                ..create
                            },
                        )
                        .await?
                        .map_err(|_| clash);
                }
                self.invalidate_mailbox();
                FolderNode::Stored(result?.folder)
            }
        };
        let tree = self.folder_tree(account_id).await?;
        let cn = tree
            .get(node)
            .and_then(|entry| folder_cn(&tree, entry))
            .filter(|_| order == PclOrder::Newer && placement == Placement::AsNamed);
        self.record_folder_change(collector, given, cn, guids.replica)?;
        self.respond(rop, index, &SynchronizationImportHierarchyChangeResponse)
    }
}

fn free_sibling_name(tree: &FolderTree, parent: FolderNode, name: &str) -> Option<String> {
    let name = name.trim();
    let mut candidate = String::with_capacity(name.len() + MAX_SUFFIX_LEN);
    for suffix in 2..=MAX_NAME_SUFFIX {
        candidate.clear();
        write!(candidate, "{name} ({suffix})").ok()?;
        if !tree.children(parent).any(|child| {
            child
                .name
                .chars()
                .flat_map(char::to_lowercase)
                .eq(candidate.chars().flat_map(char::to_lowercase))
        }) {
            return Some(candidate);
        }
    }
    None
}
