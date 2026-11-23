/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod body;
pub mod category;
pub mod collapse;
pub mod contents;
pub mod filter;
pub mod permissions;
pub mod rops;
mod search;

use super::{
    execute::{RopContext, RopError},
    folder::{folder_bag, push_change_time, push_folder_state, stored_mailbox, subtree_change},
    props::{PropBag, PropOut},
    state::{Handle, MAX_TABLE_STATE_BYTES, ServerObject, TableKind, TableObject},
    store::StoreGuids,
};
use crate::{folders::FolderEntry, mapi::ids::MapiId};
use body::MAX_BODY_TERMS;
use category::{LEAF_ROW, SortKeys};
use contents::push_row_instance;
use exchange_proto::mapi::{
    ErrorCode, MapiLimits,
    prop::{CodePage, CountWidth, PropId, PropTag, PropValue, tags},
    restriction::{Restriction, RestrictionBytes, RestrictionNode},
};
use filter::{RowFilter, SortKey};
use std::cmp::Ordering;

const MAX_RESTRICTION_BYTES: usize = 16 * 1024;
const COUNT_COLUMNS: [PropId; 2] = [tags::CONTENT_COUNT.id(), tags::CONTENT_UNREAD_COUNT.id()];

pub const HIERARCHY_COLUMNS: [PropTag; 18] = [
    tags::OBJECT_TYPE,
    tags::FOLDER_ID,
    tags::ENTRY_ID,
    tags::SOURCE_KEY,
    tags::PARENT_FOLDER_ID,
    tags::PARENT_ENTRY_ID,
    tags::PARENT_SOURCE_KEY,
    tags::DISPLAY_NAME,
    tags::CONTAINER_CLASS,
    tags::FOLDER_TYPE,
    tags::SUBFOLDERS,
    tags::CONTENT_COUNT,
    tags::CONTENT_UNREAD_COUNT,
    tags::ASSOC_CONTENT_COUNT,
    tags::DEPTH,
    tags::INSTANCE_KEY,
    tags::INST_ID,
    tags::INSTANCE_NUM,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowPurpose {
    Positions,
    Page,
    Values,
}

fn counted(tag: PropTag) -> bool {
    COUNT_COLUMNS.contains(&tag.id())
}

pub fn references(restriction: &Restriction<'_>, check: impl Fn(PropTag) -> bool) -> bool {
    restriction.nodes.iter().any(|node| match node {
        RestrictionNode::Content { tag, .. }
        | RestrictionNode::Property { tag, .. }
        | RestrictionNode::Bitmask { tag, .. }
        | RestrictionNode::Size { tag, .. }
        | RestrictionNode::Exist(tag) => check(*tag),
        RestrictionNode::CompareProps { a, b, .. } => check(*a) || check(*b),
        _ => false,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RowContent {
    Keys,
    Props { counters: bool },
}

impl TableObject {
    pub(super) fn mark_leaf_rows(&self, rows: &mut [TableRow]) {
        if self.categories.is_none() && self.wants(tags::ROW_TYPE) {
            for row in rows {
                if !matches!(
                    row.bag.get(tags::ROW_TYPE),
                    Some(PropOut::Value(PropValue::I32(LEAF_ROW)))
                ) {
                    row.bag.push_i32(tags::ROW_TYPE, LEAF_ROW);
                }
            }
        }
    }

    pub(super) fn uncounted_rows<'r>(
        &self,
        rows: &'r mut [TableRow],
    ) -> impl Iterator<Item = &'r mut TableRow> {
        let rows = if self.wants(tags::DELETED_COUNT_TOTAL) {
            rows
        } else {
            &mut []
        };
        rows.iter_mut()
            .filter(|row| !row.bag.contains(tags::DELETED_COUNT_TOTAL))
    }

    pub(super) fn wants(&self, tag: PropTag) -> bool {
        self.columns
            .iter()
            .any(|column| PropTag(*column).id() == tag.id())
    }

    pub(super) fn require_columns(&self) -> Result<(), RopError> {
        if self.columns.is_empty() {
            Err(RopError::Code(ErrorCode::NULL_OBJECT))
        } else {
            Ok(())
        }
    }

    fn row_content(
        &self,
        purpose: RowPurpose,
        restriction: Option<&Restriction<'_>>,
    ) -> RowContent {
        match purpose {
            RowPurpose::Values | RowPurpose::Page => RowContent::Props { counters: true },
            RowPurpose::Positions if restriction.is_none() && self.sort.is_empty() => {
                RowContent::Keys
            }
            RowPurpose::Positions => RowContent::Props {
                counters: self.sort.iter().any(|column| counted(PropTag(column.tag)))
                    || restriction.is_some_and(|restriction| references(restriction, counted)),
            },
        }
    }

    fn built_content(
        &self,
        purpose: RowPurpose,
        restriction: Option<&Restriction<'_>>,
    ) -> RowContent {
        match self.kind {
            TableKind::Contents { associated: false }
                if purpose == RowPurpose::Page && restriction.is_none() && self.sort.is_empty() =>
            {
                RowContent::Keys
            }
            _ => self.row_content(purpose, restriction),
        }
    }

    fn same_rows(&self, other: &TableObject) -> bool {
        self.folder == other.folder
            && self.kind == other.kind
            && self.columns == other.columns
            && self.sort == other.sort
            && self.categories == other.categories
            && self.restriction == other.restriction
    }
}

pub struct RowCache {
    handle: Handle,
    table: TableObject,
    content: RowContent,
    rows: Option<Vec<TableRow>>,
}

pub struct TableRow {
    pub key: u64,
    pub bag: PropBag,
}

impl TableRow {
    pub fn get(&self, tag: PropTag) -> Option<PropOut<'_>> {
        self.bag.get(tag)
    }

    pub fn has_all(&self, columns: &[PropTag]) -> bool {
        columns.iter().all(|tag| {
            self.bag
                .get(*tag)
                .is_some_and(|value| value.matches(tag.ptype()))
        })
    }
}

pub fn decode_restriction(bytes: &[u8]) -> Result<Option<Restriction<'_>>, RopError> {
    RestrictionBytes(bytes)
        .decode(
            CountWidth::Rop,
            false,
            MapiLimits::DEFAULT.restriction_depth,
        )
        .map_err(|_| RopError::Code(ErrorCode::TOO_COMPLEX))
}

fn bounded_restriction(bytes: &[u8]) -> Result<Option<Restriction<'_>>, RopError> {
    if bytes.len() > MAX_RESTRICTION_BYTES {
        return Err(RopError::Code(ErrorCode::TOO_COMPLEX));
    }
    decode_restriction(bytes)
}

fn bounded_filter<'r>(
    restriction: &'r Restriction<'r>,
    code_page: CodePage,
) -> Result<RowFilter<'r>, RopError> {
    RowFilter::new(restriction, code_page)
        .filter(|filter| filter.body_terms().nth(MAX_BODY_TERMS).is_none())
        .ok_or(RopError::Code(ErrorCode::TOO_COMPLEX))
}

pub fn validate_restriction(bytes: &[u8], code_page: CodePage) -> Result<(), RopError> {
    if let Some(restriction) = bounded_restriction(bytes)? {
        bounded_filter(&restriction, code_page)?;
    }
    Ok(())
}

impl RopContext<'_, '_> {
    pub fn table(&self, handle: Handle) -> Result<&TableObject, RopError> {
        match self.state.get(handle) {
            Some(ServerObject::Table(table)) => Ok(table),
            Some(_) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        }
    }

    pub fn table_mut(&mut self, handle: Handle) -> Result<&mut TableObject, RopError> {
        match self.state.get_mut(handle) {
            Some(ServerObject::Table(table)) => Ok(table),
            Some(_) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        }
    }

    pub fn charge_table(&self, handle: Handle, footprint: usize) -> Result<(), RopError> {
        if self
            .state
            .table_bytes_except(handle)
            .saturating_add(footprint)
            > MAX_TABLE_STATE_BYTES
        {
            Err(RopError::Code(ErrorCode::NOT_ENOUGH_MEMORY))
        } else {
            Ok(())
        }
    }

    pub async fn handle_rows(
        &mut self,
        handle: Handle,
        table: &TableObject,
        purpose: RowPurpose,
    ) -> Result<Vec<TableRow>, RopError> {
        if !matches!(
            table.kind,
            TableKind::Contents { .. } | TableKind::Hierarchy { .. }
        ) {
            return self.table_rows(table, purpose).await;
        }
        let restriction = decode_restriction(&table.restriction)?;
        let content = table.built_content(purpose, restriction.as_ref());
        if let Some(cache) = self.rows.as_mut()
            && cache.handle == handle
            && cache.content >= content
            && cache.table.same_rows(table)
            && let Some(rows) = cache.rows.take()
        {
            return Ok(rows);
        }
        self.rows = None;
        let rows = self.build_rows(table, restriction, content).await?;
        self.rows = Some(RowCache {
            handle,
            table: table.clone(),
            content,
            rows: None,
        });
        Ok(rows)
    }

    pub fn keep_rows(&mut self, handle: Handle, rows: Vec<TableRow>) {
        if let Some(cache) = self.rows.as_mut()
            && cache.handle == handle
            && cache.rows.is_none()
        {
            cache.rows = Some(rows);
        }
    }

    pub async fn table_rows(
        &mut self,
        table: &TableObject,
        purpose: RowPurpose,
    ) -> Result<Vec<TableRow>, RopError> {
        let restriction = decode_restriction(&table.restriction)?;
        let content = table.built_content(purpose, restriction.as_ref());
        self.build_rows(table, restriction, content).await
    }

    async fn build_rows(
        &mut self,
        table: &TableObject,
        restriction: Option<Restriction<'_>>,
        content: RowContent,
    ) -> Result<Vec<TableRow>, RopError> {
        let mut rows = match table.kind {
            TableKind::Hierarchy { depth } => {
                self.hierarchy_rows(table, depth, content, None).await?
            }
            TableKind::Contents { associated } => {
                let node = table
                    .folder
                    .id()
                    .and_then(MapiId::to_node)
                    .ok_or(ErrorCode::OBJECT_DELETED)?;
                self.require_items(table.folder.mailbox_id, node).await?;
                let envelope =
                    content != RowContent::Keys && table.envelope_in_order(restriction.as_ref());
                self.contents_rows(table, associated, content, envelope)
                    .await?
            }
            TableKind::Attachments => self.attachment_rows(table, content).await?,
            TableKind::Permissions { free_busy } => self.permission_rows(table, free_busy).await?,
            TableKind::Rules => self.rule_rows(table).await?,
            TableKind::Empty => Vec::new(),
        };
        if let Some(restriction) = restriction {
            let mut filter = RowFilter::new(&restriction, self.code_page())
                .ok_or(RopError::Code(ErrorCode::TOO_COMPLEX))?;
            let documents = match self.body_rows(table, &filter).await? {
                Some(email_rows) => {
                    self.resolve_body_terms(table.folder.mailbox_id, email_rows, &mut filter, &rows)
                        .await?
                }
                None => None,
            };
            rows.retain(|row| {
                filter.matches_document(
                    &|tag| row.get(tag),
                    documents
                        .as_ref()
                        .and_then(|documents| documents.document(row.key)),
                )
            });
        }
        if !table.sort.is_empty() {
            let mut keyed = rows
                .into_iter()
                .map(|row| {
                    let keys = table
                        .sort
                        .iter()
                        .map(|column| SortKey::of(row.get(PropTag(column.tag))))
                        .collect::<SortKeys>();
                    (keys, row)
                })
                .collect::<Vec<_>>();
            keyed.sort_by(|(a, _), (b, _)| {
                a.iter()
                    .zip(b)
                    .zip(&table.sort)
                    .map(|((a, b), column)| {
                        let order = a.compare(b);
                        if column.descending {
                            order.reverse()
                        } else {
                            order
                        }
                    })
                    .find(|order| order.is_ne())
                    .unwrap_or(Ordering::Equal)
            });
            rows = match &table.categories {
                Some(categories) => categories.categorize(keyed, &table.sort),
                None => keyed.into_iter().map(|(_, row)| row).collect(),
            };
        }
        Ok(rows)
    }

    async fn hierarchy_rows(
        &mut self,
        table: &TableObject,
        depth: bool,
        content: RowContent,
        selected: Option<&[u64]>,
    ) -> Result<Vec<TableRow>, RopError> {
        let mailbox_id = table.folder.mailbox_id;
        let node = table
            .folder
            .id()
            .and_then(MapiId::to_node)
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let tree = self.folder_tree(mailbox_id).await?;
        if tree.get(node).is_none() {
            return Err(RopError::Code(ErrorCode::OBJECT_DELETED));
        }
        let mailbox = self.mailbox(mailbox_id).await?;
        let guids = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id);
        let counters = match content {
            RowContent::Props { counters: true } => Some(self.folder_counters(mailbox_id).await?),
            _ => None,
        };
        let rights = self.view_rights(mailbox_id).await?;
        let activity = if content != RowContent::Keys
            && (table.wants(tags::LOCAL_COMMIT_TIME_MAX)
                || table.wants(tags::LAST_MODIFICATION_TIME))
        {
            Some(self.folder_activity(mailbox_id).await?)
        } else {
            None
        };
        let mut rows = Vec::new();
        let mut push = |entry: &FolderEntry, level: i32| {
            let entry_rights = rights.of(entry.node);
            if !entry_rights.is_visible() {
                return;
            }
            let key = MapiId::from_node(entry.node).counter();
            if content == RowContent::Keys
                || selected.is_some_and(|selected| selected.binary_search(&key).is_err())
            {
                rows.push(TableRow {
                    key,
                    bag: PropBag::default(),
                });
                return;
            }
            let mut bag = folder_bag(
                &tree,
                entry,
                &guids,
                &mailbox.exchange,
                counters.as_deref(),
                &rights,
            );
            entry_rights.push_props(&mut bag);
            push_folder_state(&mut bag, &tree, entry);
            if let Some(activity) = &activity {
                let base = subtree_change(&tree, entry);
                let change_id = if entry_rights.reads_items() {
                    activity.change_id(entry.node, base)
                } else {
                    base
                };
                push_change_time(&mut bag, &tree, entry, change_id);
            }
            bag.push_i32(tags::DEPTH, level);
            bag.push_binary(tags::INSTANCE_KEY, &key.to_le_bytes());
            push_row_instance(&mut bag, MapiId::from_folder(&mailbox.exchange, entry.node));
            rows.push(TableRow { key, bag });
        };
        if depth {
            for entry in tree.descendants(node) {
                let mut level = 1;
                let mut parent = entry.parent;
                while let Some(current) = parent.filter(|current| *current != node) {
                    level += 1;
                    parent = tree.get(current).and_then(|entry| entry.parent);
                }
                push(entry, level);
            }
        } else {
            for entry in tree.children(node) {
                push(entry, 1);
            }
        }
        Ok(rows)
    }

    pub(super) async fn changed_rows(
        &mut self,
        table: &TableObject,
        keys: &[u64],
    ) -> Result<Vec<TableRow>, RopError> {
        match table.kind {
            TableKind::Hierarchy { depth }
                if table.sort.is_empty() && table.restriction.is_empty() =>
            {
                self.hierarchy_rows(
                    table,
                    depth,
                    RowContent::Props { counters: true },
                    Some(keys),
                )
                .await
            }
            _ => self.table_rows(table, RowPurpose::Values).await,
        }
    }

    pub(super) async fn complete_hierarchy_rows(
        &mut self,
        table: &TableObject,
        rows: &mut [TableRow],
    ) -> Result<(), RopError> {
        let mut rows = table.uncounted_rows(rows).peekable();
        if rows.peek().is_none() {
            return Ok(());
        }
        let mailbox_id = table.folder.mailbox_id;
        let mailbox = self.mailbox(mailbox_id).await?;
        let rights = self.view_rights(mailbox_id).await?;
        let counters = self.folder_counters(mailbox_id).await?;
        for row in rows {
            let node = MapiId::from_counter(row.key).and_then(MapiId::to_node);
            let count = match (node.and_then(stored_mailbox), node, &mailbox.messages) {
                (Some(id), Some(node), Some(messages)) if rights.of(node).reads_items() => {
                    self.deleted_count(mailbox_id, messages, &counters, id)
                        .await?
                }
                _ => 0,
            };
            row.bag.push_i32(tags::DELETED_COUNT_TOTAL, count);
        }
        Ok(())
    }
}
