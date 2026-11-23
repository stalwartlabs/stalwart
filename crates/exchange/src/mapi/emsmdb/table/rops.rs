/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    HIERARCHY_COLUMNS, RowPurpose, TableRow, bounded_filter, bounded_restriction,
    category::parse_sort, contents::RowFill, permissions::PERMISSION_COLUMNS, references,
    validate_restriction,
};
use crate::mapi::emsmdb::{
    execute::{Packing, RopContext, RopError, RopResult},
    props::PropOut,
    rules::RULE_COLUMNS,
    state::{
        Categories, Handle, ServerObject, SortColumn, TableBookmark, TableKind, TableNotify,
        TableObject,
    },
};
use exchange_proto::mapi::{
    ErrorCode,
    prop::{
        PropTag,
        row::{RowSetLayout, RowSetWriter},
    },
    rop::{
        DecodedRop, ResponseHeader,
        requests::{
            FindRow, FreeBookmark, GetAttachmentTable, GetContentsTable, GetHierarchyTable,
            QueryRows, Restrict, SeekRow, SeekRowBookmark, SeekRowFractional, SetColumns,
            SortTable,
        },
        responses::{
            CreateBookmarkResponse, GetContentsTableResponse, GetHierarchyTableResponse,
            GetPropertiesListResponse, QueryPositionResponse, RestrictResponse,
            SeekRowBookmarkResponse, SeekRowResponse, SetColumnsResponse, SortTableResponse,
            table_row_options,
        },
    },
};
use smallvec::SmallVec;

const TABLE_ASSOCIATED: u8 = 0x02;
const TABLE_DEPTH: u8 = 0x04;
const TABLE_NO_NOTIFICATIONS: u8 = 0x10;
const TABLE_SOFT_DELETES: u8 = 0x20;
const TABLE_USE_UNICODE: u8 = 0x40;
const HIERARCHY_INVALID_FLAGS: u8 = 0x03;
const CONTENTS_INVALID_FLAGS: u8 = 0x05;
const QUERY_NO_ADVANCE: u8 = 0x01;
const FIND_BACKWARD: u8 = 0x01;
const BOOKMARK_BEGINNING: u8 = 0x00;
const BOOKMARK_CURRENT: u8 = 0x01;
const BOOKMARK_END: u8 = 0x02;
const BOOKMARK_CUSTOM: u8 = 0x03;
const TABLE_STATUS_COMPLETE: u8 = 0x00;
const MAX_COLUMNS: usize = 512;
const MAX_SORT_COLUMNS: usize = 16;
const MAX_BOOKMARKS: usize = 64;
const END_OF_TABLE: u32 = u32::MAX;

struct Fraction<'x>(&'x SeekRowFractional);

impl Fraction<'_> {
    fn bound(&self) -> Option<u32> {
        match self.0.numerator {
            0 => Some(0),
            numerator if numerator >= self.0.denominator => Some(END_OF_TABLE),
            _ => None,
        }
    }

    fn position(&self, len: u32) -> u32 {
        self.bound().unwrap_or_else(|| {
            let denominator = u64::from(self.0.denominator);
            let scaled =
                (u64::from(len) * u64::from(self.0.numerator) + denominator / 2) / denominator;
            u32::try_from(scaled).unwrap_or(len)
        })
    }
}

struct Seek {
    position: u32,
    moved: i32,
}

impl Seek {
    fn from(base: u32, len: u32, delta: i32) -> Self {
        let target = (i64::from(base) + i64::from(delta)).clamp(0, i64::from(len));
        let position = u32::try_from(target).unwrap_or(len);
        let moved = i32::try_from(target - i64::from(base)).unwrap_or(delta);
        Seek { position, moved }
    }
}

pub(super) fn row_count(rows: &[TableRow]) -> u32 {
    u32::try_from(rows.len()).unwrap_or(u32::MAX)
}

fn bookmark_id(bookmark: &[u8]) -> Result<u32, RopError> {
    match bookmark {
        [a, b, c, d] => Ok(u32::from_le_bytes([*a, *b, *c, *d])),
        _ => Err(RopError::Code(ErrorCode::INVALID_BOOKMARK)),
    }
}

pub(super) fn write_row(
    rows: &mut RowSetWriter<'_, '_>,
    columns: &[PropTag],
    row: &TableRow,
) -> Result<(), RopError> {
    let mut writer = rows.row(columns, row.has_all(columns))?;
    for tag in columns {
        PropOut::write_cell(&mut writer, *tag, row.get(*tag).as_ref());
    }
    Ok(())
}

impl RopContext<'_, '_> {
    pub async fn get_hierarchy_table(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &GetHierarchyTable,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let folder = match self.state.get(parent) {
            Some(ServerObject::Folder(folder)) => *folder,
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        let flags = request.table_flags;
        if flags & HIERARCHY_INVALID_FLAGS != 0 {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let mut table = TableObject::new(
            folder,
            if flags & TABLE_SOFT_DELETES != 0 {
                TableKind::Empty
            } else {
                TableKind::Hierarchy {
                    depth: flags & TABLE_DEPTH != 0,
                }
            },
            flags & TABLE_USE_UNICODE != 0,
        );
        if flags & TABLE_NO_NOTIFICATIONS != 0 {
            table.notify = TableNotify::Disabled;
        }
        let count = row_count(&self.table_rows(&table, RowPurpose::Positions).await?);
        let logon_id = self
            .state
            .logon_id(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        self.open_table(request.output_handle_index, logon_id, table)?;
        self.respond(
            rop,
            request.output_handle_index,
            &GetHierarchyTableResponse { row_count: count },
        )
    }

    pub async fn get_contents_table(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &GetContentsTable,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let folder = match self.state.get(parent) {
            Some(ServerObject::Folder(folder)) => *folder,
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        let flags = request.table_flags;
        if flags & CONTENTS_INVALID_FLAGS != 0 {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        let mut table = TableObject::new(
            folder,
            if flags & TABLE_SOFT_DELETES != 0 {
                TableKind::Empty
            } else {
                TableKind::Contents {
                    associated: flags & TABLE_ASSOCIATED != 0,
                }
            },
            flags & TABLE_USE_UNICODE != 0,
        );
        if flags & TABLE_NO_NOTIFICATIONS != 0 {
            table.notify = TableNotify::Disabled;
        }
        let count = row_count(&self.table_rows(&table, RowPurpose::Positions).await?);
        let logon_id = self
            .state
            .logon_id(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        self.open_table(request.output_handle_index, logon_id, table)?;
        self.respond(
            rop,
            request.output_handle_index,
            &GetContentsTableResponse { row_count: count },
        )
    }

    pub fn get_attachment_table(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &GetAttachmentTable,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let message = match self.state.get(parent) {
            Some(ServerObject::Message(message)) => message.without_columns(),
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        let mut table = TableObject::new(
            message.folder(),
            TableKind::Attachments,
            request.table_flags & TABLE_USE_UNICODE != 0,
        );
        table.message = Some(message);
        let logon_id = self
            .state
            .logon_id(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        self.open_table(request.output_handle_index, logon_id, table)?;
        self.respond_empty(rop, request.output_handle_index)
    }

    pub(super) fn open_table(&mut self, index: u8, logon_id: u8, table: TableObject) -> RopResult {
        let handle = self
            .state
            .insert(logon_id, ServerObject::Table(Box::new(table)))?;
        self.set_output(index, handle)
    }

    pub fn set_columns(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SetColumns<'_>,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let tags = request.property_tags.iter();
        let rejected = if tags.len() == 0 {
            Some(ErrorCode::INVALID_PARAM)
        } else if tags.len() > MAX_COLUMNS {
            Some(ErrorCode::TOO_BIG)
        } else if !request.property_tags.iter().all(PropTag::has_known_type) {
            Some(ErrorCode::INVALID_PARAM)
        } else {
            None
        };
        if let Some(code) = rejected {
            self.table_mut(handle)?.columns.clear();
            return Err(RopError::Code(code));
        }
        let table = self.table(handle)?;
        self.charge_table(
            handle,
            table.footprint() - table.columns.len() * size_of::<u32>()
                + tags.len() * size_of::<u32>(),
        )?;
        let table = self.table_mut(handle)?;
        table.columns.clear();
        table.columns.extend(tags.map(|tag| tag.0));
        self.respond(
            rop,
            index,
            &SetColumnsResponse {
                table_status: TABLE_STATUS_COMPLETE,
            },
        )
    }

    pub fn sort_table(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SortTable<'_>,
    ) -> RopResult {
        let orders = &request.sort_orders;
        if orders.orders.len() > MAX_SORT_COLUMNS {
            return Err(RopError::Code(ErrorCode::TOO_COMPLEX));
        }
        let (sort, categories) =
            parse_sort(orders.categories, orders.expanded, orders.orders.iter())?;
        let handle = self.input(rop.header.input_handle)?;
        let table = self.table(handle)?;
        if categories.is_some() && !matches!(table.kind, TableKind::Contents { .. }) {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        self.charge_table(
            handle,
            table.columns.len() * size_of::<u32>()
                + sort.len() * size_of::<SortColumn>()
                + table.restriction.len(),
        )?;
        let table = self.table_mut(handle)?;
        table.sort = sort;
        table.categories = categories;
        table.position = 0;
        table.bookmarks.clear();
        self.respond(
            rop,
            index,
            &SortTableResponse {
                table_status: TABLE_STATUS_COMPLETE,
            },
        )
    }

    pub fn restrict(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &Restrict<'_>,
    ) -> RopResult {
        let bytes = request.restriction_data.0;
        validate_restriction(bytes, self.code_page())?;
        let handle = self.input(rop.header.input_handle)?;
        let table = self.table(handle)?;
        table.kind.require(TableKind::has_restrictions)?;
        self.charge_table(
            handle,
            table.columns.len() * size_of::<u32>()
                + table.sort.len() * size_of::<SortColumn>()
                + table.categories.as_ref().map_or(0, Categories::footprint)
                + bytes.len(),
        )?;
        let table = self.table_mut(handle)?;
        table.restriction.clear();
        table.restriction.extend_from_slice(bytes);
        table.position = 0;
        table.bookmarks.clear();
        self.respond(
            rop,
            index,
            &RestrictResponse {
                table_status: TABLE_STATUS_COMPLETE,
            },
        )
    }

    pub async fn query_rows(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &QueryRows,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let table = self.table(handle)?.clone();
        table.require_columns()?;
        let mut rows = self.handle_rows(handle, &table, RowPurpose::Page).await?;
        let len = row_count(&rows);
        let position = table.position.min(len);
        let count = u32::from(request.row_count);
        let (range, origin) = if request.forward_read {
            let end = position.saturating_add(count).min(len);
            (
                position..end,
                if end == len {
                    BOOKMARK_END
                } else {
                    BOOKMARK_CURRENT
                },
            )
        } else {
            let start = position.saturating_sub(count);
            (
                start..position,
                if start == 0 {
                    BOOKMARK_END
                } else {
                    BOOKMARK_CURRENT
                },
            )
        };
        let columns: SmallVec<[PropTag; 32]> =
            table.columns.iter().map(|tag| PropTag(*tag)).collect();
        let options = table_row_options(table.unicode, self.code_page());
        let page = range.start as usize..range.end as usize;
        if let Some(selected) = rows.get_mut(page.clone()) {
            match table.kind {
                TableKind::Contents { .. } => {
                    self.complete_rows(&table, selected, table.column_fill())
                        .await?;
                    table.mark_leaf_rows(selected);
                }
                TableKind::Hierarchy { .. } => {
                    self.complete_hierarchy_rows(&table, selected).await?
                }
                _ => {}
            }
        }
        let selected = rows.get(page).unwrap_or_default();
        let mut writer = self.writer.row_writer(
            ResponseHeader::new(rop.header.id.response_id(), index, ErrorCode::SUCCESS),
            RowSetLayout::QueryRows { origin },
            options,
        )?;
        let ordered: &mut dyn Iterator<Item = &TableRow> = if request.forward_read {
            &mut selected.iter()
        } else {
            &mut selected.iter().rev()
        };
        for row in ordered {
            if write_row(&mut writer, &columns, row).is_err() {
                break;
            }
        }
        let kept = writer.finish()?;
        self.keep_rows(handle, rows);
        if request.query_rows_flags & QUERY_NO_ADVANCE == 0 {
            let table = self.table_mut(handle)?;
            table.position = if request.forward_read {
                position.saturating_add(kept)
            } else {
                position.saturating_sub(kept)
            };
            let more = if request.forward_read {
                table.position < len
            } else {
                table.position > 0
            };
            if more
                && kept < count
                && let Some(returned) = u16::try_from(kept).ok().filter(|kept| *kept > 0)
            {
                self.packable(Packing::Rows(returned));
            }
        }
        Ok(())
    }

    pub async fn query_position(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let table = self.table(handle)?.clone();
        let len = self.row_len(handle, &table).await?;
        self.respond(
            rop,
            index,
            &QueryPositionResponse {
                numerator: table.position.min(len),
                denominator: len,
            },
        )
    }

    pub async fn seek_row(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SeekRow,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let table = self.table(handle)?.clone();
        let len = self.row_len(handle, &table).await?;
        let base = match request.origin {
            BOOKMARK_BEGINNING => 0,
            BOOKMARK_CURRENT => table.position.min(len),
            BOOKMARK_END => len,
            _ => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
        };
        let seek = Seek::from(base, len, request.row_count);
        self.table_mut(handle)?.position = seek.position;
        self.respond(
            rop,
            index,
            &SeekRowResponse {
                has_sought_less: request.want_row_moved_count && seek.moved != request.row_count,
                rows_sought: seek.moved,
            },
        )
    }

    pub async fn seek_row_fractional(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SeekRowFractional,
    ) -> RopResult {
        let fraction = Fraction(request);
        let handle = self.input(rop.header.input_handle)?;
        let position = match fraction.bound() {
            Some(position) => position,
            None => {
                let table = self.table(handle)?.clone();
                fraction.position(self.row_len(handle, &table).await?)
            }
        };
        self.table_mut(handle)?.position = position;
        self.respond_empty(rop, index)
    }

    pub async fn seek_row_bookmark(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SeekRowBookmark<'_>,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let table = self.table(handle)?.clone();
        table.kind.require(TableKind::has_bookmarks)?;
        table.require_columns()?;
        let bookmark = table.find_bookmark(bookmark_id(request.bookmark)?)?;
        let rows = self
            .handle_rows(handle, &table, RowPurpose::Positions)
            .await?;
        let len = row_count(&rows);
        let (base, visible) = locate(&rows, &bookmark, len);
        self.keep_rows(handle, rows);
        let seek = Seek::from(base, len, request.row_count);
        self.table_mut(handle)?.position = seek.position;
        self.respond(
            rop,
            index,
            &SeekRowBookmarkResponse {
                row_no_longer_visible: !visible,
                has_sought_less: request.want_row_moved_count && seek.moved != request.row_count,
                rows_sought: u32::from_le_bytes(seek.moved.to_le_bytes()),
            },
        )
    }

    pub async fn create_bookmark(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let table = self.table(handle)?.clone();
        table.kind.require(TableKind::has_bookmarks)?;
        self.check_bookmark_room(handle, &table)?;
        let rows = self
            .handle_rows(handle, &table, RowPurpose::Positions)
            .await?;
        let position = table.position.min(row_count(&rows));
        let row = rows.get(position as usize).map_or(u64::MAX, |row| row.key);
        self.keep_rows(handle, rows);
        let id = self.push_bookmark(handle, row, position)?;
        self.respond(
            rop,
            index,
            &CreateBookmarkResponse {
                bookmark: &id.to_le_bytes(),
            },
        )
    }

    async fn row_len(&mut self, handle: Handle, table: &TableObject) -> Result<u32, RopError> {
        let rows = self
            .handle_rows(handle, table, RowPurpose::Positions)
            .await?;
        let len = row_count(&rows);
        self.keep_rows(handle, rows);
        Ok(len)
    }

    pub(super) fn check_bookmark_room(
        &self,
        handle: Handle,
        table: &TableObject,
    ) -> Result<(), RopError> {
        if table.bookmarks.len() >= MAX_BOOKMARKS {
            return Err(RopError::Code(ErrorCode::NOT_ENOUGH_MEMORY));
        }
        self.charge_table(handle, table.footprint() + size_of::<TableBookmark>())
    }

    pub(super) fn push_bookmark(
        &mut self,
        handle: Handle,
        row: u64,
        position: u32,
    ) -> Result<u32, RopError> {
        let table = self.table_mut(handle)?;
        let id = table.next_bookmark;
        table.next_bookmark = id.wrapping_add(1).max(1);
        table.bookmarks.push(TableBookmark { id, row, position });
        Ok(id)
    }

    pub fn free_bookmark(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &FreeBookmark<'_>,
    ) -> RopResult {
        let table = self.table_mut(self.input(rop.header.input_handle)?)?;
        table.kind.require(TableKind::has_bookmarks)?;
        table.require_columns()?;
        let id = bookmark_id(request.bookmark)?;
        let before = table.bookmarks.len();
        table.bookmarks.retain(|bookmark| bookmark.id != id);
        if table.bookmarks.len() == before {
            return Err(RopError::Code(ErrorCode::INVALID_BOOKMARK));
        }
        self.respond_empty(rop, index)
    }

    pub async fn find_row(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &FindRow<'_>,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let table = self.table(handle)?.clone();
        table.kind.require(TableKind::has_restrictions)?;
        table.require_columns()?;
        let restriction = bounded_restriction(request.restriction_data.0)?
            .ok_or(RopError::Code(ErrorCode::INVALID_PARAM))?;
        let mut filter = bounded_filter(&restriction, self.code_page())?;
        let mut rows = self.handle_rows(handle, &table, RowPurpose::Values).await?;
        let contents = matches!(table.kind, TableKind::Contents { .. });
        if contents {
            let fill = if references(&restriction, table.envelope_column()) {
                RowFill::Envelope
            } else {
                RowFill::State
            };
            self.complete_rows(&table, &mut rows, fill).await?;
        }
        let len = row_count(&rows);
        let (start, visible) = match request.origin {
            BOOKMARK_BEGINNING => (0, true),
            BOOKMARK_CURRENT => (table.position.min(len), true),
            BOOKMARK_END => (len, true),
            BOOKMARK_CUSTOM => locate(
                &rows,
                &table.find_bookmark(bookmark_id(request.bookmark)?)?,
                len,
            ),
            _ => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
        };
        let start = start as usize;
        let documents = match self.body_rows(&table, &filter).await? {
            Some(email_rows) => {
                self.resolve_body_terms(table.folder.mailbox_id, email_rows, &mut filter, &rows)
                    .await?
            }
            None => None,
        };
        let matches = |row: &&TableRow| {
            filter.matches_document(
                &|tag| row.get(tag),
                documents
                    .as_ref()
                    .and_then(|documents| documents.document(row.key)),
            )
        };
        let found = if request.find_row_flags & FIND_BACKWARD != 0 {
            rows.get(..start)
                .unwrap_or_default()
                .iter()
                .rposition(|row| matches(&row))
        } else {
            rows.get(start..)
                .unwrap_or_default()
                .iter()
                .position(|row| matches(&row))
                .map(|offset| start + offset)
        };
        let Some(position) = found else {
            self.keep_rows(handle, rows);
            return Err(RopError::Code(ErrorCode::NOT_FOUND));
        };
        if contents && let Some(row) = rows.get_mut(position..=position) {
            self.complete_rows(&table, row, table.column_fill()).await?;
            table.mark_leaf_rows(row);
        }
        let row = rows
            .get(position)
            .ok_or(RopError::Code(ErrorCode::NOT_FOUND))?;
        let columns: SmallVec<[PropTag; 32]> =
            table.columns.iter().map(|tag| PropTag(*tag)).collect();
        let options = table_row_options(table.unicode, self.code_page());
        let mut writer = self.writer.row_writer(
            ResponseHeader::new(rop.header.id.response_id(), index, ErrorCode::SUCCESS),
            RowSetLayout::FindRow {
                no_longer_visible: !visible,
            },
            options,
        )?;
        write_row(&mut writer, &columns, row)?;
        writer.finish()?;
        self.keep_rows(handle, rows);
        self.table_mut(handle)?.position = u32::try_from(position).unwrap_or(len);
        Ok(())
    }

    pub fn query_columns_all(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        let property_tags: &[PropTag] = match self.table(self.input(rop.header.input_handle)?)?.kind
        {
            TableKind::Permissions { .. } => &PERMISSION_COLUMNS,
            TableKind::Rules => &RULE_COLUMNS,
            _ => &HIERARCHY_COLUMNS,
        };
        self.respond(rop, index, &GetPropertiesListResponse { property_tags })
    }

    pub fn reset_table(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        let table = self.table_mut(self.input(rop.header.input_handle)?)?;
        table.kind.require(TableKind::has_restrictions)?;
        table.columns.clear();
        table.sort.clear();
        table.categories = None;
        table.restriction.clear();
        table.bookmarks.clear();
        table.position = 0;
        if table.notify == TableNotify::Active {
            table.notify = TableNotify::Paused;
        }
        self.respond_empty(rop, index)
    }
}

impl TableObject {
    fn find_bookmark(&self, id: u32) -> Result<TableBookmark, RopError> {
        self.bookmarks
            .iter()
            .find(|bookmark| bookmark.id == id)
            .copied()
            .ok_or(RopError::Code(ErrorCode::INVALID_BOOKMARK))
    }
}

fn locate(rows: &[TableRow], bookmark: &TableBookmark, len: u32) -> (u32, bool) {
    if bookmark.row == u64::MAX {
        return (bookmark.position.min(len), true);
    }
    match rows.iter().position(|row| row.key == bookmark.row) {
        Some(position) => (u32::try_from(position).unwrap_or(len), true),
        None => (bookmark.position.min(len), false),
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/table/rops/tests.rs"]
mod tests;
