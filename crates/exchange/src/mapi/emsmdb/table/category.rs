/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{RowPurpose, TableRow, filter::SortKey, rops::row_count};
use crate::mapi::emsmdb::{
    execute::{RopContext, RopError, RopResult},
    props::{PropBag, PropOut},
    state::{Categories, Handle, SortColumn, TableKind, TableObject},
};
use exchange_proto::mapi::{
    ErrorCode,
    prop::{PropTag, PropValue, row::RowSetLayout, tags},
    rop::{
        DecodedRop, ResponseHeader,
        requests::{CollapseRow, ExpandRow},
        responses::{CollapseRowResponse, table_row_options},
    },
    sort::{SortDirection, SortOrder},
};
use smallvec::SmallVec;

pub const MAX_TOGGLED: usize = 2048;
const HEADER_MARK: u64 = 0x8000_0001_0000_0000;
const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
pub(super) const LEAF_ROW: i32 = 1;
const EXPANDED_CATEGORY: i32 = 3;
const COLLAPSED_CATEGORY: i32 = 4;

pub type SortKeys = SmallVec<[SortKey; 2]>;

struct Group {
    level: u16,
    start: usize,
    end: usize,
    id: u64,
}

struct Header {
    start: usize,
    hides: usize,
    row: TableRow,
}

struct Headers {
    rows: Vec<Header>,
    visible_leaves: usize,
}

struct Run {
    parent: usize,
    start: usize,
    end: usize,
    best: usize,
    maximum: SortKey,
}

struct Fnv(u64);

impl Fnv {
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
        }
    }

    fn key(&mut self, key: &SortKey) {
        match key {
            SortKey::Missing => self.write(&[0]),
            SortKey::Int(value) => {
                self.write(&[1]);
                self.write(&value.to_le_bytes());
            }
            SortKey::Float(value) => {
                self.write(&[2]);
                self.write(&value.to_bits().to_le_bytes());
            }
            SortKey::Text(text) => {
                self.write(&[3]);
                self.write(text.as_bytes());
            }
            SortKey::Bytes(bytes) => {
                self.write(&[4]);
                self.write(bytes);
            }
        }
    }

    fn column(&mut self, column: &SortColumn) {
        self.write(&column.tag.to_le_bytes());
        self.write(&[u8::from(column.descending)]);
    }
}

fn header_id(parent: u64, level: u16, key: &SortKey) -> u64 {
    let mut hash = Fnv(FNV_OFFSET);
    hash.write(&parent.to_le_bytes());
    hash.write(&level.to_le_bytes());
    hash.key(key);
    hash.0 | HEADER_MARK
}

pub fn is_header_id(id: u64) -> bool {
    id & HEADER_MARK == HEADER_MARK
}

pub fn parse_sort(
    depth: u16,
    expanded: u16,
    orders: impl Iterator<Item = SortOrder>,
) -> Result<(Vec<SortColumn>, Option<Categories>), RopError> {
    let categorized = usize::from(depth);
    let mut sort = Vec::with_capacity(orders.size_hint().0);
    let mut maximum = None;
    for (position, order) in orders.enumerate() {
        let descending = match order.direction {
            SortDirection::Ascending => false,
            SortDirection::Descending => true,
            SortDirection::MaximumCategory => match sort.last() {
                Some(&SortColumn { descending, .. })
                    if position == categorized && maximum.is_none() =>
                {
                    maximum = Some(SortColumn {
                        tag: order.tag.0,
                        descending,
                    });
                    continue;
                }
                _ => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
            },
        };
        sort.push(SortColumn {
            tag: order.tag.0,
            descending,
        });
    }
    let categories = (depth > 0).then(|| Categories {
        depth,
        expanded,
        maximum,
        toggled: Vec::new(),
    });
    Ok((sort, categories))
}

fn first_change(previous: &[SortKey], current: &[SortKey]) -> Option<usize> {
    previous
        .iter()
        .zip(current)
        .position(|(a, b)| a.compare(b).is_ne())
}

fn unread(row: &TableRow) -> bool {
    matches!(
        row.get(tags::READ),
        Some(PropOut::Value(PropValue::Bool(false)))
    )
}

fn int_column(row: &TableRow, tag: PropTag) -> Option<i32> {
    match row.get(tag) {
        Some(PropOut::Value(PropValue::I32(value))) => Some(value),
        _ => None,
    }
}

fn after_expand(position: u32, header: u32, added: u32) -> u32 {
    if position > header {
        position.saturating_add(added)
    } else {
        position
    }
}

fn after_collapse(position: u32, first: u32, collapsed: u32) -> u32 {
    match position {
        position if position <= first => position,
        position if position - first < collapsed => first,
        position => position - collapsed,
    }
}

impl Categories {
    pub fn is_expanded(&self, level: u16, id: u64) -> bool {
        (level < self.expanded) != self.toggled.binary_search(&id).is_ok()
    }

    pub fn footprint(&self) -> usize {
        self.toggled.len() * size_of::<u64>()
    }

    pub fn fingerprint(&self, sort: &[SortColumn]) -> u32 {
        let mut hash = Fnv(FNV_OFFSET);
        hash.write(&self.depth.to_le_bytes());
        hash.write(&self.expanded.to_le_bytes());
        for column in sort.iter().chain(self.maximum.as_ref()) {
            hash.column(column);
        }
        let [a, b, c, d, e, f, g, h] = hash.0.to_le_bytes();
        u32::from_le_bytes([a ^ e, b ^ f, c ^ g, d ^ h])
    }

    pub fn toggle(&mut self, id: u64) -> Result<(), RopError> {
        match self.toggled.binary_search(&id) {
            Ok(position) => {
                self.toggled.remove(position);
            }
            Err(_) if self.toggled.len() >= MAX_TOGGLED => {
                return Err(RopError::Code(ErrorCode::NOT_ENOUGH_MEMORY));
            }
            Err(position) => self.toggled.insert(position, id),
        }
        Ok(())
    }

    fn is_full_without(&self, id: u64) -> bool {
        self.toggled.len() >= MAX_TOGGLED && self.toggled.binary_search(&id).is_err()
    }

    pub fn categorize(
        &self,
        keyed: Vec<(SortKeys, TableRow)>,
        sort: &[SortColumn],
    ) -> Vec<TableRow> {
        let depth = usize::from(self.depth).min(sort.len());
        let levels = sort.get(..depth).unwrap_or(sort);
        let (keyed, bests) = match self.maximum {
            Some(maximum) => by_maximum(keyed, depth, maximum),
            None => (keyed, Vec::new()),
        };
        let groups = groups(&keyed, depth);
        let headers = self.headers(&keyed, &groups, levels, &bests);
        let leaf_depth = i32::try_from(depth).unwrap_or(i32::MAX);
        let mut out = Vec::with_capacity(headers.rows.len() + headers.visible_leaves);
        let mut hidden_until = 0;
        let mut next = headers.rows.into_iter().peekable();
        for (index, (_, mut row)) in keyed.into_iter().enumerate() {
            while let Some(header) = next.next_if(|header| header.start == index) {
                hidden_until = hidden_until.max(header.hides);
                out.push(header.row);
            }
            if index >= hidden_until {
                row.bag.push_i32(tags::DEPTH, leaf_depth);
                row.bag.push_i32(tags::ROW_TYPE, LEAF_ROW);
                out.push(row);
            }
        }
        out
    }

    fn headers(
        &self,
        keyed: &[(SortKeys, TableRow)],
        groups: &[Group],
        levels: &[SortColumn],
        bests: &[usize],
    ) -> Headers {
        let mut unread_before = Vec::with_capacity(keyed.len() + 1);
        let mut total = 0u32;
        unread_before.push(total);
        unread_before.extend(keyed.iter().map(|(_, row)| {
            total += u32::from(unread(row));
            total
        }));
        let last_level = levels.len().saturating_sub(1);
        let mut bests = bests.iter().copied().peekable();
        let mut rows = Vec::with_capacity(groups.len());
        let mut hidden_until = 0;
        let mut hidden_leaves = 0;
        for group in groups {
            if group.start < hidden_until {
                continue;
            }
            let Some((_, first)) = keyed.get(group.start) else {
                continue;
            };
            let expanded = self.is_expanded(group.level, group.id);
            let unread = unread_before
                .get(group.end)
                .zip(unread_before.get(group.start))
                .map_or(0, |(end, start)| end - start);
            let mut row = header(first, levels, group, expanded, unread);
            if let Some(maximum) = self
                .maximum
                .filter(|_| usize::from(group.level) == last_level)
            {
                while bests.next_if(|best| *best < group.start).is_some() {}
                if let Some(best) = bests.next_if(|best| *best < group.end)
                    && let Some((_, row_max)) = keyed.get(best)
                {
                    push_maximum(&mut row.bag, row_max, PropTag(maximum.tag));
                }
            }
            let hides = if expanded {
                0
            } else {
                hidden_until = group.end;
                hidden_leaves += group.end - group.start;
                group.end
            };
            rows.push(Header {
                start: group.start,
                hides,
                row,
            });
        }
        Headers {
            rows,
            visible_leaves: keyed.len().saturating_sub(hidden_leaves),
        }
    }
}

fn push_maximum(bag: &mut PropBag, best: &TableRow, tag: PropTag) {
    if !bag.contains(tag)
        && let Some(value) = best.get(tag)
    {
        bag.push_out(tag, &value);
    }
}

fn by_maximum(
    keyed: Vec<(SortKeys, TableRow)>,
    depth: usize,
    maximum: SortColumn,
) -> (Vec<(SortKeys, TableRow)>, Vec<usize>) {
    let parent_levels = depth.saturating_sub(1);
    let mut runs: Vec<Run> = Vec::new();
    let mut previous: Option<&[SortKey]> = None;
    let mut parent = 0;
    for (index, (keys, row)) in keyed.iter().enumerate() {
        let keys = keys.get(..depth).unwrap_or(keys);
        let value = SortKey::of(row.get(PropTag(maximum.tag)));
        let change = previous.map(|previous| first_change(previous, keys));
        previous = Some(keys);
        match runs.last_mut() {
            Some(run) if change == Some(None) => {
                run.end = index + 1;
                if value.compare(&run.maximum).is_gt() {
                    run.maximum = value;
                    run.best = index;
                }
            }
            _ => {
                if change.flatten().is_some_and(|level| level < parent_levels) {
                    parent = index;
                }
                runs.push(Run {
                    parent,
                    start: index,
                    end: index + 1,
                    best: index,
                    maximum: value,
                });
            }
        }
    }
    runs.sort_by(|a, b| {
        a.parent.cmp(&b.parent).then_with(|| {
            let order = a.maximum.compare(&b.maximum);
            if maximum.descending {
                order.reverse()
            } else {
                order
            }
        })
    });
    let mut slots = keyed.into_iter().map(Some).collect::<Vec<_>>();
    let mut out = Vec::with_capacity(slots.len());
    let mut bests = Vec::with_capacity(runs.len());
    for run in runs {
        bests.push(out.len() + (run.best - run.start));
        out.extend(
            slots
                .get_mut(run.start..run.end)
                .into_iter()
                .flatten()
                .filter_map(Option::take),
        );
    }
    (out, bests)
}

fn groups(keyed: &[(SortKeys, TableRow)], depth: usize) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    let mut open: SmallVec<[usize; 4]> = SmallVec::new();
    let mut previous: Option<&[SortKey]> = None;
    for (index, (keys, _)) in keyed.iter().enumerate() {
        let keys = keys.get(..depth).unwrap_or(keys);
        let level = previous.map_or(0, |previous| {
            first_change(previous, keys).unwrap_or(keys.len())
        });
        while open.len() > level {
            if let Some(group) = open.pop().and_then(|group| groups.get_mut(group)) {
                group.end = index;
            }
        }
        for (level, key) in keys.iter().enumerate().skip(level) {
            let parent = open
                .last()
                .and_then(|group| groups.get(*group))
                .map_or(0, |group| group.id);
            let level = u16::try_from(level).unwrap_or(u16::MAX);
            open.push(groups.len());
            groups.push(Group {
                level,
                start: index,
                end: keyed.len(),
                id: header_id(parent, level, key),
            });
        }
        previous = Some(keys);
    }
    groups
}

fn header(
    first: &TableRow,
    levels: &[SortColumn],
    group: &Group,
    expanded: bool,
    unread: u32,
) -> TableRow {
    let mut bag = PropBag::default();
    for column in levels.iter().take(usize::from(group.level) + 1) {
        let tag = PropTag(column.tag);
        if let Some(value) = first.get(tag) {
            bag.push_out(tag, &value);
        }
    }
    bag.push_binary(tags::INSTANCE_KEY, &group.id.to_le_bytes());
    bag.push_i64(tags::INST_ID, i64::from_le_bytes(group.id.to_le_bytes()));
    bag.push_i32(tags::INSTANCE_NUM, 0);
    bag.push_i32(
        tags::ROW_TYPE,
        if expanded {
            EXPANDED_CATEGORY
        } else {
            COLLAPSED_CATEGORY
        },
    );
    bag.push_i32(tags::DEPTH, i32::from(group.level));
    bag.push_i32(
        tags::CONTENT_COUNT,
        i32::try_from(group.end - group.start).unwrap_or(i32::MAX),
    );
    bag.push_i32(
        tags::CONTENT_UNREAD_COUNT,
        i32::try_from(unread).unwrap_or(i32::MAX),
    );
    TableRow { key: group.id, bag }
}

struct HeaderAt {
    position: usize,
    level: i32,
    expanded: bool,
}

fn header_at(rows: &[TableRow], id: u64) -> Option<HeaderAt> {
    rows.iter().enumerate().find_map(|(position, row)| {
        if row.key != id {
            return None;
        }
        let expanded = match int_column(row, tags::ROW_TYPE)? {
            EXPANDED_CATEGORY => true,
            COLLAPSED_CATEGORY => false,
            _ => return None,
        };
        Some(HeaderAt {
            position,
            level: int_column(row, tags::DEPTH)?,
            expanded,
        })
    })
}

fn rows_under(rows: &[TableRow], header: &HeaderAt) -> usize {
    rows.get(header.position + 1..)
        .unwrap_or_default()
        .iter()
        .take_while(|row| int_column(row, tags::DEPTH).is_some_and(|depth| depth > header.level))
        .count()
}

impl RopContext<'_, '_> {
    fn categorized_table(&self, rop: &DecodedRop<'_>) -> Result<(Handle, TableObject), RopError> {
        let handle = self.input(rop.header.input_handle)?;
        let table = self.table(handle)?;
        if !matches!(table.kind, TableKind::Contents { .. }) {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        table.require_columns()?;
        if table.categories.is_none() {
            return Err(RopError::Code(ErrorCode::NOT_FOUND));
        }
        Ok((handle, table.clone()))
    }

    async fn prune_toggled(&mut self, table: &mut TableObject, id: u64) -> Result<(), RopError> {
        if !table
            .categories
            .as_ref()
            .is_some_and(|categories| categories.is_full_without(id))
        {
            return Ok(());
        }
        let mut everything = table.clone();
        if let Some(categories) = everything.categories.as_mut() {
            categories.expanded = categories.depth;
            categories.toggled.clear();
        }
        let rows = self.table_rows(&everything, RowPurpose::Positions).await?;
        let mut live = rows
            .iter()
            .map(|row| row.key)
            .filter(|key| is_header_id(*key))
            .collect::<Vec<_>>();
        live.sort_unstable();
        if let Some(categories) = table.categories.as_mut() {
            categories
                .toggled
                .retain(|id| live.binary_search(id).is_ok());
        }
        Ok(())
    }

    async fn stage_toggle(
        &mut self,
        handle: Handle,
        table: &mut TableObject,
        id: u64,
    ) -> Result<(), RopError> {
        self.prune_toggled(table, id).await?;
        self.charge_table(handle, table.footprint() + size_of::<u64>())?;
        table
            .categories
            .as_mut()
            .ok_or(RopError::Code(ErrorCode::NOT_FOUND))?
            .toggle(id)
    }

    pub async fn expand_row(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &ExpandRow,
    ) -> RopResult {
        if request.max_row_count > 0 {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let (handle, mut table) = self.categorized_table(rop)?;
        self.stage_toggle(handle, &mut table, request.category_id)
            .await?;
        let rows = self.table_rows(&table, RowPurpose::Positions).await?;
        let header =
            header_at(&rows, request.category_id).ok_or(RopError::Code(ErrorCode::NOT_FOUND))?;
        if !header.expanded {
            return Err(RopError::Code(ErrorCode::NOT_COLLAPSED));
        }
        let added = u32::try_from(rows_under(&rows, &header)).unwrap_or(u32::MAX);
        let options = table_row_options(table.unicode, self.code_page());
        self.writer
            .row_writer(
                ResponseHeader::new(rop.header.id.response_id(), index, ErrorCode::SUCCESS),
                RowSetLayout::ExpandRow {
                    expanded_count: added,
                },
                options,
            )?
            .finish()?;
        let header_position = u32::try_from(header.position).unwrap_or(u32::MAX);
        let stored = self.table_mut(handle)?;
        stored.categories = table.categories;
        stored.position = header_position.saturating_add(1);
        for bookmark in &mut stored.bookmarks {
            bookmark.position = after_expand(bookmark.position, header_position, added);
        }
        Ok(())
    }

    pub async fn collapse_row(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &CollapseRow,
    ) -> RopResult {
        let (handle, mut table) = self.categorized_table(rop)?;
        let rows = self.table_rows(&table, RowPurpose::Positions).await?;
        let header =
            header_at(&rows, request.category_id).ok_or(RopError::Code(ErrorCode::NOT_FOUND))?;
        if !header.expanded {
            return Err(RopError::Code(ErrorCode::NOT_EXPANDED));
        }
        let collapsed = u32::try_from(rows_under(&rows, &header)).unwrap_or(u32::MAX);
        self.stage_toggle(handle, &mut table, request.category_id)
            .await?;
        self.respond(
            rop,
            index,
            &CollapseRowResponse {
                collapsed_row_count: collapsed,
            },
        )?;
        let first = u32::try_from(header.position + 1).unwrap_or(u32::MAX);
        let len = row_count(&rows);
        let stored = self.table_mut(handle)?;
        stored.categories = table.categories;
        stored.position = after_collapse(stored.position.min(len), first, collapsed);
        for bookmark in &mut stored.bookmarks {
            bookmark.position = after_collapse(bookmark.position.min(len), first, collapsed);
        }
        Ok(())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/table/category/tests.rs"]
mod tests;
