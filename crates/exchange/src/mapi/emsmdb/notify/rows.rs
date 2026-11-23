/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::events::{GroupEvents, RowEvent, Targets};
use crate::mapi::{
    emsmdb::{
        execute::{RopContext, RopError},
        props::PropOut,
        state::{Handle, ServerObject, TableObject},
    },
    ids::MapiId,
};
use common::cache::exchange::ExchangeAccountCache;
use exchange_proto::{
    ids::Fid,
    mapi::{
        MapiLimits,
        prop::{PropId, PropTag, row::RowWriter, tags},
        rop::responses::table_row_options,
    },
};
use smallvec::SmallVec;
use std::slice;

const MAX_ROW_BYTES: usize = MapiLimits::DEFAULT.output_budget_max as usize / 2;
const ITEM_COLUMNS: [PropId; 7] = [
    tags::CONTENT_COUNT.id(),
    tags::CONTENT_UNREAD_COUNT.id(),
    tags::DELETED_COUNT_TOTAL.id(),
    tags::LAST_MODIFICATION_TIME.id(),
    tags::LOCAL_COMMIT_TIME_MAX.id(),
    tags::HIER_REV.id(),
    tags::HIERARCHY_CHANGE_NUMBER.id(),
];

impl RopContext<'_, '_> {
    pub(super) async fn hierarchy_row_events(
        &mut self,
        mailbox_id: u32,
        targets: &Targets,
        events: &mut GroupEvents,
    ) -> trc::Result<()> {
        if events.contents.is_empty() || events.all_hierarchy {
            return Ok(());
        }
        let exchange = self.mailbox(mailbox_id).await?.exchange;
        for (handle, logon_id) in targets.hierarchy_tables() {
            let table = match self.state.get(Handle(handle)) {
                Some(ServerObject::Table(table)) if tracks_items(table) => table.clone(),
                _ => continue,
            };
            let target = RowTarget {
                table: &table,
                handle,
                logon_id,
                exchange: &exchange,
            };
            match self.table_row_events(target, events).await {
                Ok(()) | Err(RopError::Code(_) | RopError::Overflow) => {}
                Err(RopError::Internal(err)) => return Err(err),
            }
            if events.all_hierarchy {
                events.rows.clear();
                break;
            }
        }
        Ok(())
    }

    async fn table_row_events(
        &mut self,
        target: RowTarget<'_>,
        events: &mut GroupEvents,
    ) -> Result<(), RopError> {
        let RowTarget {
            table,
            handle,
            logon_id,
            exchange,
        } = target;
        let mut rows = self.changed_rows(table, &events.contents).await?;
        let columns: SmallVec<[PropTag; 32]> =
            table.columns.iter().map(|tag| PropTag(*tag)).collect();
        let options = table_row_options(table.unicode, self.code_page());
        let mut previous = None;
        for row in &mut rows {
            let key = row.key;
            if events.contents.binary_search(&key).is_ok() {
                self.complete_hierarchy_rows(table, slice::from_mut(row))
                    .await?;
                let mut data = Vec::new();
                let mut writer =
                    RowWriter::standalone(&mut data, &columns, row.has_all(&columns), options);
                for tag in &columns {
                    PropOut::write_cell(&mut writer, *tag, row.get(*tag).as_ref());
                }
                drop(writer);
                if data.len() > MAX_ROW_BYTES {
                    events.all_hierarchy = true;
                    return Ok(());
                }
                events.rows.push(RowEvent {
                    handle,
                    logon_id,
                    row: row_fid(exchange, key),
                    after: previous
                        .map_or(Fid::from_le_u64(0), |previous| row_fid(exchange, previous)),
                    data,
                });
            }
            previous = Some(key);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct RowTarget<'x> {
    table: &'x TableObject,
    handle: u32,
    logon_id: u8,
    exchange: &'x ExchangeAccountCache,
}

fn tracks_items(table: &TableObject) -> bool {
    table
        .columns
        .iter()
        .any(|tag| ITEM_COLUMNS.contains(&PropTag(*tag).id()))
}

fn row_fid(exchange: &ExchangeAccountCache, key: u64) -> Fid {
    MapiId::from_counter(key)
        .and_then(MapiId::to_node)
        .map_or(Fid::from_le_u64(0), |node| {
            MapiId::from_folder(exchange, node).to_eid()
        })
}
