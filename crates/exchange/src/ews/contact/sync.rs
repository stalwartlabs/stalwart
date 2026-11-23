/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ews::item::sync::SyncWindow;
use common::Server;
use exchange_proto::ids::ews::EwsItemsState;
use store::{
    query::log::{Change, Query},
    roaring::RoaringBitmap,
};
use trc::AddContext;
use types::collection::SyncCollection;

pub(crate) enum LoggedChanges {
    All,
    Items(RoaringBitmap),
}

pub(crate) async fn logged_changes(
    server: &Server,
    account_id: u32,
    state: &EwsItemsState,
    collection: SyncCollection,
) -> trc::Result<(LoggedChanges, u64)> {
    let since = state.change_id;
    let resuming = state.after != u32::MAX;
    let query = if resuming {
        Query::Range(since, state.pinned)
    } else {
        Query::Since(since)
    };
    let changes = server
        .store()
        .changes(account_id, collection.into(), query)
        .await
        .caused_by(trc::location!())?;
    let last = if resuming {
        state.pinned
    } else {
        changes.to_change_id.max(since)
    };
    if changes.needs_full_rebuild(since) {
        return Ok((LoggedChanges::All, last));
    }
    let mut items = RoaringBitmap::new();
    for change in &changes.changes {
        if let Change::UpdateItem(id) | Change::UpdateItemMetadata(id) | Change::InsertItem(id) =
            change
            && let Ok(id) = u32::try_from(*id)
        {
            items.insert(id);
        }
    }
    Ok((LoggedChanges::Items(items), last))
}

pub(crate) fn plan(
    members: &RoaringBitmap,
    changed: LoggedChanges,
    last: u64,
    state: &mut EwsItemsState,
    max_changes: usize,
    ignored: &RoaringBitmap,
) -> SyncWindow {
    let deleted = &state.held - members;
    let created = members - &state.held;
    let mut updates = match changed {
        LoggedChanges::All => &state.held & members,
        LoggedChanges::Items(items) => items & &state.held & members,
    };
    if state.after != u32::MAX {
        updates.remove_range(..=state.after);
    }

    let mut window = SyncWindow::default();
    let mut budget = max_changes;
    for document_id in &deleted {
        if budget == 0 {
            return window;
        }
        state.held.remove(document_id);
        if !ignored.contains(document_id) {
            window.deletes.push(document_id);
            budget -= 1;
        }
    }
    for document_id in &updates {
        if !ignored.contains(document_id) {
            if budget == 0 {
                state.pinned = last;
                return window;
            }
            window.updates.push(document_id);
            budget -= 1;
        }
        state.after = document_id;
    }
    state.change_id = last;
    state.after = u32::MAX;
    state.pinned = 0;
    for document_id in &created {
        if budget == 0 {
            return window;
        }
        state.held.insert(document_id);
        if !ignored.contains(document_id) {
            window.creates.push(document_id);
            budget -= 1;
        }
    }
    window.last = true;
    window
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/ews/contact/sync/tests.rs"]
mod tests;
