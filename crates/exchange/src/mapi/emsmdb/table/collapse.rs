/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    RowPurpose,
    category::{MAX_TOGGLED, is_header_id},
    rops::row_count,
};
use crate::mapi::{
    emsmdb::{
        execute::{RopContext, RopError, RopResult},
        props::PropOut,
        state::{Handle, TableKind, TableObject},
    },
    ids::MapiId,
};
use exchange_proto::{
    ids::Eid,
    mapi::{
        ErrorCode,
        prop::{PropValue, tags},
        rop::{
            DecodedRop,
            requests::{GetCollapseState, SetCollapseState},
            responses::{GetCollapseStateResponse, SetCollapseStateResponse},
        },
    },
};
use std::borrow::Cow;

const COLLAPSE_STATE_HEADER_LEN: usize = 16;
const TOGGLED_ID_LEN: usize = size_of::<u64>();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollapseState<'x> {
    pub row_id: u64,
    pub instance: u32,
    pub fingerprint: u32,
    pub toggled: Cow<'x, [u64]>,
}

impl CollapseState<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(COLLAPSE_STATE_HEADER_LEN + self.toggled.len() * TOGGLED_ID_LEN);
        out.extend_from_slice(&self.row_id.to_le_bytes());
        out.extend_from_slice(&self.instance.to_le_bytes());
        out.extend_from_slice(&self.fingerprint.to_le_bytes());
        for id in self.toggled.iter() {
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<CollapseState<'static>> {
        let (row_id, rest) = bytes.split_first_chunk::<8>()?;
        let (instance, rest) = rest.split_first_chunk::<4>()?;
        let (fingerprint, ids) = rest.split_first_chunk::<4>()?;
        let (chunks, remainder) = ids.as_chunks::<TOGGLED_ID_LEN>();
        if !remainder.is_empty() || chunks.len() > MAX_TOGGLED {
            return None;
        }
        let mut toggled = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let id = u64::from_le_bytes(*chunk);
            if !is_header_id(id) || toggled.last().is_some_and(|last| *last >= id) {
                return None;
            }
            toggled.push(id);
        }
        Some(CollapseState {
            row_id: u64::from_le_bytes(*row_id),
            instance: u32::from_le_bytes(*instance),
            fingerprint: u32::from_le_bytes(*fingerprint),
            toggled: Cow::Owned(toggled),
        })
    }
}

impl RopContext<'_, '_> {
    fn contents_table(&self, rop: &DecodedRop<'_>) -> Result<(Handle, &TableObject), RopError> {
        let handle = self.input(rop.header.input_handle)?;
        let table = self.table(handle)?;
        if !matches!(table.kind, TableKind::Contents { .. }) {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        table.require_columns()?;
        Ok((handle, table))
    }

    pub fn get_collapse_state(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &GetCollapseState,
    ) -> RopResult {
        let (_, table) = self.contents_table(rop)?;
        let state = CollapseState {
            row_id: request.row_id,
            instance: request.row_instance_number,
            fingerprint: table
                .categories
                .as_ref()
                .map_or(0, |categories| categories.fingerprint(&table.sort)),
            toggled: Cow::Borrowed(
                table
                    .categories
                    .as_ref()
                    .map_or(&[], |categories| categories.toggled.as_slice()),
            ),
        }
        .encode();
        self.respond(
            rop,
            index,
            &GetCollapseStateResponse {
                collapse_state: &state,
            },
        )
    }

    pub async fn set_collapse_state(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SetCollapseState<'_>,
    ) -> RopResult {
        let (handle, table) = self.contents_table(rop)?;
        let mut table = table.clone();
        let state = CollapseState::decode(request.collapse_state)
            .ok_or(RopError::Code(ErrorCode::INVALID_PARAM))?;
        if let Some(categories) = table.categories.as_mut() {
            categories.toggled = if categories.fingerprint(&table.sort) == state.fingerprint {
                state.toggled.into_owned()
            } else {
                Vec::new()
            };
        }
        self.check_bookmark_room(handle, &table)?;
        let rows = self.table_rows(&table, RowPurpose::Positions).await?;
        let instance =
            MapiId::from_eid(Eid::from_wire(state.row_id.to_le_bytes())).map(MapiId::counter);
        let (row_key, position) = rows
            .iter()
            .enumerate()
            .find(|(_, row)| match row.get(tags::INST_ID) {
                Some(PropOut::Value(PropValue::I64(id))) => id.cast_unsigned() == state.row_id,
                _ => Some(row.key) == instance || row.key == state.row_id,
            })
            .and_then(|(position, row)| Some((row.key, u32::try_from(position).ok()?)))
            .unwrap_or_else(|| (state.row_id, table.position.min(row_count(&rows))));
        let id = self.push_bookmark(handle, row_key, position)?;
        let stored = self.table_mut(handle)?;
        stored.categories = table.categories;
        stored.position = position;
        self.respond(
            rop,
            index,
            &SetCollapseStateResponse {
                bookmark: &id.to_le_bytes(),
            },
        )
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/table/collapse/tests.rs"]
mod tests;
