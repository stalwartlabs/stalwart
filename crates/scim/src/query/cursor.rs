/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::error::Result;
use scim_proto::{ResourceType, message::error::Error, message::search::SearchRequest};
use std::fmt::Write;
use types::id::Id;

const CURSOR_LEN: usize = 48;

pub fn signature(resource_type: ResourceType, request: &SearchRequest<'_>) -> u64 {
    let mut buffer = Vec::with_capacity(64);
    buffer.push(resource_type as u8);
    buffer.extend_from_slice(request.filter.as_deref().unwrap_or_default().as_bytes());
    buffer.push(0);
    buffer.extend_from_slice(request.sort_by.as_deref().unwrap_or_default().as_bytes());
    buffer.push(0);
    buffer.extend_from_slice(request.sort_order.unwrap_or_default().as_str().as_bytes());

    xxhash_rust::xxh3::xxh3_64(&buffer)
}

pub fn encode(signature: u64, position: usize, anchor: Id) -> String {
    let mut cursor = String::with_capacity(CURSOR_LEN);
    let _ = write!(
        &mut cursor,
        "{signature:016x}{position:016x}{:016x}",
        anchor.id()
    );
    cursor
}

pub fn decode(cursor: &str, signature: u64, ids: &[Id]) -> Result<usize> {
    let invalid = || Error::invalid_cursor("The supplied cursor is not valid.");

    if cursor.len() != CURSOR_LEN || !cursor.is_ascii() {
        return Err(invalid().into());
    }

    let cursor_signature = u64::from_str_radix(&cursor[..16], 16).map_err(|_| invalid())?;
    let position = u64::from_str_radix(&cursor[16..32], 16).map_err(|_| invalid())? as usize;
    let anchor = u64::from_str_radix(&cursor[32..], 16).map_err(|_| invalid())?;

    if cursor_signature != signature {
        return Err(
            Error::invalid_cursor("The supplied cursor was issued for a different query.").into(),
        );
    }

    Ok(match ids.iter().position(|id| id.id() == anchor) {
        Some(anchor_position) => anchor_position + 1,
        None => position.min(ids.len()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let ids = (1..=10u64).map(Id::new).collect::<Vec<_>>();
        let cursor = encode(42, 5, ids[4]);

        assert_eq!(cursor.len(), CURSOR_LEN);
        assert_eq!(decode(&cursor, 42, &ids).unwrap(), 5);
    }

    #[test]
    fn anchor_survives_insertions() {
        let mut ids = (1..=10u64).map(Id::new).collect::<Vec<_>>();
        let cursor = encode(42, 5, ids[4]);
        ids.insert(0, Id::new(100));

        assert_eq!(decode(&cursor, 42, &ids).unwrap(), 6);
    }

    #[test]
    fn deleted_anchor_falls_back_to_position() {
        let mut ids = (1..=10u64).map(Id::new).collect::<Vec<_>>();
        let cursor = encode(42, 5, ids[4]);
        ids.remove(4);

        assert_eq!(decode(&cursor, 42, &ids).unwrap(), 5);
    }

    #[test]
    fn signature_mismatch_is_rejected() {
        let ids = (1..=10u64).map(Id::new).collect::<Vec<_>>();
        let cursor = encode(42, 5, ids[4]);

        assert!(decode(&cursor, 43, &ids).is_err());
    }

    #[test]
    fn malformed_cursors_are_rejected() {
        let ids = (1..=10u64).map(Id::new).collect::<Vec<_>>();

        for cursor in [
            "",
            "abc",
            &"z".repeat(CURSOR_LEN),
            &"0".repeat(CURSOR_LEN - 1),
        ] {
            assert!(decode(cursor, 42, &ids).is_err(), "{cursor}");
        }
    }

    #[test]
    fn position_beyond_the_end_is_clamped() {
        let ids = (1..=3u64).map(Id::new).collect::<Vec<_>>();
        let cursor = encode(42, 900, Id::new(999));

        assert_eq!(decode(&cursor, 42, &ids).unwrap(), 3);
    }
}
