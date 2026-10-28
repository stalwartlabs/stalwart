/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod logs;
pub mod metrics;
pub mod request;
pub mod resource;
pub mod traces;
pub mod value;

use trc::Value;

const NANOS_PER_SECOND: u64 = 1_000_000_000;

#[inline(always)]
pub fn unix_nanos(seconds: u64) -> u64 {
    seconds.saturating_mul(NANOS_PER_SECOND)
}

#[inline(always)]
pub fn trace_id(prefix: &[u8; 8], span_id: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    let (head, tail) = id.split_at_mut(8);
    head.copy_from_slice(prefix);
    tail.copy_from_slice(&span_id.to_be_bytes());
    id
}

#[inline(always)]
pub fn span_id_value(value: &Value) -> u64 {
    match value {
        Value::UInt(id) => *id,
        Value::Int(id) => *id as u64,
        _ => 0,
    }
}
