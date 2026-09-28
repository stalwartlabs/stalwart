/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod escape;
pub mod json;
pub mod text;
pub mod timestamp;

pub fn write_uint(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(itoa::Buffer::new().format(value).as_bytes());
}

pub fn write_int(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(itoa::Buffer::new().format(value).as_bytes());
}
