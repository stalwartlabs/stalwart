/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod escape;
pub mod json;
pub mod text;
pub mod timestamp;

use base64::{Engine, encoded_len, engine::general_purpose::STANDARD};

pub fn write_base64(out: &mut Vec<u8>, bytes: &[u8]) {
    let start = out.len();
    let Some(len) = encoded_len(bytes.len(), true) else {
        return;
    };
    out.resize(start + len, 0);
    let written = STANDARD
        .encode_slice(bytes, &mut out[start..])
        .unwrap_or_default();
    out.truncate(start + written);
}

pub fn write_uint(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(itoa::Buffer::new().format(value).as_bytes());
}

pub fn write_int(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(itoa::Buffer::new().format(value).as_bytes());
}
