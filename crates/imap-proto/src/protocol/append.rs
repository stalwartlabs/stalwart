/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Flag;
use compact_str::CompactString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: CompactString,
    pub mailbox_name: CompactString,
    pub messages: Vec<Message>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub message: Vec<u8>,
    pub flags: Vec<Flag>,
    pub received_at: Option<i64>,
}
