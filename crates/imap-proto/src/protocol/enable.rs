/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use compact_str::CompactString;

use super::{ImapResponse, capability::Capability};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: CompactString,
    pub capabilities: Vec<Capability>,
}

pub struct Response {
    pub enabled: Vec<Capability>,
}

impl ImapResponse for Response {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        if !self.enabled.is_empty() {
            buf.extend(b"* ENABLED");
            for capability in &self.enabled {
                buf.push(b' ');
                capability.serialize(buf);
            }
            buf.push(b'\r');
            buf.push(b'\n');
        }
    }

    fn size_hint(&self) -> usize {
        const FRAMING_LEN: usize = 12;
        const CAPABILITY_LEN: usize = 20;

        if self.enabled.is_empty() {
            0
        } else {
            FRAMING_LEN + self.enabled.len() * CAPABILITY_LEN
        }
    }
}
