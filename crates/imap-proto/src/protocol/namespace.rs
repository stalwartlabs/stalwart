/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ImapResponse, quoted_string};

pub struct Response {
    pub shared_prefix: Option<String>,
}

impl ImapResponse for Response {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        if let Some(shared_prefix) = &self.shared_prefix {
            buf.extend_from_slice(b"* NAMESPACE ((\"\" \"/\")) ((");
            quoted_string(buf, shared_prefix);
            buf.extend_from_slice(b" \"/\")) NIL\r\n");
        } else {
            buf.extend_from_slice(b"* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n");
        }
    }

    fn size_hint(&self) -> usize {
        const FRAMING_LEN: usize = 48;

        FRAMING_LEN
            + self
                .shared_prefix
                .as_ref()
                .map_or(0, |prefix| prefix.len() * 2 + 2)
    }
}
