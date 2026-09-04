/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ImapResponse, push_int, serialize_sequence};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub use_vanished: bool,
    pub ids: Vec<u32>,
}

impl ImapResponse for Response {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        self.serialize_to(buf);
    }
}

impl Response {
    pub fn serialize_to(&self, buf: &mut Vec<u8>) {
        if !self.use_vanished {
            for (num_deletions, id) in self.ids.iter().enumerate() {
                buf.extend_from_slice(b"* ");
                push_int(buf, id.saturating_sub(num_deletions as u32));
                buf.extend_from_slice(b" EXPUNGE\r\n");
            }
        } else {
            serialize_vanished(buf, false, &self.ids);
        }
    }
}

fn serialize_vanished(buf: &mut Vec<u8>, earlier: bool, ids: &[u32]) {
    if earlier {
        buf.extend_from_slice(b"* VANISHED (EARLIER) ");
    } else {
        buf.extend_from_slice(b"* VANISHED ");
    }
    serialize_sequence(buf, ids);
    buf.extend_from_slice(b"\r\n");
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vanished {
    pub earlier: bool,
    pub ids: Vec<u32>,
}

impl Vanished {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        serialize_vanished(buf, self.earlier, &self.ids);
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::ImapResponse;

    #[test]
    fn serialize_expunge() {
        assert_eq!(
            String::from_utf8(
                super::Response {
                    use_vanished: false,
                    ids: vec![3, 4, 5]
                }
                .serialize()
            )
            .unwrap(),
            concat!("* 3 EXPUNGE\r\n", "* 3 EXPUNGE\r\n", "* 3 EXPUNGE\r\n",)
        );

        assert_eq!(
            String::from_utf8(
                super::Response {
                    use_vanished: false,
                    ids: vec![3, 4, 7, 9, 11]
                }
                .serialize()
            )
            .unwrap(),
            concat!(
                "* 3 EXPUNGE\r\n",
                "* 3 EXPUNGE\r\n",
                "* 5 EXPUNGE\r\n",
                "* 6 EXPUNGE\r\n",
                "* 7 EXPUNGE\r\n",
            )
        );

        assert_eq!(
            String::from_utf8(
                super::Response {
                    use_vanished: true,
                    ids: vec![3, 4, 5]
                }
                .serialize()
            )
            .unwrap(),
            "* VANISHED 3:5\r\n"
        );
    }
}
