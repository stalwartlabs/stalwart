/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use crate::protocol::push_int;
use compact_str::CompactString;

use super::{ImapResponse, search::Filter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: CompactString,
    pub filter: Vec<Filter>,
    pub algorithm: Algorithm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Algorithm {
    OrderedSubject,
    References,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub is_uid: bool,
    pub threads: Vec<Vec<u32>>,
}

impl ImapResponse for Response {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"* THREAD ");
        for thread in &self.threads {
            buf.push(b'(');
            for (pos, id) in thread.iter().enumerate() {
                if pos > 0 {
                    buf.push(b' ');
                }
                push_int(buf, *id);
            }
            buf.push(b')');
        }
        buf.extend_from_slice(b"\r\n");
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::ImapResponse;

    #[test]
    fn serialize_thread() {
        assert_eq!(
            String::from_utf8(
                super::Response {
                    is_uid: true,
                    threads: vec![vec![2, 10, 11], vec![49], vec![1, 3]],
                }
                .serialize()
            )
            .unwrap(),
            "* THREAD (2 10 11)(49)(1 3)\r\n"
        );
    }
}
