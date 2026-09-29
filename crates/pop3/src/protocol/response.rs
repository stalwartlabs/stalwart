/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Mechanism, dot_stuffer::DotStuffer};
use std::{borrow::Cow, fmt::Display};
use utils::chained_bytes::ChainedBytes;

const STATUS_LINE_LEN: usize = 32;
const STUFFING_RESERVE_DIVISOR: usize = 64;

pub enum Response<'x, T> {
    Ok(Cow<'static, str>),
    Err(Cow<'static, str>),
    List(Vec<T>),
    Message(ChainedBytes<'x>),
    Capability {
        mechanisms: Vec<Mechanism>,
        stls: bool,
    },
}

impl<'x, T> Response<'x, T> {
    pub fn message(raw_message: ChainedBytes<'x>, body_offset: usize, lines: Option<u32>) -> Self {
        let Some(lines) = lines else {
            return Response::Message(raw_message);
        };
        let body_offset = body_offset.min(raw_message.len());
        let body_lines = raw_message
            .view(body_offset..raw_message.len())
            .unwrap_or_default()
            .line_prefix_len(lines as usize);
        Response::Message(
            raw_message
                .view(0..body_offset + body_lines)
                .unwrap_or(raw_message),
        )
    }
}

impl<T: Display> Response<'_, T> {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Response::Ok(message) => {
                let mut buf = Vec::with_capacity(message.len() + 6);
                buf.extend_from_slice(b"+OK ");
                buf.extend_from_slice(message.as_bytes());
                buf.extend_from_slice(b"\r\n");
                buf
            }
            Response::Err(message) => {
                let mut buf = Vec::with_capacity(message.len() + 6);
                buf.extend_from_slice(b"-ERR ");
                buf.extend_from_slice(message.as_bytes());
                buf.extend_from_slice(b"\r\n");
                buf
            }
            Response::List(octets) => {
                let mut buf = Vec::with_capacity(octets.len() * 8 + 10);
                buf.extend_from_slice(format!("+OK {} messages\r\n", octets.len()).as_bytes());
                for (num, octet) in octets.iter().enumerate() {
                    buf.extend_from_slice((num + 1).to_string().as_bytes());
                    buf.extend_from_slice(b" ");
                    buf.extend_from_slice(octet.to_string().as_bytes());
                    buf.extend_from_slice(b"\r\n");
                }
                buf.extend_from_slice(b".\r\n");
                buf
            }
            Response::Message(bytes) => {
                let mut buf = Vec::with_capacity(
                    bytes.len() + bytes.len() / STUFFING_RESERVE_DIVISOR + STATUS_LINE_LEN,
                );
                buf.extend_from_slice(b"+OK ");
                buf.extend_from_slice(itoa::Buffer::new().format(bytes.len()).as_bytes());
                buf.extend_from_slice(b" octets\r\n");
                let mut stuffer = DotStuffer::default();
                for segment in bytes.segments() {
                    stuffer.push(&mut buf, segment);
                }
                stuffer.finish(&mut buf);
                buf
            }
            Response::Capability { mechanisms, stls } => {
                let mut buf = Vec::with_capacity(256);
                buf.extend_from_slice(b"+OK Capability list follows\r\n");
                if !mechanisms.is_empty() {
                    if mechanisms.contains(&Mechanism::Plain) {
                        buf.extend_from_slice(b"USER\r\n");
                    }
                    buf.extend_from_slice(b"SASL");
                    for mechanism in mechanisms {
                        buf.extend_from_slice(b" ");
                        buf.extend_from_slice(mechanism.as_str().as_bytes());
                    }
                    buf.extend_from_slice(b"\r\n");
                }

                if *stls {
                    buf.extend_from_slice(b"STLS\r\n");
                }

                for capa in [
                    "TOP",
                    "RESP-CODES",
                    "PIPELINING",
                    "EXPIRE NEVER",
                    "UIDL",
                    "UTF8",
                    "IMPLEMENTATION Stalwart Server",
                ] {
                    buf.extend_from_slice(capa.as_bytes());
                    buf.extend_from_slice(b"\r\n");
                }

                buf.extend_from_slice(b".\r\n");
                buf
            }
        }
    }
}

impl Mechanism {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mechanism::Plain => "PLAIN",
            Mechanism::CramMd5 => "CRAM-MD5",
            Mechanism::DigestMd5 => "DIGEST-MD5",
            Mechanism::ScramSha1 => "SCRAM-SHA-1",
            Mechanism::ScramSha256 => "SCRAM-SHA-256",
            Mechanism::Apop => "APOP",
            Mechanism::Ntlm => "NTLM",
            Mechanism::Gssapi => "GSSAPI",
            Mechanism::Anonymous => "ANONYMOUS",
            Mechanism::External => "EXTERNAL",
            Mechanism::OAuthBearer => "OAUTHBEARER",
            Mechanism::XOauth2 => "XOAUTH2",
        }
    }
}

pub trait SerializeResponse {
    fn serialize(&self) -> Vec<u8>;
}

impl SerializeResponse for trc::Error {
    fn serialize(&self) -> Vec<u8> {
        let message = self
            .value_as_str(trc::Key::Details)
            .unwrap_or_else(|| self.as_ref().message());
        let mut buf = Vec::with_capacity(message.len() + 6);
        buf.extend_from_slice(b"-ERR ");
        buf.extend_from_slice(message.as_bytes());
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::Response;
    use crate::protocol::{
        Mechanism,
        dot_stuffer::tests::{reference_pop3, strings_over},
    };
    use utils::chained_bytes::ChainedBytes;

    const TOP_ALPHABET: &[u8] = b"a\r\n.";
    const TOP_MAX_LEN: usize = 6;
    const TOP_MAX_LINES: u32 = 4;

    fn naive_line_prefix_len(bytes: &[u8], lines: usize) -> usize {
        if lines == 0 {
            return 0;
        }
        bytes
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'\n')
            .nth(lines - 1)
            .map_or(bytes.len(), |(pos, _)| pos + 1)
    }

    #[test]
    fn top_returns_header_blank_line_and_n_body_lines() {
        for message in strings_over(TOP_ALPHABET, TOP_MAX_LEN) {
            for body_offset in 0..=message.len() + 1 {
                for lines in 0..=TOP_MAX_LINES {
                    let clamped = body_offset.min(message.len());
                    let (header, body) = message.split_at(clamped);
                    let prefix_len = clamped + naive_line_prefix_len(body, lines as usize);
                    let expected = message.get(..prefix_len).unwrap_or_default();
                    for split in [0, clamped, message.len()] {
                        let (head, tail) = message.split_at(split);
                        let response = Response::<u32>::message(
                            ChainedBytes::chain(head, tail),
                            body_offset,
                            Some(lines),
                        );
                        let Response::Message(bytes) = &response else {
                            panic!("TOP answers with a message");
                        };
                        assert_eq!(
                            bytes.to_vec(),
                            expected,
                            "{message:?} {body_offset} {lines}"
                        );
                        assert_eq!(response.serialize(), reference_pop3(expected));
                    }
                    assert!(expected.starts_with(header));
                }
            }
        }
        let message = b"Subject: x\r\n\r\nline 1\r\nline 2\r\n";
        let (header, body) = message.split_at(14);
        let top =
            |lines| match Response::<u32>::message(ChainedBytes::chain(header, body), 14, lines) {
                Response::Message(bytes) => bytes.to_vec(),
                _ => Vec::new(),
            };
        assert_eq!(top(Some(0)), b"Subject: x\r\n\r\n".to_vec());
        assert_eq!(top(Some(1)), b"Subject: x\r\n\r\nline 1\r\n".to_vec());
        assert_eq!(top(Some(5)), message.to_vec());
        assert_eq!(top(None), message.to_vec());
    }

    #[test]
    fn serialize_response() {
        for (cmd, expected) in [
            (
                Response::Ok("message 1 deleted".into()),
                "+OK message 1 deleted\r\n",
            ),
            (
                Response::Err("permission denied".into()),
                "-ERR permission denied\r\n",
            ),
            (
                Response::List(vec![100, 200, 300]),
                "+OK 3 messages\r\n1 100\r\n2 200\r\n3 300\r\n.\r\n",
            ),
            (
                Response::Capability {
                    mechanisms: vec![Mechanism::Plain, Mechanism::CramMd5],
                    stls: true,
                },
                concat!(
                    "+OK Capability list follows\r\n",
                    "USER\r\n",
                    "SASL PLAIN CRAM-MD5\r\n",
                    "STLS\r\n",
                    "TOP\r\n",
                    "RESP-CODES\r\n",
                    "PIPELINING\r\n",
                    "EXPIRE NEVER\r\n",
                    "UIDL\r\n",
                    "UTF8\r\n",
                    "IMPLEMENTATION Stalwart Server\r\n.\r\n"
                ),
            ),
            (
                Response::Message(ChainedBytes::chain(
                    b"Subject: test\r\n\r\n.\r\n",
                    b"test.\r\n.test\r\na",
                )),
                "+OK 35 octets\r\nSubject: test\r\n\r\n..\r\ntest.\r\n..test\r\na\r\n.\r\n",
            ),
            (
                Response::Message(ChainedBytes::new(b".first\r\n")),
                "+OK 8 octets\r\n..first\r\n.\r\n",
            ),
            (
                Response::Message(ChainedBytes::default()),
                "+OK 0 octets\r\n.\r\n",
            ),
        ] {
            assert_eq!(expected, String::from_utf8(cmd.serialize()).unwrap());
        }
    }
}
