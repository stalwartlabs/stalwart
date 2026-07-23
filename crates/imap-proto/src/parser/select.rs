/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::{CompactString, ToCompactString, format_compact};
use std::str::FromStr;
use types::id::Id;

use crate::{
    Command,
    protocol::{
        ObjectId,
        select::{self, QResync},
    },
    receiver::{Request, Token, bad},
    utf7::utf7_maybe_decode,
};

use super::{parse_number, parse_sequence_set};

impl Request<Command> {
    pub fn parse_select(self, is_utf8: bool) -> trc::Result<select::Arguments> {
        if !self.tokens.is_empty() {
            let mut tokens = self.tokens.into_iter().peekable();

            // Mailbox name
            let mailbox_name = utf7_maybe_decode(
                tokens
                    .next()
                    .unwrap()
                    .unwrap_string()
                    .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                is_utf8,
            );

            // CONDSTORE parameters
            let mut condstore = false;
            let mut qresync = None;
            let mut objectid = None;
            match tokens.next() {
                Some(Token::ParenthesisOpen) => {
                    while let Some(token) = tokens.next() {
                        match token {
                            Token::Argument(param) if param.eq_ignore_ascii_case(b"CONDSTORE") => {
                                condstore = true;
                            }
                            Token::Argument(param) if param.eq_ignore_ascii_case(b"QRESYNC") => {
                                if tokens
                                    .next()
                                    .is_none_or(|token| !token.is_parenthesis_open())
                                {
                                    return Err(bad(
                                        CompactString::from_string_buffer(self.tag),
                                        "Expected '(' after 'QRESYNC'.",
                                    ));
                                }

                                let uid_validity = parse_number::<u32>(
                                    &tokens
                                        .next()
                                        .ok_or_else(|| {
                                            bad(
                                                self.tag.to_compact_string(),
                                                "Missing uidvalidity parameter for QRESYNC.",
                                            )
                                        })?
                                        .unwrap_bytes(),
                                )
                                .map_err(|v| bad(self.tag.to_compact_string(), v))?;
                                let modseq = parse_number::<u64>(
                                    &tokens
                                        .next()
                                        .ok_or_else(|| {
                                            bad(
                                                self.tag.to_compact_string(),
                                                "Missing modseq parameter for QRESYNC.",
                                            )
                                        })?
                                        .unwrap_bytes(),
                                )
                                .map_err(|v| bad(self.tag.to_compact_string(), v))?;

                                let mut known_uids = None;
                                let mut seq_match = None;
                                let has_seq_match = match tokens.peek() {
                                    Some(Token::Argument(value)) => {
                                        known_uids = parse_sequence_set(value)
                                            .map_err(|v| bad(self.tag.to_compact_string(), v))?
                                            .into();
                                        tokens.next();
                                        if matches!(tokens.peek(), Some(Token::ParenthesisOpen)) {
                                            tokens.next();
                                            true
                                        } else {
                                            false
                                        }
                                    }
                                    Some(Token::ParenthesisOpen) => {
                                        tokens.next();
                                        true
                                    }
                                    _ => false,
                                };

                                if has_seq_match {
                                    seq_match = Some((
                                        parse_sequence_set(
                                            &tokens
                                                .next()
                                                .ok_or_else(|| {
                                                    bad(
                                            self.tag.to_compact_string(),
                                            "Missing known-sequence-set parameter for QRESYNC.",
                                        )
                                                })?
                                                .unwrap_bytes(),
                                        )
                                        .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                                        parse_sequence_set(
                                            &tokens
                                                .next()
                                                .ok_or_else(|| {
                                                    bad(
                                                self.tag.to_compact_string(),
                                                "Missing known-uid-set parameter for QRESYNC.",
                                            )
                                                })?
                                                .unwrap_bytes(),
                                        )
                                        .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                                    ));
                                    if tokens
                                        .next()
                                        .is_none_or(|token| !token.is_parenthesis_close())
                                    {
                                        return Err(bad(
                                            CompactString::from_string_buffer(self.tag),
                                            "Missing ')' for 'QRESYNC'.",
                                        ));
                                    }
                                }

                                if tokens
                                    .next()
                                    .is_none_or(|token| !token.is_parenthesis_close())
                                {
                                    return Err(bad(
                                        CompactString::from_string_buffer(self.tag),
                                        "Missing ')' for 'QRESYNC'.",
                                    ));
                                }

                                qresync = QResync {
                                    uid_validity,
                                    modseq,
                                    known_uids,
                                    seq_match,
                                }
                                .into();
                            }
                            Token::Argument(param) if param.eq_ignore_ascii_case(b"OBJECTID") => {
                                let mut oid = ObjectId::default();
                                if matches!(tokens.peek(), Some(Token::ParenthesisOpen)) {
                                    tokens.next();
                                    while let Some(token) = tokens.next() {
                                        match token {
                                            Token::ParenthesisClose => break,
                                            Token::Argument(key) => {
                                                let value = tokens
                                                    .next()
                                                    .ok_or_else(|| {
                                                        bad(
                                                            self.tag.to_compact_string(),
                                                            "Expected value after OBJECTID key.",
                                                        )
                                                    })?
                                                    .unwrap_bytes();
                                                let id = std::str::from_utf8(&value)
                                                    .ok()
                                                    .and_then(|v| Id::from_str(v).ok());
                                                hashify::fnc_map_ignore_case!(key.as_slice(),
                                                    "MAILBOXID" => { oid.mailbox_id = id; },
                                                    "ACCOUNTID" => { oid.account_id = id; },
                                                    "EMAILID" => { oid.email_id = id; },
                                                    "THREADID" => { oid.thread_id = id; },
                                                    _ => {}
                                                );
                                            }
                                            _ => {
                                                return Err(bad(
                                                    CompactString::from_string_buffer(self.tag),
                                                    format_compact!(
                                                        "Unexpected value '{}'.",
                                                        token
                                                    ),
                                                ));
                                            }
                                        }
                                    }
                                }
                                objectid = Some(oid);
                            }
                            Token::ParenthesisClose => {
                                break;
                            }
                            _ => {
                                return Err(bad(
                                    CompactString::from_string_buffer(self.tag),
                                    format_compact!("Unexpected value '{}'.", token),
                                ));
                            }
                        }
                    }
                }
                Some(token) => {
                    return Err(bad(
                        CompactString::from_string_buffer(self.tag),
                        format_compact!("Unexpected value '{}'.", token),
                    ));
                }
                None => (),
            }

            Ok(select::Arguments {
                mailbox_name,
                tag: self.tag,
                condstore,
                qresync,
                objectid,
            })
        } else {
            Err(self.into_error("Missing mailbox name."))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        protocol::{
            ObjectId, Sequence,
            select::{self, QResync},
        },
        receiver::Receiver,
    };
    use std::str::FromStr;
    use types::id::Id;

    #[test]
    fn parse_select_objectid() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A1 SELECT \"foo\" (OBJECTID)\r\n",
                select::Arguments {
                    mailbox_name: "foo".into(),
                    tag: "A1".into(),
                    condstore: false,
                    qresync: None,
                    objectid: Some(ObjectId::default()),
                },
            ),
            (
                "A2 SELECT \"foo\" (OBJECTID (MAILBOXID abc ACCOUNTID xyz))\r\n",
                select::Arguments {
                    mailbox_name: "foo".into(),
                    tag: "A2".into(),
                    condstore: false,
                    qresync: None,
                    objectid: Some(ObjectId {
                        mailbox_id: Some(Id::from_str("abc").unwrap()),
                        account_id: Some(Id::from_str("xyz").unwrap()),
                        ..Default::default()
                    }),
                },
            ),
            (
                "A3 EXAMINE \"foo\" (OBJECTID (MAILBOXID abc))\r\n",
                select::Arguments {
                    mailbox_name: "foo".into(),
                    tag: "A3".into(),
                    condstore: false,
                    qresync: None,
                    objectid: Some(ObjectId {
                        mailbox_id: Some(Id::from_str("abc").unwrap()),
                        ..Default::default()
                    }),
                },
            ),
            (
                "A4 SELECT \"foo\" (CONDSTORE OBJECTID)\r\n",
                select::Arguments {
                    mailbox_name: "foo".into(),
                    tag: "A4".into(),
                    condstore: true,
                    qresync: None,
                    objectid: Some(ObjectId::default()),
                },
            ),
            (
                "A5 SELECT \"foo\" (OBJECTID (FOOBAR baz MAILBOXID abc))\r\n",
                select::Arguments {
                    mailbox_name: "foo".into(),
                    tag: "A5".into(),
                    condstore: false,
                    qresync: None,
                    objectid: Some(ObjectId {
                        mailbox_id: Some(Id::from_str("abc").unwrap()),
                        ..Default::default()
                    }),
                },
            ),
            (
                "A6 SELECT \"foo\" (OBJECTID (MAILBOXID 456))\r\n",
                select::Arguments {
                    mailbox_name: "foo".into(),
                    tag: "A6".into(),
                    condstore: false,
                    qresync: None,
                    objectid: Some(ObjectId::default()),
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_select(true)
                    .unwrap(),
                arguments,
                "Failed to parse {command}"
            );
        }
    }

    #[test]
    fn parse_select() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A142 SELECT INBOX\r\n",
                select::Arguments {
                    mailbox_name: "INBOX".into(),
                    tag: "A142".into(),
                    condstore: false,
                    qresync: None,
                    objectid: None,
                },
            ),
            (
                "A142 SELECT \"my funky mailbox\"\r\n",
                select::Arguments {
                    mailbox_name: "my funky mailbox".into(),
                    tag: "A142".into(),
                    condstore: false,
                    qresync: None,
                    objectid: None,
                },
            ),
            (
                "A142 SELECT INBOX (CONDSTORE)\r\n",
                select::Arguments {
                    mailbox_name: "INBOX".into(),
                    tag: "A142".into(),
                    condstore: true,
                    qresync: None,
                    objectid: None,
                },
            ),
            (
                "A142 SELECT INBOX (QRESYNC (3857529045 20010715194032001 1:198))\r\n",
                select::Arguments {
                    mailbox_name: "INBOX".into(),
                    tag: "A142".into(),
                    condstore: false,
                    qresync: QResync {
                        uid_validity: 3857529045,
                        modseq: 20010715194032001,
                        known_uids: Some(Sequence::Range {
                            start: Some(1),
                            end: Some(198),
                        }),
                        seq_match: None,
                    }
                    .into(),
                    objectid: None,
                },
            ),
            (
                concat!(
                    "A03 SELECT INBOX (QRESYNC (67890007 90060115194045000 ",
                    "41:211,214:541) CONDSTORE)\r\n"
                ),
                select::Arguments {
                    mailbox_name: "INBOX".into(),
                    tag: "A03".into(),
                    condstore: true,
                    qresync: QResync {
                        uid_validity: 67890007,
                        modseq: 90060115194045000,
                        known_uids: Some(Sequence::List {
                            items: vec![
                                Sequence::Range {
                                    start: Some(41),
                                    end: Some(211),
                                },
                                Sequence::Range {
                                    start: Some(214),
                                    end: Some(541),
                                },
                            ],
                        }),
                        seq_match: None,
                    }
                    .into(),
                    objectid: None,
                },
            ),
            (
                concat!(
                    "B04 SELECT INBOX (QRESYNC (67890007 ",
                    "90060115194045000 1:29997 (5000,7500,9000,9990:9999 15000,",
                    "22500,27000,29970,29973,29976,29979,29982,29985,29988,29991,",
                    "29994,29997)))\r\n"
                ),
                select::Arguments {
                    mailbox_name: "INBOX".into(),
                    tag: "B04".into(),
                    condstore: false,
                    qresync: QResync {
                        uid_validity: 67890007,
                        modseq: 90060115194045000,
                        known_uids: Some(Sequence::Range {
                            start: Some(1),
                            end: Some(29997),
                        }),
                        seq_match: Some((
                            Sequence::List {
                                items: vec![
                                    Sequence::Number { value: 5000 },
                                    Sequence::Number { value: 7500 },
                                    Sequence::Number { value: 9000 },
                                    Sequence::Range {
                                        start: Some(9990),
                                        end: Some(9999),
                                    },
                                ],
                            },
                            Sequence::List {
                                items: vec![
                                    Sequence::Number { value: 15000 },
                                    Sequence::Number { value: 22500 },
                                    Sequence::Number { value: 27000 },
                                    Sequence::Number { value: 29970 },
                                    Sequence::Number { value: 29973 },
                                    Sequence::Number { value: 29976 },
                                    Sequence::Number { value: 29979 },
                                    Sequence::Number { value: 29982 },
                                    Sequence::Number { value: 29985 },
                                    Sequence::Number { value: 29988 },
                                    Sequence::Number { value: 29991 },
                                    Sequence::Number { value: 29994 },
                                    Sequence::Number { value: 29997 },
                                ],
                            },
                        )),
                    }
                    .into(),
                    objectid: None,
                },
            ),
            (
                "A12 SELECT \"INBOX\" (QRESYNC (1693237464 16582))\r\n",
                select::Arguments {
                    mailbox_name: "INBOX".into(),
                    tag: "A12".into(),
                    condstore: false,
                    qresync: QResync {
                        uid_validity: 1693237464,
                        modseq: 16582,
                        known_uids: None,
                        seq_match: None,
                    }
                    .into(),
                    objectid: None,
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap_or_else(|err| panic!(
                        "Failed to parse command '{}': {:?}",
                        command, err
                    ))
                    .parse_select(true)
                    .unwrap_or_else(|err| panic!(
                        "Failed to parse command '{}': {:?}",
                        command, err
                    )),
                arguments,
                "Failed to parse {}",
                command
            );
        }
    }
}
