/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::parse_number;
use crate::{
    Command,
    protocol::metadata::{Depth, Entry, EntryValue, GetArguments, Scope, SetArguments},
    receiver::{Request, Token, bad},
};
use compact_str::CompactString;
use std::{borrow::Cow, iter::Peekable, vec::IntoIter};

type Tokens = Peekable<IntoIter<Token>>;

impl Request<Command> {
    pub fn parse_get_metadata(self, is_utf8: bool) -> trc::Result<GetArguments> {
        let mut arguments = GetArguments {
            tag: self.tag,
            mailbox_name: CompactString::const_new(""),
            max_size: None,
            depth: Depth::Zero,
            entries: Vec::new(),
        };
        arguments
            .parse(&mut self.tokens.into_iter().peekable(), is_utf8)
            .map_err(|err| bad(arguments.tag.clone(), err))?;
        Ok(arguments)
    }

    pub fn parse_set_metadata(self, is_utf8: bool) -> trc::Result<SetArguments> {
        let mut arguments = SetArguments {
            tag: self.tag,
            mailbox_name: CompactString::const_new(""),
            entries: Vec::new(),
        };
        arguments
            .parse(&mut self.tokens.into_iter(), is_utf8)
            .map_err(|err| bad(arguments.tag.clone(), err))?;
        Ok(arguments)
    }
}

impl GetArguments {
    fn parse(&mut self, tokens: &mut Tokens, is_utf8: bool) -> super::Result<()> {
        if tokens.next_if(Token::is_parenthesis_open).is_some() {
            self.parse_options(tokens)?;
        }

        self.mailbox_name = tokens
            .next()
            .ok_or("Missing mailbox name.")?
            .unwrap_mailbox_name(is_utf8)?;

        let mut is_list = tokens.next_if(Token::is_parenthesis_open).is_some();
        if is_list
            && tokens
                .peek()
                .is_some_and(|token| !token.as_bytes().starts_with(b"/"))
        {
            self.parse_options(tokens)?;
            is_list = tokens.next_if(Token::is_parenthesis_open).is_some();
        }

        if is_list {
            self.entries = Entry::parse_list(tokens)?;
            if tokens.next().is_some() {
                return Err("Unexpected arguments after entry specifiers.".into());
            }
        } else {
            for token in tokens {
                self.entries.push(Entry::parse(token.as_bytes())?);
            }
            if self.entries.is_empty() {
                return Err("Missing entry specifier.".into());
            }
        }

        self.entries.sort_unstable();
        self.entries.dedup();
        Ok(())
    }

    fn parse_options(&mut self, tokens: &mut Tokens) -> super::Result<()> {
        while let Some(token) = tokens.next() {
            match token {
                Token::ParenthesisClose => return Ok(()),
                Token::Argument(option) => {
                    hashify::fnc_map_ignore_case!(option.as_slice(),
                        "MAXSIZE" => {
                            self.max_size = Some(parse_number(
                                tokens.next().ok_or("Missing MAXSIZE value.")?.as_bytes(),
                            )?);
                        },
                        "DEPTH" => {
                            self.depth =
                                Depth::parse(tokens.next().ok_or("Missing DEPTH value.")?.as_bytes())?;
                        },
                        _ => {
                            return Err(format!(
                                "Unsupported GETMETADATA option {:?}.",
                                String::from_utf8_lossy(&option)
                            )
                            .into());
                        }
                    )
                }
                _ => return Err("Invalid GETMETADATA option.".into()),
            }
        }

        Err("Unterminated GETMETADATA options.".into())
    }
}

impl SetArguments {
    fn parse(&mut self, tokens: &mut IntoIter<Token>, is_utf8: bool) -> super::Result<()> {
        self.mailbox_name = tokens
            .next()
            .ok_or("Missing mailbox name.")?
            .unwrap_mailbox_name(is_utf8)?;

        if tokens
            .next()
            .is_none_or(|token| !token.is_parenthesis_open())
        {
            return Err("Expected a parenthesized list of entries and values.".into());
        }

        loop {
            let entry = match tokens.next().ok_or("Unterminated entry value list.")? {
                Token::ParenthesisClose if !self.entries.is_empty() => break,
                Token::ParenthesisOpen | Token::ParenthesisClose => {
                    return Err("Invalid entry value list.".into());
                }
                token => Entry::parse(token.as_bytes())?,
            };
            let value = match tokens.next().ok_or("Missing entry value.")? {
                Token::Argument(value) if value.eq_ignore_ascii_case(b"NIL") => None,
                Token::ParenthesisOpen | Token::ParenthesisClose => {
                    return Err("Missing entry value.".into());
                }
                token => Some(Cow::Owned(token.unwrap_bytes().into_vec())),
            };
            self.entries.push(EntryValue { entry, value });
        }

        if tokens.next().is_some() {
            return Err("Unexpected arguments after entry values.".into());
        }

        self.entries.reverse();
        self.entries.sort_by(|a, b| a.entry.cmp(&b.entry));
        self.entries.dedup_by(|a, b| a.entry == b.entry);
        Ok(())
    }
}

impl Entry<'static> {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        if let Some(ch) = value
            .iter()
            .find(|&&ch| !(0x1a..0x80).contains(&ch) || ch == b'*' || ch == b'%')
        {
            return Err(format!("Invalid character {:?} in entry name.", *ch as char).into());
        }

        let name = std::str::from_utf8(value).map_err(|_| "Invalid entry name.")?;
        let (scope, rest) = name
            .strip_prefix('/')
            .map(|name| {
                name.split_once('/')
                    .map_or((name, None), |(scope, rest)| (scope, Some(rest)))
            })
            .ok_or("Entry names must begin with /shared or /private.")?;
        let scope = hashify::map_ignore_case!(scope.as_bytes(), Scope,
            "shared" => Scope::Shared,
            "private" => Scope::Private,
        )
        .copied()
        .ok_or("Entry names must begin with /shared or /private.")?;
        let rest = rest.ok_or("Entry names must have at least two components.")?;

        let mut path = String::with_capacity(rest.len() + 1);
        path.push('/');
        path.push_str(rest);
        if path.ends_with('/') || path.contains("//") {
            return Err(format!("Invalid entry name {name:?}.").into());
        }
        path.make_ascii_lowercase();

        let mut components = path.split('/').skip(1);
        if let (Some("vendor"), _, None) = (components.next(), components.next(), components.next())
        {
            return Err("Vendor entry names must have at least four components.".into());
        }

        Ok(Entry {
            scope,
            path: Cow::Owned(path),
        })
    }

    pub(crate) fn parse_list(tokens: &mut impl Iterator<Item = Token>) -> super::Result<Vec<Self>> {
        let mut entries = Vec::new();
        for token in tokens {
            match token {
                Token::ParenthesisClose if !entries.is_empty() => return Ok(entries),
                Token::ParenthesisOpen | Token::ParenthesisClose => {
                    return Err("Invalid entry specifier list.".into());
                }
                token => entries.push(Entry::parse(token.as_bytes())?),
            }
        }

        Err("Unterminated entry specifier list.".into())
    }
}

impl Depth {
    fn parse(value: &[u8]) -> super::Result<Self> {
        hashify::map_ignore_case!(value, Depth,
            "0" => Depth::Zero,
            "1" => Depth::One,
            "infinity" => Depth::Infinity,
        )
        .copied()
        .ok_or_else(|| "DEPTH must be 0, 1 or infinity.".into())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        protocol::metadata::{Depth, Entry, EntryValue, GetArguments, Scope, SetArguments},
        receiver::Receiver,
    };
    use std::borrow::Cow;

    fn entry(scope: Scope, path: &'static str) -> Entry<'static> {
        Entry {
            scope,
            path: Cow::Borrowed(path),
        }
    }

    fn value(entry: Entry<'static>, value: Option<&[u8]>) -> EntryValue<'static> {
        EntryValue {
            entry,
            value: value.map(|value| Cow::Owned(value.to_vec())),
        }
    }

    #[test]
    fn parse_get_metadata() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "a GETMETADATA \"\" /shared/comment\r\n",
                GetArguments {
                    tag: "a".into(),
                    mailbox_name: "".into(),
                    max_size: None,
                    depth: Depth::Zero,
                    entries: vec![entry(Scope::Shared, "/comment")],
                },
            ),
            (
                "a GETMETADATA \"INBOX\" (/shared/comment /private/comment)\r\n",
                GetArguments {
                    tag: "a".into(),
                    mailbox_name: "INBOX".into(),
                    max_size: None,
                    depth: Depth::Zero,
                    entries: vec![
                        entry(Scope::Shared, "/comment"),
                        entry(Scope::Private, "/comment"),
                    ],
                },
            ),
            (
                "a GETMETADATA (MAXSIZE 1024 DEPTH infinity) INBOX (/Shared/Vendor/CMU/Cyrus-IMAPd)\r\n",
                GetArguments {
                    tag: "a".into(),
                    mailbox_name: "INBOX".into(),
                    max_size: Some(1024),
                    depth: Depth::Infinity,
                    entries: vec![entry(Scope::Shared, "/vendor/cmu/cyrus-imapd")],
                },
            ),
            (
                "a GETMETADATA \"INBOX\" (MAXSIZE 1024) (/shared/comment /private/comment)\r\n",
                GetArguments {
                    tag: "a".into(),
                    mailbox_name: "INBOX".into(),
                    max_size: Some(1024),
                    depth: Depth::Zero,
                    entries: vec![
                        entry(Scope::Shared, "/comment"),
                        entry(Scope::Private, "/comment"),
                    ],
                },
            ),
            (
                "a GETMETADATA \"INBOX\" (DEPTH 1) (/private/filters/values)\r\n",
                GetArguments {
                    tag: "a".into(),
                    mailbox_name: "INBOX".into(),
                    max_size: None,
                    depth: Depth::One,
                    entries: vec![entry(Scope::Private, "/filters/values")],
                },
            ),
            (
                "a GETMETADATA (depth 0) \"&AOk-t&AOk-\" (/private/x /SHARED/Y)\r\n",
                GetArguments {
                    tag: "a".into(),
                    mailbox_name: "\u{e9}t\u{e9}".into(),
                    max_size: None,
                    depth: Depth::Zero,
                    entries: vec![entry(Scope::Shared, "/y"), entry(Scope::Private, "/x")],
                },
            ),
            (
                "a GETMETADATA \"INBOX\" /private/comment /shared/comment\r\n",
                GetArguments {
                    tag: "a".into(),
                    mailbox_name: "INBOX".into(),
                    max_size: None,
                    depth: Depth::Zero,
                    entries: vec![
                        entry(Scope::Shared, "/comment"),
                        entry(Scope::Private, "/comment"),
                    ],
                },
            ),
            (
                "a GETMETADATA INBOX (DEPTH 1 MAXSIZE 5 MAXSIZE 7) /shared/b /SHARED/A /shared/b\r\n",
                GetArguments {
                    tag: "a".into(),
                    mailbox_name: "INBOX".into(),
                    max_size: Some(7),
                    depth: Depth::One,
                    entries: vec![entry(Scope::Shared, "/a"), entry(Scope::Shared, "/b")],
                },
            ),
            (
                "a GETMETADATA (DEPTH INFINITY) nil (/Private/X /private/x /shared/x)\r\n",
                GetArguments {
                    tag: "a".into(),
                    mailbox_name: "nil".into(),
                    max_size: None,
                    depth: Depth::Infinity,
                    entries: vec![entry(Scope::Shared, "/x"), entry(Scope::Private, "/x")],
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_get_metadata(false)
                    .unwrap(),
                arguments,
                "{command:?}"
            );
        }

        for command in [
            "a GETMETADATA\r\n",
            "a GETMETADATA INBOX\r\n",
            "a GETMETADATA INBOX ()\r\n",
            "a GETMETADATA INBOX (/shared/comment\r\n",
            "a GETMETADATA INBOX comment\r\n",
            "a GETMETADATA INBOX /sharedcomment\r\n",
            "a GETMETADATA INBOX /shared/comment/\r\n",
            "a GETMETADATA INBOX /shared//comment\r\n",
            "a GETMETADATA INBOX /shared/*\r\n",
            "a GETMETADATA INBOX /shared/%\r\n",
            "a GETMETADATA INBOX \"/shared/caf\u{e9}\"\r\n",
            "a GETMETADATA INBOX \"/shared/a\tb\"\r\n",
            "a GETMETADATA (MAXSIZE) INBOX /shared/comment\r\n",
            "a GETMETADATA (MAXSIZE abc) INBOX /shared/comment\r\n",
            "a GETMETADATA (DEPTH 2) INBOX /shared/comment\r\n",
            "a GETMETADATA (UNKNOWN 1) INBOX /shared/comment\r\n",
            "a GETMETADATA (DEPTH) INBOX /shared/comment\r\n",
            "a GETMETADATA (MAXSIZE 1 INBOX /shared/comment\r\n",
            "a GETMETADATA INBOX (/shared/comment) extra\r\n",
            "a GETMETADATA INBOX /shared/comment (/private/comment)\r\n",
            "a GETMETADATA INBOX (MAXSIZE 1)\r\n",
            "a GETMETADATA INBOX /sharedx/comment\r\n",
            "a GETMETADATA INBOX /public/comment\r\n",
            "a GETMETADATA INBOX /\r\n",
            "a GETMETADATA INBOX /shared/\r\n",
            "a GETMETADATA INBOX /shared\r\n",
            "a GETMETADATA (DEPTH infinity) INBOX (/private)\r\n",
            "a GETMETADATA INBOX /shared/vendor/cmu\r\n",
            "a GETMETADATA INBOX /Private/Vendor\r\n",
        ] {
            assert!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_get_metadata(false)
                    .is_err(),
                "{command:?}"
            );
        }
    }

    #[test]
    fn parse_set_metadata() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "a SETMETADATA INBOX (/private/comment {33+}\r\nMy new comment across\r\ntwo lines.)\r\n",
                SetArguments {
                    tag: "a".into(),
                    mailbox_name: "INBOX".into(),
                    entries: vec![value(
                        entry(Scope::Private, "/comment"),
                        Some(b"My new comment across\r\ntwo lines."),
                    )],
                },
            ),
            (
                "a SETMETADATA INBOX (/private/comment NIL)\r\n",
                SetArguments {
                    tag: "a".into(),
                    mailbox_name: "INBOX".into(),
                    entries: vec![value(entry(Scope::Private, "/comment"), None)],
                },
            ),
            (
                concat!(
                    "a SETMETADATA \"\" (/private/comment \"NIL\" /Shared/Comment nil ",
                    "/shared/vendor/cmu/color \"\" /private/vendor/kolab/folder-type ~{3+}\r\na\0b)\r\n"
                ),
                SetArguments {
                    tag: "a".into(),
                    mailbox_name: "".into(),
                    entries: vec![
                        value(entry(Scope::Shared, "/comment"), None),
                        value(entry(Scope::Shared, "/vendor/cmu/color"), Some(b"")),
                        value(entry(Scope::Private, "/comment"), Some(b"NIL")),
                        value(
                            entry(Scope::Private, "/vendor/kolab/folder-type"),
                            Some(b"a\0b"),
                        ),
                    ],
                },
            ),
            (
                "a SETMETADATA NIL (/shared/comment {0+}\r\n)\r\n",
                SetArguments {
                    tag: "a".into(),
                    mailbox_name: "NIL".into(),
                    entries: vec![value(entry(Scope::Shared, "/comment"), Some(b""))],
                },
            ),
            (
                "a SETMETADATA nil (/shared/comment NIL)\r\n",
                SetArguments {
                    tag: "a".into(),
                    mailbox_name: "nil".into(),
                    entries: vec![value(entry(Scope::Shared, "/comment"), None)],
                },
            ),
            (
                concat!(
                    "a SETMETADATA \"nil\" (/shared/comment {3+}\r\nnil ",
                    "/private/comment ~{3+}\r\nNIL /shared/vendor/a/b NIL)\r\n"
                ),
                SetArguments {
                    tag: "a".into(),
                    mailbox_name: "nil".into(),
                    entries: vec![
                        value(entry(Scope::Shared, "/comment"), Some(b"nil")),
                        value(entry(Scope::Shared, "/vendor/a/b"), None),
                        value(entry(Scope::Private, "/comment"), Some(b"NIL")),
                    ],
                },
            ),
            (
                concat!(
                    "a SETMETADATA Nil (/shared/comment \"a\" /private/comment x ",
                    "/SHARED/comment \"b\" /private/comment NIL /shared/Comment c)\r\n"
                ),
                SetArguments {
                    tag: "a".into(),
                    mailbox_name: "Nil".into(),
                    entries: vec![
                        value(entry(Scope::Shared, "/comment"), Some(b"c")),
                        value(entry(Scope::Private, "/comment"), None),
                    ],
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_set_metadata(false)
                    .unwrap(),
                arguments,
                "{command:?}"
            );
        }

        for command in [
            "a SETMETADATA INBOX\r\n",
            "a SETMETADATA INBOX ()\r\n",
            "a SETMETADATA INBOX /shared/comment value\r\n",
            "a SETMETADATA INBOX (/shared/comment)\r\n",
            "a SETMETADATA INBOX (/shared/comment value\r\n",
            "a SETMETADATA INBOX (/shared value)\r\n",
            "a SETMETADATA INBOX (/shared/vendor/cmu value)\r\n",
            "a SETMETADATA INBOX (/shared/vendor value)\r\n",
            "a SETMETADATA INBOX (/other/comment value)\r\n",
            "a SETMETADATA INBOX (/shared/comment (value))\r\n",
            "a SETMETADATA INBOX (/shared/comment value) extra\r\n",
            "a SETMETADATA INBOX (NIL value)\r\n",
            "a SETMETADATA INBOX (/shared/comment NIL /shared/other\r\n",
            "a SETMETADATA (/shared/comment value)\r\n",
        ] {
            assert!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_set_metadata(false)
                    .is_err(),
                "{command:?}"
            );
        }
    }
}
