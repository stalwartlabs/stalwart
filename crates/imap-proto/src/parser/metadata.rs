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
    utf7::utf7_maybe_decode,
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

        self.mailbox_name = utf7_maybe_decode(
            tokens
                .next()
                .ok_or("Missing mailbox name.")?
                .unwrap_string()?,
            is_utf8,
        );

        match tokens.next().ok_or("Missing entry specifier.")? {
            Token::ParenthesisOpen
                if tokens
                    .peek()
                    .is_some_and(|token| !token.as_bytes().starts_with(b"/")) =>
            {
                self.parse_options(tokens)?;
                let first = tokens.next().ok_or("Missing entry specifier.")?;
                self.parse_entries(first, tokens)?;
            }
            first => self.parse_entries(first, tokens)?,
        }

        if tokens.next().is_none() {
            Ok(())
        } else {
            Err("Unexpected arguments after entry specifiers.".into())
        }
    }

    fn parse_options(&mut self, tokens: &mut Tokens) -> super::Result<()> {
        while let Some(token) = tokens.next() {
            match token {
                Token::ParenthesisClose => return Ok(()),
                Token::Argument(option) if option.eq_ignore_ascii_case(b"MAXSIZE") => {
                    self.max_size = Some(parse_number(
                        tokens.next().ok_or("Missing MAXSIZE value.")?.as_bytes(),
                    )?);
                }
                Token::Argument(option) if option.eq_ignore_ascii_case(b"DEPTH") => {
                    self.depth =
                        Depth::parse(tokens.next().ok_or("Missing DEPTH value.")?.as_bytes())?;
                }
                token => {
                    return Err(
                        format!("Unsupported GETMETADATA option {:?}.", token.to_string()).into(),
                    );
                }
            }
        }

        Err("Unterminated GETMETADATA options.".into())
    }

    fn parse_entries(&mut self, first: Token, tokens: &mut Tokens) -> super::Result<()> {
        if !first.is_parenthesis_open() {
            self.entries.push(Entry::parse_specifier(first.as_bytes())?);
            return Ok(());
        }

        for token in tokens.by_ref() {
            match token {
                Token::ParenthesisClose if !self.entries.is_empty() => return Ok(()),
                Token::ParenthesisOpen | Token::ParenthesisClose => {
                    return Err("Invalid entry specifier list.".into());
                }
                token => self.entries.push(Entry::parse_specifier(token.as_bytes())?),
            }
        }

        Err("Unterminated entry specifier list.".into())
    }
}

impl SetArguments {
    fn parse(&mut self, tokens: &mut IntoIter<Token>, is_utf8: bool) -> super::Result<()> {
        self.mailbox_name = utf7_maybe_decode(
            tokens
                .next()
                .ok_or("Missing mailbox name.")?
                .unwrap_string()?,
            is_utf8,
        );

        if tokens
            .next()
            .is_none_or(|token| !token.is_parenthesis_open())
        {
            return Err("Expected a parenthesized list of entries and values.".into());
        }

        while let Some(token) = tokens.next() {
            let entry = match token {
                Token::ParenthesisClose if !self.entries.is_empty() => {
                    return if tokens.next().is_none() {
                        Ok(())
                    } else {
                        Err("Unexpected arguments after entry values.".into())
                    };
                }
                Token::ParenthesisOpen | Token::ParenthesisClose => {
                    return Err("Invalid entry value list.".into());
                }
                token => Entry::parse_name(token.as_bytes())?,
            };
            let value = match tokens.next().ok_or("Missing entry value.")? {
                Token::NilAtom => None,
                Token::ParenthesisOpen | Token::ParenthesisClose => {
                    return Err("Missing entry value.".into());
                }
                token => Some(Cow::Owned(token.unwrap_bytes().into_vec())),
            };
            self.entries.push(EntryValue { entry, value });
        }

        Err("Unterminated entry value list.".into())
    }
}

impl Entry<'static> {
    pub fn parse_specifier(value: &[u8]) -> super::Result<Self> {
        if let Some(ch) = value
            .iter()
            .find(|&&ch| !(0x1a..0x80).contains(&ch) || ch == b'*' || ch == b'%')
        {
            return Err(format!("Invalid character {:?} in entry name.", *ch as char).into());
        }

        let name = std::str::from_utf8(value).map_err(|_| "Invalid entry name.")?;
        let (scope, path) = [Scope::Shared, Scope::Private]
            .into_iter()
            .find_map(|scope| {
                let prefix = scope.as_str();
                name.split_at_checked(prefix.len())
                    .filter(|(head, path)| {
                        head.eq_ignore_ascii_case(prefix)
                            && (path.is_empty() || path.starts_with('/'))
                    })
                    .map(|(_, path)| (scope, path))
            })
            .ok_or("Entry names must begin with /shared or /private.")?;

        if path.ends_with('/') || path.contains("//") {
            return Err(format!("Invalid entry name {name:?}.").into());
        }

        Ok(Entry {
            scope,
            path: Cow::Owned(path.to_ascii_lowercase()),
        })
    }

    pub fn parse_name(value: &[u8]) -> super::Result<Self> {
        let entry = Entry::parse_specifier(value)?;
        let mut components = entry.path.split('/').skip(1);
        let error = match (components.next(), components.next(), components.next()) {
            (None, _, _) => Some("Entry names must have at least two components."),
            (Some("vendor"), _, None) => {
                Some("Vendor entry names must have at least four components.")
            }
            _ => None,
        };

        match error {
            Some(error) => Err(error.into()),
            None => Ok(entry),
        }
    }
}

impl Depth {
    fn parse(value: &[u8]) -> super::Result<Self> {
        match value {
            b"0" => Ok(Depth::Zero),
            b"1" => Ok(Depth::One),
            _ if value.eq_ignore_ascii_case(b"infinity") => Ok(Depth::Infinity),
            _ => Err("DEPTH must be 0, 1 or infinity.".into()),
        }
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
                "a GETMETADATA (MAXSIZE 1024 DEPTH infinity) INBOX (/Shared/Vendor/CMU)\r\n",
                GetArguments {
                    tag: "a".into(),
                    mailbox_name: "INBOX".into(),
                    max_size: Some(1024),
                    depth: Depth::Infinity,
                    entries: vec![entry(Scope::Shared, "/vendor/cmu")],
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
                "a GETMETADATA (depth 0) \"&AOk-t&AOk-\" (/private /SHARED)\r\n",
                GetArguments {
                    tag: "a".into(),
                    mailbox_name: "\u{e9}t\u{e9}".into(),
                    max_size: None,
                    depth: Depth::Zero,
                    entries: vec![entry(Scope::Private, ""), entry(Scope::Shared, "")],
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
            "a GETMETADATA INBOX /shared/comment /private/comment\r\n",
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
                        value(entry(Scope::Private, "/comment"), Some(b"NIL")),
                        value(entry(Scope::Shared, "/comment"), None),
                        value(entry(Scope::Shared, "/vendor/cmu/color"), Some(b"")),
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
