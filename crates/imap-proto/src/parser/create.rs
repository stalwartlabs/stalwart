/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::format_compact;

use crate::{
    Command,
    protocol::{create, list::Attribute},
    receiver::{Request, Token, bad},
};

impl Request<Command> {
    pub fn parse_create(self, is_utf8: bool) -> trc::Result<create::Arguments> {
        if !self.tokens.is_empty() {
            let mut tokens = self.tokens.into_iter();
            let mailbox_name = tokens
                .next()
                .unwrap()
                .unwrap_mailbox_name_strict(is_utf8)
                .map_err(|v| bad(self.tag.clone(), v))?;
            let mailbox_role = if let Some(Token::ParenthesisOpen) = tokens.next() {
                match tokens.next() {
                    Some(Token::Argument(param)) if param.eq_ignore_ascii_case(b"USE") => (),
                    _ => {
                        return Err(bad(self.tag, "Failed to parse, expected 'USE'."));
                    }
                }
                if tokens
                    .next()
                    .is_none_or(|token| !token.is_parenthesis_open())
                {
                    return Err(bad(self.tag, "Expected '(' after 'USE'."));
                }
                match tokens.next() {
                    Some(Token::Argument(value)) => match Attribute::parse_special_use(&value) {
                        Some(Attribute::All) => {
                            return Err(bad(
                                self.tag,
                                "A mailbox with the \"\\All\" attribute already exists.",
                            ));
                        }
                        Some(tag) => Some(tag),
                        None => {
                            return Err(bad(
                                self.tag,
                                format_compact!(
                                    "Special use attribute {:?} is not supported.",
                                    String::from_utf8_lossy(&value)
                                ),
                            ));
                        }
                    },
                    _ => {
                        return Err(bad(self.tag, "Invalid SPECIAL-USE attribute."));
                    }
                }
            } else {
                None
            };

            Ok(create::Arguments {
                mailbox_name,
                mailbox_role,
                tag: self.tag,
            })
        } else {
            Err(self.into_error("Missing arguments."))
        }
    }
}

impl Attribute {
    pub fn parse_special_use(value: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(value, Attribute,
            "\\Archive" => Attribute::Archive,
            "\\Drafts" => Attribute::Drafts,
            "\\Junk" => Attribute::Junk,
            "\\Sent" => Attribute::Sent,
            "\\Trash" => Attribute::Trash,
            "\\Important" => Attribute::Important,
            "\\Memos" => Attribute::Memos,
            "\\Scheduled" => Attribute::Scheduled,
            "\\Snoozed" => Attribute::Snoozed,
            "\\All" => Attribute::All,
        )
        .copied()
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        protocol::{create, list::Attribute},
        receiver::Receiver,
    };

    #[test]
    fn parse_create() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A142 CREATE 12345\r\n",
                create::Arguments {
                    tag: "A142".into(),
                    mailbox_name: "12345".into(),
                    mailbox_role: None,
                },
            ),
            (
                "A142 CREATE \"my funky mailbox\"\r\n",
                create::Arguments {
                    tag: "A142".into(),
                    mailbox_name: "my funky mailbox".into(),
                    mailbox_role: None,
                },
            ),
            (
                "t1 CREATE \"Important Messages\" (USE (\\Important))\r\n",
                create::Arguments {
                    tag: "t1".into(),
                    mailbox_name: "Important Messages".into(),
                    mailbox_role: Some(Attribute::Important),
                },
            ),
            (
                "A142 CREATE \"Test-ąęć-Test\"\r\n",
                create::Arguments {
                    tag: "A142".into(),
                    mailbox_name: "Test-ąęć-Test".into(),
                    mailbox_role: None,
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_create(true)
                    .unwrap(),
                arguments
            );
        }
    }

    #[test]
    fn parse_create_decodes_modified_utf7_strictly() {
        let mut receiver = Receiver::new();

        for (command, mailbox_name) in [
            ("A1 CREATE INBOX.Sent\r\n", "INBOX.Sent"),
            ("A2 CREATE \"Item 3 is &AKM-1.\"\r\n", "Item 3 is £1."),
            ("A3 CREATE &ZeVnLIqe-/&U,BTFw-\r\n", "日本語/台北"),
            ("A4 CREATE \"Plus &- minus\"\r\n", "Plus & minus"),
            ("A5 CREATE \"Test-ąęć-Test\"\r\n", "Test-ąęć-Test"),
            ("A6 CREATE \"Hello, World!\"\r\n", "Hello, World!"),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_create(false)
                    .unwrap(),
                create::Arguments {
                    tag: command.split_once(' ').unwrap().0.into(),
                    mailbox_name: mailbox_name.into(),
                    mailbox_role: None,
                }
            );
        }

        for command in [
            "B1 CREATE &AKM\r\n",
            "B2 CREATE \"Hello, World&ACE-\"\r\n",
            "B3 CREATE &AKM-&AKM-\r\n",
            "B4 CREATE \"Test-ąęć-&AKM-\"\r\n",
            "B5 CREATE &2D0-\r\n",
            "B6 CREATE \"Sent &AKM.\"\r\n",
        ] {
            assert!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_create(false)
                    .is_err(),
                "{command:?}"
            );
        }
    }
}
