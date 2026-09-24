/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::{capability::Capability, enable},
    receiver::{Request, Token, bad},
};

impl Request<Command> {
    pub fn parse_enable(self) -> trc::Result<enable::Arguments> {
        if self.tokens.is_empty() {
            return Err(self.into_error("Missing arguments."));
        }

        let mut capabilities = Vec::with_capacity(self.tokens.len());
        for token in self.tokens {
            match token {
                Token::Argument(name) => capabilities.extend(Capability::parse(&name)),
                _ => return Err(bad(self.tag, "Invalid capability name.")),
            }
        }

        Ok(enable::Arguments {
            tag: self.tag,
            capabilities,
        })
    }
}

impl Capability {
    pub fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "IMAP4rev2" => Some(Self::IMAP4rev2),
            "STARTTLS" => Some(Self::StartTLS),
            "LOGINDISABLED" => Some(Self::LoginDisabled),
            "CONDSTORE" => Some(Self::CondStore),
            "QRESYNC" => Some(Self::QResync),
            "UTF8=ACCEPT" => Some(Self::Utf8Accept),
            "OBJECTID+" => Some(Self::ObjectIdPlus),
            "UIDONLY" => Some(Self::UidOnly),
            _ => None,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        protocol::{capability::Capability, enable},
        receiver::Receiver,
    };

    #[test]
    fn parse_enable() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "t2 ENABLE IMAP4rev2 CONDSTORE\r\n",
                enable::Arguments {
                    tag: "t2".into(),
                    capabilities: vec![Capability::IMAP4rev2, Capability::CondStore],
                },
            ),
            (
                "t3 ENABLE OBJECTID+\r\n",
                enable::Arguments {
                    tag: "t3".into(),
                    capabilities: vec![Capability::ObjectIdPlus],
                },
            ),
            (
                "t4 ENABLE CONDSTORE OBJECTID+ UTF8=ACCEPT\r\n",
                enable::Arguments {
                    tag: "t4".into(),
                    capabilities: vec![
                        Capability::CondStore,
                        Capability::ObjectIdPlus,
                        Capability::Utf8Accept,
                    ],
                },
            ),
            (
                "t5 ENABLE METADATA X-UNKNOWN condstore\r\n",
                enable::Arguments {
                    tag: "t5".into(),
                    capabilities: vec![Capability::CondStore],
                },
            ),
            (
                "t6 ENABLE METADATA-SERVER\r\n",
                enable::Arguments {
                    tag: "t6".into(),
                    capabilities: vec![],
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_enable()
                    .unwrap(),
                arguments,
                "Failed to parse {command}"
            );
        }
    }
}
