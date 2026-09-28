/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::subscribe,
    receiver::{Request, bad},
};

impl Request<Command> {
    pub fn parse_subscribe(self, is_utf8: bool) -> trc::Result<subscribe::Arguments> {
        match self.tokens.len() {
            1 => Ok(subscribe::Arguments {
                mailbox_name: self
                    .tokens
                    .into_iter()
                    .next()
                    .unwrap()
                    .unwrap_mailbox_name(is_utf8)
                    .map_err(|v| bad(self.tag.clone(), v))?,
                tag: self.tag,
            }),
            0 => Err(self.into_error("Missing mailbox name.")),
            _ => Err(self.into_error("Too many arguments.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{protocol::subscribe, receiver::Receiver};

    #[test]
    fn parse_subscribe() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A142 SUBSCRIBE #news.comp.mail.mime\r\n",
                subscribe::Arguments {
                    mailbox_name: "#news.comp.mail.mime".into(),
                    tag: "A142".into(),
                },
            ),
            (
                "A142 SUBSCRIBE \"#news.comp.mail.mime\"\r\n",
                subscribe::Arguments {
                    mailbox_name: "#news.comp.mail.mime".into(),
                    tag: "A142".into(),
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_subscribe(true)
                    .unwrap(),
                arguments
            );
        }
    }
}
