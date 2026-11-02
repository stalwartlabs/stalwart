/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::id::{self, ClientId},
    receiver::{Request, Token},
};

const MAX_ID_PAIRS: usize = 30;

impl Request<Command> {
    pub fn parse_id(self) -> id::Arguments {
        let client = match self.tokens.as_slice() {
            [Token::ParenthesisOpen, pairs @ .., Token::ParenthesisClose] => pairs
                .as_chunks::<2>()
                .0
                .iter()
                .take(MAX_ID_PAIRS)
                .find_map(|pair| match pair {
                    [Token::Argument(field), Token::Argument(value)]
                        if field.eq_ignore_ascii_case(b"name") =>
                    {
                        Some(ClientId::parse(value))
                    }
                    _ => None,
                })
                .unwrap_or_default(),
            _ => ClientId::Unknown,
        };

        id::Arguments {
            tag: self.tag,
            client,
        }
    }
}

impl ClientId {
    pub fn parse(name: &[u8]) -> Self {
        hashify::fnc_map_ignore_case!(name,
            "Microsoft Office 365" => Self::MicrosoftOffice365,
            _ => Self::Unknown,
        )
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/imap-proto/src/parser/id/tests.rs"]
mod tests;
