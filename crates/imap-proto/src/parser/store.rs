/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::format_compact;

use crate::{
    Command,
    protocol::{
        Flag,
        store::{self, Operation},
    },
    receiver::{Request, Token, bad},
};

use super::{MAX_FLAGS, parse_number, parse_sequence_set};

impl Request<Command> {
    pub fn parse_store(self) -> trc::Result<store::Arguments> {
        let mut tokens = self.tokens.into_iter().peekable();

        // Sequence set
        let sequence_set = parse_sequence_set(
            &tokens
                .next()
                .ok_or_else(|| bad(self.tag.clone(), "Missing sequence set."))?
                .unwrap_bytes(),
        )
        .map_err(|v| bad(self.tag.clone(), v))?;
        let mut unchanged_since = None;

        // CONDSTORE parameters
        if let Some(Token::ParenthesisOpen) = tokens.peek() {
            tokens.next();
            while let Some(token) = tokens.next() {
                match token {
                    Token::Argument(param) if param.eq_ignore_ascii_case(b"UNCHANGEDSINCE") => {
                        unchanged_since = parse_number::<u64>(
                            &tokens
                                .next()
                                .ok_or_else(|| {
                                    bad(self.tag.clone(), "Missing UNCHANGEDSINCE parameter.")
                                })?
                                .unwrap_bytes(),
                        )
                        .map_err(|v| bad(self.tag.clone(), v))?
                        .into();
                    }
                    Token::ParenthesisClose => {
                        break;
                    }
                    _ => {
                        return Err(bad(
                            self.tag.clone(),
                            format_compact!("Unsupported parameter '{}'.", token),
                        ));
                    }
                }
            }
        }

        // Operation
        let operation = tokens
            .next()
            .ok_or_else(|| bad(self.tag.clone(), "Missing message data item name."))?
            .unwrap_bytes();
        let (is_silent, operation) = hashify::fnc_map_ignore_case!(operation.as_slice(),
            "FLAGS" => Some((false, Operation::Set)),
            "FLAGS.SILENT" => Some((true, Operation::Set)),
            "+FLAGS" => Some((false, Operation::Add)),
            "+FLAGS.SILENT" => Some((true, Operation::Add)),
            "-FLAGS" => Some((false, Operation::Clear)),
            "-FLAGS.SILENT" => Some((true, Operation::Clear)),
            _ => None,
        )
        .ok_or_else(|| {
            bad(
                self.tag.clone(),
                format_compact!(
                    "Unsupported message data item name: {:?}",
                    String::from_utf8_lossy(&operation)
                ),
            )
        })?;

        // Flags
        let mut keywords = Vec::new();
        match tokens
            .next()
            .ok_or_else(|| bad(self.tag.clone(), "Missing flags to set."))?
        {
            Token::ParenthesisOpen => {
                for token in tokens {
                    match token {
                        Token::Argument(flag) => {
                            let flag =
                                Flag::parse_imap(flag).map_err(|v| bad(self.tag.clone(), v))?;
                            if !keywords.contains(&flag) {
                                if keywords.len() == MAX_FLAGS {
                                    return Err(bad(self.tag.clone(), "Too many flags."));
                                }
                                keywords.push(flag);
                            }
                        }
                        Token::ParenthesisClose => {
                            break;
                        }
                        _ => {
                            return Err(bad(self.tag.clone(), "Unsupported flag."));
                        }
                    }
                }
            }
            Token::Argument(flag) => {
                keywords.push(Flag::parse_imap(flag).map_err(|v| bad(self.tag.clone(), v))?);
            }
            _ => {
                return Err(bad(self.tag, "Invalid flags parameter."));
            }
        }

        Ok(store::Arguments {
            tag: self.tag,
            sequence_set,
            operation,
            is_silent,
            keywords,
            unchanged_since,
        })
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/imap-proto/src/parser/store/tests.rs"]
mod tests;
