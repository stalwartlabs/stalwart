/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MAX_FLAGS, parse_datetime};
use crate::{
    Command,
    protocol::{
        Flag,
        append::{self, Message},
    },
    receiver::{Request, Token, bad},
};

enum State {
    None,
    Flags,
    UTF8,
    UTF8Data,
}

impl Request<Command> {
    pub fn parse_append(self, is_utf8: bool) -> trc::Result<append::Arguments> {
        match self.tokens.len() {
            0 | 1 => Err(self.into_error("Missing arguments.")),
            _ => {
                // Obtain mailbox name
                let mut tokens = self.tokens.into_iter().peekable();
                let mailbox_name = tokens
                    .next()
                    .unwrap()
                    .unwrap_mailbox_name(is_utf8)
                    .map_err(|v| bad(self.tag.clone(), v))?;
                let mut messages = Vec::new();

                while tokens.peek().is_some() {
                    // Parse flags
                    let mut message = Message {
                        message: vec![],
                        flags: vec![],
                        received_at: None,
                    };
                    let mut state = State::None;
                    let mut seen_flags = false;

                    while let Some(token) = tokens.next() {
                        match token {
                            Token::ParenthesisOpen => {
                                state = match state {
                                    State::None if !seen_flags => {
                                        seen_flags = true;
                                        State::Flags
                                    }
                                    State::UTF8 => State::UTF8Data,
                                    _ => {
                                        return Err(bad(
                                            self.tag.clone(),
                                            "Invalid opening parenthesis found.",
                                        ));
                                    }
                                };
                            }
                            Token::ParenthesisClose => match state {
                                State::None | State::UTF8 => {
                                    return Err(bad(
                                        self.tag.clone(),
                                        "Invalid closing parenthesis found.",
                                    ));
                                }
                                State::Flags => {
                                    state = State::None;
                                }
                                State::UTF8Data => {
                                    break;
                                }
                            },
                            Token::Argument(value) => match state {
                                State::None => {
                                    if value.eq_ignore_ascii_case(b"utf8") {
                                        state = State::UTF8;
                                    } else if matches!(tokens.peek(), Some(Token::Argument(_)))
                                        && value.len() <= 28
                                        && !value.contains(&b'\n')
                                    {
                                        if let Ok(date_time) = parse_datetime(&value) {
                                            message.received_at = Some(date_time);
                                        } else {
                                            return Err(bad(
                                                self.tag.clone(),
                                                "Failed to parse received time.",
                                            ));
                                        }
                                    } else {
                                        message.message = value.into_vec();
                                        break;
                                    }
                                }
                                State::Flags => {
                                    let flag = Flag::parse_imap(value)
                                        .map_err(|v| bad(self.tag.clone(), v))?;
                                    if !message.flags.contains(&flag) {
                                        if message.flags.len() == MAX_FLAGS {
                                            return Err(bad(self.tag.clone(), "Too many flags."));
                                        }
                                        message.flags.push(flag);
                                    }
                                }
                                State::UTF8 => {
                                    return Err(bad(
                                        self.tag.clone(),
                                        "Expected parenthesis after UTF8.",
                                    ));
                                }
                                State::UTF8Data => {
                                    if message.message.is_empty() {
                                        message.message = value.into_vec();
                                    } else {
                                        return Err(bad(
                                            self.tag.clone(),
                                            "Invalid parameter after message literal.",
                                        ));
                                    }
                                }
                            },
                            _ => {
                                return Err(bad(self.tag.clone(), "Invalid arguments."));
                            }
                        }
                    }

                    messages.push(message);
                }

                Ok(append::Arguments {
                    tag: self.tag,
                    mailbox_name,
                    messages,
                })
            }
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/imap-proto/src/parser/append/tests.rs"]
mod tests;
