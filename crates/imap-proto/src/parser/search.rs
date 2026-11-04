/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::iter::Peekable;
use std::vec::IntoIter;

use mail_parser::decoders::charsets::DecoderFnc;
use mail_parser::decoders::charsets::charset_decoder;

use crate::Command;
use crate::protocol::search::{self, Filter};
use crate::protocol::search::{ModSeqEntry, ResultOption};
use crate::protocol::{Flag, ProtocolVersion};
use crate::receiver::{ArgumentBytes, Request, Token, bad};

use super::{parse_date, parse_number, parse_sequence_set};

const FILTERS_INIT_LEN: usize = 16;
const MAX_FILTER_DEPTH: usize = 32;

impl Request<Command> {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse_search(self, version: ProtocolVersion) -> trc::Result<search::Arguments> {
        if self.tokens.is_empty() {
            return Err(self.into_error("Missing search criteria."));
        }

        let mut tokens = self.tokens.into_iter().peekable();
        let mut result_options = Vec::new();
        let mut decoder = None;
        let mut is_esearch = version.is_rev2();

        loop {
            match tokens.peek() {
                Some(Token::Argument(value)) if value.eq_ignore_ascii_case(b"return") => {
                    tokens.next();
                    is_esearch = true;
                    result_options =
                        parse_result_options(&mut tokens).map_err(|v| bad(self.tag.clone(), v))?;
                }
                Some(Token::Argument(value)) if value.eq_ignore_ascii_case(b"charset") => {
                    tokens.next();
                    decoder = charset_decoder(
                        &tokens
                            .next()
                            .ok_or_else(|| bad(self.tag.clone(), "Missing charset."))?
                            .unwrap_bytes(),
                    );
                }
                _ => break,
            }
        }

        let filter = parse_filters(&mut tokens, decoder).map_err(|v| bad(self.tag.clone(), v))?;

        match filter.len() {
            0 => Err(bad(self.tag.clone(), "No filters found in command.")),
            _ => Ok(search::Arguments {
                tag: self.tag,
                result_options,
                filter,
                sort: None,
                is_esearch,
            }),
        }
    }
}

pub fn parse_result_options(
    tokens: &mut Peekable<IntoIter<Token>>,
) -> super::Result<Vec<ResultOption>> {
    let mut result_options = Vec::new();
    if tokens
        .next()
        .is_none_or(|token| !token.is_parenthesis_open())
    {
        return Err(Cow::from("Invalid result option, expected parenthesis."));
    }

    for token in tokens {
        match token {
            Token::ParenthesisClose => break,
            Token::Argument(value) => {
                result_options.push(ResultOption::parse(&value)?);
            }
            _ => return Err(Cow::from("Invalid result option argument.")),
        }
    }

    Ok(result_options)
}

pub fn parse_filters(
    tokens: &mut Peekable<IntoIter<Token>>,
    decoder: Option<DecoderFnc>,
) -> super::Result<Vec<Filter>> {
    let mut filters = Vec::with_capacity(tokens.len().min(FILTERS_INIT_LEN));
    let mut filters_len = 0;
    let mut filters_stack = Vec::new();
    let mut operator = Filter::And;

    while let Some(token) = tokens.next() {
        let mut found_parenthesis = false;
        match token {
            Token::Argument(value) => {
                hashify::fnc_map_ignore_case!(value.as_slice(),
                    "ALL" => {
                        filters.push(Filter::All);

                    },
                    "ANSWERED" => {
                        filters.push(Filter::Answered);

                    },
                    "BCC" => {
                        filters.push(Filter::Bcc(decode_argument(tokens, decoder)?));

                    },
                    "BEFORE" => {
                        filters.push(Filter::Before(parse_date(
                            &tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected date"))?
                                .unwrap_bytes(),
                        )?));

                    },
                    "BODY" => {
                        filters.push(Filter::Body(decode_argument(tokens, decoder)?));


                    },
                    "CC" => {
                        filters.push(Filter::Cc(decode_argument(tokens, decoder)?));


                    },
                    "DELETED" => {
                        filters.push(Filter::Deleted);


                    },
                    "DRAFT" => {
                        filters.push(Filter::Draft);


                    },
                    "FLAGGED" => {
                        filters.push(Filter::Flagged);


                    },
                    "FROM" => {
                        filters.push(Filter::From(decode_argument(tokens, decoder)?));


                    },
                    "HEADER" => {
                        filters.push(Filter::Header(
                            decode_argument(tokens, decoder)?,
                            decode_argument(tokens, decoder)?,
                        ));


                    },
                    "KEYWORD" => {
                        filters.push(Filter::Keyword(Flag::parse_imap(
                            tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected keyword"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "LARGER" => {
                        filters.push(Filter::Larger(parse_number::<u32>(
                            &tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected integer"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "ON" => {
                        filters.push(Filter::On(parse_date(
                            &tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected date"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "SEEN" => {
                        filters.push(Filter::Seen);


                    },
                    "SENTBEFORE" => {
                        filters.push(Filter::SentBefore(parse_date(
                            &tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected date"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "SENTON" => {
                        filters.push(Filter::SentOn(parse_date(
                            &tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected date"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "SENTSINCE" => {
                        filters.push(Filter::SentSince(parse_date(
                            &tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected date"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "SINCE" => {
                        filters.push(Filter::Since(parse_date(
                            &tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected date"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "SMALLER" => {
                        filters.push(Filter::Smaller(parse_number::<u32>(
                            &tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected integer"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "SUBJECT" => {
                        filters.push(Filter::Subject(decode_argument(tokens, decoder)?));


                    },
                    "TEXT" => {
                        filters.push(Filter::Text(decode_argument(tokens, decoder)?));


                    },
                    "TO" => {
                        filters.push(Filter::To(decode_argument(tokens, decoder)?));


                    },
                    "UID" => {
                        filters.push(Filter::Sequence(
                            parse_sequence_set(
                                &tokens
                                    .next()
                                    .ok_or_else(|| Cow::from("Missing sequence set."))?
                                    .unwrap_bytes(),
                            )?,
                            true,
                        ));


                    },
                    "UNANSWERED" => {
                        filters.push(Filter::Unanswered);


                    },
                    "UNDELETED" => {
                        filters.push(Filter::Undeleted);


                    },
                    "UNDRAFT" => {
                        filters.push(Filter::Undraft);


                    },
                    "UNFLAGGED" => {
                        filters.push(Filter::Unflagged);


                    },
                    "UNKEYWORD" => {
                        filters.push(Filter::Unkeyword(Flag::parse_imap(
                            tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected keyword"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "UNSEEN" => {
                        filters.push(Filter::Unseen);


                    },
                    "UIDAFTER" => {
                        filters.push(Filter::UidAfter(parse_number::<u32>(
                            &tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected integer"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "UIDBEFORE" => {
                        filters.push(Filter::UidBefore(parse_number::<u32>(
                            &tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected integer"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "OLDER" => {
                        filters.push(Filter::Older(parse_number::<u32>(
                            &tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected integer"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "YOUNGER" => {
                        filters.push(Filter::Younger(parse_number::<u32>(
                            &tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected integer"))?
                                .unwrap_bytes(),
                        )?));


                    },
                    "OLD" => {
                        filters.push(Filter::Old);

                    },
                    "NEW" => {
                        filters.push(Filter::New);

                    },
                    "RECENT" => {
                        filters.push(Filter::Recent);

                    },
                    "MODSEQ" => {
                        let param = tokens
                            .next()
                            .ok_or_else(|| Cow::from("Missing MODSEQ parameters."))?
                            .unwrap_bytes();
                        if param.is_empty() || param.iter().any(|ch| !ch.is_ascii_digit()) {
                            if param.len() <= 7 || !param.starts_with(b"/flags/") {
                                return Err(format!(
                                    "Unsupported MODSEQ parameter '{}'.",
                                    String::from_utf8_lossy(&param)
                                )
                                .into());
                            }
                            let flag = Flag::parse_imap(ArgumentBytes::from_slice(&param[7..]))?;
                            let mod_seq_entry = match tokens.next() {
                                Some(Token::Argument(value)) if value.eq_ignore_ascii_case(b"all") => {
                                    ModSeqEntry::All(flag)
                                }
                                Some(Token::Argument(value))
                                    if value.eq_ignore_ascii_case(b"shared") =>
                                {
                                    ModSeqEntry::Shared(flag)
                                }
                                Some(Token::Argument(value)) if value.eq_ignore_ascii_case(b"priv") => {
                                    ModSeqEntry::Private(flag)
                                }
                                Some(token) => {
                                    return Err(
                                        format!("Unsupported MODSEQ parameter '{}'.", token).into()
                                    );
                                }
                                None => {
                                    return Err("Missing MODSEQ entry-type-req parameter.".into());
                                }
                            };
                            filters.push(Filter::ModSeq((
                                parse_number::<u64>(
                                    &tokens
                                        .next()
                                        .ok_or_else(|| {
                                            Cow::from("Missing MODSEQ mod-sequence-valzer parameter.")
                                        })?
                                        .unwrap_bytes(),
                                )?,
                                mod_seq_entry,
                            )));
                        } else {
                            filters.push(Filter::ModSeq((
                                parse_number::<u64>(&param)?,
                                ModSeqEntry::None,
                            )));
                        }

                    },
                    "EMAILID" => {
                        filters.push(Filter::EmailId(
                            tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected an EMAILID value."))?
                                .unwrap_string()?,
                        ));

                    },
                    "THREADID" => {
                        filters.push(Filter::ThreadId(
                            tokens
                                .next()
                                .ok_or_else(|| Cow::from("Expected an THREADID value."))?
                                .unwrap_string()?,
                        ));

                    },
                    "OR" => {
                        if filters_stack.len() >= MAX_FILTER_DEPTH {
                            return Err(Cow::from("Too many nested filters"));
                        }

                        filters_stack.push((filters, operator, filters_len));
                        filters_len = 0;
                        filters = Vec::with_capacity(2);
                        operator = Filter::Or;
                        continue;
                    },
                    "NOT" => {
                        if filters_stack.len() >= MAX_FILTER_DEPTH {
                            return Err(Cow::from("Too many nested filters"));
                        }

                        filters_stack.push((filters, operator, filters_len));
                        filters_len = 0;
                        filters = Vec::with_capacity(1);
                        operator = Filter::Not;
                        continue;
                    },
                    _ => {
                        filters.push(Filter::Sequence(parse_sequence_set(&value)?, false));
                    }
                );

                filters_len += 1;
            }
            Token::ParenthesisOpen => {
                if filters_stack.len() >= MAX_FILTER_DEPTH {
                    return Err(Cow::from("Too many nested filters"));
                }

                filters_stack.push((filters, operator, filters_len));
                filters_len = 0;
                filters = Vec::with_capacity(5);
                operator = Filter::And;
                continue;
            }
            Token::ParenthesisClose => {
                if filters_stack.is_empty() {
                    return Err(Cow::from("Unexpected parenthesis."));
                }

                found_parenthesis = true;
            }
            token => return Err(format!("Unexpected token {:?}.", token.to_string()).into()),
        }

        if !filters_stack.is_empty()
            && (found_parenthesis
                || (operator == Filter::Or && filters_len == 2)
                || (operator == Filter::Not && filters_len == 1))
        {
            while let Some((mut prev_filters, prev_operator, prev_filters_len)) =
                filters_stack.pop()
            {
                if operator == Filter::And && (prev_operator == Filter::And || filters_len == 1) {
                    prev_filters.extend(filters);
                    filters_len += prev_filters_len;
                } else {
                    prev_filters.push(operator);
                    prev_filters.extend(filters);
                    prev_filters.push(Filter::End);
                    filters_len = prev_filters_len + 1;
                }
                operator = prev_operator;
                filters = prev_filters;

                if operator == Filter::And || (operator == Filter::Or && filters_len < 2) {
                    break;
                }
            }
        }
    }
    Ok(filters)
}

pub fn decode_argument(
    tokens: &mut Peekable<IntoIter<Token>>,
    decoder: Option<DecoderFnc>,
) -> super::Result<String> {
    let argument = tokens
        .next()
        .ok_or_else(|| Cow::from("Expected string."))?
        .unwrap_bytes();

    if let Some(decoder) = decoder {
        Ok(decoder(&argument))
    } else {
        Ok(String::from_utf8(argument.into_vec())
            .map_err(|_| Cow::from("Invalid UTF-8 argument."))?)
    }
}

impl ResultOption {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        hashify::fnc_map_ignore_case!(
            value,
            "min" => Some(Self::Min),
            "max" => Some(Self::Max),
            "all" => Some(Self::All),
            "count" => Some(Self::Count),
            "save" => Some(Self::Save),
            "context" => Some(Self::Context),
            _ => None,
        )
        .ok_or_else(|| {
            format!(
                "Invalid result option '{}'.",
                String::from_utf8_lossy(value)
            )
            .into()
        })
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/imap-proto/src/parser/search/tests.rs"]
mod tests;
