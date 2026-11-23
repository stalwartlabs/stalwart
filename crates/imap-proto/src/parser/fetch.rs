/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PushUnique, parse_number, parse_sequence_set};
use crate::{
    Command,
    protocol::fetch::{self, Attribute, Section},
    receiver::{Request, Token, bad},
};
use compact_str::format_compact;
use std::borrow::Cow;
use std::iter::Peekable;
use std::vec::IntoIter;

const ATTRIBUTES_INIT_LEN: usize = 8;
const FIELDS_INIT_LEN: usize = 32;
const MAX_FETCH_ATTRIBUTES: usize = 128;
const MAX_HEADER_FIELDS: usize = 256;

impl Request<Command> {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse_fetch(self) -> trc::Result<fetch::Arguments> {
        if self.tokens.len() < 2 {
            return Err(self.into_error("Missing parameters."));
        }

        let mut tokens = self.tokens.into_iter().peekable();
        let mut attributes = Vec::with_capacity(tokens.len().min(ATTRIBUTES_INIT_LEN));
        let sequence_set = parse_sequence_set(
            &tokens
                .next()
                .ok_or_else(|| bad(self.tag.clone(), "Missing sequence set."))?
                .unwrap_bytes(),
        )
        .map_err(|v| bad(self.tag.clone(), v))?;

        let mut in_parentheses = false;
        let mut header_fields_left = MAX_HEADER_FIELDS;

        while let Some(token) = tokens.next() {
            match token {
                Token::Argument(_) if attributes.len() == MAX_FETCH_ATTRIBUTES => {
                    return Err(bad(self.tag, "Too many fetch attributes."));
                }
                Token::Argument(value) => {
                    hashify::fnc_map_ignore_case!(value.as_slice(),
                        "ALL" => {
                            attributes = vec![
                                Attribute::Flags,
                                Attribute::InternalDate,
                                Attribute::Rfc822Size,
                                Attribute::Envelope,
                            ];
                            break;
                        },
                        "FULL" => {
                            attributes = vec![
                                Attribute::Flags,
                                Attribute::InternalDate,
                                Attribute::Rfc822Size,
                                Attribute::Envelope,
                                Attribute::Body,
                            ];
                            break;
                        },
                        "FAST" => {
                            attributes = vec![
                                Attribute::Flags,
                                Attribute::InternalDate,
                                Attribute::Rfc822Size,
                            ];
                            break;
                        },
                        "ENVELOPE" => {
                            attributes.push_unique(Attribute::Envelope);
                        },
                        "FLAGS" => {
                            attributes.push_unique(Attribute::Flags);
                        },
                        "INTERNALDATE" => {
                            attributes.push_unique(Attribute::InternalDate);
                        },
                        "BODYSTRUCTURE" => {
                            attributes.push_unique(Attribute::BodyStructure);
                        },
                        "UID" => {
                            attributes.push_unique(Attribute::Uid);
                        },
                        "RFC822" => {
                            attributes.push_unique(
                                if tokens.peek().is_some_and(|token| token.is_dot()) {
                                    tokens.next();
                                    let rfc822 = tokens
                                        .next()
                                        .ok_or_else(|| {
                                            bad(self.tag.clone(), "Missing RFC822 parameter.")
                                        })?
                                        .unwrap_bytes();
                                    if rfc822.eq_ignore_ascii_case(b"HEADER") {
                                        Attribute::Rfc822Header
                                    } else if rfc822.eq_ignore_ascii_case(b"SIZE") {
                                        Attribute::Rfc822Size
                                    } else if rfc822.eq_ignore_ascii_case(b"TEXT") {
                                        Attribute::Rfc822Text
                                    } else {
                                        return Err(bad(
                                            self.tag,
                                            format_compact!(
                                                "Invalid RFC822 parameter {:?}.",
                                                String::from_utf8_lossy(&rfc822)
                                            ),
                                        ));
                                    }
                                } else {
                                    Attribute::Rfc822
                                },
                            );
                        },
                        "BODY" => {
                            let is_peek = match tokens.peek() {
                                Some(Token::BracketOpen) => {
                                    tokens.next();
                                    false
                                }
                                Some(Token::Dot) => {
                                    tokens.next();
                                    if tokens
                                        .next()
                                        .is_none_or( |token| !token.eq_ignore_ascii_case(b"PEEK"))
                                    {
                                        return Err(bad(
                                            self.tag.clone(),
                                            "Expected 'PEEK' after '.'.",
                                        ));
                                    }
                                    if tokens.next().is_none_or( |token| !token.is_bracket_open()) {
                                        return Err(bad(
                                            self.tag.clone(),
                                            "Expected '[' after 'BODY.PEEK'",
                                        ));
                                    }
                                    true
                                }
                                _ => {
                                    attributes.push_unique(Attribute::Body);

                                    if !in_parentheses {
                                        break;
                                    } else {
                                        continue;
                                    }
                                }
                            };

                            let sections = Section::parse_section_spec(&mut tokens, &mut header_fields_left)
                                .map_err(|v| bad(self.tag.clone(), v))?;

                            attributes.push_unique(Attribute::BodySection {
                                peek: is_peek,
                                sections,
                                partial: parse_partial(&mut tokens)
                                    .map_err(|v| bad(self.tag.clone(), v))?,
                            });
                        },
                        "BINARY" => {
                            let (is_peek, is_size) = if let Some(Token::Dot) = tokens.peek() {
                                tokens.next();
                                let param = tokens
                                    .next()
                                    .ok_or({
                                        bad(self.tag.clone(),"Missing parameter after 'BINARY.'.")
                                    })?
                                    .unwrap_bytes();
                                if param.eq_ignore_ascii_case(b"PEEK") {
                                    (true, false)
                                } else if param.eq_ignore_ascii_case(b"SIZE") {
                                    (false, true)
                                } else {
                                    return Err(bad(
                                        self.tag,
                                        "Expected 'PEEK' or 'SIZE' after 'BINARY.'.",
                                    ));
                                }
                            } else {
                                (false, false)
                            };

                            if tokens.next().is_none_or( |token| !token.is_bracket_open()) {
                                return Err(bad(self.tag.clone(), "Expected '[' after 'BINARY'."));
                            }
                            let sections = Section::parse_section_part(&mut tokens)
                                .map_err(|v| bad(self.tag.clone(), v))?;
                            attributes.push_unique(if !is_size {
                                Attribute::Binary {
                                    peek: is_peek,
                                    sections,
                                    partial: parse_partial(&mut tokens)
                                        .map_err(|v| bad(self.tag.clone(), v))?,
                                }
                            } else {
                                Attribute::BinarySize { sections }
                            });
                        },
                        "PREVIEW" => {
                            attributes.push_unique(Attribute::Preview {
                                lazy: if let Some(Token::ParenthesisOpen) = tokens.peek() {
                                    tokens.next();
                                    let mut is_lazy = false;
                                    while let Some(token) = tokens.next() {
                                        match token {
                                            Token::ParenthesisClose => break,
                                            Token::Argument(value) if value.eq_ignore_ascii_case(b"LAZY") => {
                                                    is_lazy = true;
                                            }
                                            _ => (),
                                        }
                                    }
                                    is_lazy
                                } else {
                                    false
                                },
                            });
                        },
                        "MODSEQ" => {
                            attributes.push_unique(Attribute::ModSeq);
                        },
                        "OBJECTID" => {
                            attributes.push_unique(Attribute::ObjectId);
                        },
                        _ => {
                            return Err(bad(
                                self.tag,
                                format_compact!("Invalid attribute {:?}", String::from_utf8_lossy(&value)),
                            ));
                        }
                    );

                    if !in_parentheses {
                        break;
                    }
                }
                Token::ParenthesisOpen => {
                    if !in_parentheses {
                        in_parentheses = true;
                    } else {
                        return Err(bad(self.tag.clone(), "Unexpected parenthesis open."));
                    }
                }
                Token::ParenthesisClose => {
                    if in_parentheses {
                        break;
                    } else {
                        return Err(bad(self.tag.clone(), "Unexpected parenthesis close."));
                    }
                }
                _ => {
                    return Err(bad(
                        self.tag,
                        format_compact!("Invalid fetch argument {:?}.", token.to_string()),
                    ));
                }
            }
        }

        // CONDSTORE parameters
        let mut changed_since = None;
        let mut include_vanished = false;
        if let Some(Token::ParenthesisOpen) = tokens.peek() {
            tokens.next();
            while let Some(token) = tokens.next() {
                match token {
                    Token::Argument(param) if param.eq_ignore_ascii_case(b"CHANGEDSINCE") => {
                        changed_since = parse_number::<u64>(
                            &tokens
                                .next()
                                .ok_or_else(|| {
                                    bad(self.tag.clone(), "Missing CHANGEDSINCE parameter.")
                                })?
                                .unwrap_bytes(),
                        )
                        .map_err(|v| bad(self.tag.clone(), v))?
                        .into();
                    }
                    Token::Argument(param) if param.eq_ignore_ascii_case(b"VANISHED") => {
                        include_vanished = true;
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

        if !attributes.is_empty() {
            Ok(fetch::Arguments {
                tag: self.tag,
                sequence_set,
                attributes,
                changed_since,
                include_vanished,
            })
        } else {
            Err(bad(self.tag, "No data items to fetch specified."))
        }
    }
}

pub fn parse_partial(tokens: &mut Peekable<IntoIter<Token>>) -> super::Result<Option<(u32, u32)>> {
    if tokens.peek().is_none_or(|token| !token.is_lt()) {
        return Ok(None);
    }
    tokens.next();

    let start = parse_number::<u32>(
        &tokens
            .next()
            .ok_or_else(|| Cow::from("Missing partial start."))?
            .unwrap_bytes(),
    )?;

    if tokens.next().is_none_or(|token| !token.is_dot()) {
        return Err("Expected '.' after partial start.".into());
    }

    let end = parse_number::<u32>(
        &tokens
            .next()
            .ok_or_else(|| Cow::from("Missing partial end."))?
            .unwrap_bytes(),
    )?;

    if end == 0 {
        return Err("Invalid partial range.".into());
    }

    if tokens.next().is_none_or(|token| !token.is_gt()) {
        return Err("Expected '>' after range.".into());
    }

    Ok(Some((start, end)))
}

#[derive(Debug, Clone, Copy)]
enum SectionPosition {
    Start,
    AfterPart,
    AfterDot,
    AfterText,
}

impl Section {
    fn parse_section_spec(
        tokens: &mut Peekable<IntoIter<Token>>,
        header_fields_left: &mut usize,
    ) -> super::Result<Vec<Section>> {
        let mut sections = Vec::new();
        let mut position = SectionPosition::Start;
        loop {
            let token = tokens
                .next()
                .ok_or_else(|| Cow::from("Expected ']' after section-spec."))?;
            position = match (position, token) {
                (
                    SectionPosition::Start
                    | SectionPosition::AfterPart
                    | SectionPosition::AfterText,
                    Token::BracketClose,
                ) => return Ok(sections),
                (SectionPosition::AfterPart, Token::Dot) => SectionPosition::AfterDot,
                (SectionPosition::Start | SectionPosition::AfterDot, Token::Argument(value)) => {
                    if let Some(num) = Section::part_number(&value) {
                        sections.push(Section::Part { num });
                        SectionPosition::AfterPart
                    } else if value.eq_ignore_ascii_case(b"MIME") {
                        if matches!(position, SectionPosition::Start) {
                            return Err("Expected a part number before 'MIME'.".into());
                        }
                        sections.push(Section::Mime);
                        SectionPosition::AfterText
                    } else {
                        sections.push(Section::parse_section_msgtext(
                            &value,
                            tokens,
                            header_fields_left,
                        )?);
                        SectionPosition::AfterText
                    }
                }
                (_, token) => {
                    return Err(
                        format!("Unexpected {:?} in section-spec.", token.to_string()).into(),
                    );
                }
            };
        }
    }

    fn parse_section_msgtext(
        value: &[u8],
        tokens: &mut Peekable<IntoIter<Token>>,
        header_fields_left: &mut usize,
    ) -> super::Result<Section> {
        if value.eq_ignore_ascii_case(b"TEXT") {
            return Ok(Section::Text);
        }
        if !value.eq_ignore_ascii_case(b"HEADER") {
            return Err(format!(
                "Expected a part number, 'HEADER', 'TEXT' or 'MIME', found {:?}.",
                String::from_utf8_lossy(value)
            )
            .into());
        }
        if tokens.next_if(Token::is_dot).is_none() {
            return Ok(Section::Header);
        }
        if tokens
            .next()
            .is_none_or(|token| !token.eq_ignore_ascii_case(b"FIELDS"))
        {
            return Err("Expected 'FIELDS' after 'HEADER.'.".into());
        }
        let not = tokens.next_if(Token::is_dot).is_some();
        if not
            && tokens
                .next()
                .is_none_or(|token| !token.eq_ignore_ascii_case(b"NOT"))
        {
            return Err("Expected 'NOT' after 'HEADER.FIELDS.'.".into());
        }
        if tokens
            .next()
            .is_none_or(|token| !token.is_parenthesis_open())
        {
            return Err("Expected '(' after 'HEADER.FIELDS'.".into());
        }
        let mut fields = Vec::with_capacity(tokens.len().min(FIELDS_INIT_LEN));
        loop {
            match tokens.next() {
                Some(Token::ParenthesisClose) if !fields.is_empty() => {
                    return Ok(Section::HeaderFields { not, fields });
                }
                Some(Token::Argument(value)) if Section::is_field_name(&value) => {
                    *header_fields_left = header_fields_left
                        .checked_sub(1)
                        .ok_or_else(|| Cow::from("Too many header field names."))?;
                    fields.push(
                        String::from_utf8(value.into_vec())
                            .map_err(|_| Cow::from("Invalid UTF-8 in header field name."))?,
                    );
                }
                Some(Token::Argument(_) | Token::Nil) => {
                    return Err(
                        "Header field names must be RFC 5322 field-names (printable US-ASCII except ':').".into(),
                    );
                }
                _ => return Err("Expected a header field name.".into()),
            }
        }
    }

    fn parse_section_part(tokens: &mut Peekable<IntoIter<Token>>) -> super::Result<Vec<u32>> {
        let mut sections = Vec::new();
        let mut position = SectionPosition::Start;
        loop {
            let token = tokens
                .next()
                .ok_or_else(|| Cow::from("Expected ']' after section-part."))?;
            position = match (position, token) {
                (SectionPosition::Start | SectionPosition::AfterPart, Token::BracketClose) => {
                    return Ok(sections);
                }
                (SectionPosition::AfterPart, Token::Dot) => SectionPosition::AfterDot,
                (SectionPosition::Start | SectionPosition::AfterDot, Token::Argument(value)) => {
                    sections.push(Section::part_number(&value).ok_or_else(|| {
                        Cow::from(format!(
                            "Expected a non-zero part number, found {:?}.",
                            String::from_utf8_lossy(&value)
                        ))
                    })?);
                    SectionPosition::AfterPart
                }
                (_, token) => {
                    return Err(
                        format!("Unexpected {:?} in section-part.", token.to_string()).into(),
                    );
                }
            };
        }
    }

    fn is_field_name(value: &[u8]) -> bool {
        !value.is_empty() && value.iter().all(|ch| matches!(ch, 33..=57 | 59..=126))
    }

    fn part_number(value: &[u8]) -> Option<u32> {
        match value {
            [b'1'..=b'9', rest @ ..] if rest.iter().all(u8::is_ascii_digit) => {
                std::str::from_utf8(value).ok()?.parse().ok()
            }
            _ => None,
        }
    }
}

/*

   fetch           = "FETCH" SP sequence-set SP (
                     "ALL" / "FULL" / "FAST" /
                     fetch-att / "(" fetch-att *(SP fetch-att) ")")

   fetch-att       = "ENVELOPE" / "FLAGS" / "INTERNALDATE" /
                     "RFC822" [".HEADER" / ".SIZE" / ".TEXT"] /
                     "BODY" ["STRUCTURE"] / "UID" /
                     "BODY" section [partial] /
                     "BODY.PEEK" section [partial] /
                     "BINARY" [".PEEK"] section-binary [partial] /
                     "BINARY.SIZE" section-binary

   partial         = "<" number64 "." nz-number64 ">"
                       ; Partial FETCH request. 0-based offset of
                       ; the first octet, followed by the number of
                       ; octets in the fragment.

   section         = "[" [section-spec] "]"

   section-binary  = "[" [section-part] "]"

   section-msgtext = "HEADER" /
                     "HEADER.FIELDS" [".NOT"] SP header-list /
                     "TEXT"
                       ; top-level or MESSAGE/RFC822 or
                       ; MESSAGE/GLOBAL part

   section-part    = nz-number *("." nz-number)
                       ; body part reference.
                       ; Allows for accessing nested body parts.

   section-spec    = section-msgtext / (section-part ["." section-text])

   section-text    = section-msgtext / "MIME"
                       ; text other than actual body part (headers,
                       ; etc.)


*/

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/imap-proto/src/parser/fetch/tests.rs"]
mod tests;
