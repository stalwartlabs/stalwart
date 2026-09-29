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

        while let Some(token) = tokens.next() {
            match token {
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

                            let sections = Section::parse_section_spec(&mut tokens)
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
    fn parse_section_spec(tokens: &mut Peekable<IntoIter<Token>>) -> super::Result<Vec<Section>> {
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
                        sections.push(Section::parse_section_msgtext(&value, tokens)?);
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
                Some(Token::Argument(value)) if Section::is_field_name(&value) => fields.push(
                    String::from_utf8(value.into_vec())
                        .map_err(|_| Cow::from("Invalid UTF-8 in header field name."))?,
                ),
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

#[cfg(test)]
mod tests {
    use crate::{
        Command, ResponseType,
        protocol::{
            Sequence,
            fetch::{self, Attribute, Section},
        },
        receiver::Receiver,
    };

    #[test]
    fn parse_fetch() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A654 FETCH 2:4 (FLAGS BODY[HEADER.FIELDS (DATE FROM)])\r\n",
                fetch::Arguments {
                    tag: "A654".into(),
                    sequence_set: Sequence::range(2.into(), 4.into()),
                    attributes: vec![
                        Attribute::Flags,
                        Attribute::BodySection {
                            peek: false,
                            sections: vec![Section::HeaderFields {
                                not: false,
                                fields: vec!["DATE".into(), "FROM".into()],
                            }],
                            partial: None,
                        },
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 BODY[]\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![Attribute::BodySection {
                        peek: false,
                        sections: vec![],
                        partial: None,
                    }],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 (BODY[HEADER])\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![Attribute::BodySection {
                        peek: false,
                        sections: vec![Section::Header],
                        partial: None,
                    }],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 (BODY.PEEK[HEADER.FIELDS (X-MAILER)] PREVIEW(LAZY))\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::BodySection {
                            peek: true,
                            sections: vec![Section::HeaderFields {
                                not: false,
                                fields: vec!["X-MAILER".into()],
                            }],
                            partial: None,
                        },
                        Attribute::Preview { lazy: true },
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 (BODY[HEADER.FIELDS.NOT (FROM TO SUBJECT)])\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![Attribute::BodySection {
                        peek: false,
                        sections: vec![Section::HeaderFields {
                            not: true,
                            fields: vec!["FROM".into(), "TO".into(), "SUBJECT".into()],
                        }],
                        partial: None,
                    }],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 (BODY[1.MIME] BODY[TEXT] PREVIEW)\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::BodySection {
                            peek: false,
                            sections: vec![Section::Part { num: 1 }, Section::Mime],
                            partial: None,
                        },
                        Attribute::BodySection {
                            peek: false,
                            sections: vec![Section::Text],
                            partial: None,
                        },
                        Attribute::Preview { lazy: false },
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 (BODYSTRUCTURE ENVELOPE FLAGS INTERNALDATE UID)\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::BodyStructure,
                        Attribute::Envelope,
                        Attribute::Flags,
                        Attribute::InternalDate,
                        Attribute::Uid,
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 (RFC822 RFC822.HEADER RFC822.SIZE RFC822.TEXT)\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::Rfc822,
                        Attribute::Rfc822Header,
                        Attribute::Rfc822Size,
                        Attribute::Rfc822Text,
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                concat!(
                    "A001 FETCH 1 (",
                    "BODY[4.2.HEADER]<0.20> ",
                    "BODY.PEEK[3.2.2.2] ",
                    "BODY[4.2.TEXT]<4.100> ",
                    "BINARY[1.2.3] ",
                    "BINARY.PEEK[4] ",
                    "BINARY[6.5.4]<100.200> ",
                    "BINARY.PEEK[7]<9.88> ",
                    "BINARY.SIZE[9.1]",
                    ")\r\n"
                ),
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::BodySection {
                            peek: false,
                            sections: vec![
                                Section::Part { num: 4 },
                                Section::Part { num: 2 },
                                Section::Header,
                            ],
                            partial: Some((0, 20)),
                        },
                        Attribute::BodySection {
                            peek: true,
                            sections: vec![
                                Section::Part { num: 3 },
                                Section::Part { num: 2 },
                                Section::Part { num: 2 },
                                Section::Part { num: 2 },
                            ],
                            partial: None,
                        },
                        Attribute::BodySection {
                            peek: false,
                            sections: vec![
                                Section::Part { num: 4 },
                                Section::Part { num: 2 },
                                Section::Text,
                            ],
                            partial: Some((4, 100)),
                        },
                        Attribute::Binary {
                            peek: false,
                            sections: vec![1, 2, 3],
                            partial: None,
                        },
                        Attribute::Binary {
                            peek: true,
                            sections: vec![4],
                            partial: None,
                        },
                        Attribute::Binary {
                            peek: false,
                            sections: vec![6, 5, 4],
                            partial: Some((100, 200)),
                        },
                        Attribute::Binary {
                            peek: true,
                            sections: vec![7],
                            partial: Some((9, 88)),
                        },
                        Attribute::BinarySize {
                            sections: vec![9, 1],
                        },
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 ALL\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::Flags,
                        Attribute::InternalDate,
                        Attribute::Rfc822Size,
                        Attribute::Envelope,
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 FULL\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::Flags,
                        Attribute::InternalDate,
                        Attribute::Rfc822Size,
                        Attribute::Envelope,
                        Attribute::Body,
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 FAST\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::Flags,
                        Attribute::InternalDate,
                        Attribute::Rfc822Size,
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "s100 UID FETCH 1:* (FLAGS MODSEQ) (CHANGEDSINCE 12345 VANISHED)\r\n",
                fetch::Arguments {
                    tag: "s100".into(),
                    sequence_set: Sequence::range(1.into(), None),
                    attributes: vec![Attribute::Flags, Attribute::ModSeq],
                    changed_since: 12345.into(),
                    include_vanished: true,
                },
            ),
            (
                "9 UID FETCH 1:* UID (VANISHED CHANGEDSINCE 1)\r\n",
                fetch::Arguments {
                    tag: "9".into(),
                    sequence_set: Sequence::range(1.into(), None),
                    attributes: vec![Attribute::Uid],
                    changed_since: 1.into(),
                    include_vanished: true,
                },
            ),
            (
                "A010 FETCH 1:* (OBJECTID)\r\n",
                fetch::Arguments {
                    tag: "A010".into(),
                    sequence_set: Sequence::range(1.into(), None),
                    attributes: vec![Attribute::ObjectId],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A011 FETCH 1 (UID OBJECTID FLAGS)\r\n",
                fetch::Arguments {
                    tag: "A011".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![Attribute::Uid, Attribute::ObjectId, Attribute::Flags],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_fetch()
                    .expect(command),
                arguments,
                "{}",
                command
            );
        }
    }

    #[test]
    fn mime_requires_a_part_number() {
        let mut receiver = Receiver::new();
        for command in [
            "A001 FETCH 1 BODY[MIME]\r\n",
            "A002 FETCH 1 BODY.PEEK[MIME]<0.10>\r\n",
            "A003 FETCH 1 (UID BODY[HEADER.MIME])\r\n",
            "A004 FETCH 1 BODY[TEXT.MIME]\r\n",
        ] {
            let err = receiver
                .parse(&mut command.as_bytes().iter())
                .expect("command is framed")
                .parse_fetch()
                .expect_err(command);
            assert_eq!(
                err.value_as_str(trc::Key::Type),
                Some(ResponseType::Bad.as_str()),
                "{command}"
            );
        }
        for command in [
            "A005 FETCH 1 BODY[1.MIME]\r\n",
            "A006 FETCH 1 BODY[4.2.MIME]<0.10>\r\n",
        ] {
            receiver
                .parse(&mut command.as_bytes().iter())
                .expect("command is framed")
                .parse_fetch()
                .expect(command);
        }
    }

    fn fetch_attribute(receiver: &mut Receiver<Command>, item: &str) -> trc::Result<Attribute> {
        let command = format!("A1 FETCH 1 {item}\r\n");
        receiver
            .parse(&mut command.as_bytes().iter())
            .expect("command is framed")
            .parse_fetch()
            .map(|mut arguments| arguments.attributes.remove(0))
    }

    #[test]
    fn header_field_names_are_rfc_5322_field_names() {
        let mut receiver = Receiver::new();
        for (list, names) in [
            ("(Subject)", vec!["Subject"]),
            (
                "(X-Spam-Status Message-ID)",
                vec!["X-Spam-Status", "Message-ID"],
            ),
            ("(\"X(Y\" \"A]\" \"%*{\")", vec!["X(Y", "A]", "%*{"]),
            ("(\"A\\\"B\" \"C\\\\D\")", vec!["A\"B", "C\\D"]),
            ("({3+}\r\n!~;)", vec!["!~;"]),
        ] {
            for not in ["", ".NOT"] {
                let item = format!("BODY.PEEK[HEADER.FIELDS{not} {list}]");
                match fetch_attribute(&mut receiver, &item) {
                    Ok(Attribute::BodySection { sections, .. }) => assert_eq!(
                        sections,
                        vec![Section::HeaderFields {
                            not: !not.is_empty(),
                            fields: names.iter().map(|name| name.to_string()).collect(),
                        }],
                        "{item}"
                    ),
                    other => panic!("{item}: {other:?}"),
                }
            }
        }
        for list in [
            "(\"A B\")",
            "(\"\")",
            "(\"A:B\")",
            "(Subject \":\")",
            "(\"A\tB\")",
            "(\"A\u{7f}B\")",
            "(\"caf\u{e9}\")",
            "(\"\u{1}\")",
            "({3+}\r\nA\rB)",
            "({3+}\r\nA\nB)",
            "({4+}\r\nA\r\nB)",
            "({3+}\r\nA\u{0}B)",
            "({0+}\r\n)",
        ] {
            for item in [
                format!("BODY[HEADER.FIELDS {list}]"),
                format!("BODY.PEEK[1.HEADER.FIELDS.NOT {list}]<0.5>"),
            ] {
                let err = fetch_attribute(&mut receiver, &item).expect_err(&item);
                assert_eq!(
                    err.value_as_str(trc::Key::Type),
                    Some(ResponseType::Bad.as_str()),
                    "{item:?}"
                );
            }
        }
    }

    #[test]
    fn sections_follow_the_rfc_9051_grammar() {
        let part = |num| Section::Part { num };
        let fields = |not, names: &[&str]| Section::HeaderFields {
            not,
            fields: names.iter().map(|name| name.to_string()).collect(),
        };
        let mut receiver = Receiver::new();
        for (spec, sections) in [
            ("", vec![]),
            ("HEADER", vec![Section::Header]),
            ("header", vec![Section::Header]),
            ("HEADER.FIELDS (From)", vec![fields(false, &["From"])]),
            ("HEADER.FIELDS.NOT (A B)", vec![fields(true, &["A", "B"])]),
            ("TEXT", vec![Section::Text]),
            ("1", vec![part(1)]),
            ("4294967295", vec![part(u32::MAX)]),
            ("1.2.30", vec![part(1), part(2), part(30)]),
            ("1.MIME", vec![part(1), Section::Mime]),
            ("2.1.MIME", vec![part(2), part(1), Section::Mime]),
            ("3.HEADER", vec![part(3), Section::Header]),
            ("3.1.TEXT", vec![part(3), part(1), Section::Text]),
            (
                "3.HEADER.FIELDS (Subject)",
                vec![part(3), fields(false, &["Subject"])],
            ),
            (
                "3.2.HEADER.FIELDS.NOT (Subject To)",
                vec![part(3), part(2), fields(true, &["Subject", "To"])],
            ),
        ] {
            for item in [format!("BODY[{spec}]"), format!("BODY.PEEK[{spec}]<0.5>")] {
                match fetch_attribute(&mut receiver, &item) {
                    Ok(Attribute::BodySection {
                        sections: parsed, ..
                    }) => assert_eq!(parsed, sections, "{item}"),
                    other => panic!("{item}: {other:?}"),
                }
            }
        }
        for (spec, sections) in [
            ("", vec![]),
            ("1", vec![1]),
            ("1.2.3", vec![1, 2, 3]),
            ("4294967295", vec![u32::MAX]),
        ] {
            for item in [
                format!("BINARY[{spec}]"),
                format!("BINARY.PEEK[{spec}]<0.5>"),
                format!("BINARY.SIZE[{spec}]"),
            ] {
                match fetch_attribute(&mut receiver, &item) {
                    Ok(
                        Attribute::Binary {
                            sections: parsed, ..
                        }
                        | Attribute::BinarySize { sections: parsed },
                    ) => assert_eq!(parsed, sections, "{item}"),
                    other => panic!("{item}: {other:?}"),
                }
            }
        }

        for spec in [
            "MIME",
            "0.MIME",
            "1.MIME.TEXT",
            "TEXT.1.MIME",
            "MIME.1",
            "1.MIME.MIME",
            "1.MIME.1",
            "1.MIME.HEADER",
            "1.HEADER.FIELDS (A).MIME",
            "1.HEADER.TEXT",
            "1.TEXT.2",
            "HEADER.MIME",
            "HEADER.TEXT",
            "HEADER.1",
            "HEADER.HEADER",
            "TEXT.MIME",
            "TEXT.HEADER",
            "TEXT.1",
            "TEXT.TEXT",
            "0",
            "1.0",
            "01",
            "1.02",
            "+1",
            "-1",
            "4294967296",
            ".1",
            "1.",
            "1..2",
            ".",
            "1 2",
            "1.2 3",
            "HEADER.FIELDS",
            "HEADER.FIELDS ()",
            "HEADER.FIELDS.NOT ()",
            "1.HEADER.FIELDS ()",
            "HEADER.FIELDS.NOT",
            "HEADER.FIELDS.X (A)",
            "HEADER.X",
            "HEADERS",
            "BODY",
            "1.BODY",
        ] {
            for item in [format!("BODY[{spec}]"), format!("BODY.PEEK[{spec}]<0.5>")] {
                let err = fetch_attribute(&mut receiver, &item).expect_err(&item);
                assert_eq!(
                    err.value_as_str(trc::Key::Type),
                    Some(ResponseType::Bad.as_str()),
                    "{item}"
                );
            }
        }
        for item in ["BODY[1", "BODY[HEADER", "BODY[1.MIME", "BINARY[1"] {
            let err = fetch_attribute(&mut receiver, item).expect_err(item);
            assert_eq!(
                err.value_as_str(trc::Key::Type),
                Some(ResponseType::Bad.as_str()),
                "{item}"
            );
        }
        for spec in [
            "0",
            "1.0",
            "01",
            "+1",
            ".1",
            "1.",
            "1..2",
            ".",
            "1 2",
            "1.MIME",
            "MIME",
            "TEXT",
            "HEADER",
            "4294967296",
        ] {
            for item in [
                format!("BINARY[{spec}]"),
                format!("BINARY.PEEK[{spec}]"),
                format!("BINARY.SIZE[{spec}]"),
            ] {
                let err = fetch_attribute(&mut receiver, &item).expect_err(&item);
                assert_eq!(
                    err.value_as_str(trc::Key::Type),
                    Some(ResponseType::Bad.as_str()),
                    "{item}"
                );
            }
        }
    }
}
