/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Envelope,
    compiler::{
        CompileError, ErrorType, Value,
        grammar::{Capability, Comparator, instruction::CompilerState},
        lexer::{Token, word::Word},
    },
};

use crate::compiler::grammar::{AddressPart, MatchType, test::Test};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(crate) struct TestEnvelope {
    pub envelope_list: Box<[Envelope]>,
    pub key_list: Box<[Value]>,
    pub address_part: AddressPart,
    pub match_type: MatchType,
    pub comparator: Comparator,
    pub zone: Option<i64>,
    pub is_not: bool,
}

impl CompilerState<'_> {
    pub(crate) fn parse_test_envelope(&mut self) -> Result<Test, CompileError> {
        let mut address_part = AddressPart::All;
        let mut match_type = MatchType::Is;
        let mut comparator = Comparator::AsciiCaseMap;
        let mut envelope_list = None;
        let key_list;
        let mut zone = None;

        loop {
            let mut token_info = self.tokens.unwrap_next()?;
            match token_info.token {
                Token::Tag(
                    word @ (Word::LocalPart | Word::Domain | Word::All | Word::User | Word::Detail),
                ) => {
                    self.validate_argument(
                        1,
                        if matches!(word, Word::User | Word::Detail) {
                            Capability::SubAddress.into()
                        } else {
                            None
                        },
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    address_part = word.into();
                }
                Token::Tag(
                    word @ (Word::Is
                    | Word::Contains
                    | Word::Matches
                    | Word::Value
                    | Word::Count
                    | Word::Regex
                    | Word::List),
                ) => {
                    self.validate_argument(
                        2,
                        match word {
                            Word::Value | Word::Count => Capability::Relational.into(),
                            Word::Regex => Capability::Regex.into(),
                            Word::List => Capability::ExtLists.into(),
                            _ => None,
                        },
                        token_info.line_num,
                        token_info.line_pos,
                    )?;

                    match_type = self.parse_match_type(word)?;
                }
                Token::Tag(Word::Comparator) => {
                    self.validate_argument(3, None, token_info.line_num, token_info.line_pos)?;
                    comparator = self.parse_comparator()?;
                }
                Token::Tag(Word::Zone) => {
                    self.validate_argument(
                        4,
                        Capability::EnvelopeDeliverBy.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    zone = self.parse_timezone_offset()?.into();
                }
                _ => {
                    if envelope_list.is_none() {
                        let mut envelopes = Vec::new();
                        let line_num = token_info.line_num;
                        let line_pos = token_info.line_pos;

                        match token_info.token {
                            Token::StringConstant(s) => {
                                match Envelope::try_from(s.into_string().to_ascii_lowercase()) {
                                    Ok(envelope) => {
                                        envelopes.push(envelope);
                                    }
                                    Err(invalid) => {
                                        token_info.token = Token::Comma;
                                        return Err(
                                            token_info.custom(ErrorType::InvalidEnvelope(invalid))
                                        );
                                    }
                                }
                            }
                            Token::BracketOpen => loop {
                                let mut token_info = self.tokens.unwrap_next()?;
                                match token_info.token {
                                    Token::StringConstant(s) => {
                                        match Envelope::try_from(
                                            s.into_string().to_ascii_lowercase(),
                                        ) {
                                            Ok(envelope) => {
                                                if !envelopes.contains(&envelope) {
                                                    envelopes.push(envelope);
                                                }
                                            }
                                            Err(invalid) => {
                                                token_info.token = Token::Comma;
                                                return Err(token_info
                                                    .custom(ErrorType::InvalidEnvelope(invalid)));
                                            }
                                        }
                                    }
                                    Token::Comma => (),
                                    Token::BracketClose if !envelopes.is_empty() => break,
                                    _ => return Err(token_info.expected("constant string")),
                                }
                            },
                            _ => return Err(token_info.expected("constant string")),
                        }

                        for envelope in &envelopes {
                            match envelope {
                                Envelope::ByTimeAbsolute
                                | Envelope::ByTimeRelative
                                | Envelope::ByMode
                                | Envelope::ByTrace => {
                                    self.validate_argument(
                                        0,
                                        Capability::EnvelopeDeliverBy.into(),
                                        line_num,
                                        line_pos,
                                    )?;
                                }

                                Envelope::Notify
                                | Envelope::Orcpt
                                | Envelope::Ret
                                | Envelope::Envid => {
                                    self.validate_argument(
                                        0,
                                        Capability::EnvelopeDsn.into(),
                                        line_num,
                                        line_pos,
                                    )?;
                                }
                                _ => (),
                            }
                        }

                        envelope_list = envelopes.into();
                    } else {
                        key_list = self.parse_raw_strings_token(token_info)?;
                        break;
                    }
                }
            }
        }
        let key_list = self.validate_match(&match_type, &comparator, key_list)?;

        Ok(Test::Envelope(Box::new(TestEnvelope {
            envelope_list: envelope_list.unwrap().into(),
            key_list: key_list.into(),
            address_part,
            match_type,
            comparator,
            zone,
            is_not: false,
        })))
    }
}

impl TryFrom<String> for Envelope {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Some(envelope) = lookup_envelope(&value) {
            Ok(envelope)
        } else {
            Err(value)
        }
    }
}

impl<'x> TryFrom<&'x str> for Envelope {
    type Error = &'x str;

    fn try_from(value: &'x str) -> Result<Self, Self::Error> {
        if let Some(envelope) = lookup_envelope(value) {
            Ok(envelope)
        } else {
            Err(value)
        }
    }
}

fn lookup_envelope(input: &str) -> Option<Envelope> {
    hashify::map!(
        input.as_bytes(), Envelope,
        "from" => Envelope::From,
        "to" => Envelope::To,
        "bytimeabsolute" => Envelope::ByTimeAbsolute,
        "bytimerelative" => Envelope::ByTimeRelative,
        "bymode" => Envelope::ByMode,
        "bytrace" => Envelope::ByTrace,
        "notify" => Envelope::Notify,
        "orcpt" => Envelope::Orcpt,
        "ret" => Envelope::Ret,
        "envid" => Envelope::Envid,
    )
    .copied()
}
