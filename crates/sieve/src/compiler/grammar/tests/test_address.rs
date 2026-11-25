/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::compiler::{
    CompileError, Value,
    grammar::{Capability, Comparator, instruction::CompilerState, test::Test},
    lexer::{Token, word::Word},
};

use crate::compiler::grammar::{AddressPart, MatchType};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(crate) struct TestAddress {
    pub header_list: Box<[Value]>,
    pub key_list: Box<[Value]>,
    pub address_part: AddressPart,
    pub match_type: MatchType,
    pub comparator: Comparator,
    pub index: Option<i32>,

    pub mime_anychild: bool,
    pub is_not: bool,
}

impl CompilerState<'_> {
    pub(crate) fn parse_test_address(&mut self) -> Result<Test, CompileError> {
        let mut address_part = AddressPart::All;
        let mut match_type = MatchType::Is;
        let mut comparator = Comparator::AsciiCaseMap;
        let mut header_list = None;
        let key_list;
        let mut index = None;
        let mut index_last = false;

        let mut mime = false;
        let mut mime_anychild = false;

        loop {
            let token_info = self.tokens.unwrap_next()?;
            match token_info.token {
                Token::Tag(
                    word @ (Word::LocalPart
                    | Word::Domain
                    | Word::All
                    | Word::User
                    | Word::Detail
                    | Word::Name),
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
                Token::Tag(Word::Index) => {
                    self.validate_argument(
                        4,
                        Capability::Index.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    index = (self.tokens.expect_number(u16::MAX as usize)? as i32).into();
                }
                Token::Tag(Word::Last) => {
                    self.validate_argument(
                        5,
                        Capability::Index.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    index_last = true;
                }
                Token::Tag(Word::Mime) => {
                    self.validate_argument(
                        6,
                        Capability::Mime.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    mime = true;
                }
                Token::Tag(Word::AnyChild) => {
                    self.validate_argument(
                        7,
                        Capability::Mime.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    mime_anychild = true;
                }
                _ => {
                    if header_list.is_none() {
                        let headers = self.parse_raw_strings_token(token_info)?;
                        header_list = self.resolve_header_names(headers).into();
                    } else {
                        key_list = self.parse_raw_strings_token(token_info)?;
                        break;
                    }
                }
            }
        }

        if !mime && mime_anychild {
            return Err(self.tokens.unwrap_next()?.missing_tag(":mime"));
        }
        let key_list = self.validate_match(&match_type, &comparator, key_list)?;

        Ok(Test::Address(Box::new(TestAddress {
            header_list: header_list.unwrap().into(),
            key_list: key_list.into(),
            address_part,
            match_type,
            comparator,
            index: if index_last { index.map(|i| -i) } else { index },
            mime_anychild,
            is_not: false,
        })))
    }
}

impl From<Word> for AddressPart {
    fn from(word: Word) -> Self {
        match word {
            Word::LocalPart => AddressPart::LocalPart,
            Word::Domain => AddressPart::Domain,
            Word::All => AddressPart::All,
            Word::User => AddressPart::User,
            Word::Detail => AddressPart::Detail,
            Word::Name => AddressPart::Name,
            _ => unreachable!(),
        }
    }
}
