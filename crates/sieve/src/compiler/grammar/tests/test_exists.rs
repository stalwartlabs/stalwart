/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::compiler::{
    CompileError, Value,
    grammar::{Capability, instruction::CompilerState},
    lexer::{Token, word::Word},
};

use crate::compiler::grammar::test::Test;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(crate) struct TestExists {
    pub header_names: Box<[Value]>,
    pub mime_anychild: bool,
    pub is_not: bool,
}

impl CompilerState<'_> {
    pub(crate) fn parse_test_exists(&mut self) -> Result<Test, CompileError> {
        let mut header_names = None;

        let mut mime = false;
        let mut mime_anychild = false;

        while header_names.is_none() {
            let token_info = self.tokens.unwrap_next()?;
            match token_info.token {
                Token::Tag(Word::Mime) => {
                    self.validate_argument(
                        1,
                        Capability::Mime.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    mime = true;
                }
                Token::Tag(Word::AnyChild) => {
                    self.validate_argument(
                        2,
                        Capability::Mime.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    mime_anychild = true;
                }
                _ => {
                    let headers = self.parse_raw_strings_token(token_info)?;
                    header_names = self.resolve_header_names(headers).into();
                }
            }
        }

        if !mime && mime_anychild {
            return Err(self.tokens.unwrap_next()?.missing_tag(":mime"));
        }

        Ok(Test::Exists(Box::new(TestExists {
            header_names: header_names.unwrap().into(),
            mime_anychild,
            is_not: false,
        })))
    }
}
