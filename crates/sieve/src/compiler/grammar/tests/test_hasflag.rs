/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::compiler::{
    CompileError, ErrorType, RawValue, Value, VariableType,
    grammar::{Capability, Comparator, instruction::CompilerState},
    lexer::{Token, tokenizer::TokenInfo, word::Word},
};

use crate::compiler::grammar::{MatchType, test::Test};

/*
   Usage: hasflag [MATCH-TYPE] [COMPARATOR]
          [<variable-list: string-list>]
          <list-of-flags: string-list>
*/

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(crate) struct TestHasFlag {
    pub comparator: Comparator,
    pub match_type: MatchType,
    pub variable_list: Box<[VariableType]>,
    pub flags: Box<[Value]>,
    pub is_not: bool,
}

impl CompilerState<'_> {
    pub(crate) fn parse_test_hasflag(&mut self) -> Result<Test, CompileError> {
        let mut match_type = MatchType::Is;
        let mut comparator = Comparator::AsciiCaseMap;
        let mut is_local = false;

        let maybe_variables;
        let variables_line_num;
        let variables_line_pos;

        loop {
            let token_info = self.tokens.unwrap_next()?;
            match token_info.token {
                Token::Tag(
                    word @ (Word::Is
                    | Word::Contains
                    | Word::Matches
                    | Word::Value
                    | Word::Count
                    | Word::Regex),
                ) => {
                    self.validate_argument(
                        1,
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
                    self.validate_argument(2, None, token_info.line_num, token_info.line_pos)?;
                    comparator = self.parse_comparator()?;
                }
                Token::Tag(Word::Local) => {
                    is_local = true;
                }
                _ => {
                    variables_line_num = token_info.line_num;
                    variables_line_pos = token_info.line_pos;
                    maybe_variables = self.parse_raw_strings_token(token_info)?;
                    break;
                }
            }
        }

        match self.tokens.peek() {
            Some(Ok(TokenInfo {
                token: Token::StringConstant(_) | Token::StringVariable(_) | Token::BracketOpen,
                line_num,
                line_pos,
            })) => {
                if !maybe_variables.is_empty() {
                    let line_num = *line_num;
                    let line_pos = *line_pos;
                    self.validate_flag_variable_name(variables_line_num, variables_line_pos)?;

                    let mut variable_list = Vec::with_capacity(maybe_variables.len());
                    for variable in maybe_variables {
                        let var_name = match variable {
                            RawValue::Text(text) => text,
                            RawValue::Value(Value::Text(id)) => self.constant(id).to_string(),
                            _ => {
                                return Err(self
                                    .tokens
                                    .unwrap_next()?
                                    .custom(ErrorType::ExpectedConstantString));
                            }
                        };
                        variable_list.push(self.register_variable(var_name, is_local).map_err(
                            |error_type| CompileError {
                                line_num,
                                line_pos,
                                error_type,
                            },
                        )?);
                    }
                    let flags = self.parse_raw_strings(false)?;
                    let flags = self.validate_match(&match_type, &comparator, flags)?;

                    Ok(Test::HasFlag(Box::new(TestHasFlag {
                        comparator,
                        match_type,
                        variable_list: variable_list.into(),
                        flags: flags.into(),
                        is_not: false,
                    })))
                } else {
                    Err(self
                        .tokens
                        .unwrap_next()?
                        .custom(ErrorType::ExpectedConstantString))
                }
            }
            _ => {
                let flags = self.validate_match(&match_type, &comparator, maybe_variables)?;

                Ok(Test::HasFlag(Box::new(TestHasFlag {
                    comparator,
                    match_type,
                    variable_list: Vec::new().into(),
                    flags: flags.into(),
                    is_not: false,
                })))
            }
        }
    }
}
