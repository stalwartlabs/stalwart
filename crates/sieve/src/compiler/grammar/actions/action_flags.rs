/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::compiler::{
    CompileError, ErrorType, Value, VariableType,
    grammar::instruction::{CompilerState, Instruction},
    lexer::{Token, word::Word},
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(crate) struct EditFlags {
    pub action: Action,
    pub name: Option<VariableType>,
    pub flags: Box<[Value]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub(crate) enum Action {
    Set = 0,
    Add = 1,
    Remove = 2,
}

impl CompilerState<'_> {
    pub(crate) fn parse_flag_action(&mut self, word: Word) -> Result<(), CompileError> {
        let token_info = self.tokens.unwrap_next()?;
        let action = match word {
            Word::SetFlag => Action::Set,
            Word::AddFlag => Action::Add,
            Word::RemoveFlag => Action::Remove,
            _ => unreachable!(),
        };

        let instruction = Instruction::EditFlags(Box::new(
            match (
                &token_info.token,
                self.tokens.peek().map(|r| r.map(|t| &t.token)),
            ) {
                (
                    Token::StringConstant(_),
                    Some(Ok(
                        Token::StringConstant(_) | Token::StringVariable(_) | Token::BracketOpen,
                    )),
                ) => {
                    self.validate_flag_variable_name(token_info.line_num, token_info.line_pos)?;
                    EditFlags {
                        name: self.parse_variable_name(token_info, false)?.into(),
                        flags: self.parse_strings(false)?.into(),
                        action,
                    }
                }
                (Token::BracketOpen, _)
                | (
                    Token::StringConstant(_) | Token::StringVariable(_),
                    Some(Ok(Token::Semicolon)),
                ) => EditFlags {
                    name: None,
                    flags: self.parse_strings_token(token_info)?.into(),
                    action,
                },
                _ => {
                    return Err(token_info.custom(ErrorType::InvalidArguments));
                }
            },
        ));

        self.instructions.push(instruction);

        Ok(())
    }
}
