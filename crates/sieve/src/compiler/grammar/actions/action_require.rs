/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::compiler::{
    CompileError, ErrorType,
    grammar::{
        Capability,
        instruction::{CompilerState, Instruction},
    },
    lexer::{Token, tokenizer::TokenInfo},
};

impl CompilerState<'_> {
    fn add_capability(
        &mut self,
        capabilities: &mut Vec<Capability>,
        capability: Capability,
        token_info: &TokenInfo,
    ) -> Result<(), CompileError> {
        if self.compiler.disabled_capabilities.contains(&capability)
            || (self.compiler.unknown_capabilities_disabled && capability.is_unknown())
        {
            return Err(CompileError {
                line_num: token_info.line_num,
                line_pos: token_info.line_pos,
                error_type: ErrorType::UnsupportedCapability(capability),
            });
        }
        if !self.has_capability(&capability) {
            let parent_capability = if matches!(&capability, Capability::SpamTestPlus) {
                Some(Capability::SpamTest)
            } else {
                None
            };
            capabilities.push(capability.clone());
            self.block.capabilities.insert(capability);

            if let Some(capability) = parent_capability
                && !self.has_capability(&capability)
            {
                capabilities.push(capability.clone());
                self.block.capabilities.insert(capability);
            }
        }
        Ok(())
    }

    pub(crate) fn parse_require(&mut self) -> Result<(), CompileError> {
        let mut capabilities = Vec::new();

        let token_info = self.tokens.unwrap_next()?;
        match token_info.token {
            Token::BracketOpen => loop {
                let token_info = self.tokens.unwrap_next()?;
                match token_info.token {
                    Token::StringConstant(ref value) => {
                        self.add_capability(
                            &mut capabilities,
                            Capability::parse(value.to_string().as_ref()),
                            &token_info,
                        )?;
                        let token_info = self.tokens.unwrap_next()?;
                        match token_info.token {
                            Token::Comma => (),
                            Token::BracketClose => break,
                            _ => {
                                return Err(token_info.expected("']' or ','"));
                            }
                        }
                    }
                    _ => {
                        return Err(token_info.expected("string"));
                    }
                }
            },
            Token::StringConstant(ref value) => {
                self.add_capability(
                    &mut capabilities,
                    Capability::parse(value.to_string().as_ref()),
                    &token_info,
                )?;
            }
            _ => {
                return Err(token_info.expected("'[' or string"));
            }
        }

        if !capabilities.is_empty() {
            if self.block.require_pos == usize::MAX {
                self.block.require_pos = self.instructions.len();
                self.instructions
                    .push(Instruction::Require(capabilities.into_boxed_slice()));
            } else if let Some(Instruction::Require(capabilties)) =
                self.instructions.get_mut(self.block.require_pos)
            {
                let mut merged = std::mem::take(capabilties).into_vec();
                merged.extend(capabilities);
                *capabilties = merged.into_boxed_slice();
            } else {
                #[cfg(all(test, stalwart_tests))]
                panic!(
                    "Invalid require instruction position {}.",
                    self.block.require_pos
                )
            }
        }

        Ok(())
    }
}
