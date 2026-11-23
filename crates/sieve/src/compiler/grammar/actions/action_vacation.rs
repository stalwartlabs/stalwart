/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    FileCarbonCopy,
    compiler::{
        CompileError, Value,
        grammar::{
            Capability,
            instruction::{CompilerState, Instruction},
            test::Test,
        },
        lexer::{Token, word::Word},
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(crate) struct Vacation {
    pub subject: Option<Value>,
    pub from: Option<Value>,
    pub mime: bool,
    pub fcc: Option<FileCarbonCopy<Value>>,
    pub reason: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(crate) struct TestVacation {
    pub addresses: Box<[Value]>,
    pub period: Period,
    pub handle: Option<Value>,
    pub reason: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum Period {
    Days(u64) = 0,
    Seconds(u64) = 1,
    Default = 2,
}

/*

vacation [":days" number] [":subject" string]
                     [":from" string] [":addresses" string-list]
                     [":mime"] [":handle" string] <reason: string>

vacation [FCC]
                     [":days" number | ":seconds" number]
                     [":subject" string]
                     [":from" string]
                     [":addresses" string-list]
                     [":mime"]
                     [":handle" string]
                     <reason: string>

":flags" <list-of-flags: string-list>


   FCC         = ":fcc" string *FCC-OPTS
                   ; per Section 2.6.2 of RFC 5228,
                   ; the tagged arguments in FCC may appear in any order

   FCC-OPTS    = CREATE / IMAP-FLAGS / SPECIAL-USE
                   ; each option MUST NOT appear more than once

   CREATE      = ":create"
   IMAP-FLAGS  = ":flags" string-list
   SPECIAL-USE = ":specialuse" string
*/

impl CompilerState<'_> {
    pub(crate) fn parse_vacation(&mut self) -> Result<(), CompileError> {
        let mut period = Period::Default;
        let mut subject = None;
        let mut from = None;
        let mut handle = None;
        let mut addresses = Vec::new();
        let mut mime = false;
        let reason;

        let mut fcc = None;
        let mut create = false;
        let mut flags = Vec::new();
        let mut special_use = None;
        let mut mailbox_id = None;

        loop {
            let token_info = self.tokens.unwrap_next()?;
            match token_info.token {
                Token::Tag(Word::Mime) => {
                    self.validate_argument(1, None, token_info.line_num, token_info.line_pos)?;
                    mime = true;
                }
                Token::Tag(Word::Create) => {
                    self.validate_argument(
                        2,
                        Capability::Mailbox.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    create = true;
                }
                Token::Tag(Word::Days) => {
                    self.validate_argument(3, None, token_info.line_num, token_info.line_pos)?;
                    period = Period::Days(self.tokens.expect_number(u64::MAX as usize)? as u64);
                }
                Token::Tag(Word::Seconds) => {
                    self.validate_argument(
                        3,
                        Capability::VacationSeconds.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    period = Period::Seconds(self.tokens.expect_number(u64::MAX as usize)? as u64);
                }
                Token::Tag(Word::Subject) => {
                    self.validate_argument(4, None, token_info.line_num, token_info.line_pos)?;
                    subject = self.parse_string()?.into();
                }
                Token::Tag(Word::From) => {
                    self.validate_argument(5, None, token_info.line_num, token_info.line_pos)?;
                    from = self.parse_string()?.into();
                }
                Token::Tag(Word::Handle) => {
                    self.validate_argument(6, None, token_info.line_num, token_info.line_pos)?;
                    handle = self.parse_string()?.into();
                }
                Token::Tag(Word::SpecialUse) => {
                    self.validate_argument(
                        7,
                        Capability::SpecialUse.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    special_use = self.parse_string()?.into();
                }
                Token::Tag(Word::MailboxId) => {
                    self.validate_argument(
                        8,
                        Capability::MailboxId.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    mailbox_id = self.parse_string()?.into();
                }
                Token::Tag(Word::Fcc) => {
                    self.validate_argument(
                        9,
                        Capability::Fcc.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    fcc = self.parse_string()?.into();
                }
                Token::Tag(Word::Flags) => {
                    self.validate_argument(
                        10,
                        Capability::Imap4Flags.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    flags = self.parse_strings(false)?;
                }
                Token::Tag(Word::Addresses) => {
                    self.validate_argument(11, None, token_info.line_num, token_info.line_pos)?;
                    addresses = self.parse_strings(false)?;
                }
                _ => {
                    reason = self.parse_string_token(token_info)?;
                    break;
                }
            }
        }

        if fcc.is_none()
            && (create || !flags.is_empty() || special_use.is_some() || mailbox_id.is_some())
        {
            return Err(self.tokens.unwrap_next()?.missing_tag(":fcc"));
        }

        self.instructions
            .push(Instruction::Test(Box::new(Test::Vacation(Box::new(
                TestVacation {
                    period,
                    handle,
                    reason: reason.clone(),
                    addresses: addresses.into(),
                },
            )))));

        self.instructions
            .push(Instruction::Jz((self.instructions.len() + 2) as u32));

        self.instructions
            .push(Instruction::Vacation(Box::new(Vacation {
                reason,
                subject,
                from,
                mime,
                fcc: if let Some(fcc) = fcc {
                    FileCarbonCopy {
                        mailbox: fcc,
                        create,
                        flags: flags.into(),
                        special_use,
                        mailbox_id,
                    }
                    .into()
                } else {
                    None
                },
            })));

        Ok(())
    }
}
