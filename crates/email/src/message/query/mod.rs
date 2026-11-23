/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod filter;
mod text;

pub use filter::{QueryFilter, RowFilter, push_condition};
use store::roaring::RoaringBitmap;
use types::keyword::Keyword;

#[derive(Debug, Clone, PartialEq)]
pub enum MailFilter {
    Condition(MailCondition),
    And,
    Or,
    Not,
    Close,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MailCondition {
    InMailbox(u32),
    InMailboxOtherThan(Box<[u32]>),
    InThread(u32),
    HasKeyword(Keyword),
    NotKeyword(Keyword),
    HasAttachment(bool),
    ReceivedBefore(i64),
    ReceivedAfter(i64),
    SentBefore(i64),
    SentAfter(i64),
    MinSize(u32),
    MaxSize(u32),
    Text(MailTextField, String),
    Header(String, Option<String>),
    ThreadKeyword(Keyword, ThreadKeywordMatch),
    DocumentSet(RoaringBitmap),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailTextField {
    Any,
    From,
    To,
    Cc,
    Bcc,
    Subject,
    Body,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadKeywordMatch {
    All,
    Some,
    None,
}
