/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    MailCondition, MailFilter, MailTextField, ThreadKeywordMatch,
    text::{push_text, strip_subject_prefix},
};
use crate::cache::email::{MessageAccess, MessageCacheAccess, SearchOperator, thread_keywords};
use common::{MessageStoreCache, cache::email::MessageRef};
use mail_parser::HeaderName;
use nlp::language::Language;
use std::ops::RangeInclusive;
use store::{
    roaring::RoaringBitmap,
    search::{EmailSearchField, KeyValueMatch, SearchFilter},
};
use types::keyword::{HASATTACHMENT, HASNOATTACHMENT, Keyword};

pub struct RowFilter {
    pub access: MessageAccess,
    mailboxes: Mailboxes,
    not_in_mailboxes: Option<Box<[u32]>>,
    thread_id: Option<u32>,
    all_keywords: u32,
    no_keywords: u32,
    received: Option<RangeInclusive<i64>>,
    sent: Option<RangeInclusive<i64>>,
    size: Option<RangeInclusive<i64>>,
    pub residual: Option<RoaringBitmap>,
}

enum Mailboxes {
    Any,
    One(u32),
    All(Vec<u32>),
}

pub struct QueryFilter {
    pub row: RowFilter,
    pub residual: Vec<SearchFilter>,
    pub text: Vec<SearchFilter>,
    visible: Option<RoaringBitmap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Absorbed {
    Yes,
    Contradiction,
}

impl RowFilter {
    pub fn new(access: MessageAccess) -> Self {
        RowFilter {
            access,
            mailboxes: Mailboxes::Any,
            not_in_mailboxes: None,
            thread_id: None,
            all_keywords: 0,
            no_keywords: 0,
            received: None,
            sent: None,
            size: None,
            residual: None,
        }
    }

    #[inline(always)]
    pub fn matches(&self, message: MessageRef<'_>) -> bool {
        (match &self.mailboxes {
            Mailboxes::Any => true,
            Mailboxes::One(mailbox_id) => message.has_mailbox_id(*mailbox_id),
            Mailboxes::All(mailbox_ids) => mailbox_ids
                .iter()
                .all(|mailbox_id| message.has_mailbox_id(*mailbox_id)),
        }) && (self.all_keywords | self.no_keywords == 0 || {
            let keywords = message.keywords();
            keywords & self.all_keywords == self.all_keywords && keywords & self.no_keywords == 0
        }) && self
            .thread_id
            .is_none_or(|thread_id| message.thread_id() == thread_id)
            && self
                .received
                .as_ref()
                .is_none_or(|range| range.contains(&(message.received_at() as i64)))
            && self
                .sent
                .as_ref()
                .is_none_or(|range| range.contains(&message.sent_at_absolute()))
            && self
                .size
                .as_ref()
                .is_none_or(|range| range.contains(&i64::from(message.size())))
            && self.not_in_mailboxes.as_deref().is_none_or(|mailboxes| {
                message
                    .mailboxes()
                    .iter()
                    .any(|uid| mailboxes.binary_search(&uid.mailbox_id).is_err())
            })
            && self
                .residual
                .as_ref()
                .is_none_or(|documents| documents.contains(message.document_id()))
            && self.access.allows(message)
    }

    fn absorb(&mut self, condition: MailCondition) -> Result<Absorbed, MailCondition> {
        match condition {
            MailCondition::InMailbox(mailbox_id) => {
                match &mut self.mailboxes {
                    Mailboxes::Any => self.mailboxes = Mailboxes::One(mailbox_id),
                    Mailboxes::One(current) if *current == mailbox_id => (),
                    Mailboxes::One(current) => {
                        self.mailboxes = Mailboxes::All(vec![*current, mailbox_id]);
                    }
                    Mailboxes::All(current) => current.push(mailbox_id),
                }
                Ok(Absorbed::Yes)
            }
            MailCondition::InThread(thread_id) => Ok(narrow_id(&mut self.thread_id, thread_id)),
            MailCondition::InMailboxOtherThan(mut mailboxes) if self.not_in_mailboxes.is_none() => {
                mailboxes.sort_unstable();
                self.not_in_mailboxes = Some(mailboxes);
                Ok(Absorbed::Yes)
            }
            MailCondition::HasKeyword(keyword) => match keyword.id() {
                Ok(id) => {
                    self.all_keywords |= 1 << id;
                    Ok(Absorbed::Yes)
                }
                Err(_) => Err(MailCondition::HasKeyword(keyword)),
            },
            MailCondition::NotKeyword(keyword) => match keyword.id() {
                Ok(id) => {
                    self.no_keywords |= 1 << id;
                    Ok(Absorbed::Yes)
                }
                Err(_) => Err(MailCondition::NotKeyword(keyword)),
            },
            MailCondition::HasAttachment(has_attachment) => {
                self.all_keywords |= if has_attachment {
                    1 << HASATTACHMENT
                } else {
                    1 << HASNOATTACHMENT
                };
                Ok(Absorbed::Yes)
            }
            MailCondition::ReceivedBefore(timestamp) => {
                narrow_range(&mut self.received, i64::MIN, timestamp.saturating_sub(1))
            }
            MailCondition::ReceivedAfter(timestamp) => {
                narrow_range(&mut self.received, timestamp, i64::MAX)
            }
            MailCondition::SentBefore(timestamp) => {
                narrow_range(&mut self.sent, i64::MIN, timestamp.saturating_sub(1))
            }
            MailCondition::SentAfter(timestamp) => {
                narrow_range(&mut self.sent, timestamp.saturating_add(1), i64::MAX)
            }
            MailCondition::MinSize(size) => narrow_range(&mut self.size, i64::from(size), i64::MAX),
            MailCondition::MaxSize(size) => {
                narrow_range(&mut self.size, i64::MIN, i64::from(size) - 1)
            }
            condition => Err(condition),
        }
    }
}

fn narrow_id(current: &mut Option<u32>, id: u32) -> Absorbed {
    match current {
        Some(current) if *current != id => Absorbed::Contradiction,
        _ => {
            *current = Some(id);
            Absorbed::Yes
        }
    }
}

fn narrow_range(
    current: &mut Option<RangeInclusive<i64>>,
    from: i64,
    to: i64,
) -> Result<Absorbed, MailCondition> {
    let range = match current.take() {
        Some(range) => (*range.start()).max(from)..=(*range.end()).min(to),
        None => from..=to,
    };
    let absorbed = if range.is_empty() {
        Absorbed::Contradiction
    } else {
        Absorbed::Yes
    };
    *current = Some(range);
    Ok(absorbed)
}

impl QueryFilter {
    pub fn parse(
        filters: Vec<MailFilter>,
        cache: &MessageStoreCache,
        access: MessageAccess,
        default_language: Language,
    ) -> Option<Self> {
        let mut row = RowFilter::new(access);
        let mut residual = Vec::new();
        let mut text = Vec::new();
        let mut subtrees = 0usize;
        let mut is_empty = false;
        let mut visible = None;
        let verbatim = has_empty_group(&filters);

        for filter in filters {
            let top_level = !verbatim && subtrees == 0;
            match filter {
                MailFilter::Condition(condition) if top_level => match row.absorb(condition) {
                    Ok(Absorbed::Yes) => (),
                    Ok(Absorbed::Contradiction) => is_empty = true,
                    Err(condition) if is_text(&condition) => push_condition(
                        &mut text,
                        condition,
                        cache,
                        &row.access,
                        &mut visible,
                        default_language,
                    ),
                    Err(condition) => push_condition(
                        &mut residual,
                        condition,
                        cache,
                        &row.access,
                        &mut visible,
                        default_language,
                    ),
                },
                MailFilter::Condition(condition) => push_condition(
                    &mut residual,
                    condition,
                    cache,
                    &row.access,
                    &mut visible,
                    default_language,
                ),
                MailFilter::And if top_level => (),
                MailFilter::And => {
                    subtrees += 1;
                    residual.push(SearchFilter::And);
                }
                MailFilter::Or => {
                    subtrees += 1;
                    residual.push(SearchFilter::Or);
                }
                MailFilter::Not => {
                    subtrees += 1;
                    residual.push(SearchFilter::Not);
                }
                MailFilter::Close if subtrees > 0 || verbatim => {
                    subtrees = subtrees.saturating_sub(1);
                    residual.push(SearchFilter::End);
                }
                MailFilter::Close => (),
            }
        }

        if let Mailboxes::All(mailbox_ids) = &mut row.mailboxes {
            mailbox_ids.sort_unstable();
            mailbox_ids.dedup();
        }

        (!is_empty).then_some(QueryFilter {
            row,
            residual,
            text,
            visible,
        })
    }

    pub fn visible(&mut self, cache: &MessageStoreCache) -> Option<&RoaringBitmap> {
        visible_ids(cache, &self.row.access, &mut self.visible)
    }

    pub fn readable(&mut self, cache: &MessageStoreCache) -> RoaringBitmap {
        match &self.row.access {
            MessageAccess::All => cache.email_document_ids(),
            access => self
                .visible
                .take()
                .unwrap_or_else(|| readable_ids(cache, access)),
        }
    }

    pub fn into_row(self) -> RowFilter {
        let QueryFilter {
            mut row, visible, ..
        } = self;
        if matches!(row.access, MessageAccess::Mailboxes(_)) {
            row.residual = row.residual.or(visible);
            if row.residual.is_some() {
                row.access = MessageAccess::All;
            }
        }
        row
    }

    pub fn residual_filters(&mut self) -> Vec<SearchFilter> {
        let mut filters = std::mem::take(&mut self.residual);
        filters.append(&mut self.text);
        filters
    }

    pub fn take_text(&mut self) -> Option<Vec<SearchFilter>> {
        if self.text.is_empty() {
            return None;
        }
        let mut external = Vec::new();
        let mut depth = 0usize;
        let mut start = 0;
        let mut locality = Locality::None;
        for (end, filter) in self.residual.iter().enumerate() {
            locality = locality.with(filter);
            match filter {
                SearchFilter::And | SearchFilter::Or | SearchFilter::Not => depth += 1,
                SearchFilter::End => depth = depth.saturating_sub(1),
                _ => (),
            }
            if depth == 0 {
                match locality {
                    Locality::Mixed => return None,
                    Locality::External => external.push(start..end + 1),
                    Locality::None | Locality::Local => (),
                }
                start = end + 1;
                locality = Locality::None;
            }
        }

        let mut text = std::mem::take(&mut self.text);
        if !external.is_empty() {
            let mut external = external.into_iter().peekable();
            let mut local = Vec::with_capacity(self.residual.len());
            for (pos, filter) in std::mem::take(&mut self.residual).into_iter().enumerate() {
                while external.next_if(|range| range.end <= pos).is_some() {}
                if external.peek().is_some_and(|range| range.contains(&pos)) {
                    text.push(filter);
                } else {
                    local.push(filter);
                }
            }
            self.residual = local;
        }
        Some(text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Locality {
    None,
    Local,
    External,
    Mixed,
}

impl Locality {
    fn with(self, filter: &SearchFilter) -> Self {
        let other = match filter {
            SearchFilter::DocumentSet(_) => Locality::Local,
            SearchFilter::Text { .. }
            | SearchFilter::KeyValue { .. }
            | SearchFilter::Integer { .. } => Locality::External,
            SearchFilter::And | SearchFilter::Or | SearchFilter::Not | SearchFilter::End => {
                return self;
            }
        };
        match self {
            Locality::None => other,
            current if current == other => current,
            _ => Locality::Mixed,
        }
    }
}

fn readable_ids(cache: &MessageStoreCache, access: &MessageAccess) -> RoaringBitmap {
    cache
        .emails
        .iter()
        .filter(|message| access.allows(*message))
        .map(|message| message.document_id())
        .collect()
}

fn visible_ids<'x>(
    cache: &MessageStoreCache,
    access: &MessageAccess,
    visible: &'x mut Option<RoaringBitmap>,
) -> Option<&'x RoaringBitmap> {
    match access {
        MessageAccess::All => None,
        access => Some(visible.get_or_insert_with(|| readable_ids(cache, access))),
    }
}

fn has_empty_group(filters: &[MailFilter]) -> bool {
    let mut leaves: Vec<usize> = Vec::new();
    for filter in filters {
        match filter {
            MailFilter::And | MailFilter::Or | MailFilter::Not => leaves.push(0),
            MailFilter::Close => match leaves.pop() {
                Some(0) => return true,
                Some(count) => {
                    if let Some(parent) = leaves.last_mut() {
                        *parent += count;
                    }
                }
                None => (),
            },
            MailFilter::Condition(MailCondition::Header(name, _))
                if HeaderName::parse(name.as_str()).is_none() => {}
            MailFilter::Condition(_) => {
                if let Some(count) = leaves.last_mut() {
                    *count += 1;
                }
            }
        }
    }
    leaves.contains(&0)
}

fn is_text(condition: &MailCondition) -> bool {
    matches!(
        condition,
        MailCondition::Text(..) | MailCondition::Header(..)
    )
}

pub fn push_condition(
    filters: &mut Vec<SearchFilter>,
    condition: MailCondition,
    cache: &MessageStoreCache,
    access: &MessageAccess,
    visible: &mut Option<RoaringBitmap>,
    default_language: Language,
) {
    match condition {
        MailCondition::Text(MailTextField::Any, text) => {
            let (text, language) = Language::detect(text, default_language);
            push_text(filters, &strip_subject_prefix(&text), language);
        }
        MailCondition::Text(MailTextField::From, text) => filters.push(SearchFilter::has_text(
            EmailSearchField::From,
            text,
            Language::None,
        )),
        MailCondition::Text(MailTextField::To, text) => filters.push(SearchFilter::has_text(
            EmailSearchField::To,
            text,
            Language::None,
        )),
        MailCondition::Text(MailTextField::Cc, text) => filters.push(SearchFilter::has_text(
            EmailSearchField::Cc,
            text,
            Language::None,
        )),
        MailCondition::Text(MailTextField::Bcc, text) => filters.push(SearchFilter::has_text(
            EmailSearchField::Bcc,
            text,
            Language::None,
        )),
        MailCondition::Text(MailTextField::Subject, text) => {
            filters.push(SearchFilter::has_text_detect(
                EmailSearchField::Subject,
                strip_subject_prefix(&text),
                default_language,
            ))
        }
        MailCondition::Text(MailTextField::Body, text) => filters.push(
            SearchFilter::has_text_detect(EmailSearchField::Body, text, default_language),
        ),
        MailCondition::Header(header_name, value) => {
            match (HeaderName::parse(header_name), value) {
                (Some(HeaderName::Subject), Some(value)) => {
                    filters.push(SearchFilter::has_text_detect(
                        EmailSearchField::Subject,
                        strip_subject_prefix(&value),
                        default_language,
                    ))
                }
                (Some(HeaderName::From), Some(value)) => filters.push(SearchFilter::has_text(
                    EmailSearchField::From,
                    value,
                    Language::None,
                )),
                (Some(HeaderName::To), Some(value)) => filters.push(SearchFilter::has_text(
                    EmailSearchField::To,
                    value,
                    Language::None,
                )),
                (Some(HeaderName::Cc), Some(value)) => filters.push(SearchFilter::has_text(
                    EmailSearchField::Cc,
                    value,
                    Language::None,
                )),
                (Some(HeaderName::Bcc), Some(value)) => filters.push(SearchFilter::has_text(
                    EmailSearchField::Bcc,
                    value,
                    Language::None,
                )),
                (Some(header_name), value) => {
                    let op = match value {
                        Some(value)
                            if matches!(
                                header_name,
                                HeaderName::MessageId
                                    | HeaderName::InReplyTo
                                    | HeaderName::References
                                    | HeaderName::ResentMessageId
                            ) =>
                        {
                            KeyValueMatch::Equals(value)
                        }
                        Some(value) => KeyValueMatch::Contains(value),
                        None => KeyValueMatch::Exists,
                    };
                    filters.push(SearchFilter::KeyValue {
                        field: EmailSearchField::Headers.into(),
                        key: header_name.as_str().to_lowercase(),
                        op,
                    });
                }
                (None, _) => {}
            }
        }
        MailCondition::InMailbox(mailbox_id) => filters.push(SearchFilter::is_in_set(
            RoaringBitmap::from_iter(cache.in_mailbox(mailbox_id).map(|item| item.document_id())),
        )),
        MailCondition::InMailboxOtherThan(mut mailboxes) => {
            mailboxes.sort_unstable();
            filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                cache.emails.iter().filter_map(|item| {
                    if item
                        .mailboxes()
                        .iter()
                        .any(|mb| mailboxes.binary_search(&mb.mailbox_id).is_err())
                    {
                        Some(item.document_id())
                    } else {
                        None
                    }
                }),
            )));
        }
        MailCondition::ReceivedBefore(timestamp) => {
            filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                cache
                    .received(timestamp, SearchOperator::LowerThan)
                    .map(|m| m.document_id()),
            )))
        }
        MailCondition::ReceivedAfter(timestamp) => {
            filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                cache
                    .received(timestamp, SearchOperator::GreaterEqualThan)
                    .map(|m| m.document_id()),
            )))
        }
        MailCondition::MinSize(size) => {
            filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                cache
                    .size(size, SearchOperator::GreaterEqualThan)
                    .map(|m| m.document_id()),
            )))
        }
        MailCondition::MaxSize(size) => {
            filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                cache
                    .size(size, SearchOperator::LowerThan)
                    .map(|m| m.document_id()),
            )))
        }
        MailCondition::ThreadKeyword(keyword, ThreadKeywordMatch::All) => {
            filters.push(SearchFilter::is_in_set(thread_keywords(
                cache,
                &keyword,
                true,
                None,
                visible_ids(cache, access, visible),
            )))
        }
        MailCondition::ThreadKeyword(keyword, ThreadKeywordMatch::Some) => {
            filters.push(SearchFilter::is_in_set(thread_keywords(
                cache,
                &keyword,
                false,
                None,
                visible_ids(cache, access, visible),
            )))
        }
        MailCondition::ThreadKeyword(keyword, ThreadKeywordMatch::None) => {
            filters.push(SearchFilter::Not);
            filters.push(SearchFilter::is_in_set(thread_keywords(
                cache,
                &keyword,
                false,
                None,
                visible_ids(cache, access, visible),
            )));
            filters.push(SearchFilter::End);
        }
        MailCondition::HasKeyword(keyword) => filters.push(SearchFilter::is_in_set(
            RoaringBitmap::from_iter(cache.with_keyword(&keyword).map(|item| item.document_id())),
        )),
        MailCondition::NotKeyword(keyword) => {
            filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                cache
                    .without_keyword(&keyword)
                    .map(|item| item.document_id()),
            )))
        }
        MailCondition::HasAttachment(has_attach) => {
            let keyword = if has_attach {
                Keyword::HasAttachment
            } else {
                Keyword::HasNoAttachment
            };

            filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                cache.with_keyword(&keyword).map(|item| item.document_id()),
            )));
        }
        MailCondition::DocumentSet(set) => filters.push(SearchFilter::is_in_set(set)),
        MailCondition::SentBefore(timestamp) => {
            filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                cache
                    .sent(timestamp, SearchOperator::LowerThan)
                    .map(|m| m.document_id()),
            )))
        }
        MailCondition::SentAfter(timestamp) => {
            filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                cache
                    .sent(timestamp, SearchOperator::GreaterThan)
                    .map(|m| m.document_id()),
            )))
        }
        MailCondition::InThread(thread_id) => filters.push(SearchFilter::is_in_set(
            RoaringBitmap::from_iter(cache.in_thread(thread_id).map(|item| item.document_id())),
        )),
    }
}
