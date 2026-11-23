/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::MessageStoreCache;
use compact_str::ToCompactString;
use email::{
    cache::email::MessageAccess,
    message::query::{MailCondition, MailFilter, MailTextField, QueryFilter, ThreadKeywordMatch},
};
use jmap_proto::{
    method::query::Filter,
    object::email::{EmailFilter, EmailQueryFilter},
};
use nlp::language::Language;
use store::roaring::RoaringBitmap;

pub(super) fn parse_filter(
    filters: Vec<Filter<EmailQueryFilter>>,
    cache: &MessageStoreCache,
    access: MessageAccess,
    mut metadata_matches: impl Iterator<Item = RoaringBitmap>,
    default_language: Language,
) -> trc::Result<Option<QueryFilter>> {
    let mut mail_filters = Vec::with_capacity(filters.len());
    for filter in filters {
        mail_filters.push(match filter {
            Filter::Property(EmailQueryFilter::Email(condition)) => {
                MailFilter::Condition(mail_condition(condition)?)
            }
            Filter::Property(EmailQueryFilter::Metadata(_)) => MailFilter::Condition(
                MailCondition::DocumentSet(metadata_matches.next().unwrap_or_default()),
            ),
            Filter::And => MailFilter::And,
            Filter::Or => MailFilter::Or,
            Filter::Not => MailFilter::Not,
            Filter::Close => MailFilter::Close,
        });
    }
    Ok(QueryFilter::parse(
        mail_filters,
        cache,
        access,
        default_language,
    ))
}

pub(super) fn mail_condition(condition: EmailFilter) -> trc::Result<MailCondition> {
    Ok(match condition {
        EmailFilter::InMailbox(id) => MailCondition::InMailbox(id.document_id()),
        EmailFilter::InMailboxOtherThan(ids) => {
            MailCondition::InMailboxOtherThan(ids.iter().map(|id| id.document_id()).collect())
        }
        EmailFilter::InThread(id) => MailCondition::InThread(id.document_id()),
        EmailFilter::Before(date) => MailCondition::ReceivedBefore(date.timestamp()),
        EmailFilter::After(date) => MailCondition::ReceivedAfter(date.timestamp()),
        EmailFilter::SentBefore(date) => MailCondition::SentBefore(date.timestamp()),
        EmailFilter::SentAfter(date) => MailCondition::SentAfter(date.timestamp()),
        EmailFilter::MinSize(size) => MailCondition::MinSize(size),
        EmailFilter::MaxSize(size) => MailCondition::MaxSize(size),
        EmailFilter::HasKeyword(keyword) => MailCondition::HasKeyword(keyword),
        EmailFilter::NotKeyword(keyword) => MailCondition::NotKeyword(keyword),
        EmailFilter::HasAttachment(has_attachment) => MailCondition::HasAttachment(has_attachment),
        EmailFilter::AllInThreadHaveKeyword(keyword) => {
            MailCondition::ThreadKeyword(keyword, ThreadKeywordMatch::All)
        }
        EmailFilter::SomeInThreadHaveKeyword(keyword) => {
            MailCondition::ThreadKeyword(keyword, ThreadKeywordMatch::Some)
        }
        EmailFilter::NoneInThreadHaveKeyword(keyword) => {
            MailCondition::ThreadKeyword(keyword, ThreadKeywordMatch::None)
        }
        EmailFilter::Text(text) => MailCondition::Text(MailTextField::Any, text),
        EmailFilter::From(text) => MailCondition::Text(MailTextField::From, text),
        EmailFilter::To(text) => MailCondition::Text(MailTextField::To, text),
        EmailFilter::Cc(text) => MailCondition::Text(MailTextField::Cc, text),
        EmailFilter::Bcc(text) => MailCondition::Text(MailTextField::Bcc, text),
        EmailFilter::Subject(text) => MailCondition::Text(MailTextField::Subject, text),
        EmailFilter::Body(text) => MailCondition::Text(MailTextField::Body, text),
        EmailFilter::Header(header) => {
            let mut header = header.into_iter();
            let name = header.next().ok_or_else(|| {
                trc::JmapEvent::InvalidArguments
                    .into_err()
                    .details("Header name is missing.")
            })?;
            MailCondition::Header(name, header.next())
        }
        EmailFilter::Id(ids) => {
            MailCondition::DocumentSet(ids.iter().map(|id| id.document_id()).collect())
        }
        other @ EmailFilter::_T(_) => {
            return Err(trc::JmapEvent::UnsupportedFilter
                .into_err()
                .details(other.to_compact_string()));
        }
    })
}
