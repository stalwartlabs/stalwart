/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    cache::email::{MessageCacheAccess, thread_keywords},
    message::metadata::{AddressHeader, EnvelopeView, Mailbox, Occurrence},
};
use common::{MessageStoreCache, Server, cache::email::MessageRef};
use mail_parser::{HeaderName, ParsedValue, thread_name};
use std::collections::BinaryHeap;
use store::{
    IterateParams, U32_LEN, ValueKey,
    ahash::AHashMap,
    dispatch::DocumentSet,
    roaring::RoaringBitmap,
    search::{QueryResults, SearchComparator, SearchQuery},
    write::{ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{collection::Collection, field::EmailField, keyword::Keyword};

pub const MAX_SORT_KEY_LEN: usize = 40;
pub const MAX_CACHE_SORT_KEYS: usize = 4;
const SORT_KEY_FIELDS: usize = 3;
const SIGN_BIT: u64 = 1 << 63;

pub type SortKey = [u8; MAX_SORT_KEY_LEN];

#[derive(Debug, Clone, Default)]
pub struct MessageSortKeys {
    pub from: String,
    pub to: String,
    pub subject: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSortField {
    From,
    To,
    Subject,
}

pub enum MessageCacheField {
    ReceivedAt,
    SentAt,
    Size,
    Keyword(Keyword),
    ThreadKeyword { keyword: Keyword, match_all: bool },
}

pub enum MessageComparator {
    Search(SearchComparator),
    SortKey {
        field: MessageSortField,
        ascending: bool,
    },
    Cache {
        field: MessageCacheField,
        ascending: bool,
    },
}

pub trait EmailSortKeys: Sync + Send {
    fn query_emails(
        &self,
        account_id: u32,
        cache: &MessageStoreCache,
        query: SearchQuery,
        comparators: Vec<MessageComparator>,
    ) -> impl Future<Output = trc::Result<Vec<u32>>> + Send;

    fn message_sort_ranks(
        &self,
        account_id: u32,
        documents: &RoaringBitmap,
        fields: &[MessageSortField],
    ) -> impl Future<Output = trc::Result<[Option<AHashMap<u32, u32>>; SORT_KEY_FIELDS]>> + Send;
}

impl EmailSortKeys for Server {
    async fn query_emails(
        &self,
        account_id: u32,
        cache: &MessageStoreCache,
        query: SearchQuery,
        comparators: Vec<MessageComparator>,
    ) -> trc::Result<Vec<u32>> {
        let results = self
            .search_store()
            .filter_account(query)
            .await
            .caused_by(trc::location!())?;

        if results.len() < 2 || comparators.is_empty() {
            return Ok(results.into_iter().collect());
        }

        let mut sort_key_fields: Vec<MessageSortField> = Vec::with_capacity(SORT_KEY_FIELDS);
        for comparator in &comparators {
            if let MessageComparator::SortKey { field, .. } = comparator
                && !sort_key_fields.as_slice().contains(field)
            {
                sort_key_fields.push(*field);
            }
        }
        let mut sort_key_ranks = if !sort_key_fields.is_empty() {
            self.message_sort_ranks(account_id, &results, &sort_key_fields)
                .await
                .caused_by(trc::location!())?
        } else {
            Default::default()
        };

        let mut sorted_comparators = Vec::with_capacity(comparators.len());
        for comparator in comparators {
            sorted_comparators.push(match comparator {
                MessageComparator::Search(comparator) => comparator,
                MessageComparator::SortKey { field, ascending } => SearchComparator::sorted_set(
                    sort_key_ranks[field.index()].take().unwrap_or_default(),
                    ascending,
                ),
                MessageComparator::Cache { field, ascending } => {
                    cache_comparator(cache, &results, field, ascending)
                }
            });
        }

        Ok(QueryResults::new(results, sorted_comparators).into_sorted())
    }

    async fn message_sort_ranks(
        &self,
        account_id: u32,
        documents: &RoaringBitmap,
        fields: &[MessageSortField],
    ) -> trc::Result<[Option<AHashMap<u32, u32>>; SORT_KEY_FIELDS]> {
        let collection: u8 = Collection::Email.into();
        let class = ValueClass::Immutable(EmailField::SortKeys.into());
        let mut sort_keys: [Vec<(SortKey, u32)>; SORT_KEY_FIELDS] = Default::default();
        let ranges = documents
            .scan_ranges(self.core.storage.data.scan_gap())
            .into_iter()
            .map(|(from_document_id, to_document_id)| {
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection,
                        document_id: from_document_id,
                        class: class.clone(),
                    },
                    ValueKey {
                        account_id,
                        collection,
                        document_id: to_document_id,
                        class: class.clone(),
                    },
                )
            })
            .collect::<Vec<_>>();

        let mut collect = |key: &[u8], value: &[u8]| {
            let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
            if documents.contains(document_id) {
                for field in fields {
                    if let Some(sort_key) = MessageSortKeys::deserialize_field(value, *field) {
                        let sort_key = &sort_key.as_bytes()[..sort_key.len().min(MAX_SORT_KEY_LEN)];
                        let mut padded_sort_key: SortKey = [0u8; MAX_SORT_KEY_LEN];
                        padded_sort_key[..sort_key.len()].copy_from_slice(sort_key);
                        sort_keys[field.index()].push((padded_sort_key, document_id));
                    }
                }
            }
            Ok(true)
        };

        match ranges.len() {
            0 => Ok(()),
            1 => {
                self.core
                    .storage
                    .data
                    .iterate(ranges.into_iter().next().unwrap(), &mut collect)
                    .await
            }
            _ => {
                self.core
                    .storage
                    .data
                    .iterate_many(ranges, &mut collect)
                    .await
            }
        }
        .add_context(|err| {
            err.caused_by(trc::location!())
                .account_id(account_id)
                .collection(collection)
        })?;

        let mut ranks: [Option<AHashMap<u32, u32>>; SORT_KEY_FIELDS] = Default::default();
        for field in fields {
            let sort_keys = &mut sort_keys[field.index()];
            sort_keys.sort_unstable_by_key(|(sort_key, _)| *sort_key);

            let mut field_ranks = AHashMap::with_capacity(sort_keys.len());
            let mut rank = 1u32;
            let mut prev_sort_key: Option<&SortKey> = None;
            for (sort_key, document_id) in sort_keys.iter() {
                if prev_sort_key.is_some_and(|prev| prev != sort_key) {
                    rank += 1;
                }
                field_ranks.insert(*document_id, rank);
                prev_sort_key = Some(sort_key);
            }
            ranks[field.index()] = Some(field_ranks);
        }

        Ok(ranks)
    }
}

impl MessageSortField {
    #[inline(always)]
    pub fn index(&self) -> usize {
        match self {
            MessageSortField::From => 0,
            MessageSortField::To => 1,
            MessageSortField::Subject => 2,
        }
    }
}

pub struct CacheSorter {
    keys: Vec<CacheSortKey>,
}

struct CacheSortKey {
    field: CacheSortField,
    ascending: bool,
}

enum CacheSortField {
    ReceivedAt,
    SentAt,
    Size,
    Keyword(Keyword),
    DocumentSet(RoaringBitmap),
}

pub struct TopMessages(std::vec::IntoIter<RankedMessage>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RankedMessage {
    key: [u64; MAX_CACHE_SORT_KEYS],
    document_id: u32,
    thread_id: u32,
}

impl CacheSorter {
    pub fn supports(comparators: &[MessageComparator]) -> bool {
        comparators.len() <= MAX_CACHE_SORT_KEYS
            && comparators.iter().all(|comparator| {
                matches!(
                    comparator,
                    MessageComparator::Cache { .. }
                        | MessageComparator::Search(SearchComparator::DocumentSet { .. })
                )
            })
    }

    pub fn new(
        cache: &MessageStoreCache,
        comparators: Vec<MessageComparator>,
    ) -> Result<Self, Vec<MessageComparator>> {
        if !CacheSorter::supports(&comparators) {
            return Err(comparators);
        }
        let keys = comparators
            .into_iter()
            .filter_map(|comparator| match comparator {
                MessageComparator::Cache { field, ascending } => Some(CacheSortKey {
                    field: match field {
                        MessageCacheField::ReceivedAt => CacheSortField::ReceivedAt,
                        MessageCacheField::SentAt => CacheSortField::SentAt,
                        MessageCacheField::Size => CacheSortField::Size,
                        MessageCacheField::Keyword(keyword) => CacheSortField::Keyword(keyword),
                        MessageCacheField::ThreadKeyword { keyword, match_all } => {
                            CacheSortField::DocumentSet(thread_keywords(
                                cache, &keyword, match_all, None, None,
                            ))
                        }
                    },
                    ascending,
                }),
                MessageComparator::Search(SearchComparator::DocumentSet { set, ascending }) => {
                    Some(CacheSortKey {
                        field: CacheSortField::DocumentSet(set),
                        ascending,
                    })
                }
                MessageComparator::Search(SearchComparator::SortedSet { .. })
                | MessageComparator::SortKey { .. } => None,
            })
            .collect();
        Ok(CacheSorter { keys })
    }

    pub fn top<'x>(
        &self,
        cache: &MessageStoreCache,
        messages: impl Iterator<Item = MessageRef<'x>>,
        count: usize,
    ) -> (TopMessages, usize) {
        let mut heap = BinaryHeap::with_capacity(count.min(cache.emails.len()));
        let mut total = 0;
        for message in messages {
            total += 1;
            if count == 0 {
                continue;
            }
            let ranked = self.rank(cache, message);
            if heap.len() < count {
                heap.push(ranked);
            } else if let Some(mut last) = heap.peek_mut()
                && ranked < *last
            {
                *last = ranked;
            }
        }
        (TopMessages(heap.into_sorted_vec().into_iter()), total)
    }

    fn rank(&self, cache: &MessageStoreCache, message: MessageRef<'_>) -> RankedMessage {
        let mut key = [0u64; MAX_CACHE_SORT_KEYS];
        for (slot, sort_key) in key.iter_mut().zip(&self.keys) {
            let value = match &sort_key.field {
                CacheSortField::ReceivedAt => message.received_at(),
                CacheSortField::SentAt => (message.sent_at_absolute() as u64) ^ SIGN_BIT,
                CacheSortField::Size => u64::from(message.size()),
                CacheSortField::Keyword(keyword) => u64::from(cache.has_keyword(message, keyword)),
                CacheSortField::DocumentSet(documents) => {
                    u64::from(documents.contains(message.document_id()))
                }
            };
            *slot = if sort_key.ascending { value } else { !value };
        }
        RankedMessage {
            key,
            document_id: message.document_id(),
            thread_id: message.thread_id(),
        }
    }
}

impl Iterator for TopMessages {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|ranked| (ranked.document_id, ranked.thread_id))
    }
}

pub fn cache_comparator(
    cache: &MessageStoreCache,
    documents: &RoaringBitmap,
    field: MessageCacheField,
    ascending: bool,
) -> SearchComparator {
    match field {
        MessageCacheField::ReceivedAt => SearchComparator::sorted_set(
            documents
                .iter()
                .filter_map(|document_id| {
                    cache
                        .email_by_id(&document_id)
                        .map(|item| (document_id, item.received_at() as u32))
                })
                .collect(),
            ascending,
        ),
        MessageCacheField::Size => SearchComparator::sorted_set(
            documents
                .iter()
                .filter_map(|document_id| {
                    cache
                        .email_by_id(&document_id)
                        .map(|item| (document_id, item.size()))
                })
                .collect(),
            ascending,
        ),
        MessageCacheField::SentAt => {
            let mut sorted = documents
                .iter()
                .filter_map(|document_id| {
                    cache.email_by_id(&document_id).map(|item| {
                        (
                            item.received_at() as i64 + item.sent_at() as i64,
                            document_id,
                        )
                    })
                })
                .collect::<Vec<_>>();
            sorted.sort_unstable_by_key(|(sent_at, _)| *sent_at);

            let mut set = AHashMap::with_capacity(sorted.len());
            let mut rank = 1u32;
            let mut prev_sent_at = None;
            for (sent_at, document_id) in sorted {
                if prev_sent_at.is_some_and(|prev| prev != sent_at) {
                    rank += 1;
                }
                set.insert(document_id, rank);
                prev_sent_at = Some(sent_at);
            }

            SearchComparator::sorted_set(set, ascending)
        }
        MessageCacheField::Keyword(keyword) => SearchComparator::set(
            documents
                .iter()
                .filter(|document_id| {
                    cache
                        .email_by_id(document_id)
                        .is_some_and(|item| cache.has_keyword(item, &keyword))
                })
                .collect(),
            ascending,
        ),
        MessageCacheField::ThreadKeyword { keyword, match_all } => SearchComparator::set(
            thread_keywords(cache, &keyword, match_all, Some(documents), None),
            ascending,
        ),
    }
}

impl MessageSortKeys {
    pub fn new(from: Option<Mailbox<'_>>, to: Option<Mailbox<'_>>, subject: Option<&str>) -> Self {
        MessageSortKeys {
            from: from.map(Mailbox::sort_key).unwrap_or_default(),
            to: to.map(Mailbox::sort_key).unwrap_or_default(),
            subject: subject
                .map(|subject| sort_key([thread_name(subject)]))
                .unwrap_or_default(),
        }
    }

    pub fn from_message(message: &mail_parser::Message<'_>) -> Self {
        let headers = message.root().headers();
        let first_mailbox = |name: HeaderName<'static>| {
            headers
                .get(name)
                .and_then(|header| header.value().as_address())
                .and_then(|list| list.mailboxes().next())
                .map(|mailbox| Mailbox {
                    name: mailbox.name(),
                    address: mailbox.address(),
                })
        };
        MessageSortKeys::new(
            first_mailbox(HeaderName::From),
            first_mailbox(HeaderName::To),
            headers.subject(),
        )
    }

    pub fn from_envelope(envelope: EnvelopeView<'_>) -> Self {
        MessageSortKeys::new(
            envelope
                .addresses(AddressHeader::From, Occurrence::Last)
                .first(),
            envelope
                .addresses(AddressHeader::To, Occurrence::Last)
                .first(),
            envelope.subject(),
        )
    }

    pub fn serialize(&self) -> Vec<u8> {
        let sort_keys = [&self.from, &self.to, &self.subject];
        let mut out = Vec::with_capacity(
            SORT_KEY_FIELDS + self.from.len() + self.to.len() + self.subject.len(),
        );
        for sort_key in sort_keys {
            debug_assert!(sort_key.len() <= MAX_SORT_KEY_LEN);
            out.push(sort_key.len() as u8);
        }
        for sort_key in sort_keys {
            out.extend_from_slice(sort_key.as_bytes());
        }
        out
    }

    pub fn deserialize_field(bytes: &[u8], field: MessageSortField) -> Option<&str> {
        let offset = SORT_KEY_FIELDS
            + bytes
                .get(..field.index())?
                .iter()
                .map(|len| *len as usize)
                .sum::<usize>();

        std::str::from_utf8(bytes.get(offset..offset + *bytes.get(field.index())? as usize)?).ok()
    }
}

impl<'x> Mailbox<'x> {
    pub fn first_of(parsed: &'x ParsedValue<'_>) -> Option<Self> {
        parsed
            .value()
            .as_address()?
            .mailboxes()
            .next()
            .map(|mailbox| Mailbox {
                name: mailbox.name(),
                address: mailbox.address(),
            })
    }

    fn sort_key(self) -> String {
        sort_key([
            self.name.unwrap_or_default(),
            self.address.unwrap_or_default(),
        ])
    }
}

fn sort_key<const N: usize>(values: [&str; N]) -> String {
    let mut sort_key = String::with_capacity(MAX_SORT_KEY_LEN);
    let mut pending_space = false;

    for value in values {
        for ch in value.chars() {
            if ch.is_whitespace() {
                pending_space = !sort_key.is_empty();
                continue;
            } else if pending_space {
                if sort_key.len() + 1 > MAX_SORT_KEY_LEN {
                    return sort_key;
                }
                sort_key.push(' ');
                pending_space = false;
            }

            for ch in ch.to_uppercase() {
                if sort_key.len() + ch.len_utf8() > MAX_SORT_KEY_LEN {
                    return sort_key;
                }
                sort_key.push(ch);
            }
        }
        pending_space = !sort_key.is_empty();
    }

    sort_key
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/email/src/message/sortkeys/tests.rs"]
mod tests;
