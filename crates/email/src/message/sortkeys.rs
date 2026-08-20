/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    cache::email::{MessageCacheAccess, thread_keywords},
    message::metadata::{
        MessageMetadata, MetadataAddress, MetadataHeaderName, MetadataHeaderValue,
    },
};
use common::{MessageStoreCache, Server};
use mail_parser::parsers::fields::thread::thread_name;
use store::{
    IterateParams, U32_LEN, ValueKey,
    ahash::AHashMap,
    roaring::RoaringBitmap,
    search::{QueryResults, SearchComparator, SearchQuery},
    write::{ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{collection::Collection, field::EmailField, keyword::Keyword};

pub const MAX_SORT_KEY_LEN: usize = 40;
const SORT_KEY_FIELDS: usize = 3;
const MAX_SCAN_RANGES: usize = 1024;
const MAX_SCAN_GAP: u32 = 64;

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

        let mut sort_key_fields = Vec::with_capacity(SORT_KEY_FIELDS);
        for comparator in &comparators {
            if let MessageComparator::SortKey { field, .. } = comparator
                && !sort_key_fields.contains(field)
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
        let ranges = scan_ranges(documents)
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
                    if let Some(sort_key) = MessageSortKeys::deserialize_field(value, *field)
                        && !sort_key.is_empty()
                    {
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
    fn index(&self) -> usize {
        match self {
            MessageSortField::From => 0,
            MessageSortField::To => 1,
            MessageSortField::Subject => 2,
        }
    }
}

fn scan_ranges(documents: &RoaringBitmap) -> Vec<(u32, u32)> {
    let (Some(min), Some(max)) = (documents.min(), documents.max()) else {
        return Vec::new();
    };
    let full_range = vec![(min, max)];
    if documents.len() * MAX_SCAN_GAP as u64 >= (max - min) as u64 {
        return full_range;
    }

    let mut ranges = Vec::new();
    let mut range = (min, min);
    for document_id in documents.iter().skip(1) {
        if document_id - range.1 <= MAX_SCAN_GAP {
            range.1 = document_id;
        } else {
            if ranges.len() + 1 >= MAX_SCAN_RANGES {
                return full_range;
            }
            ranges.push(range);
            range = (document_id, document_id);
        }
    }
    ranges.push(range);

    ranges
}

fn cache_comparator(
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
                        .emails
                        .index
                        .get(&document_id)
                        .map(|position| (document_id, *position + 1))
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
                        .map(|item| (document_id, item.size))
                })
                .collect(),
            ascending,
        ),
        MessageCacheField::SentAt => {
            let mut sorted = documents
                .iter()
                .filter_map(|document_id| {
                    cache
                        .email_by_id(&document_id)
                        .map(|item| (item.received_at as i64 + item.sent_at as i64, document_id))
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
            thread_keywords(cache, &keyword, match_all, Some(documents)),
            ascending,
        ),
    }
}

impl MessageSortKeys {
    pub fn from_metadata(metadata: &MessageMetadata) -> Self {
        let mut keys = MessageSortKeys::default();
        let Some(part) = metadata
            .contents
            .first()
            .and_then(|part| part.parts.first())
        else {
            return keys;
        };

        let (mut has_from, mut has_to, mut has_subject) = (false, false, false);
        for header in part.headers.iter().rev() {
            match &header.name {
                MetadataHeaderName::From if !has_from => {
                    keys.from = address_sort_key(&header.value);
                    has_from = true;
                }
                MetadataHeaderName::To if !has_to => {
                    keys.to = address_sort_key(&header.value);
                    has_to = true;
                }
                MetadataHeaderName::Subject if !has_subject => {
                    keys.subject = match &header.value {
                        MetadataHeaderValue::Text(text) => sort_key([thread_name(text)]),
                        MetadataHeaderValue::TextList(texts) => texts
                            .first()
                            .map(|text| sort_key([thread_name(text)]))
                            .unwrap_or_default(),
                        _ => String::new(),
                    };
                    has_subject = true;
                }
                _ => (),
            }

            if has_from && has_to && has_subject {
                break;
            }
        }

        keys
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

fn address_sort_key(value: &MetadataHeaderValue) -> String {
    let address = match value {
        MetadataHeaderValue::AddressList(addresses) => addresses.first(),
        MetadataHeaderValue::AddressGroup(groups) => {
            groups.iter().find_map(|group| group.addresses.first())
        }
        _ => None,
    };

    match address {
        Some(MetadataAddress { name, address }) => sort_key([
            name.as_deref().unwrap_or_default(),
            address.as_deref().unwrap_or_default(),
        ]),
        None => String::new(),
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

            for ch in ch.to_lowercase() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::metadata::build_metadata_contents;
    use mail_parser::MessageParser;
    use types::blob_hash::BlobHash;

    fn sort_keys_of(raw_message: &str) -> MessageSortKeys {
        let message = MessageParser::new().parse(raw_message.as_bytes()).unwrap();
        MessageSortKeys::from_metadata(&MessageMetadata {
            contents: build_metadata_contents(message),
            blob_hash: BlobHash::default(),
            blob_body_offset: 0,
            preview: Default::default(),
            raw_headers: Default::default(),
        })
    }

    #[test]
    fn sort_key_normalization() {
        assert_eq!(
            sort_key(["  John\tDOE  ", "jdoe@Example.com"]),
            "john doe jdoe@example.com"
        );
        assert_eq!(sort_key(["", "jdoe@example.com"]), "jdoe@example.com");
        assert_eq!(sort_key(["", ""]), "");
        assert_eq!(
            sort_key([
                "Bartolomeo Cristofori di Francesco",
                "b.cristofori@example.com"
            ]),
            "bartolomeo cristofori di francesco b.cri"
        );
    }

    #[test]
    fn sort_key_scan_ranges() {
        assert_eq!(scan_ranges(&RoaringBitmap::new()), vec![]);
        assert_eq!(
            scan_ranges(&RoaringBitmap::from_iter(0..100u32)),
            vec![(0, 99)]
        );
        assert_eq!(
            scan_ranges(&RoaringBitmap::from_iter([5u32, 60])),
            vec![(5, 60)]
        );
        assert_eq!(
            scan_ranges(&RoaringBitmap::from_iter([5u32, 900_000])),
            vec![(5, 5), (900_000, 900_000)]
        );
        assert_eq!(
            scan_ranges(&RoaringBitmap::from_iter([
                5u32, 6, 7, 5_000, 5_001, 90_000
            ])),
            vec![(5, 7), (5_000, 5_001), (90_000, 90_000)]
        );
        assert_eq!(
            scan_ranges(&RoaringBitmap::from_iter(
                (0..MAX_SCAN_RANGES as u32).map(|id| id * 1_000)
            ))
            .len(),
            MAX_SCAN_RANGES
        );
        assert_eq!(
            scan_ranges(&RoaringBitmap::from_iter(
                (0..=MAX_SCAN_RANGES as u32).map(|id| id * 1_000)
            )),
            vec![(0, MAX_SCAN_RANGES as u32 * 1_000)]
        );
    }

    #[test]
    fn sort_key_serialization() {
        for keys in [
            MessageSortKeys {
                from: "john doe jdoe@example.com".into(),
                to: "jane roe jroe@example.com".into(),
                subject: "hello world".into(),
            },
            MessageSortKeys::default(),
        ] {
            let bytes = keys.serialize();
            for (field, expected) in [
                (MessageSortField::From, &keys.from),
                (MessageSortField::To, &keys.to),
                (MessageSortField::Subject, &keys.subject),
            ] {
                assert_eq!(
                    MessageSortKeys::deserialize_field(&bytes, field),
                    Some(expected.as_str())
                );
            }
        }

        assert_eq!(
            MessageSortKeys::deserialize_field(&[], MessageSortField::From),
            None
        );
    }

    #[test]
    fn sort_keys_from_metadata() {
        let keys = sort_keys_of(concat!(
            "From: \"Doe, John\" <jdoe@example.com>\r\n",
            "To: Jane Roe <jroe@example.com>, Other <other@example.com>\r\n",
            "Subject: Re: Fwd: Hello   World\r\n",
            "\r\n",
            "body\r\n"
        ));
        assert_eq!(keys.from, "doe, john jdoe@example.com");
        assert_eq!(keys.to, "jane roe jroe@example.com");
        assert_eq!(keys.subject, "hello world");

        let keys = sort_keys_of(concat!(
            "From: jdoe@example.com\r\n",
            "To: Undisclosed recipients:;\r\n",
            "\r\n",
            "body\r\n"
        ));
        assert_eq!(keys.from, "jdoe@example.com");
        assert_eq!(keys.to, "");
        assert_eq!(keys.subject, "");
    }
}
