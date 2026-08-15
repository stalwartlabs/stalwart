/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::metadata::{
    MessageMetadata, MetadataAddress, MetadataHeaderName, MetadataHeaderValue,
};
use common::Server;
use mail_parser::parsers::fields::thread::thread_name;
use store::{
    IterateParams, U32_LEN, ValueKey,
    ahash::AHashMap,
    dispatch::DocumentSet,
    roaring::RoaringBitmap,
    search::{QueryResults, SearchComparator, SearchQuery},
    write::{ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{collection::Collection, field::EmailField};
use utils::codec::leb128::Leb128_;

pub const MAX_SORT_KEY_LEN: usize = 40;

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

pub enum MessageComparator {
    Search(SearchComparator),
    SortKey {
        field: MessageSortField,
        ascending: bool,
    },
}

pub trait EmailSortKeys: Sync + Send {
    fn query_emails(
        &self,
        account_id: u32,
        query: SearchQuery,
        comparators: Vec<MessageComparator>,
    ) -> impl Future<Output = trc::Result<Vec<u32>>> + Send;

    fn message_sort_ranks<I>(
        &self,
        account_id: u32,
        documents: &I,
        field: MessageSortField,
    ) -> impl Future<Output = trc::Result<AHashMap<u32, u32>>> + Send
    where
        I: DocumentSet + Send + Sync;
}

impl EmailSortKeys for Server {
    async fn query_emails(
        &self,
        account_id: u32,
        query: SearchQuery,
        comparators: Vec<MessageComparator>,
    ) -> trc::Result<Vec<u32>> {
        if !comparators
            .iter()
            .any(|comparator| matches!(comparator, MessageComparator::SortKey { .. }))
        {
            return self
                .search_store()
                .query_account(
                    query.with_comparators(
                        comparators
                            .into_iter()
                            .filter_map(|comparator| match comparator {
                                MessageComparator::Search(comparator) => Some(comparator),
                                MessageComparator::SortKey { .. } => None,
                            })
                            .collect(),
                    ),
                )
                .await
                .caused_by(trc::location!());
        }

        let results = self
            .search_store()
            .query_account(query)
            .await
            .caused_by(trc::location!())?;
        if results.len() < 2 {
            return Ok(results);
        }

        let mut sorted_comparators = Vec::with_capacity(comparators.len());
        for comparator in comparators {
            sorted_comparators.push(match comparator {
                MessageComparator::Search(comparator) => comparator,
                MessageComparator::SortKey { field, ascending } => SearchComparator::sorted_set(
                    self.message_sort_ranks(account_id, &results, field)
                        .await
                        .caused_by(trc::location!())?,
                    ascending,
                ),
            });
        }

        Ok(QueryResults::new(RoaringBitmap::from_iter(&results), sorted_comparators).into_sorted())
    }

    async fn message_sort_ranks<I>(
        &self,
        account_id: u32,
        documents: &I,
        field: MessageSortField,
    ) -> trc::Result<AHashMap<u32, u32>>
    where
        I: DocumentSet + Send + Sync,
    {
        let collection: u8 = Collection::Email.into();
        let class = ValueClass::Property(EmailField::SortKeys.into());
        let mut sort_keys: Vec<(SortKey, u32)> = Vec::with_capacity(documents.len());

        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection,
                        document_id: documents.min(),
                        class: class.clone(),
                    },
                    ValueKey {
                        account_id,
                        collection,
                        document_id: documents.max(),
                        class,
                    },
                ),
                |key, value| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    if documents.contains(document_id)
                        && let Some(sort_key) = MessageSortKeys::deserialize_field(value, field)
                        && !sort_key.is_empty()
                    {
                        let sort_key = &sort_key.as_bytes()[..sort_key.len().min(MAX_SORT_KEY_LEN)];
                        let mut padded_sort_key: SortKey = [0u8; MAX_SORT_KEY_LEN];
                        padded_sort_key[..sort_key.len()].copy_from_slice(sort_key);
                        sort_keys.push((padded_sort_key, document_id));
                    }
                    Ok(true)
                },
            )
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })?;

        sort_keys.sort_unstable_by_key(|(sort_key, _)| *sort_key);

        let mut ranks = AHashMap::with_capacity(sort_keys.len());
        let mut rank = 0u32;
        let mut prev_sort_key: Option<&SortKey> = None;
        for (sort_key, document_id) in &sort_keys {
            if prev_sort_key.is_some_and(|prev| prev != sort_key) {
                rank += 1;
            }
            ranks.insert(*document_id, rank);
            prev_sort_key = Some(sort_key);
        }

        Ok(ranks)
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
        let mut out = Vec::with_capacity(self.from.len() + self.to.len() + self.subject.len() + 3);
        for sort_key in [&self.from, &self.to, &self.subject] {
            sort_key.len().to_leb128_bytes(&mut out);
            out.extend_from_slice(sort_key.as_bytes());
        }
        out
    }

    pub fn deserialize_field(bytes: &[u8], field: MessageSortField) -> Option<&str> {
        let position = match field {
            MessageSortField::From => 0,
            MessageSortField::To => 1,
            MessageSortField::Subject => 2,
        };
        let mut offset = 0;

        for index in 0..=position {
            let (len, bytes_read) = usize::from_leb128_bytes_pos(bytes.get(offset..)?)?;
            offset += bytes_read;
            let sort_key = bytes.get(offset..offset + len)?;
            if index == position {
                return std::str::from_utf8(sort_key).ok();
            }
            offset += len;
        }

        None
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
