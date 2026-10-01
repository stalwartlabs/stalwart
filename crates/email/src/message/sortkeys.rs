/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    cache::email::{MessageCacheAccess, thread_keywords},
    message::metadata::{AddressHeader, EnvelopeView, Mailbox, Occurrence},
};
use common::{MessageStoreCache, Server};
use mail_parser::{HeaderName, ParsedValue, thread_name};
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
const SORT_KEY_FIELDS: usize = 3;

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
            .scan_ranges()
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
    fn index(&self) -> usize {
        match self {
            MessageSortField::From => 0,
            MessageSortField::To => 1,
            MessageSortField::Subject => 2,
        }
    }
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
            thread_keywords(cache, &keyword, match_all, Some(documents)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::metadata::{ExtraHeaders, MessageMetadata, MetadataStructure};
    use mail_parser::MessageParser;
    use store::Deserialize;
    use types::blob_hash::BlobHash;

    #[test]
    fn sort_key_normalization() {
        assert_eq!(
            sort_key(["  John\tDOE  ", "jdoe@Example.com"]),
            "JOHN DOE JDOE@EXAMPLE.COM"
        );
        assert_eq!(sort_key(["", "jdoe@example.com"]), "JDOE@EXAMPLE.COM");
        assert_eq!(sort_key(["", ""]), "");
        assert_eq!(
            sort_key([
                "Bartolomeo Cristofori di Francesco",
                "b.cristofori@example.com"
            ]),
            "BARTOLOMEO CRISTOFORI DI FRANCESCO B.CRI"
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
    fn sort_keys_from_message_and_envelope() {
        for (raw, from, to, subject) in [
            (
                concat!(
                    "From: \"Doe, John\" <jdoe@example.com>\r\n",
                    "To: Jane Roe <jroe@example.com>, Other <other@example.com>\r\n",
                    "Subject: Re: Fwd: Hello   World\r\n",
                    "\r\n",
                    "body\r\n"
                ),
                "DOE, JOHN JDOE@EXAMPLE.COM",
                "JANE ROE JROE@EXAMPLE.COM",
                "HELLO WORLD",
            ),
            (
                concat!(
                    "From: jdoe@example.com\r\n",
                    "To: Undisclosed recipients:;\r\n",
                    "\r\n",
                    "body\r\n"
                ),
                "JDOE@EXAMPLE.COM",
                "",
                "",
            ),
            (
                concat!(
                    "From: first@example.com\r\n",
                    "To: Team: Ann <ann@example.com>, bob@example.com;, carl@example.com\r\n",
                    "Subject: first\r\n",
                    "From: Last Sender <last@example.com>\r\n",
                    "Subject: Fwd: second\r\n",
                    "\r\n",
                    "body\r\n"
                ),
                "LAST SENDER LAST@EXAMPLE.COM",
                "ANN ANN@EXAMPLE.COM",
                "SECOND",
            ),
            (
                concat!(
                    "From: _under@example.com\r\n",
                    "Subject: Ad: Re: Ad: Re: Ad: x\r\n",
                    "\r\n",
                    "body\r\n"
                ),
                "_UNDER@EXAMPLE.COM",
                "",
                "X",
            ),
            (
                concat!(
                    "Subject: [list] Re: caf\u{e9} stra\u{df}e\r\n",
                    "\r\n",
                    "body\r\n"
                ),
                "",
                "",
                "CAF\u{c9} STRASSE",
            ),
        ] {
            let message = MessageParser::new()
                .parse(raw.as_bytes())
                .expect("message parses");
            let row =
                MessageMetadata::build(&message, &ExtraHeaders::default(), BlobHash::default())
                    .encode()
                    .expect("row encodes");
            let structure = MetadataStructure::deserialize(&row).expect("structure");
            let meta = structure.unarchive().expect("archive");
            for keys in [
                MessageSortKeys::from_message(&message),
                MessageSortKeys::from_envelope(meta.root().envelope()),
            ] {
                assert_eq!(keys.from, from, "{raw:?}");
                assert_eq!(keys.to, to, "{raw:?}");
                assert_eq!(keys.subject, subject, "{raw:?}");
            }
        }
    }
}
