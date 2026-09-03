/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::messagedata::{EmailMessageData, KeywordsIter, MessageData};
use common::{
    CustomKeywords, MessageCache, MessageStoreCache, MessagesCache, Server, auth::AccessToken,
    cache::email::MessageRef, sharing::EffectiveAcl,
};
use compact_str::CompactString;
use std::sync::Arc;
use store::{
    ahash::{AHashMap, AHashSet},
    roaring::RoaringBitmap,
};
use trc::AddContext;
use types::{acl::Acl, keyword::Keyword};
use utils::map::bitmap::Bitmap;

pub(crate) const HAS_CUSTOM_KEYWORDS: u32 = 1 << 31;

struct MessagesCacheBuilder {
    pub change_id: u64,
    pub items: Vec<MessageCache>,
    pub keywords: Vec<CustomKeywords>,
}

pub(crate) async fn update_email_cache(
    server: &Server,
    account_id: u32,
    changed_ids: &AHashMap<u32, bool>,
    store_cache: &MessageStoreCache,
) -> trc::Result<MessagesCache> {
    let mut fetch_ids = changed_ids
        .iter()
        .filter(|(_, is_update)| **is_update)
        .map(|(document_id, _)| *document_id)
        .collect::<Vec<_>>();
    fetch_ids.sort_unstable();

    let mut fetched: AHashMap<u32, MessageCache> = AHashMap::with_capacity(fetch_ids.len());
    let mut fetched_keywords: Vec<CustomKeywords> = Vec::new();

    if !fetch_ids.is_empty() {
        server
            .message_datas(account_id, &fetch_ids, |document_id, mut data| {
                if !data.keywords_extra.is_empty() {
                    fetched_keywords.push(CustomKeywords {
                        names: std::mem::take(&mut data.keywords_extra).into_boxed_slice(),
                        document_id,
                    });
                    data.keywords |= HAS_CUSTOM_KEYWORDS;
                }

                fetched.insert(
                    document_id,
                    MessageCache::new(
                        document_id,
                        data.mailboxes,
                        data.keywords,
                        data.thread_id,
                        data.change_id,
                        data.size,
                        data.received_at,
                        data.sent_at,
                    ),
                );
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
        fetched_keywords.sort_unstable_by_key(|k| k.document_id);
    }

    Ok(merge_email_cache(
        &store_cache.emails,
        changed_ids,
        &fetch_ids,
        fetched,
        fetched_keywords,
    ))
}

fn merge_email_cache(
    cache: &MessagesCache,
    changed_ids: &AHashMap<u32, bool>,
    fetch_ids: &[u32],
    mut fetched: AHashMap<u32, MessageCache>,
    fetched_keywords: Vec<CustomKeywords>,
) -> MessagesCache {
    let mut inserts = Vec::new();
    let mut deletes = changed_ids
        .iter()
        .filter(|(_, is_update)| !**is_update)
        .map(|(document_id, _)| *document_id)
        .collect::<Vec<_>>();
    for document_id in fetch_ids {
        if !cache.contains(*document_id) {
            if let Some(item) = fetched.remove(document_id) {
                inserts.push(item);
            }
        } else if !fetched.contains_key(document_id) {
            deletes.push(*document_id);
        }
    }
    inserts.sort_unstable_by_key(sort_rank);
    deletes.sort_unstable();

    let keywords = merge_custom_keywords(cache, changed_ids, fetched_keywords);

    let mut patches = Vec::with_capacity(fetched.len());
    for (document_id, record) in fetched {
        if let Some(position) = cache.position(document_id) {
            patches.push((position, record));
        }
    }

    if inserts.is_empty() && deletes.is_empty() {
        cache.patch(0, &patches, keywords)
    } else {
        cache.splice(0, &deletes, &patches, &inserts, keywords)
    }
}

fn merge_custom_keywords(
    cache: &MessagesCache,
    changed_ids: &AHashMap<u32, bool>,
    fetched_keywords: Vec<CustomKeywords>,
) -> Arc<[CustomKeywords]> {
    if fetched_keywords.is_empty()
        && !changed_ids.keys().any(|document_id| {
            cache
                .keywords()
                .binary_search_by_key(document_id, |entry| entry.document_id)
                .is_ok()
        })
    {
        return cache.shared_keywords();
    }

    let mut retained = cache
        .keywords()
        .iter()
        .filter(|k| !changed_ids.contains_key(&k.document_id))
        .peekable();
    let mut keywords = Vec::with_capacity(cache.keywords().len() + fetched_keywords.len());
    let mut added = fetched_keywords.into_iter().peekable();
    loop {
        match (retained.peek(), added.peek()) {
            (Some(old), Some(new)) => {
                if old.document_id <= new.document_id {
                    keywords.push(retained.next().unwrap().clone());
                } else {
                    keywords.push(added.next().unwrap());
                }
            }
            (Some(_), None) => keywords.push(retained.next().unwrap().clone()),
            (None, Some(_)) => keywords.push(added.next().unwrap()),
            (None, None) => break,
        }
    }
    keywords.into()
}

#[inline(always)]
fn sort_rank(item: &MessageCache) -> (u64, u32) {
    (item.received_at(), item.document_id())
}

pub(crate) async fn full_email_cache_build(
    server: &Server,
    account_id: u32,
) -> trc::Result<MessagesCache> {
    // Build cache
    let mut cache = MessagesCacheBuilder {
        items: Vec::with_capacity(16),
        keywords: Default::default(),
        change_id: 0,
    };

    server
        .message_datas(account_id, &(), |document_id, mut data| {
            if !data.keywords_extra.is_empty() {
                cache.keywords.push(CustomKeywords {
                    names: data.keywords_extra.into_boxed_slice(),
                    document_id,
                });
                data.keywords |= HAS_CUSTOM_KEYWORDS;
            }

            cache.items.push(MessageCache::new(
                document_id,
                data.mailboxes,
                data.keywords,
                data.thread_id,
                data.change_id,
                data.size,
                data.received_at,
                data.sent_at,
            ));
            Ok(true)
        })
        .await
        .caused_by(trc::location!())?;

    Ok(cache.build())
}

impl MessagesCacheBuilder {
    pub fn build(mut self) -> MessagesCache {
        self.items.sort_unstable_by_key(sort_rank);
        self.keywords.sort_unstable_by_key(|k| k.document_id);
        MessagesCache::new(self.change_id, self.items, self.keywords)
    }
}

pub fn thread_keywords(
    cache: &MessageStoreCache,
    keyword: &Keyword,
    match_all: bool,
    documents: Option<&RoaringBitmap>,
) -> RoaringBitmap {
    let threads = documents.map(|documents| {
        documents
            .iter()
            .filter_map(|document_id| cache.email_by_id(&document_id).map(|item| item.thread_id()))
            .collect::<AHashSet<_>>()
    });
    let mut thread_keywords: AHashMap<u32, (bool, bool)> = AHashMap::new();
    for item in cache.emails.iter() {
        if threads
            .as_ref()
            .is_none_or(|threads| threads.contains(&item.thread_id()))
        {
            let has_keyword = cache.has_keyword(item, keyword);
            let entry = thread_keywords
                .entry(item.thread_id())
                .or_insert((false, true));
            entry.0 |= has_keyword;
            entry.1 &= has_keyword;
        }
    }

    let matches = |document_id: &u32| {
        cache.email_by_id(document_id).is_some_and(|item| {
            thread_keywords
                .get(&item.thread_id())
                .is_some_and(|(has_any, has_all)| if match_all { *has_all } else { *has_any })
        })
    };

    match documents {
        Some(documents) => documents.iter().filter(matches).collect(),
        None => cache
            .emails
            .iter()
            .map(|item| item.document_id())
            .filter(matches)
            .collect(),
    }
}

pub enum SearchOperator {
    LowerThan,
    LowerEqualThan,
    GreaterThan,
    GreaterEqualThan,
    Equal,
    Contains,
}

pub trait MessageCacheAccess {
    fn email_by_id(&self, id: &u32) -> Option<MessageRef<'_>>;

    fn has_email_id(&self, id: &u32) -> bool;

    fn custom_keywords(&self, message: MessageRef<'_>) -> &[CompactString];

    fn message_data(&self, document_id: u32) -> Option<MessageData>;

    fn in_mailbox(&self, mailbox_id: u32) -> impl Iterator<Item = MessageRef<'_>>;

    fn in_mailboxes(&self, mailbox_ids: &[u32]) -> impl Iterator<Item = MessageRef<'_>>;

    fn in_thread(&self, thread_id: u32) -> impl Iterator<Item = MessageRef<'_>>;

    fn with_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = MessageRef<'_>>;

    fn without_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = MessageRef<'_>>;

    fn in_mailbox_with_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = MessageRef<'_>>;

    fn in_mailbox_without_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = MessageRef<'_>>;

    fn email_document_ids(&self) -> RoaringBitmap;

    fn shared_messages(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap;

    fn expand_keywords(&self, message: MessageRef<'_>) -> impl Iterator<Item = Keyword>;

    fn has_keyword(&self, message: MessageRef<'_>, keyword: &Keyword) -> bool;

    fn received(&self, date: i64, comp: SearchOperator) -> impl Iterator<Item = MessageRef<'_>>;

    fn sent(&self, date: i64, comp: SearchOperator) -> impl Iterator<Item = MessageRef<'_>>;

    fn size(&self, size: u32, comp: SearchOperator) -> impl Iterator<Item = MessageRef<'_>>;
}

impl MessageCacheAccess for MessageStoreCache {
    fn in_mailbox(&self, mailbox_id: u32) -> impl Iterator<Item = MessageRef<'_>> {
        self.emails
            .iter()
            .filter(move |m| m.mailboxes().iter().any(|m| m.mailbox_id == mailbox_id))
    }

    fn in_mailboxes(&self, mailbox_ids: &[u32]) -> impl Iterator<Item = MessageRef<'_>> {
        self.emails.iter().filter(move |m| {
            m.mailboxes()
                .iter()
                .any(|mb| mailbox_ids.contains(&mb.mailbox_id))
        })
    }

    fn in_thread(&self, thread_id: u32) -> impl Iterator<Item = MessageRef<'_>> {
        self.emails
            .iter()
            .filter(move |m| m.thread_id() == thread_id)
    }

    fn with_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = MessageRef<'_>> {
        self.emails
            .iter()
            .filter(move |m| self.has_keyword(*m, keyword))
    }

    fn without_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = MessageRef<'_>> {
        self.emails
            .iter()
            .filter(move |m| !self.has_keyword(*m, keyword))
    }

    fn received(&self, date: i64, comp: SearchOperator) -> impl Iterator<Item = MessageRef<'_>> {
        self.emails.iter().filter(move |m| match comp {
            SearchOperator::LowerThan => (m.received_at() as i64) < date,
            SearchOperator::LowerEqualThan => (m.received_at() as i64) <= date,
            SearchOperator::GreaterThan => (m.received_at() as i64) > date,
            SearchOperator::GreaterEqualThan => (m.received_at() as i64) >= date,
            SearchOperator::Equal => (m.received_at() as i64) == date,
            SearchOperator::Contains => unreachable!(),
        })
    }

    fn sent(&self, date: i64, comp: SearchOperator) -> impl Iterator<Item = MessageRef<'_>> {
        self.emails.iter().filter(move |m| {
            let sent_at = m.received_at() as i64 + m.sent_at() as i64;
            match comp {
                SearchOperator::LowerThan => sent_at < date,
                SearchOperator::LowerEqualThan => sent_at <= date,
                SearchOperator::GreaterThan => sent_at > date,
                SearchOperator::GreaterEqualThan => sent_at >= date,
                SearchOperator::Equal => sent_at == date,
                SearchOperator::Contains => unreachable!(),
            }
        })
    }

    fn size(&self, size: u32, comp: SearchOperator) -> impl Iterator<Item = MessageRef<'_>> {
        self.emails.iter().filter(move |m| match comp {
            SearchOperator::LowerThan => m.size() < size,
            SearchOperator::LowerEqualThan => m.size() <= size,
            SearchOperator::GreaterThan => m.size() > size,
            SearchOperator::GreaterEqualThan => m.size() >= size,
            SearchOperator::Equal => m.size() == size,
            SearchOperator::Contains => unreachable!(),
        })
    }

    fn in_mailbox_with_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = MessageRef<'_>> {
        self.emails.iter().filter(move |m| {
            m.mailboxes().iter().any(|uid| uid.mailbox_id == mailbox_id)
                && self.has_keyword(*m, keyword)
        })
    }

    fn in_mailbox_without_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = MessageRef<'_>> {
        self.emails.iter().filter(move |m| {
            m.mailboxes().iter().any(|uid| uid.mailbox_id == mailbox_id)
                && !self.has_keyword(*m, keyword)
        })
    }

    fn shared_messages(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap {
        let check_acls = check_acls.into();
        let mut shared_messages = RoaringBitmap::new();
        for mailbox in &self.mailboxes.items {
            if mailbox
                .acls
                .as_slice()
                .effective_acl(access_token)
                .contains_all(check_acls)
            {
                shared_messages.extend(
                    self.in_mailbox(mailbox.document_id)
                        .map(|item| item.document_id()),
                );
            }
        }
        shared_messages
    }

    fn email_document_ids(&self) -> RoaringBitmap {
        RoaringBitmap::from_iter(self.emails.document_ids())
    }

    fn email_by_id(&self, id: &u32) -> Option<MessageRef<'_>> {
        self.emails.by_id(*id)
    }

    fn has_email_id(&self, id: &u32) -> bool {
        self.emails.contains(*id)
    }

    fn custom_keywords(&self, message: MessageRef<'_>) -> &[CompactString] {
        if message.keywords() & HAS_CUSTOM_KEYWORDS != 0 {
            self.emails.custom_keywords_of(message.document_id())
        } else {
            &[]
        }
    }

    fn message_data(&self, document_id: u32) -> Option<MessageData> {
        let message = self.email_by_id(&document_id)?;

        Some(MessageData {
            mailboxes: message.mailboxes().iter().copied().collect(),
            keywords: message.keywords() & !HAS_CUSTOM_KEYWORDS,
            keywords_extra: self.custom_keywords(message).to_vec(),
            thread_id: message.thread_id(),
            size: message.size(),
            received_at: message.received_at(),
            sent_at: message.sent_at(),
            change_id: message.change_id(),
        })
    }

    fn expand_keywords(&self, message: MessageRef<'_>) -> impl Iterator<Item = Keyword> {
        KeywordsIter(message.keywords() & !HAS_CUSTOM_KEYWORDS).chain(
            self.custom_keywords(message)
                .iter()
                .map(|name| Keyword::Other(name.clone())),
        )
    }

    fn has_keyword(&self, message: MessageRef<'_>, keyword: &Keyword) -> bool {
        match keyword.id() {
            Ok(id) => (message.keywords() & (1 << id)) != 0,
            Err(name) => self
                .custom_keywords(message)
                .iter()
                .any(|n| n.as_str() == name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{CACHE_CHUNK, MessageUid, MessagesCache};
    use std::sync::Arc;

    const BASE: u64 = 1_700_000_000;

    fn message(document_id: u32) -> MessageCache {
        let mailboxes = (0..((document_id % 3) + 1))
            .map(|slot| MessageUid {
                mailbox_id: (document_id + slot) % 7,
                uid: document_id + slot,
            })
            .collect();

        MessageCache::new(
            document_id,
            mailboxes,
            if document_id % 11 == 0 {
                HAS_CUSTOM_KEYWORDS
            } else {
                document_id % 17
            },
            document_id / 5,
            (document_id as u64) * 3,
            400 + document_id,
            BASE + (document_id % 13) as u64,
            -10 + (document_id as i32 % 300),
        )
    }

    fn sample(count: u32) -> (Vec<MessageCache>, Vec<CustomKeywords>) {
        let mut items = (0..count).map(message).collect::<Vec<_>>();
        items.sort_unstable_by_key(sort_rank);

        let mut keywords = items
            .iter()
            .filter(|item| item.keywords() & HAS_CUSTOM_KEYWORDS != 0)
            .map(|item| CustomKeywords {
                names: vec![CompactString::from(format!("label-{}", item.document_id()))]
                    .into_boxed_slice(),
                document_id: item.document_id(),
            })
            .collect::<Vec<_>>();
        keywords.sort_unstable_by_key(|entry| entry.document_id);

        (items, keywords)
    }

    fn assert_equals_a_rebuild(merged: &MessagesCache, expected: &MessagesCache) {
        assert_eq!(merged.len(), expected.len(), "length");
        for (left, right) in merged.iter().zip(expected.iter()) {
            assert_eq!(left.position(), right.position(), "position");
            assert_eq!(left.document_id(), right.document_id(), "document id");
            assert_eq!(left.received_at(), right.received_at(), "received at");
            assert_eq!(left.keywords(), right.keywords(), "keywords");
            assert_eq!(left.mailboxes(), right.mailboxes(), "mailboxes");
        }
        for document_id in expected.document_ids() {
            assert_eq!(
                merged.position(document_id),
                expected.position(document_id),
                "position of document {document_id}"
            );
            assert_eq!(
                merged.custom_keywords_of(document_id),
                expected.custom_keywords_of(document_id),
                "custom keywords of document {document_id}"
            );
        }
    }

    #[test]
    fn an_update_followed_by_a_delete_leaves_no_ghost() {
        let (items, keywords) = sample(CACHE_CHUNK as u32 * 2 + 1);
        let cache = MessagesCache::new(1, items.clone(), keywords.clone());

        let ghost = items[items.len() / 2].document_id();
        let changed_ids = AHashMap::from_iter([(ghost, true)]);
        let merged = merge_email_cache(&cache, &changed_ids, &[ghost], AHashMap::new(), Vec::new());

        assert!(
            !merged.contains(ghost),
            "a document that vanished from the store must not survive as a ghost"
        );
        assert_eq!(merged.len(), cache.len() - 1);

        let expected = MessagesCache::new(
            1,
            items
                .iter()
                .filter(|item| item.document_id() != ghost)
                .cloned()
                .collect(),
            keywords
                .iter()
                .filter(|entry| entry.document_id != ghost)
                .cloned()
                .collect(),
        );
        assert_equals_a_rebuild(&merged, &expected);
    }

    #[test]
    fn a_flag_toggle_shares_the_custom_keywords() {
        let (items, keywords) = sample(CACHE_CHUNK as u32 + 100);
        let cache = MessagesCache::new(1, items.clone(), keywords);
        assert!(
            !cache.keywords().is_empty(),
            "the fixture must carry custom keywords"
        );

        let toggled = items
            .iter()
            .find(|item| item.keywords() & HAS_CUSTOM_KEYWORDS == 0)
            .expect("a message without custom keywords")
            .document_id();
        let item = cache.by_id(toggled).unwrap();
        let record = MessageCache::new(
            item.document_id(),
            item.mailboxes().iter().copied().collect(),
            item.keywords() ^ (1 << 3),
            item.thread_id(),
            item.change_id() + 1,
            item.size(),
            item.received_at(),
            item.sent_at(),
        );

        let changed_ids = AHashMap::from_iter([(toggled, true)]);
        let merged = merge_email_cache(
            &cache,
            &changed_ids,
            &[toggled],
            AHashMap::from_iter([(toggled, record)]),
            Vec::new(),
        );

        assert_eq!(merged.len(), cache.len());
        assert!(
            Arc::ptr_eq(&cache.shared_keywords(), &merged.shared_keywords()),
            "a flag toggle that touches no custom keyword must not rebuild the keyword array"
        );
    }
}
