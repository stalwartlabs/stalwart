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

    let mut inserts = Vec::new();
    for document_id in &fetch_ids {
        if !store_cache.emails.contains(*document_id)
            && let Some(item) = fetched.remove(document_id)
        {
            inserts.push(item);
        }
    }
    inserts.sort_unstable_by_key(sort_rank);

    let has_deletes = changed_ids.values().any(|is_update| !*is_update);

    let keywords = merge_custom_keywords(store_cache, changed_ids, fetched_keywords);

    if inserts.is_empty() && !has_deletes {
        let mut patches = Vec::with_capacity(fetched.len());
        for (document_id, record) in fetched {
            if let Some(position) = store_cache.emails.position(document_id) {
                patches.push((position, record));
            }
        }
        return Ok(store_cache.emails.patch(0, &patches, keywords.into()));
    }

    let mut items = Vec::with_capacity(store_cache.emails.len() + inserts.len());
    let mut inserts = inserts.into_iter().peekable();
    for item in store_cache.emails.iter() {
        let rank = item.sort_rank();
        while inserts.peek().is_some_and(|new| sort_rank(new) <= rank) {
            items.push(inserts.next().unwrap());
        }

        match changed_ids.get(&item.document_id()) {
            Some(true) => {
                if let Some(updated) = fetched.remove(&item.document_id()) {
                    debug_assert_eq!(
                        updated.received_at(),
                        item.received_at(),
                        "received_at mutated for document {}, the merge assumes it cannot",
                        item.document_id()
                    );
                    items.push(updated);
                }
            }
            Some(false) => {}
            None => items.push(item.to_record()),
        }
    }
    items.extend(inserts);

    Ok(MessagesCacheBuilder {
        change_id: 0,
        items,
        keywords,
    }
    .finish())
}

fn merge_custom_keywords(
    store_cache: &MessageStoreCache,
    changed_ids: &AHashMap<u32, bool>,
    fetched_keywords: Vec<CustomKeywords>,
) -> Vec<CustomKeywords> {
    let mut retained = store_cache
        .emails
        .keywords()
        .iter()
        .filter(|k| !changed_ids.contains_key(&k.document_id))
        .peekable();
    let mut keywords =
        Vec::with_capacity(store_cache.emails.keywords().len() + fetched_keywords.len());
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
    keywords
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
        self.finish()
    }

    pub fn finish(self) -> MessagesCache {
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
