/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    cache::mailbox::MailboxCacheAccess,
    message::messagedata::{
        EmailMessageData, KEYWORD_BITS, KeywordDiff, KeywordsIter, MessageData, SERVER_SET_KEYWORDS,
    },
};
use common::{
    CustomKeywords, MessageCache, MessageStoreCache, MessagesCache, Server, auth::AccessToken,
    cache::email::MessageRef,
};
use compact_str::CompactString;
use std::sync::Arc;
use store::{
    ahash::{AHashMap, AHashSet},
    roaring::RoaringBitmap,
};
use trc::AddContext;
use types::{
    acl::Acl,
    id::Id,
    keyword::{DRAFT, Keyword, SEEN},
    metadata::MetadataKinds,
};
use utils::map::bitmap::Bitmap;

pub(crate) const HAS_CUSTOM_KEYWORDS: u32 = 1 << 31;
const READ_KEYWORDS: u32 = (1 << SEEN) | (1 << DRAFT);

pub struct KeywordWrites {
    writes: Vec<KeywordWrite>,
    mailboxes_changed: bool,
}

pub(crate) struct KeywordWrite {
    pub position: u32,
    pub document_id: u32,
    pub keywords: u32,
    pub commit_point: u32,
}

const _: () = assert!(size_of::<KeywordWrite>() <= 16);

impl KeywordWrites {
    pub fn with_capacity(capacity: usize) -> Self {
        KeywordWrites {
            writes: Vec::with_capacity(capacity),
            mailboxes_changed: false,
        }
    }

    pub fn push(
        &mut self,
        message: MessageRef<'_>,
        diff: &KeywordDiff,
        commit_point: usize,
    ) -> bool {
        let (Some(keywords), Ok(commit_point)) = (
            diff.keyword_bits(message.keywords()),
            u32::try_from(commit_point),
        ) else {
            return false;
        };
        self.writes.push(KeywordWrite {
            position: message.position(),
            document_id: message.document_id(),
            keywords,
            commit_point,
        });
        true
    }

    pub fn set_mailboxes_changed(&mut self) {
        self.mailboxes_changed = true;
    }

    pub(crate) fn writes(&self) -> &[KeywordWrite] {
        &self.writes
    }

    pub(crate) fn mailboxes_changed(&self) -> bool {
        self.mailboxes_changed
    }
}

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
        fetched,
        fetched_keywords,
    ))
}

fn merge_email_cache(
    cache: &MessagesCache,
    changed_ids: &AHashMap<u32, bool>,
    mut fetched: AHashMap<u32, MessageCache>,
    fetched_keywords: Vec<CustomKeywords>,
) -> MessagesCache {
    let mut inserts = Vec::new();
    let mut deletes = Vec::new();
    for (document_id, is_update) in changed_ids {
        if !*is_update {
            deletes.push(*document_id);
        } else if !cache.contains(*document_id) {
            if let Some(item) = fetched.remove(document_id) {
                inserts.push(item);
            }
        } else if !fetched.contains_key(document_id) {
            deletes.push(*document_id);
        }
    }
    inserts.sort_unstable_by_key(MessageCache::sort_rank);
    deletes.sort_unstable();

    let keywords = merge_custom_keywords(cache, changed_ids, fetched_keywords);

    let patches = fetched
        .into_iter()
        .filter_map(|(document_id, record)| {
            cache
                .position(document_id)
                .map(|position| (position, record))
        })
        .collect::<Vec<_>>();

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
        self.items.sort_unstable_by_key(MessageCache::sort_rank);
        self.keywords.sort_unstable_by_key(|k| k.document_id);
        MessagesCache::new(self.change_id, self.items, self.keywords)
    }
}

pub fn thread_keywords(
    cache: &MessageStoreCache,
    keyword: &Keyword,
    match_all: bool,
    documents: Option<&RoaringBitmap>,
    visible: Option<&RoaringBitmap>,
) -> RoaringBitmap {
    let is_visible = |document_id: u32| visible.is_none_or(|visible| visible.contains(document_id));
    let mut tagged = RoaringBitmap::new();
    let mut untagged = RoaringBitmap::new();
    let mut tally = |item: MessageRef<'_>| {
        if cache.has_keyword(item, keyword) {
            tagged.insert(item.thread_id());
        } else if match_all {
            untagged.insert(item.thread_id());
        }
    };
    let members = match documents {
        Some(documents) => {
            let members = documents
                .iter()
                .filter_map(|document_id| {
                    cache
                        .email_by_id(&document_id)
                        .map(|item| (document_id, item.thread_id()))
                })
                .collect::<Vec<_>>();
            let threads = members
                .iter()
                .map(|(_, thread_id)| *thread_id)
                .collect::<AHashSet<_>>();
            for item in cache.emails.iter().filter(|item| {
                is_visible(item.document_id()) && threads.contains(&item.thread_id())
            }) {
                tally(item);
            }
            members
        }
        None => {
            let capacity = visible
                .map_or(cache.emails.len(), |visible| {
                    usize::try_from(visible.len()).unwrap_or(usize::MAX)
                })
                .min(cache.emails.len());
            let mut members = Vec::with_capacity(capacity);
            for item in cache
                .emails
                .iter()
                .filter(|item| is_visible(item.document_id()))
            {
                members.push((item.document_id(), item.thread_id()));
                tally(item);
            }
            members
        }
    };
    tagged -= untagged;
    members
        .into_iter()
        .filter(|(_, thread_id)| tagged.contains(*thread_id))
        .map(|(document_id, _)| document_id)
        .collect()
}

pub enum SearchOperator {
    LowerThan,
    LowerEqualThan,
    GreaterThan,
    GreaterEqualThan,
    Equal,
    Contains,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MailboxCounters {
    pub total: usize,
    pub unread: usize,
    pub threads: AHashSet<u32>,
    pub unread_threads: AHashSet<u32>,
}

impl MailboxCounters {
    #[inline]
    fn add(&mut self, thread_id: u32, is_unread: bool, count_threads: bool) {
        self.total += 1;
        self.unread += usize::from(is_unread);
        if count_threads {
            self.threads.insert(thread_id);
            if is_unread {
                self.unread_threads.insert(thread_id);
            }
        }
    }
}

pub enum MessageAccess {
    All,
    Mailboxes(RoaringBitmap),
}

impl MessageAccess {
    #[inline]
    pub fn allows(&self, message: MessageRef<'_>) -> bool {
        match self {
            MessageAccess::All => true,
            MessageAccess::Mailboxes(mailboxes) => message
                .mailboxes()
                .iter()
                .any(|uid| mailboxes.contains(uid.mailbox_id)),
        }
    }

    #[inline]
    pub fn allows_mailbox(&self, mailbox_id: u32) -> bool {
        match self {
            MessageAccess::All => true,
            MessageAccess::Mailboxes(mailboxes) => mailboxes.contains(mailbox_id),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            MessageAccess::All => false,
            MessageAccess::Mailboxes(mailboxes) => mailboxes.is_empty(),
        }
    }
}

pub trait MessageCacheAccess {
    fn email_by_id(&self, id: &u32) -> Option<MessageRef<'_>>;

    fn email_by_jmap_id(&self, id: Id) -> Option<MessageRef<'_>>;

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

    fn mailbox_counters(
        &self,
        mailbox_ids: impl IntoIterator<Item = u32>,
        count_threads: bool,
    ) -> AHashMap<u32, MailboxCounters>;

    fn shared_messages(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap;

    fn expand_keywords(&self, message: MessageRef<'_>) -> impl Iterator<Item = Keyword>;

    fn has_keyword(&self, message: MessageRef<'_>, keyword: &Keyword) -> bool;

    fn keyword_count(&self, message: MessageRef<'_>) -> usize;

    fn metadata_kinds(&self, message: MessageRef<'_>) -> MetadataKinds;

    fn with_metadata(&self) -> impl Iterator<Item = MessageRef<'_>>;

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
        let access = MessageAccess::Mailboxes(self.shared_mailboxes(access_token, check_acls));
        if access.is_empty() {
            return RoaringBitmap::new();
        }
        self.emails
            .iter()
            .filter(|message| access.allows(*message))
            .map(|message| message.document_id())
            .collect()
    }

    fn email_document_ids(&self) -> RoaringBitmap {
        RoaringBitmap::from_sorted_iter(self.emails.document_ids())
            .unwrap_or_else(|_| RoaringBitmap::from_iter(self.emails.document_ids()))
    }

    fn mailbox_counters(
        &self,
        mailbox_ids: impl IntoIterator<Item = u32>,
        count_threads: bool,
    ) -> AHashMap<u32, MailboxCounters> {
        let mut counters = mailbox_ids
            .into_iter()
            .map(|mailbox_id| (mailbox_id, MailboxCounters::default()))
            .collect::<AHashMap<_, _>>();
        if counters.is_empty() {
            return counters;
        }

        for message in self.emails.iter() {
            let mailboxes = message.mailboxes();
            let mut is_unread = None;
            for (pos, uid) in mailboxes.iter().enumerate() {
                if let Some(counter) = counters.get_mut(&uid.mailbox_id)
                    && !mailboxes
                        .iter()
                        .take(pos)
                        .any(|prev| prev.mailbox_id == uid.mailbox_id)
                {
                    let is_unread =
                        *is_unread.get_or_insert_with(|| message.keywords() & READ_KEYWORDS == 0);
                    counter.add(message.thread_id(), is_unread, count_threads);
                }
            }
        }

        counters
    }

    fn email_by_id(&self, id: &u32) -> Option<MessageRef<'_>> {
        self.emails.by_id(*id)
    }

    fn email_by_jmap_id(&self, id: Id) -> Option<MessageRef<'_>> {
        self.emails
            .by_id(id.document_id())
            .filter(|message| message.thread_id() == id.prefix_id())
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
        KeywordsIter(message.keywords() & KEYWORD_BITS).chain(
            self.custom_keywords(message)
                .iter()
                .map(|name| Keyword::Other(name.clone())),
        )
    }

    fn keyword_count(&self, message: MessageRef<'_>) -> usize {
        (message.keywords() & KEYWORD_BITS & !SERVER_SET_KEYWORDS).count_ones() as usize
            + self.custom_keywords(message).len()
    }

    fn metadata_kinds(&self, message: MessageRef<'_>) -> MetadataKinds {
        MessageData::metadata_kinds_of(message.keywords())
    }

    fn with_metadata(&self) -> impl Iterator<Item = MessageRef<'_>> {
        self.emails
            .iter()
            .filter(|message| MessageData::has_metadata(message.keywords()))
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

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/email/src/cache/email/tests.rs"]
mod tests;
