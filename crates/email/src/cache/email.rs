/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::messagedata::{EmailMessageData, KeywordsIter, MessageData};
use common::{
    CustomKeywords, MessageCache, MessageStoreCache, MessageUid, MessagesCache, Server,
    auth::AccessToken, sharing::EffectiveAcl,
};
use store::{ValueKey, ahash::AHashMap, roaring::RoaringBitmap, search::SearchOperator};
use trc::AddContext;
use types::{acl::Acl, collection::Collection, keyword::Keyword};
use utils::map::bitmap::Bitmap;

pub(crate) const HAS_CUSTOM_KEYWORDS: u32 = 1 << 31;

struct MessagesCacheBuilder {
    pub change_id: u64,
    pub items: Vec<MessageCache>,
    pub index: AHashMap<u32, u32>,
    pub keywords: Vec<CustomKeywords>,
}

pub(crate) async fn update_email_cache(
    server: &Server,
    account_id: u32,
    changed_ids: &AHashMap<u32, bool>,
    store_cache: &MessageStoreCache,
) -> trc::Result<MessagesCache> {
    let mut new_cache = MessagesCacheBuilder {
        index: AHashMap::new(),
        items: Vec::with_capacity(store_cache.emails.items.len()),
        change_id: 0,
        keywords: Vec::with_capacity(store_cache.emails.keywords.len()),
    };

    for (&document_id, is_update) in changed_ids {
        if *is_update
            && let Some(mut data) = server
                .store()
                .get_value::<MessageData>(ValueKey::archive(
                    account_id,
                    Collection::Email,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
        {
            if !data.keywords_extra.is_empty() {
                new_cache.keywords.push(CustomKeywords {
                    names: data.keywords_extra.into_boxed_slice(),
                    document_id,
                });
                data.keywords |= HAS_CUSTOM_KEYWORDS;
            }

            new_cache.items.push(MessageCache {
                mailboxes: data.mailboxes,
                keywords: data.keywords,
                thread_id: data.thread_id,
                change_id: data.change_id,
                document_id,
                size: data.size,
                received_at: data.received_at,
                sent_at: data.sent_at,
            });
        }
    }

    for item in &store_cache.emails.items {
        if !changed_ids.contains_key(&item.document_id) {
            if item.keywords & HAS_CUSTOM_KEYWORDS != 0
                && let Some(custom_keywords) = store_cache
                    .emails
                    .keywords
                    .iter()
                    .find(|k| k.document_id == item.document_id)
            {
                new_cache.keywords.push(CustomKeywords {
                    names: custom_keywords.names.clone(),
                    document_id: item.document_id,
                });
            }

            new_cache.items.push(item.clone());
        }
    }

    Ok(new_cache.build())
}

pub(crate) async fn full_email_cache_build(
    server: &Server,
    account_id: u32,
) -> trc::Result<MessagesCache> {
    // Build cache
    let mut cache = MessagesCacheBuilder {
        items: Vec::with_capacity(16),
        index: AHashMap::default(),
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

            cache.items.push(MessageCache {
                mailboxes: data.mailboxes,
                keywords: data.keywords,
                thread_id: data.thread_id,
                change_id: data.change_id,
                document_id,
                size: data.size,
                received_at: data.received_at,
                sent_at: data.sent_at,
            });
            Ok(true)
        })
        .await
        .caused_by(trc::location!())?;

    Ok(cache.build())
}

impl MessagesCacheBuilder {
    pub fn build(mut self) -> MessagesCache {
        self.items.sort_unstable_by_key(|m| m.received_at);
        self.index = AHashMap::with_capacity(self.items.len());

        let mut size = self
            .keywords
            .iter()
            .map(|k| {
                std::mem::size_of::<CustomKeywords>()
                    + (k.names.len() * std::mem::size_of::<String>())
            })
            .sum::<usize>() as u64;
        for (i, item) in self.items.iter().enumerate() {
            self.index.insert(item.document_id, i as u32);
            size += (std::mem::size_of::<MessageCache>()
                + (std::mem::size_of::<u32>() * 2)
                + (item.mailboxes.len() * std::mem::size_of::<MessageUid>()))
                as u64;
        }

        MessagesCache {
            change_id: self.change_id,
            items: self.items.into_boxed_slice(),
            index: self.index,
            keywords: self.keywords.into_boxed_slice(),
            size,
        }
    }
}

pub trait MessageCacheAccess {
    fn email_by_id(&self, id: &u32) -> Option<&MessageCache>;

    fn has_email_id(&self, id: &u32) -> bool;

    fn in_mailbox(&self, mailbox_id: u32) -> impl Iterator<Item = &MessageCache>;

    fn in_mailboxes(&self, mailbox_ids: &[u32]) -> impl Iterator<Item = &MessageCache>;

    fn in_thread(&self, thread_id: u32) -> impl Iterator<Item = &MessageCache>;

    fn with_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = &MessageCache>;

    fn without_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = &MessageCache>;

    fn in_mailbox_with_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = &MessageCache>;

    fn in_mailbox_without_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = &MessageCache>;

    fn email_document_ids(&self) -> RoaringBitmap;

    fn shared_messages(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap;

    fn expand_keywords(&self, message: &MessageCache) -> impl Iterator<Item = Keyword>;

    fn has_keyword(&self, message: &MessageCache, keyword: &Keyword) -> bool;

    fn received(&self, date: i64, comp: SearchOperator) -> impl Iterator<Item = &MessageCache>;

    fn sent(&self, date: i64, comp: SearchOperator) -> impl Iterator<Item = &MessageCache>;

    fn size(&self, size: u32, comp: SearchOperator) -> impl Iterator<Item = &MessageCache>;
}

impl MessageCacheAccess for MessageStoreCache {
    fn in_mailbox(&self, mailbox_id: u32) -> impl Iterator<Item = &MessageCache> {
        self.emails
            .items
            .iter()
            .filter(move |m| m.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id))
    }

    fn in_mailboxes(&self, mailbox_ids: &[u32]) -> impl Iterator<Item = &MessageCache> {
        self.emails.items.iter().filter(move |m| {
            m.mailboxes
                .iter()
                .any(|mb| mailbox_ids.contains(&mb.mailbox_id))
        })
    }

    fn in_thread(&self, thread_id: u32) -> impl Iterator<Item = &MessageCache> {
        self.emails
            .items
            .iter()
            .filter(move |m| m.thread_id == thread_id)
    }

    fn with_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = &MessageCache> {
        self.emails
            .items
            .iter()
            .filter(move |m| self.has_keyword(m, keyword))
    }

    fn without_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = &MessageCache> {
        self.emails
            .items
            .iter()
            .filter(move |m| !self.has_keyword(m, keyword))
    }

    fn received(&self, date: i64, comp: SearchOperator) -> impl Iterator<Item = &MessageCache> {
        self.emails.items.iter().filter(move |m| match comp {
            SearchOperator::LowerThan => (m.received_at as i64) < date,
            SearchOperator::LowerEqualThan => (m.received_at as i64) <= date,
            SearchOperator::GreaterThan => (m.received_at as i64) > date,
            SearchOperator::GreaterEqualThan => (m.received_at as i64) >= date,
            SearchOperator::Equal => (m.received_at as i64) == date,
            SearchOperator::Contains => unreachable!(),
        })
    }

    fn sent(&self, date: i64, comp: SearchOperator) -> impl Iterator<Item = &MessageCache> {
        self.emails.items.iter().filter(move |m| {
            let sent_at = m.received_at as i64 + m.sent_at as i64;
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

    fn size(&self, size: u32, comp: SearchOperator) -> impl Iterator<Item = &MessageCache> {
        self.emails.items.iter().filter(move |m| match comp {
            SearchOperator::LowerThan => m.size < size,
            SearchOperator::LowerEqualThan => m.size <= size,
            SearchOperator::GreaterThan => m.size > size,
            SearchOperator::GreaterEqualThan => m.size >= size,
            SearchOperator::Equal => m.size == size,
            SearchOperator::Contains => unreachable!(),
        })
    }

    fn in_mailbox_with_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = &MessageCache> {
        self.emails.items.iter().filter(move |m| {
            m.mailboxes.iter().any(|uid| uid.mailbox_id == mailbox_id)
                && self.has_keyword(m, keyword)
        })
    }

    fn in_mailbox_without_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = &MessageCache> {
        self.emails.items.iter().filter(move |m| {
            m.mailboxes.iter().any(|uid| uid.mailbox_id == mailbox_id)
                && !self.has_keyword(m, keyword)
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
                        .map(|item| item.document_id),
                );
            }
        }
        shared_messages
    }

    fn email_document_ids(&self) -> RoaringBitmap {
        RoaringBitmap::from_iter(self.emails.index.keys())
    }

    fn email_by_id(&self, id: &u32) -> Option<&MessageCache> {
        self.emails
            .index
            .get(id)
            .and_then(|idx| self.emails.items.get(*idx as usize))
    }

    fn has_email_id(&self, id: &u32) -> bool {
        self.emails.index.contains_key(id)
    }

    fn expand_keywords(&self, message: &MessageCache) -> impl Iterator<Item = Keyword> {
        KeywordsIter(message.keywords & !HAS_CUSTOM_KEYWORDS).chain(
            (message.keywords & HAS_CUSTOM_KEYWORDS != 0)
                .then(|| {
                    self.emails
                        .keywords
                        .iter()
                        .filter(|k| k.document_id == message.document_id)
                        .flat_map(|k| k.names.iter().map(|n| Keyword::Other(n.clone())))
                })
                .into_iter()
                .flatten(),
        )
    }

    fn has_keyword(&self, message: &MessageCache, keyword: &Keyword) -> bool {
        match keyword.id() {
            Ok(id) => (message.keywords & (1 << id)) != 0,
            Err(name) => {
                message.keywords & HAS_CUSTOM_KEYWORDS != 0
                    && self.emails.keywords.iter().any(|k| {
                        k.document_id == message.document_id
                            && k.names.iter().any(|n| n.as_str() == name)
                    })
            }
        }
    }
}
