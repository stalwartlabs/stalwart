/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{MessageUid, Server};
use compact_str::CompactString;
use store::{
    Deserialize, IterateParams, Serialize, U32_LEN, U64_LEN, ValueKey,
    dispatch::DocumentSet,
    write::{
        AssignedIds, BatchBuilder, MergeResult, PendingId, SerializeWithIds, SetValue,
        SizedSetValue, Slot, SlotRange, ValueClass, key::DeserializeBigEndian,
    },
};
use tinyvec::TinyVec;
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::Field,
    keyword::{HASATTACHMENT, HASNOATTACHMENT, Keyword},
};
use utils::codec::leb128::{Leb128_, Leb128Iterator};

#[derive(Debug, Clone)]
pub struct MessageData {
    pub mailboxes: TinyVec<[MessageUid; 2]>,
    pub keywords: u32,
    pub keywords_extra: Vec<CompactString>,
    pub thread_id: u32,
    pub size: u32,
    pub received_at: u64,
    pub sent_at: i32,
    pub change_id: u64,
}

pub trait EmailMessageData: Sync + Send {
    fn message_datas<I, CB>(
        &self,
        account_id: u32,
        documents: &I,
        cb: CB,
    ) -> impl Future<Output = trc::Result<()>> + Send
    where
        I: DocumentSet + Send + Sync,
        CB: FnMut(u32, MessageData) -> trc::Result<bool> + Send + Sync;
}

impl EmailMessageData for Server {
    async fn message_datas<I, CB>(
        &self,
        account_id: u32,
        documents: &I,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        I: DocumentSet + Send + Sync,
        CB: FnMut(u32, MessageData) -> trc::Result<bool> + Send + Sync,
    {
        let collection: u8 = Collection::Email.into();

        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection,
                        document_id: documents.min(),
                        class: ValueClass::Property(Field::ARCHIVE.into()),
                    },
                    ValueKey {
                        account_id,
                        collection,
                        document_id: documents.max(),
                        class: ValueClass::Property(Field::ARCHIVE.into()),
                    },
                ),
                |key, value| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    if documents.contains(document_id) {
                        MessageData::deserialize(value).and_then(|archive| cb(document_id, archive))
                    } else {
                        Ok(true)
                    }
                },
            )
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })
    }
}

impl MessageData {
    pub fn set_keywords(&mut self, keywords: Vec<Keyword>) {
        self.keywords &= (1 << HASATTACHMENT) | (1 << HASNOATTACHMENT);
        self.keywords_extra.clear();
        for keyword in keywords {
            match keyword.into_id() {
                Ok(id) => self.keywords |= 1 << id,
                Err(name) => {
                    if !self
                        .keywords_extra
                        .iter()
                        .any(|k| k.as_str() == name.as_str())
                    {
                        self.keywords_extra.push(name);
                    }
                }
            }
        }
    }

    pub fn add_keyword(&mut self, keyword: Keyword) -> bool {
        match keyword.into_id() {
            Ok(id) => {
                let id = 1 << id;
                if self.keywords & id == 0 {
                    self.keywords |= id;
                    true
                } else {
                    false
                }
            }
            Err(name) => {
                if !self
                    .keywords_extra
                    .iter()
                    .any(|k| k.as_str() == name.as_str())
                {
                    self.keywords_extra.push(name);
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn remove_keyword(&mut self, keyword: &Keyword) -> bool {
        match keyword.id() {
            Ok(id) => {
                let id = 1 << id;
                if self.keywords & id != 0 {
                    self.keywords &= !id;
                    true
                } else {
                    false
                }
            }
            Err(name) => {
                let prev_len = self.keywords_extra.len();
                self.keywords_extra.retain(|k| k.as_str() != name);
                self.keywords_extra.len() != prev_len
            }
        }
    }

    pub fn set_mailboxes(&mut self, mailboxes: TinyVec<[MessageUid; 2]>) {
        self.mailboxes = mailboxes;
    }

    pub fn add_mailbox(&mut self, mailbox: MessageUid) {
        if !self.mailboxes.contains(&mailbox) {
            self.mailboxes.push(mailbox);
        }
    }

    pub fn remove_mailbox(&mut self, mailbox: u32) {
        self.mailboxes.retain(|m| m.mailbox_id != mailbox);
    }

    pub fn has_keyword(&self, keyword: &Keyword) -> bool {
        match keyword.id() {
            Ok(id) => (self.keywords & (1 << id)) != 0,
            Err(name) => self.keywords_extra.iter().any(|k| k.as_str() == name),
        }
    }

    pub fn has_keyword_changes(&self, prev_data: &MessageData) -> bool {
        self.keywords != prev_data.keywords || self.keywords_extra != prev_data.keywords_extra
    }

    pub fn keyword_diff(&self, prev_data: &MessageData) -> KeywordDiff {
        KeywordDiff::Patch {
            added: self.keywords & !prev_data.keywords,
            removed: prev_data.keywords & !self.keywords,
            added_extra: self
                .keywords_extra
                .iter()
                .filter(|k| !prev_data.keywords_extra.contains(*k))
                .cloned()
                .collect(),
            removed_extra: prev_data
                .keywords_extra
                .iter()
                .filter(|k| !self.keywords_extra.contains(*k))
                .cloned()
                .collect(),
        }
    }

    pub fn added_keywords(&self, prev_data: &MessageData) -> impl Iterator<Item = Keyword> {
        KeywordsIter(self.keywords & !prev_data.keywords)
    }

    pub fn removed_keywords(&self, prev_data: &MessageData) -> impl Iterator<Item = Keyword> {
        KeywordsIter(prev_data.keywords & !self.keywords)
    }

    pub fn keywords(&self) -> impl Iterator<Item = Keyword> {
        KeywordsIter(self.keywords).chain(self.keywords_extra.iter().cloned().map(Keyword::Other))
    }

    pub fn added_mailboxes(&self, prev_data: &MessageData) -> impl Iterator<Item = &MessageUid> {
        self.mailboxes.iter().filter(|m| {
            prev_data
                .mailboxes
                .iter()
                .all(|pm| pm.mailbox_id != m.mailbox_id)
        })
    }

    pub fn removed_mailboxes<'x>(
        &'x self,
        prev_data: &'x MessageData,
    ) -> impl Iterator<Item = &'x MessageUid> {
        prev_data.mailboxes.iter().filter(|m| {
            self.mailboxes
                .iter()
                .all(|pm| pm.mailbox_id != m.mailbox_id)
        })
    }

    pub fn has_mailbox_changes(&self, prev_data: &MessageData) -> bool {
        self.mailboxes.len() != prev_data.mailboxes.len()
            || !self.mailboxes.iter().all(|m| {
                prev_data
                    .mailboxes
                    .iter()
                    .any(|pm| pm.mailbox_id == m.mailbox_id)
            })
    }

    pub fn has_mailbox_id(&self, mailbox_id: u32) -> bool {
        self.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id)
    }

    pub fn message_uid(&self, mailbox_id: u32) -> Option<u32> {
        self.mailboxes
            .iter()
            .find(|m| m.mailbox_id == mailbox_id)
            .map(|m| m.uid)
    }
}

impl Serialize for MessageData {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        self.serialize_with_change_id(self.change_id)
    }
}

#[derive(Debug)]
pub enum KeywordDiff {
    Replace(Vec<Keyword>),
    Patch {
        added: u32,
        removed: u32,
        added_extra: Vec<CompactString>,
        removed_extra: Vec<CompactString>,
    },
}

impl KeywordDiff {
    pub fn replace(keywords: Vec<Keyword>) -> Self {
        KeywordDiff::Replace(keywords)
    }

    pub fn added(keyword: Keyword) -> Self {
        let (added, added_extra) = match keyword.into_id() {
            Ok(id) => (1 << id, Vec::new()),
            Err(name) => (0, vec![name]),
        };

        KeywordDiff::Patch {
            added,
            removed: 0,
            added_extra,
            removed_extra: Vec::new(),
        }
    }

    fn apply(&self, data: &mut MessageData) -> bool {
        let prev_keywords = data.keywords;

        match self {
            KeywordDiff::Replace(keywords) => {
                let prev_extra = data.keywords_extra.clone();
                data.set_keywords(keywords.clone());

                data.keywords != prev_keywords || data.keywords_extra != prev_extra
            }
            KeywordDiff::Patch {
                added,
                removed,
                added_extra,
                removed_extra,
            } => {
                let prev_extra_len = data.keywords_extra.len();

                data.keywords = (data.keywords | added) & !removed;
                if !removed_extra.is_empty() {
                    data.keywords_extra.retain(|k| !removed_extra.contains(k));
                }

                let mut extra_changed = data.keywords_extra.len() != prev_extra_len;
                for keyword in added_extra {
                    if !data.keywords_extra.contains(keyword) {
                        data.keywords_extra.push(keyword.clone());
                        extra_changed = true;
                    }
                }

                data.keywords != prev_keywords || extra_changed
            }
        }
    }
}

pub fn merge_keywords(batch: &mut BatchBuilder, thread_id: u32, diff: KeywordDiff) {
    batch.log_item_update(SyncCollection::Email, Some(PendingId::Assigned(thread_id)));
    batch.merge_fnc(Field::ARCHIVE, move |ids, bytes| {
        let Some(bytes) = bytes else {
            return Ok(MergeResult::Skip);
        };

        let mut data = MessageData::deserialize(bytes)?;
        if !diff.apply(&mut data) {
            return Ok(MergeResult::Skip);
        }

        data.serialize_with_change_id(ids.current_change_id())
            .map(MergeResult::Update)
    });
}

impl MessageData {
    pub fn serialize_with_change_id(&self, change_id: u64) -> trc::Result<Vec<u8>> {
        Ok(self.serialize_resolved(change_id, None, SlotRange::default(), None))
    }

    pub fn size_hint(&self) -> usize {
        std::mem::size_of::<MessageData>()
            + (std::mem::size_of::<MessageUid>() * self.mailboxes.len().saturating_sub(2))
            + (self
                .keywords_extra
                .iter()
                .map(|k| k.len() + 1)
                .sum::<usize>())
    }

    pub fn pending_uids(&self) -> usize {
        self.mailboxes.iter().filter(|mb| mb.uid == 0).count()
    }

    fn serialize_resolved(
        &self,
        change_id: u64,
        ids: Option<&AssignedIds>,
        uid_slots: SlotRange,
        thread_slot: Option<Slot>,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size_hint());
        let mut next_uid_slot = 0;

        self.mailboxes.len().to_leb128_bytes(&mut out);
        for mb in self.mailboxes.iter() {
            mb.mailbox_id.to_leb128_bytes(&mut out);
            let uid = match ids {
                Some(ids) if mb.uid == 0 && next_uid_slot < uid_slots.len() => {
                    let uid = ids.slot(uid_slots.get(next_uid_slot));
                    next_uid_slot += 1;
                    uid
                }
                _ => mb.uid,
            };
            uid.to_leb128_bytes(&mut out);
        }

        match (ids, thread_slot) {
            (Some(ids), Some(thread_slot)) => ids.slot(thread_slot),
            _ => self.thread_id,
        }
        .to_leb128_bytes(&mut out);

        self.size.to_leb128_bytes(&mut out);
        self.received_at.to_leb128_bytes(&mut out);
        (((self.sent_at << 1) ^ (self.sent_at >> 31)) as u32).to_leb128_bytes(&mut out);

        out.extend_from_slice(&self.keywords.to_be_bytes());

        for s in self.keywords_extra.iter() {
            s.len().to_leb128_bytes(&mut out);
            out.extend_from_slice(s.as_bytes());
        }

        out.extend_from_slice(&change_id.to_be_bytes());

        out
    }
}

pub struct PendingMessageData {
    pub data: MessageData,
    pub uid_slots: SlotRange,
    pub thread_slot: Option<Slot>,
    pub change_id: Option<u64>,
}

impl SerializeWithIds for PendingMessageData {
    fn serialize_with_ids(&mut self, ids: &AssignedIds) -> trc::Result<(Vec<u8>, Option<u32>)> {
        let change_id = match self.change_id {
            Some(change_id) => change_id,
            None => ids.try_current_change_id().ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .caused_by(trc::location!())
                    .ctx(
                        trc::Key::Reason,
                        "No change id was allocated for this message",
                    )
            })?,
        };

        Ok((
            self.data
                .serialize_resolved(change_id, Some(ids), self.uid_slots, self.thread_slot),
            None,
        ))
    }

    fn size_hint(&self) -> usize {
        self.data.size_hint()
    }
}

impl From<PendingMessageData> for SizedSetValue {
    fn from(data: PendingMessageData) -> Self {
        SetValue::serializable(data)
    }
}

impl Deserialize for MessageData {
    fn deserialize(data: &[u8]) -> trc::Result<Self> {
        deserialize(data)
            .ok_or_else(|| trc::Error::corrupted_key(b"", data.into(), trc::location!()))
    }
}

#[inline(always)]
fn deserialize(data: &[u8]) -> Option<MessageData> {
    let mut iter = data.iter();
    let num_mailboxes: usize = iter.next_leb128()?;
    let mut data = MessageData {
        mailboxes: TinyVec::with_capacity(num_mailboxes),
        keywords: 0,
        keywords_extra: Vec::new(),
        thread_id: 0,
        size: 0,
        received_at: 0,
        sent_at: 0,
        change_id: 0,
    };
    for _ in 0..num_mailboxes {
        let mailbox_id: u32 = iter.next_leb128()?;
        let uid: u32 = iter.next_leb128()?;
        data.mailboxes.push(MessageUid { mailbox_id, uid });
    }

    data.thread_id = iter.next_leb128()?;
    data.size = iter.next_leb128()?;
    data.received_at = iter.next_leb128()?;
    data.sent_at = {
        let v: u32 = iter.next_leb128()?;
        ((v >> 1) as i32) ^ -((v & 1) as i32)
    };

    let bytes = iter.as_slice();
    data.keywords = u32::from_be_bytes(bytes.get(..U32_LEN)?.try_into().ok()?);
    let mut pos = U32_LEN;

    while bytes.len() - pos > U64_LEN {
        let (len, bytes_read) = usize::from_leb128_bytes_pos(&bytes[pos..])?;
        let text = bytes
            .get(pos + bytes_read..pos + bytes_read + len)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())?;
        data.keywords_extra.push(CompactString::from(text));
        pos += bytes_read + len;
    }

    data.change_id = u64::from_be_bytes(bytes.get(pos..pos + U64_LEN)?.try_into().ok()?);

    Some(data)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct KeywordsIter(pub u32);

impl Iterator for KeywordsIter {
    type Item = Keyword;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0 != 0 {
            let item = 31 - self.0.leading_zeros();
            self.0 ^= 1 << item;
            Keyword::try_from_id(item as usize).ok()
        } else {
            None
        }
    }
}
