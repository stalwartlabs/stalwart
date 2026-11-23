/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    execute::{RopContext, RopError},
    ics::TransferContext,
    message::{
        attachment_at, attachment_mut,
        load::{embedded, embedded_mut},
        object_row::is_category,
    },
    state::{EmsmdbState, Handle, MessageObject, ServerObject},
};
pub use crate::store::object::RowBaseline;
use crate::{mapi::ids::MapiId, session::ExchangeSessionSlot, store::object::ConflictState};
use common::{
    Server,
    network::memory::{MemoryClass, MemoryReservation},
};
use exchange_proto::{
    convert::{
        RECEIVED_REPRESENTING_IDS,
        model::{AttachData, Attachment, MessageContent, PropBag as ContentBag},
    },
    mapi::{
        ErrorCode,
        prop::{OwnedPropValue, PropId, PropKey, PropKeyRef, PropTag, tags},
    },
};
use smallvec::SmallVec;
use std::{sync::Arc, time::Duration};

const STAGED_TTL: Duration = Duration::from_secs(15 * 60);
const VALUE_OVERHEAD: u64 = 16;
pub const MAX_STAGED_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_STAGED_OBJECTS: usize = 256;
const INLINE_HELD: usize = 32;
const INLINE_TOUCHED_KEYS: usize = 8;
const MAX_TOUCHED_KEYS: usize = 64;
const FLAG_KEYS: [PropId; 3] = [
    tags::MESSAGE_FLAGS.id(),
    tags::READ.id(),
    tags::FLAG_STATUS.id(),
];

pub struct StagedContent {
    objects: Vec<StagedEntry>,
    total: u64,
    message_cap: u64,
    reservation: MemoryReservation,
}

struct StagedEntry {
    id: u32,
    charge: u64,
    object: StagedObject,
}

pub enum StagedObject {
    Message(Box<StagedMessage>),
    Stream(Vec<u8>),
    Transfer(Box<TransferContext>),
}

pub struct StagedMessage {
    pub content: Arc<MessageContent>,
    pub base: Option<MapiId>,
    pub associated: bool,
    pub next_attachment: u32,
    pub unsaved: SmallVec<[u32; 4]>,
    pub unsaved_embedded: UnsavedEmbedded,
    pub touched: Touched,
    pub flags_touched: TouchedFlags,
    pub categories_touched: bool,
    pub representing_touched: TouchedRepresenting,
    pub origin: Option<u64>,
    pub change: Option<u64>,
    pub row: RowBaseline,
    pub failed: SmallVec<[FailedCommit; 1]>,
    pub import: Option<Box<MessageImport>>,
}

pub struct MessageImport {
    pub collector: u32,
    pub version: ConflictState,
    pub item: Option<u32>,
    pub resolution: ImportResolution,
    pub stored_change: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportResolution {
    Newer,
    Merged,
    ForeignKey,
}

impl ImportResolution {
    pub fn recorded(self, change: Option<u64>, id: MapiId) -> (Option<u64>, Option<MapiId>) {
        match self {
            ImportResolution::Newer => (change, Some(id)),
            ImportResolution::Merged => (None, Some(id)),
            ImportResolution::ForeignKey => (change, None),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailedCommit {
    pub code: ErrorCode,
    pub attachment: Option<u32>,
    pub prop: PropId,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TouchedFlags(u8);

fn key_bit(ids: &[PropId], key: PropKeyRef<'_>) -> Option<u8> {
    match key {
        PropKeyRef::Tag(id) => ids
            .iter()
            .position(|candidate| *candidate == id)
            .map(|index| 1 << index),
        PropKeyRef::Lid { .. } | PropKeyRef::Name { .. } => None,
    }
}

impl TouchedFlags {
    pub const ALL: TouchedFlags = TouchedFlags(u8::MAX);

    fn bit(key: PropKeyRef<'_>) -> Option<u8> {
        key_bit(&FLAG_KEYS, key)
    }

    pub fn is_flag_key(key: PropKeyRef<'_>) -> bool {
        Self::bit(key).is_some()
    }

    pub fn contains(self, tag: PropTag) -> bool {
        Self::bit(PropKeyRef::Tag(tag.id())).is_some_and(|bit| self.0 & bit != 0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TouchedRepresenting(u8);

impl TouchedRepresenting {
    pub const ALL: TouchedRepresenting = TouchedRepresenting(u8::MAX);

    fn insert(&mut self, key: PropKeyRef<'_>) {
        if let Some(bit) = key_bit(&RECEIVED_REPRESENTING_IDS, key) {
            self.0 |= bit;
        }
    }

    pub fn contains(self, id: PropId) -> bool {
        key_bit(&RECEIVED_REPRESENTING_IDS, PropKeyRef::Tag(id))
            .is_some_and(|bit| self.0 & bit != 0)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct UnsavedEmbedded(Vec<Box<[u32]>>);

impl UnsavedEmbedded {
    pub fn record(&mut self, path: &[u32]) {
        if !self.contains(path) {
            self.0.push(path.into());
        }
    }

    pub fn contains(&self, path: &[u32]) -> bool {
        self.0.iter().any(|unsaved| **unsaved == *path)
    }

    pub fn saved(&mut self, path: &[u32]) {
        self.0.retain(|unsaved| **unsaved != *path);
    }

    pub fn forget_under(&mut self, path: &[u32], number: Option<u32>) {
        self.0.retain(|unsaved| {
            !unsaved
                .strip_prefix(path)
                .and_then(<[u32]>::first)
                .is_some_and(|child| number.is_none_or(|number| number == *child))
        });
    }

    fn take_outermost(&mut self) -> Option<Box<[u32]>> {
        let (position, _) = self
            .0
            .iter()
            .enumerate()
            .min_by_key(|(_, path)| path.len())?;
        Some(self.0.swap_remove(position))
    }
}

pub enum EmbeddedDiscard<'p> {
    Released(&'p [u32]),
    Committed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Touched {
    Keys(SmallVec<[PropKey; INLINE_TOUCHED_KEYS]>),
    Structure,
}

pub struct StagedSlot<'x> {
    server: &'x Server,
    account_id: u32,
    session: u128,
    content: Option<StagedContent>,
}

impl StagedMessage {
    pub fn new(content: Arc<MessageContent>, base: Option<MapiId>, associated: bool) -> Self {
        StagedMessage {
            next_attachment: u32::try_from(content.attachments.len()).unwrap_or(u32::MAX),
            content,
            base,
            associated,
            unsaved: SmallVec::new(),
            unsaved_embedded: UnsavedEmbedded::default(),
            touched: Touched::Keys(SmallVec::new()),
            flags_touched: TouchedFlags::default(),
            categories_touched: false,
            representing_touched: TouchedRepresenting::default(),
            origin: None,
            change: None,
            row: RowBaseline::Untracked,
            failed: SmallVec::new(),
            import: None,
        }
    }

    pub fn edit_key(&mut self, key: PropKeyRef<'_>) -> &mut MessageContent {
        if let Some(bit) = TouchedFlags::bit(key) {
            self.flags_touched.0 |= bit;
        } else if is_category(key) {
            self.categories_touched = true;
        } else {
            self.representing_touched.insert(key);
            if let Touched::Keys(keys) = &mut self.touched
                && !keys.iter().any(|touched| touched.as_ref() == key)
            {
                if keys.len() < MAX_TOUCHED_KEYS {
                    keys.push(key.to_key());
                } else {
                    self.touched = Touched::Structure;
                }
            }
        }
        Arc::make_mut(&mut self.content)
    }

    pub fn edit_structure(&mut self) -> &mut MessageContent {
        self.touched = Touched::Structure;
        Arc::make_mut(&mut self.content)
    }

    pub fn content_at(&self, path: &[u32]) -> Result<&MessageContent, ErrorCode> {
        embedded(&self.content, path).ok_or(ErrorCode::OBJECT_DELETED)
    }

    pub fn edit_at(&mut self, path: &[u32]) -> Result<&mut MessageContent, ErrorCode> {
        embedded_mut(self.edit_structure(), path).ok_or(ErrorCode::OBJECT_DELETED)
    }

    pub fn edit_key_at(
        &mut self,
        path: &[u32],
        key: PropKeyRef<'_>,
    ) -> Result<&mut MessageContent, ErrorCode> {
        if path.is_empty() {
            Ok(self.edit_key(key))
        } else {
            self.edit_at(path)
        }
    }

    pub fn discard_embedded(&mut self, path: &[u32]) -> u64 {
        let Some((number, parent)) = path.split_last() else {
            return 0;
        };
        self.unsaved_embedded.forget_under(parent, Some(*number));
        let removed = match self
            .content_at(parent)
            .ok()
            .and_then(|content| attachment_at(content, *number))
        {
            Some(Attachment {
                data: AttachData::Embedded(message),
                ..
            }) => content_size(message),
            _ => return 0,
        };
        if let Some(item) = self
            .edit_at(parent)
            .ok()
            .and_then(|content| attachment_mut(content, *number))
        {
            item.data = AttachData::None;
        }
        removed
    }

    pub fn discard_unsaved_embedded(&mut self) -> u64 {
        let mut removed = 0u64;
        while let Some(path) = self.unsaved_embedded.take_outermost() {
            removed = removed.saturating_add(self.discard_embedded(&path));
        }
        removed
    }

    pub fn fail_commit(&mut self, failure: FailedCommit) {
        self.clear_failed(failure.attachment, |prop| prop == failure.prop);
        self.failed.push(failure);
    }

    pub fn clear_failed(&mut self, attachment: Option<u32>, cleared: impl Fn(PropId) -> bool) {
        self.failed
            .retain(|failure| failure.attachment != attachment || !cleared(failure.prop));
    }

    pub fn saved(&mut self, base: MapiId) {
        self.base = Some(base);
        self.touched = Touched::Keys(SmallVec::new());
        self.flags_touched = TouchedFlags::default();
        self.categories_touched = false;
        self.representing_touched = TouchedRepresenting::default();
        self.import = None;
    }
}

impl StagedContent {
    fn new(server: &Server) -> Self {
        StagedContent {
            objects: Vec::new(),
            total: 0,
            message_cap: MAX_STAGED_BYTES
                .min(u64::try_from(server.core.email.mail_max_size).unwrap_or(u64::MAX)),
            reservation: server.memory_reservation(MemoryClass::Read),
        }
    }

    pub fn message_cap(&self) -> u64 {
        self.message_cap
    }

    pub fn headroom(&self) -> u64 {
        self.message_cap
            .min(MAX_STAGED_BYTES.saturating_sub(self.total))
    }

    pub fn reserve_for(&mut self, charge: u64) -> Result<(), ErrorCode> {
        if charge > self.message_cap {
            return Err(ErrorCode::TOO_BIG);
        }
        if self.objects.len() >= MAX_STAGED_OBJECTS {
            return Err(ErrorCode::TOO_MANY_OPEN_OBJECTS);
        }
        let total = self.total.saturating_add(charge);
        if total > MAX_STAGED_BYTES || !self.reservation.reserve_to(total) {
            return Err(ErrorCode::NOT_ENOUGH_MEMORY);
        }
        Ok(())
    }

    fn entry(&mut self, id: u32) -> Option<&mut StagedEntry> {
        self.objects.iter_mut().find(|entry| entry.id == id)
    }

    pub fn message(&mut self, id: u32) -> Option<&mut StagedMessage> {
        match &mut self.entry(id)?.object {
            StagedObject::Message(message) => Some(message),
            StagedObject::Stream(_) | StagedObject::Transfer(_) => None,
        }
    }

    pub fn stream(&mut self, id: u32) -> Option<&mut Vec<u8>> {
        match &mut self.entry(id)?.object {
            StagedObject::Stream(bytes) => Some(bytes),
            StagedObject::Message(_) | StagedObject::Transfer(_) => None,
        }
    }

    pub fn transfer(&mut self, id: u32) -> Option<&mut TransferContext> {
        match &mut self.entry(id)?.object {
            StagedObject::Transfer(context) => Some(context),
            StagedObject::Message(_) | StagedObject::Stream(_) => None,
        }
    }

    pub fn insert(&mut self, id: u32, object: StagedObject, charge: u64) -> Result<(), ErrorCode> {
        if charge > self.message_cap {
            return Err(ErrorCode::TOO_BIG);
        }
        self.remove(id);
        if self.objects.len() >= MAX_STAGED_OBJECTS {
            return Err(ErrorCode::TOO_MANY_OPEN_OBJECTS);
        }
        self.reserve(charge)?;
        self.objects.push(StagedEntry { id, charge, object });
        Ok(())
    }

    pub fn set_charge(&mut self, id: u32, charge: u64) -> Result<(), ErrorCode> {
        let previous = self.entry(id).ok_or(ErrorCode::NULL_OBJECT)?.charge;
        self.recharge(
            id,
            charge.saturating_sub(previous),
            previous.saturating_sub(charge),
        )
    }

    pub fn charge(&mut self, id: u32, extra: u64) -> Result<(), ErrorCode> {
        self.recharge(id, extra, 0)
    }

    pub fn recharge(&mut self, id: u32, added: u64, removed: u64) -> Result<(), ErrorCode> {
        let cap = self.message_cap;
        let entry = self.entry(id).ok_or(ErrorCode::NULL_OBJECT)?;
        let previous = entry.charge;
        let charge = previous.saturating_add(added).saturating_sub(removed);
        if charge > cap {
            return Err(ErrorCode::TOO_BIG);
        }
        if charge > previous {
            self.reserve(charge - previous)?;
        } else {
            self.total = self.total.saturating_sub(previous - charge);
            self.reservation.shrink_to(self.total);
        }
        if let Some(entry) = self.entry(id) {
            entry.charge = charge;
        }
        Ok(())
    }

    fn reserve(&mut self, extra: u64) -> Result<(), ErrorCode> {
        let total = self.total.saturating_add(extra);
        if total > MAX_STAGED_BYTES || !self.reservation.reserve_to(total) {
            return Err(ErrorCode::NOT_ENOUGH_MEMORY);
        }
        self.total = total;
        Ok(())
    }

    pub fn discard_embedded(
        &mut self,
        id: u32,
        discard: EmbeddedDiscard<'_>,
    ) -> Result<(), ErrorCode> {
        let removed = match (self.message(id), discard) {
            (Some(message), EmbeddedDiscard::Released(path))
                if message.unsaved_embedded.contains(path) =>
            {
                message.discard_embedded(path)
            }
            (Some(message), EmbeddedDiscard::Committed) => message.discard_unsaved_embedded(),
            _ => return Ok(()),
        };
        if removed > 0 {
            self.recharge(id, 0, removed)
        } else {
            Ok(())
        }
    }

    pub fn remove(&mut self, id: u32) -> Option<StagedObject> {
        let position = self.objects.iter().position(|entry| entry.id == id)?;
        let entry = self.objects.swap_remove(position);
        self.total = self.total.saturating_sub(entry.charge);
        self.reservation.shrink_to(self.total);
        Some(entry.object)
    }

    fn retain_held(&mut self, state: &EmsmdbState) {
        if self.objects.is_empty() {
            return;
        }
        let mut held: SmallVec<[u32; INLINE_HELD]> = state.held_staged().collect();
        held.sort_unstable();
        let mut released = 0u64;
        self.objects.retain(|entry| {
            let held = held.binary_search(&entry.id).is_ok();
            if !held {
                released = released.saturating_add(entry.charge);
            }
            held
        });
        if released > 0 {
            self.total = self.total.saturating_sub(released);
            self.reservation.shrink_to(self.total);
        }
    }
}

impl<'x> StagedSlot<'x> {
    pub fn new(server: &'x Server, account_id: u32, session: u128) -> Self {
        StagedSlot {
            server,
            account_id,
            session,
            content: None,
        }
    }

    fn checkout(&mut self, state: &EmsmdbState) -> &mut StagedContent {
        let content = match self.content.take() {
            Some(content) => content,
            None => {
                let mut content = self
                    .server
                    .exchange_session::<StagedContent>(self.account_id, self.session)
                    .and_then(|stored| {
                        self.server.remove_exchange_session::<StagedContent>(
                            self.account_id,
                            self.session,
                        );
                        Arc::try_unwrap(stored).ok()
                    })
                    .unwrap_or_else(|| StagedContent::new(self.server));
                content.retain_held(state);
                content
            }
        };
        self.content.insert(content)
    }
}

impl Drop for StagedSlot<'_> {
    fn drop(&mut self) {
        if let Some(content) = self.content.take()
            && !content.objects.is_empty()
            && self
                .server
                .insert_exchange_session(
                    self.account_id,
                    self.session,
                    Arc::new(content),
                    STAGED_TTL,
                )
                .is_err()
        {
            trc::event!(
                Limit(trc::LimitEvent::MemoryBudget),
                AccountId = self.account_id,
                Details = "MAPI staged objects dropped"
            );
        }
    }
}

pub fn forget_staged_content(server: &Server, account_id: u32, session: u128) {
    server.remove_exchange_session::<StagedContent>(account_id, session);
}

impl RopContext<'_, '_> {
    pub fn staged(&mut self) -> &mut StagedContent {
        self.staged.checkout(self.state)
    }

    pub fn prune_staged(&mut self) {
        let state = &*self.state;
        self.staged.checkout(state).retain_held(state);
    }

    pub fn release_embedded(&mut self, handle: Handle) {
        let state = &*self.state;
        if let Some(ServerObject::Message(message)) = state.get(handle)
            && let Some(id) = message.staged
            && !message.path.is_empty()
        {
            let content = self.staged.checkout(state);
            if content
                .message(id)
                .is_some_and(|staged| staged.unsaved_embedded.contains(&message.path))
                && !state.shares_embedded(id, &message.path)
            {
                content
                    .discard_embedded(id, EmbeddedDiscard::Released(&message.path))
                    .unwrap_or_default();
            }
        }
    }

    pub fn staged_message(
        &mut self,
        message: &MessageObject,
    ) -> Result<&mut StagedMessage, RopError> {
        let id = message.staged.ok_or(ErrorCode::NULL_OBJECT)?;
        self.staged()
            .message(id)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))
    }

    pub fn staged_root(&mut self, id: u32) -> Result<Arc<MessageContent>, RopError> {
        self.staged()
            .message(id)
            .map(|message| message.content.clone())
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))
    }
}

pub fn value_size(value: &OwnedPropValue) -> u64 {
    let bytes = match value {
        OwnedPropValue::String8(bytes)
        | OwnedPropValue::ServerId(bytes)
        | OwnedPropValue::Restriction(bytes)
        | OwnedPropValue::RuleAction(bytes) => bytes.len(),
        OwnedPropValue::Unicode(text) => text.len(),
        OwnedPropValue::Binary(bytes) => bytes.len(),
        OwnedPropValue::MvString8(items) => items.iter().map(|item| item.len()).sum(),
        OwnedPropValue::MvUnicode(items) => items.iter().map(|item| item.len()).sum(),
        OwnedPropValue::MvBinary(items) => items.iter().map(|item| item.len()).sum(),
        OwnedPropValue::MvI16(items) => size_of_val::<[i16]>(items),
        OwnedPropValue::MvI32(items) => size_of_val::<[i32]>(items),
        OwnedPropValue::MvF32(items) => size_of_val::<[f32]>(items),
        OwnedPropValue::MvF64(items) | OwnedPropValue::MvAppTime(items) => {
            size_of_val::<[f64]>(items)
        }
        OwnedPropValue::MvCurrency(items) | OwnedPropValue::MvI64(items) => {
            size_of_val::<[i64]>(items)
        }
        OwnedPropValue::MvTime(items) => size_of_val(items.as_ref()),
        OwnedPropValue::MvGuid(items) => size_of_val(items.as_ref()),
        _ => 8,
    };
    u64::try_from(bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(VALUE_OVERHEAD)
}

pub fn bag_size(bag: &ContentBag) -> u64 {
    bag.iter().fold(0u64, |total, (_, value)| {
        total.saturating_add(value_size(value))
    })
}

pub fn content_size(content: &MessageContent) -> u64 {
    let recipients = content
        .recipients
        .iter()
        .fold(0u64, |total, bag| total.saturating_add(bag_size(bag)));
    let attachments = content.attachments.iter().fold(0u64, |total, item| {
        total.saturating_add(attachment_size(item))
    });
    bag_size(&content.props)
        .saturating_add(recipients)
        .saturating_add(attachments)
}

pub fn attachment_size(item: &Attachment) -> u64 {
    let data = match &item.data {
        AttachData::Bytes(bytes) => u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        AttachData::Embedded(message) => content_size(message),
        AttachData::None | AttachData::Deferred(_) => 0,
    };
    bag_size(&item.props).saturating_add(data)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/staged/tests.rs"]
mod tests;
