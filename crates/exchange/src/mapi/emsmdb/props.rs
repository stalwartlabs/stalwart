/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    access::LogonAccess,
    execute::{RopContext, RopError, RopResult},
    state::ServerObject,
    store::{StoreView, push_user_entry_id, store_props},
};
use crate::{
    folders::rights::FolderRights,
    mapi::ids::{IdSpace, MapiId},
    vacation::vacation_in_effect,
};
use exchange_proto::{
    common::{FileTime, LeReader},
    ids::entryid::EntryId,
    mapi::{
        ErrorCode, MapiLimits,
        prop::{
            CodePage, CountWidth, OwnedPropValue, PropTag, PropType, PropValue, decode_value,
            encode_owned, encode_value,
            row::{RowOptions, RowSetLayout, RowWriter},
            tags,
        },
        rop::{
            DecodedRop, ResponseHeader,
            requests::{GetPropertiesAll, GetPropertiesSpecific},
            responses::{GetPropertiesListResponse, property_row_options},
            writer::{RopResponse, RopWriter},
        },
    },
};
use smallvec::SmallVec;
use std::ops::Range;
use store::write::now;
use types::type_state::DataType;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PropOut<'x> {
    Value(PropValue<'x>),
    Text(&'x str),
}

impl PropOut<'_> {
    fn ptype(&self) -> PropType {
        match self {
            PropOut::Value(value) => value.ptype(),
            PropOut::Text(_) => PropType::Unicode,
        }
    }

    pub fn matches(&self, requested: PropType) -> bool {
        let actual = self.ptype();
        requested == PropType::Unspecified
            || requested == actual
            || actual == PropType::Error
            || (actual == PropType::Unicode && requested == PropType::String8)
    }

    pub fn write_cell(row: &mut RowWriter<'_>, requested: PropTag, value: Option<&Self>) {
        match value {
            Some(value) if value.matches(requested.ptype()) => match value {
                PropOut::Value(value) => row.value(value),
                PropOut::Text(text) => row.unicode(text),
            },
            _ => row.missing(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PropDemand<'x> {
    All,
    Names,
    Tags(&'x [PropTag]),
}

impl PropDemand<'_> {
    pub fn wants_value(self, tag: PropTag) -> bool {
        match self {
            PropDemand::All => true,
            PropDemand::Names => false,
            PropDemand::Tags(tags) => tags.iter().any(|candidate| candidate.id() == tag.id()),
        }
    }
}

pub struct PropertiesAll<'x> {
    pub values: &'x [(PropTag, PropOut<'x>)],
    pub unicode: bool,
    pub size_limit: u16,
    pub code_page: CodePage,
}

impl PropertiesAll<'_> {
    fn encode_one(&self, out: &mut Vec<u8>, tag: PropTag, value: &PropOut<'_>) {
        let start = out.len();
        let ptype = match value {
            PropOut::Text(_) if !self.unicode => PropType::String8,
            value => value.ptype(),
        };
        out.extend_from_slice(&tag.with_type(ptype).0.to_le_bytes());
        let value_start = out.len();
        match value {
            PropOut::Value(value) => encode_value(out, value, CountWidth::Rop),
            PropOut::Text(text) if self.unicode => {
                out.reserve(text.len().saturating_mul(2).saturating_add(2));
                for unit in text.encode_utf16() {
                    out.extend_from_slice(&unit.to_le_bytes());
                }
                out.extend_from_slice(&[0, 0]);
            }
            PropOut::Text(text) => {
                self.code_page.narrow_str(text, usize::MAX, out);
                out.push(0);
            }
        }
        if self.size_limit != 0
            && out.len().saturating_sub(value_start) > usize::from(self.size_limit)
        {
            out.truncate(start);
            out.extend_from_slice(&tag.with_type(PropType::Error).0.to_le_bytes());
            out.extend_from_slice(&ErrorCode::NOT_ENOUGH_MEMORY.0.to_le_bytes());
        }
    }
}

impl RopResponse for PropertiesAll<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let values = self
            .values
            .get(..usize::from(u16::MAX))
            .unwrap_or(self.values);
        out.extend_from_slice(
            &u16::try_from(values.len())
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        for (tag, value) in values {
            self.encode_one(out, *tag, value);
        }
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.values.len().saturating_mul(16))
    }
}

#[derive(Debug, Clone)]
enum BagValue {
    I32(i32),
    I64(i64),
    Bool(bool),
    Text(Range<usize>),
    Binary(Range<usize>),
    Encoded(PropType, Range<usize>),
    Error(ErrorCode),
}

pub const MAX_INLINE_VALUE: usize = 0x8000;

#[derive(Debug, Default)]
pub struct PropBag {
    text: String,
    binary: Vec<u8>,
    values: SmallVec<[(PropTag, BagValue); 24]>,
}

impl PropBag {
    pub fn with_capacity(binary: usize) -> Self {
        PropBag {
            text: String::with_capacity(64),
            binary: Vec::with_capacity(binary),
            values: SmallVec::new(),
        }
    }

    pub fn push_i32(&mut self, tag: PropTag, value: i32) {
        self.values.push((tag, BagValue::I32(value)));
    }

    pub fn push_i64(&mut self, tag: PropTag, value: i64) {
        self.values.push((tag, BagValue::I64(value)));
    }

    pub fn push_bool(&mut self, tag: PropTag, value: bool) {
        self.values.push((tag, BagValue::Bool(value)));
    }

    pub fn push_error(&mut self, tag: PropTag, code: ErrorCode) {
        self.values.push((tag, BagValue::Error(code)));
    }

    pub fn push_text(&mut self, tag: PropTag, value: &str) {
        if value.len() > MAX_INLINE_VALUE {
            return self.push_error(tag, ErrorCode::NOT_ENOUGH_MEMORY);
        }
        let start = self.text.len();
        self.text.push_str(value);
        self.values
            .push((tag, BagValue::Text(start..self.text.len())));
    }

    pub fn push_binary(&mut self, tag: PropTag, bytes: &[u8]) {
        if bytes.len() > MAX_INLINE_VALUE {
            return self.push_error(tag, ErrorCode::NOT_ENOUGH_MEMORY);
        }
        let start = self.binary.len();
        self.binary.extend_from_slice(bytes);
        self.values
            .push((tag, BagValue::Binary(start..self.binary.len())));
    }

    pub fn push_binary_with(&mut self, tag: PropTag, encode: impl FnOnce(&mut Vec<u8>)) {
        let start = self.binary.len();
        encode(&mut self.binary);
        if self.binary.len() - start > MAX_INLINE_VALUE {
            self.binary.truncate(start);
            return self.push_error(tag, ErrorCode::NOT_ENOUGH_MEMORY);
        }
        self.values
            .push((tag, BagValue::Binary(start..self.binary.len())));
    }

    pub fn push_entry_id(&mut self, tag: PropTag, entry_id: &EntryId<'_>) {
        let start = self.binary.len();
        if entry_id.encode(&mut self.binary).is_ok() {
            self.values
                .push((tag, BagValue::Binary(start..self.binary.len())));
        } else {
            self.binary.truncate(start);
        }
    }

    pub fn push_time(&mut self, tag: PropTag, value: FileTime) {
        self.push_encoded(tag, &PropValue::Time(value));
    }

    fn push_encoded(&mut self, tag: PropTag, value: &PropValue<'_>) {
        let start = self.binary.len();
        encode_value(&mut self.binary, value, CountWidth::Rop);
        self.values.push((
            tag,
            BagValue::Encoded(value.ptype(), start..self.binary.len()),
        ));
    }

    pub fn push_out(&mut self, tag: PropTag, value: &PropOut<'_>) {
        match value {
            PropOut::Text(text) => self.push_text(tag, text),
            PropOut::Value(PropValue::I32(v)) => self.push_i32(tag, *v),
            PropOut::Value(PropValue::I64(v)) => self.push_i64(tag, *v),
            PropOut::Value(PropValue::Bool(v)) => self.push_bool(tag, *v),
            PropOut::Value(PropValue::Binary(v)) => self.push_binary(tag, v),
            PropOut::Value(PropValue::Error(code)) => self.push_error(tag, *code),
            PropOut::Value(value) => self.push_encoded(tag, value),
        }
    }

    pub fn push_owned(&mut self, tag: PropTag, value: &OwnedPropValue) {
        match value {
            OwnedPropValue::I32(v) => self.push_i32(tag, *v),
            OwnedPropValue::I64(v) => self.push_i64(tag, *v),
            OwnedPropValue::Bool(v) => self.push_bool(tag, *v),
            OwnedPropValue::Unicode(v) => self.push_text(tag, v),
            OwnedPropValue::Binary(v) => self.push_binary(tag, v),
            OwnedPropValue::Error(code) => self.push_error(tag, *code),
            OwnedPropValue::Null | OwnedPropValue::Object => {}
            value => {
                let start = self.binary.len();
                encode_owned(&mut self.binary, value, CountWidth::Rop);
                self.values.push((
                    tag,
                    BagValue::Encoded(value.ptype(), start..self.binary.len()),
                ));
            }
        }
    }

    pub fn remove(&mut self, tag: PropTag) {
        self.values
            .retain(|(candidate, _)| candidate.id() != tag.id());
    }

    pub fn contains(&self, tag: PropTag) -> bool {
        self.values
            .iter()
            .any(|(candidate, _)| candidate.id() == tag.id())
    }

    fn out(&self, value: &BagValue) -> PropOut<'_> {
        match value {
            BagValue::I32(v) => PropOut::Value(PropValue::I32(*v)),
            BagValue::I64(v) => PropOut::Value(PropValue::I64(*v)),
            BagValue::Bool(v) => PropOut::Value(PropValue::Bool(*v)),
            BagValue::Text(range) => {
                PropOut::Text(self.text.get(range.clone()).unwrap_or_default())
            }
            BagValue::Binary(range) => PropOut::Value(PropValue::Binary(
                self.binary.get(range.clone()).unwrap_or_default(),
            )),
            BagValue::Error(code) => PropOut::Value(PropValue::Error(*code)),
            BagValue::Encoded(ptype, range) => PropOut::Value(
                decode_value(
                    &mut LeReader::new(self.binary.get(range.clone()).unwrap_or_default()),
                    *ptype,
                    CountWidth::Rop,
                    &MapiLimits::DEFAULT,
                )
                .unwrap_or(PropValue::Error(ErrorCode::NOT_FOUND)),
            ),
        }
    }

    pub fn get(&self, tag: PropTag) -> Option<PropOut<'_>> {
        let mut same_id = None;
        for (candidate, value) in &self.values {
            if *candidate == tag {
                return Some(self.out(value));
            }
            if same_id.is_none() && candidate.id() == tag.id() {
                same_id = Some(value);
            }
        }
        same_id.map(|value| self.out(value))
    }

    pub fn tags(&self) -> impl Iterator<Item = PropTag> + '_ {
        self.values.iter().map(|(tag, _)| *tag)
    }

    pub fn all(&self) -> SmallVec<[(PropTag, PropOut<'_>); 24]> {
        self.values
            .iter()
            .map(|(tag, value)| (*tag, self.out(value)))
            .collect()
    }
}

impl RopContext<'_, '_> {
    pub fn code_page(&self) -> CodePage {
        CodePage(u16::try_from(self.state.code_page).unwrap_or(CodePage::WINDOWS_1252.0))
    }

    async fn property_source(
        &mut self,
        rop: &DecodedRop<'_>,
        demand: PropDemand<'_>,
    ) -> Result<PropBag, RopError> {
        let handle = self.input(rop.header.input_handle)?;
        match self.state.get(handle) {
            Some(ServerObject::Logon(logon)) => {
                let mailbox_id = logon.mailbox_id;
                let tree = self.folder_tree(mailbox_id).await?;
                let mailbox = self.mailbox(mailbox_id).await?;
                let view = if LogonAccess::reads_all(self.logon_access(mailbox_id)) {
                    StoreView::Full
                } else {
                    StoreView::Identity
                };
                let server = self.request.server;
                let mut bag = store_props(server, &mailbox, &tree, view).await?;
                if demand.wants_value(tags::USER_ENTRY_ID) {
                    push_user_entry_id(server, self.request.access_token.account_id(), &mut bag)
                        .await?;
                }
                if view == StoreView::Full {
                    let out_of_office = self.types.contains(DataType::VacationResponse)
                        && demand.wants_value(tags::OUT_OF_OFFICE_STATE)
                        && vacation_in_effect(server, mailbox_id, now()).await?;
                    bag.push_bool(tags::OUT_OF_OFFICE_STATE, out_of_office);
                }
                Ok(bag)
            }
            Some(ServerObject::Folder(folder)) => {
                let folder = *folder;
                self.folder_props(&folder, demand).await
            }
            Some(ServerObject::Message(message)) => {
                let message = message.without_columns();
                let mut bag = self.message_props(&message).await?;
                if (matches!(demand, PropDemand::Names)
                    || demand.wants_value(tags::LAST_MODIFIER_NAME))
                    && !bag.contains(tags::LAST_MODIFIER_NAME)
                {
                    let account = self.request.server.account(message.mailbox_id).await?;
                    bag.push_text(
                        tags::LAST_MODIFIER_NAME,
                        account.description.as_deref().unwrap_or(&account.name),
                    );
                }
                if let PropDemand::Names = demand {
                    if message.path.is_empty()
                        && message.id().is_some_and(|id| {
                            matches!(
                                id.space,
                                IdSpace::Email | IdSpace::Fai | IdSpace::Event | IdSpace::Contact
                            )
                        })
                    {
                        bag.push_binary(tags::CHANGE_KEY, &[]);
                        bag.push_binary(tags::PREDECESSOR_CHANGE_LIST, &[]);
                    }
                } else if demand.wants_value(tags::CHANGE_KEY)
                    || demand.wants_value(tags::PREDECESSOR_CHANGE_LIST)
                {
                    self.push_versions(&message, &mut bag).await?;
                }
                if let Some(node) = MapiId::from_counter(message.folder).and_then(MapiId::to_node) {
                    let associated = message.id().is_some_and(|id| id.space == IdSpace::Fai);
                    let rights = if self.request.access_token.is_account_id(message.mailbox_id) {
                        FolderRights::OWNER
                    } else {
                        self.folder_rights(message.mailbox_id, node).await?
                    };
                    rights.push_message_props(node, associated, &mut bag);
                }
                Ok(bag)
            }
            Some(ServerObject::Attachment(attachment)) => {
                let attachment = attachment.as_ref().clone();
                let mut bag = self.attachment_props(&attachment).await?;
                let message = &attachment.message;
                let created = match message.staged.filter(|_| message.path.is_empty()) {
                    Some(id) => self
                        .staged()
                        .message(id)
                        .is_some_and(|staged| staged.unsaved.contains(&attachment.number)),
                    None => false,
                };
                let writable = if created {
                    false
                } else if self.request.access_token.is_account_id(message.mailbox_id) {
                    true
                } else if let Some(node) =
                    MapiId::from_counter(message.folder).and_then(MapiId::to_node)
                {
                    let associated = message.id().is_some_and(|id| id.space == IdSpace::Fai);
                    self.folder_rights(message.mailbox_id, node)
                        .await?
                        .message_access(node, associated)
                        & FolderRights::ACCESS_MODIFY
                        != 0
                } else {
                    false
                };
                bag.push_i32(tags::ACCESS_LEVEL, i32::from(writable));
                Ok(bag)
            }
            Some(
                ServerObject::Table(_)
                | ServerObject::Stream(_)
                | ServerObject::Subscription(_)
                | ServerObject::Transfer(_),
            ) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        }
    }

    pub async fn get_properties_specific(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &GetPropertiesSpecific<'_>,
    ) -> RopResult {
        let columns: SmallVec<[PropTag; 32]> = request.property_tags.iter().collect();
        let source = self
            .property_source(rop, PropDemand::Tags(&columns))
            .await?;
        let mut limit = 0;
        loop {
            let mark = self.writer.mark();
            let options = property_row_options(request.want_unicode, limit, self.code_page());
            match write_specific(&mut self.writer, rop, index, options, &columns, &source) {
                Err(RopError::Overflow) => {
                    self.writer.rollback(mark);
                    limit =
                        shrink_limit(limit, self.writer.remaining()).ok_or(RopError::Overflow)?;
                }
                other => return other,
            }
        }
    }

    pub async fn get_properties_all(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &GetPropertiesAll,
    ) -> RopResult {
        let source = self.property_source(rop, PropDemand::All).await?;
        let code_page = self.code_page();
        let values = source.all();
        let mut size_limit = 0;
        loop {
            match self.respond(
                rop,
                index,
                &PropertiesAll {
                    values: &values,
                    unicode: request.want_unicode,
                    size_limit,
                    code_page,
                },
            ) {
                Err(RopError::Overflow) => {
                    size_limit = shrink_limit(size_limit, self.writer.remaining())
                        .ok_or(RopError::Overflow)?;
                }
                other => return other,
            }
        }
    }

    pub async fn get_properties_list(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        let source = self.property_source(rop, PropDemand::Names).await?;
        let tags: SmallVec<[PropTag; 32]> = source.tags().collect();
        self.respond(
            rop,
            index,
            &GetPropertiesListResponse {
                property_tags: &tags,
            },
        )
    }
}

fn shrink_limit(limit: u16, room: usize) -> Option<u16> {
    let room = u16::try_from(room / 2).unwrap_or(u16::MAX);
    let next = if limit == 0 {
        room
    } else {
        (limit / 2).min(room)
    };
    (next > 0 && (limit == 0 || next < limit)).then_some(next)
}

fn write_specific(
    writer: &mut RopWriter<'_>,
    rop: &DecodedRop<'_>,
    index: u8,
    options: RowOptions,
    columns: &[PropTag],
    source: &PropBag,
) -> RopResult {
    let mut rows = writer.row_writer(
        ResponseHeader::new(rop.header.id.response_id(), index, ErrorCode::SUCCESS),
        RowSetLayout::Single,
        options,
    )?;
    let mut row = rows.row(columns, true)?;
    for tag in columns {
        PropOut::write_cell(&mut row, *tag, source.get(*tag).as_ref());
    }
    drop(row);
    rows.finish()?;
    Ok(())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/props/tests.rs"]
mod tests;
