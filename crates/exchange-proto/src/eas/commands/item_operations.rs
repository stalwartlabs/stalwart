/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use smallvec::SmallVec;

use super::appdata::{ApplicationData, MAX_LIST_ITEMS};
use super::sync::options::MAX_BODY_PREFERENCES;
use super::{
    Children, CommandError, Counter, ItemRange, MAX_ID_LEN, MAX_ITEM_OPERATIONS, MAX_LIST_LEN,
    MAX_LONG_ID_LEN, read_body_preference, read_bool, read_bytes, read_id, read_range, read_str,
    read_u8, required,
};
use crate::common::time::EasDateForm;
use crate::eas::status::ItemOperationsStatus;
use crate::eas::tokens::tag::{
    airsync as sync, airsyncbase as asb, document_library as dl, item_operations as io,
    rights_management as rm, search,
};
use crate::eas::tokens::{ProtocolVersion, Tag};
use crate::eas::types::{BodyPreference, Class, EasDateTime};
use crate::eas::wbxml::{Decoder, Encoder};

pub const MAX_STORE_LEN: usize = 256;
pub const MAX_USER_NAME_LEN: usize = 100;
pub const MAX_PASSWORD_LEN: usize = 256;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchOptions<'a> {
    pub schema: Option<SmallVec<[Tag; 16]>>,
    pub range: Option<ItemRange>,
    pub user_name: Option<Cow<'a, str>>,
    pub password: Option<Cow<'a, str>>,
    pub body_preferences: SmallVec<[BodyPreference; 2]>,
    pub body_part_preferences: SmallVec<[BodyPreference; 1]>,
    pub mime_support: Option<u8>,
    pub rights_management_support: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest<'a> {
    pub store: Cow<'a, str>,
    pub collection_id: Option<Cow<'a, str>>,
    pub server_id: Option<Cow<'a, str>>,
    pub long_id: Option<Cow<'a, str>>,
    pub link_id: Option<Cow<'a, str>>,
    pub file_reference: Option<Cow<'a, str>>,
    pub remove_rights_management_protection: bool,
    pub options: FetchOptions<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemOperation<'a> {
    EmptyFolderContents {
        collection_id: Cow<'a, str>,
        delete_sub_folders: bool,
    },
    Fetch(Box<FetchRequest<'a>>),
    Move {
        conversation_id: Cow<'a, [u8]>,
        dst_fld_id: Cow<'a, str>,
        move_always: MoveAlways,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MoveAlways {
    #[default]
    Missing,
    Set,
    Malformed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemOperationsRequest<'a> {
    pub operations: Vec<ItemOperation<'a>>,
    pub accept_multipart: bool,
}

impl<'a> ItemOperationsRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut request = ItemOperationsRequest::default();
        let mut counter = Counter::new(MAX_ITEM_OPERATIONS);
        let mut children = Children::root(dec, io::ITEM_OPERATIONS)?;
        while let Some(tag) = children.next(dec)? {
            let operation = match tag {
                io::EMPTY_FOLDER_CONTENTS => parse_empty_folder(dec)?,
                io::FETCH => ItemOperation::Fetch(Box::new(FetchRequest::parse(dec)?)),
                io::MOVE => parse_move(dec)?,
                _ => continue,
            };
            counter.bump(tag)?;
            request.operations.push(operation);
        }
        if request.operations.is_empty() {
            return Err(CommandError::Missing { tag: io::FETCH });
        }
        Ok(request)
    }
}

fn has_child(dec: &mut Decoder<'_>, expected: Tag) -> Result<bool, CommandError> {
    let mut found = false;
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        found |= tag == expected;
    }
    Ok(found)
}

fn parse_empty_folder<'a>(dec: &mut Decoder<'a>) -> Result<ItemOperation<'a>, CommandError> {
    let mut collection_id = None;
    let mut delete_sub_folders = false;
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        match tag {
            sync::COLLECTION_ID => collection_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
            io::OPTIONS => delete_sub_folders |= has_child(dec, io::DELETE_SUB_FOLDERS)?,
            _ => {}
        }
    }
    Ok(ItemOperation::EmptyFolderContents {
        collection_id: required(collection_id, sync::COLLECTION_ID)?,
        delete_sub_folders,
    })
}

fn parse_move<'a>(dec: &mut Decoder<'a>) -> Result<ItemOperation<'a>, CommandError> {
    let mut conversation_id = None;
    let mut dst_fld_id = None;
    let mut move_always = MoveAlways::Missing;
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        match tag {
            io::CONVERSATION_ID => conversation_id = Some(read_bytes(dec, tag)?),
            io::DST_FLD_ID => dst_fld_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
            io::OPTIONS => parse_move_options(dec, &mut move_always)?,
            _ => {}
        }
    }
    Ok(ItemOperation::Move {
        conversation_id: required(conversation_id, io::CONVERSATION_ID)?,
        dst_fld_id: required(dst_fld_id, io::DST_FLD_ID)?,
        move_always,
    })
}

fn parse_move_options(
    dec: &mut Decoder<'_>,
    move_always: &mut MoveAlways,
) -> Result<(), CommandError> {
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        if tag == io::MOVE_ALWAYS {
            let (_, content) = dec.element_bytes()?;
            if *move_always != MoveAlways::Malformed {
                *move_always = if content.is_empty() {
                    MoveAlways::Set
                } else {
                    MoveAlways::Malformed
                };
            }
        }
    }
    Ok(())
}

impl<'a> FetchRequest<'a> {
    fn parse(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut store = None;
        let mut fetch = FetchRequest {
            store: Cow::Borrowed(""),
            collection_id: None,
            server_id: None,
            long_id: None,
            link_id: None,
            file_reference: None,
            remove_rights_management_protection: false,
            options: FetchOptions::default(),
        };
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                io::STORE => store = Some(read_id(dec, tag, MAX_STORE_LEN)?),
                sync::COLLECTION_ID => fetch.collection_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                sync::SERVER_ID => fetch.server_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                search::LONG_ID => fetch.long_id = Some(read_id(dec, tag, MAX_LONG_ID_LEN)?),
                dl::LINK_ID => fetch.link_id = Some(read_str(dec, tag)?),
                asb::FILE_REFERENCE if fetch.file_reference.is_some() => {
                    return Err(CommandError::InvalidValue { tag });
                }
                asb::FILE_REFERENCE => fetch.file_reference = Some(read_str(dec, tag)?),
                rm::REMOVE_RIGHTS_MANAGEMENT_PROTECTION => {
                    dec.skip_element()?;
                    fetch.remove_rights_management_protection = true;
                }
                io::OPTIONS => fetch.options = FetchOptions::parse(dec)?,
                _ => {}
            }
        }
        fetch.store = required(store, io::STORE)?;
        Ok(fetch)
    }
}

impl<'a> FetchOptions<'a> {
    fn parse(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut options = FetchOptions::default();
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                io::SCHEMA => {
                    let schema = options.schema.get_or_insert_with(SmallVec::new);
                    let mut properties = Children::of(dec);
                    while let Some(property) = properties.next(dec)? {
                        if schema.len() >= MAX_LIST_ITEMS {
                            return Err(CommandError::TooMany {
                                tag,
                                limit: MAX_LIST_LEN,
                            });
                        }
                        schema.push(property);
                    }
                }
                io::RANGE => options.range = Some(read_range(dec, tag)?),
                io::USER_NAME => options.user_name = Some(read_id(dec, tag, MAX_USER_NAME_LEN)?),
                io::PASSWORD => options.password = Some(read_id(dec, tag, MAX_PASSWORD_LEN)?),
                asb::BODY_PREFERENCE => {
                    if options.body_preferences.len() >= usize::from(MAX_BODY_PREFERENCES) {
                        return Err(CommandError::TooMany {
                            tag,
                            limit: u32::from(MAX_BODY_PREFERENCES),
                        });
                    }
                    options.body_preferences.push(read_body_preference(dec)?);
                }
                asb::BODY_PART_PREFERENCE => {
                    if options.body_part_preferences.len() >= usize::from(MAX_BODY_PREFERENCES) {
                        return Err(CommandError::TooMany {
                            tag,
                            limit: u32::from(MAX_BODY_PREFERENCES),
                        });
                    }
                    options
                        .body_part_preferences
                        .push(read_body_preference(dec)?);
                }
                sync::MIME_SUPPORT => options.mime_support = Some(read_u8(dec, tag)?),
                rm::RIGHTS_MANAGEMENT_SUPPORT => {
                    options.rights_management_support = Some(read_bool(dec, tag)?)
                }
                _ => {}
            }
        }
        Ok(options)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileProperties<'x> {
    pub content_type: Option<&'x str>,
    pub range: Option<ItemRange>,
    pub total: Option<u64>,
    pub data: Option<&'x [u8]>,
    pub part: Option<u32>,
    pub version: Option<EasDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FetchProperties<'x> {
    Item(ApplicationData<'x>),
    File(FileProperties<'x>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FetchResult<'x> {
    pub status: ItemOperationsStatus,
    pub collection_id: Option<&'x str>,
    pub server_id: Option<&'x str>,
    pub long_id: Option<&'x str>,
    pub class: Option<Class>,
    pub link_id: Option<&'x str>,
    pub file_reference: Option<&'x str>,
    pub properties: Option<FetchProperties<'x>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ItemOperationResult<'x> {
    Move {
        status: ItemOperationsStatus,
        conversation_id: &'x [u8],
    },
    EmptyFolderContents {
        status: ItemOperationsStatus,
        collection_id: &'x str,
    },
    Fetch(FetchResult<'x>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ItemOperationsResponse<'x> {
    pub status: ItemOperationsStatus,
    pub results: Vec<ItemOperationResult<'x>>,
}

impl ItemOperationsResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(io::ITEM_OPERATIONS)
            .text_u64(io::STATUS, u64::from(self.status.0));
        if !self.results.is_empty() {
            enc.start(io::RESPONSE);
            for result in &self.results {
                result.encode(enc);
            }
            enc.end();
        }
        enc.end();
    }
}

impl ItemOperationResult<'_> {
    fn encode(&self, enc: &mut Encoder) {
        match self {
            ItemOperationResult::Move {
                status,
                conversation_id,
            } => {
                enc.start(io::MOVE)
                    .text_u64(io::STATUS, u64::from(status.0))
                    .opaque(io::CONVERSATION_ID, conversation_id)
                    .end();
            }
            ItemOperationResult::EmptyFolderContents {
                status,
                collection_id,
            } => {
                enc.start(io::EMPTY_FOLDER_CONTENTS)
                    .text_u64(io::STATUS, u64::from(status.0))
                    .text_str(sync::COLLECTION_ID, collection_id)
                    .end();
            }
            ItemOperationResult::Fetch(fetch) => fetch.encode(enc),
        }
    }
}

impl FetchResult<'_> {
    fn encode(&self, enc: &mut Encoder) {
        enc.start(io::FETCH)
            .text_u64(io::STATUS, u64::from(self.status.0));
        for (tag, value) in [
            (sync::COLLECTION_ID, self.collection_id),
            (sync::SERVER_ID, self.server_id),
            (search::LONG_ID, self.long_id),
        ] {
            if let Some(value) = value {
                enc.text_str(tag, value);
            }
        }
        if let Some(class) = self.class
            && enc.allows(sync::CLASS)
        {
            enc.text_str(sync::CLASS, class.as_str());
        }
        for (tag, value) in [
            (dl::LINK_ID, self.link_id),
            (asb::FILE_REFERENCE, self.file_reference),
        ] {
            if let Some(value) = value {
                enc.text_str(tag, value);
            }
        }
        match &self.properties {
            Some(FetchProperties::Item(data)) => {
                enc.start(io::PROPERTIES);
                data.encode_fields(enc);
                enc.end();
            }
            Some(FetchProperties::File(file)) => file.encode(enc),
            None => {}
        }
        enc.end();
    }
}

impl FileProperties<'_> {
    fn encode(&self, enc: &mut Encoder) {
        enc.start(io::PROPERTIES);
        if let Some(content_type) = self.content_type {
            enc.text_str(asb::CONTENT_TYPE, content_type);
        }
        if let Some(range) = &self.range {
            range.encode(enc, io::RANGE);
        }
        if let Some(total) = self.total {
            enc.text_u64(io::TOTAL, total);
        }
        if let Some(data) = self.data {
            enc.text_base64(io::DATA, data);
        }
        if let Some(part) = self.part {
            enc.text_u64(io::PART, u64::from(part));
        }
        if let Some(version) = self.version {
            enc.text_with(io::VERSION, |out| {
                version.write(out, EasDateForm::Punctuated)
            });
        }
        enc.end();
    }
}
