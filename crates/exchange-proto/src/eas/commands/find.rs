/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::appdata::eas_struct;
use super::resolve_recipients::PictureOptions;
use super::search::GalEntry;
use super::{
    Children, CommandError, ItemRange, MAX_ID_LEN, read_id, read_range, read_str, read_u32,
    required,
};
use crate::eas::status::FindStatus;
use crate::eas::tokens::ProtocolVersion;
use crate::eas::tokens::tag::{airsync as sync, email, email2, find, item_operations as io};
use crate::eas::types::{Class, EasDateTime};
use crate::eas::wbxml::{Decoder, Encoder};

pub const SEARCH_ID_LEN: usize = 36;
pub const MAX_GAL_QUERY_LEN: usize = 256;
pub const MIN_GAL_QUERY_LEN: usize = 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FindOptions {
    pub range: Option<ItemRange>,
    pub deep_traversal: bool,
    pub picture: Option<PictureOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindCriterion<'a> {
    Mailbox {
        free_text: Cow<'a, str>,
        class: Option<Class>,
        collection_id: Option<Cow<'a, str>>,
        options: FindOptions,
    },
    Gal {
        query: Cow<'a, str>,
        options: FindOptions,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindRequest<'a> {
    pub search_id: Cow<'a, str>,
    pub criterion: FindCriterion<'a>,
}

impl<'a> FindRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, version: ProtocolVersion) -> Result<Self, CommandError> {
        if version != ProtocolVersion::V161 {
            return Err(CommandError::NotSupported { tag: find::FIND });
        }
        let mut search_id = None;
        let mut criterion = None;
        let mut children = Children::root(dec, find::FIND)?;
        while let Some(tag) = children.next(dec)? {
            match tag {
                find::SEARCH_ID => {
                    let id = read_str(dec, tag)?;
                    if id.len() != SEARCH_ID_LEN {
                        return Err(CommandError::InvalidValue { tag });
                    }
                    search_id = Some(id);
                }
                find::EXECUTE_SEARCH => {
                    let mut execute = Children::of(dec);
                    while let Some(tag) = execute.next(dec)? {
                        match tag {
                            find::MAIL_BOX_SEARCH_CRITERION => {
                                criterion = Some(parse_criterion(dec, false)?)
                            }
                            find::GAL_SEARCH_CRITERION => {
                                criterion = Some(parse_criterion(dec, true)?)
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(FindRequest {
            search_id: required(search_id, find::SEARCH_ID)?,
            criterion: required(criterion, find::EXECUTE_SEARCH)?,
        })
    }
}

fn parse_criterion<'a>(
    dec: &mut Decoder<'a>,
    gal: bool,
) -> Result<FindCriterion<'a>, CommandError> {
    let mut free_text = None;
    let mut class = None;
    let mut collection_id = None;
    let mut options = FindOptions::default();
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        match tag {
            find::QUERY if gal => {
                let query = read_id(dec, tag, MAX_GAL_QUERY_LEN)?;
                if query.len() < MIN_GAL_QUERY_LEN {
                    return Err(CommandError::InvalidValue { tag });
                }
                free_text = Some(query);
            }
            find::QUERY => {
                let mut query = Children::of(dec);
                while let Some(tag) = query.next(dec)? {
                    match tag {
                        find::FREE_TEXT => free_text = Some(read_str(dec, tag)?),
                        sync::CLASS => {
                            class = Some(
                                Class::parse(read_str(dec, tag)?.as_bytes())
                                    .ok_or(CommandError::InvalidValue { tag })?,
                            )
                        }
                        sync::COLLECTION_ID => collection_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                        _ => {}
                    }
                }
            }
            find::OPTIONS => options = parse_options(dec)?,
            _ => {}
        }
    }
    let free_text = required(free_text, if gal { find::QUERY } else { find::FREE_TEXT })?;
    Ok(if gal {
        FindCriterion::Gal {
            query: free_text,
            options,
        }
    } else {
        FindCriterion::Mailbox {
            free_text,
            class,
            collection_id,
            options,
        }
    })
}

fn parse_options(dec: &mut Decoder<'_>) -> Result<FindOptions, CommandError> {
    let mut options = FindOptions::default();
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        match tag {
            find::RANGE => options.range = Some(read_range(dec, tag)?),
            find::DEEP_TRAVERSAL => {
                dec.skip_element()?;
                options.deep_traversal = true;
            }
            find::PICTURE => {
                let mut picture = PictureOptions::default();
                let mut fields = Children::of(dec);
                while let Some(tag) = fields.next(dec)? {
                    match tag {
                        find::MAX_SIZE => picture.max_size = Some(read_u32(dec, tag)?),
                        find::MAX_PICTURES => picture.max_pictures = Some(read_u32(dec, tag)?),
                        _ => {}
                    }
                }
                options.picture = Some(picture);
            }
            _ => {}
        }
    }
    Ok(options)
}

eas_struct!(FindMailProperties<'a> {
    subject: Cow<'a, str> = email::SUBJECT,
    date_received: EasDateTime = email::DATE_RECEIVED,
    display_to: Cow<'a, str> = email::DISPLAY_TO,
    display_cc: Cow<'a, str> = find::DISPLAY_CC,
    display_bcc: Cow<'a, str> = find::DISPLAY_BCC,
    importance: u8 = email::IMPORTANCE,
    read: bool = email::READ,
    is_draft: bool = email2::IS_DRAFT,
    preview: Cow<'a, str> = find::PREVIEW,
    has_attachments: bool = find::HAS_ATTACHMENTS,
    from: Cow<'a, str> = email::FROM,
});

#[derive(Debug, Clone, PartialEq)]
pub enum FindProperties<'x> {
    Mail(FindMailProperties<'x>),
    Gal(GalEntry<'x>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FindResult<'x> {
    pub class: Option<Class>,
    pub server_id: Option<&'x str>,
    pub collection_id: Option<&'x str>,
    pub properties: FindProperties<'x>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FindStoreResult<'x> {
    pub store: &'x str,
    pub status: FindStatus,
    pub results: Vec<FindResult<'x>>,
    pub range: Option<ItemRange>,
    pub total: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FindResponse<'x> {
    pub status: FindStatus,
    pub response: Option<FindStoreResult<'x>>,
}

impl FindResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(find::FIND)
            .text_u64(find::STATUS, u64::from(self.status.0));
        if let Some(response) = &self.response {
            enc.start(find::RESPONSE)
                .text_str(io::STORE, response.store)
                .text_u64(find::STATUS, u64::from(response.status.0));
            for result in &response.results {
                enc.start(find::RESULT);
                if let Some(class) = result.class {
                    enc.text_str(sync::CLASS, class.as_str());
                }
                if let Some(server_id) = result.server_id {
                    enc.text_str(sync::SERVER_ID, server_id);
                }
                if let Some(collection_id) = result.collection_id {
                    enc.text_str(sync::COLLECTION_ID, collection_id);
                }
                enc.start(find::PROPERTIES);
                match &result.properties {
                    FindProperties::Mail(mail) => mail.encode_fields(enc),
                    FindProperties::Gal(entry) => entry.encode_fields(enc),
                }
                enc.end().end();
            }
            if let Some(range) = &response.range {
                range.encode(enc, find::RANGE);
            }
            enc.text_u64(find::TOTAL, u64::from(response.total)).end();
        }
        enc.end();
    }
}
