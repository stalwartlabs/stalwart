/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use smallvec::SmallVec;

use super::appdata::{ApplicationData, Opaque, eas_struct};
use super::resolve_recipients::PictureOptions;
use super::sync::options::MAX_BODY_PREFERENCES;
use super::{
    Children, CommandError, ItemRange, MAX_ID_LEN, read_body_preference, read_bool, read_id,
    read_range, read_str, read_u8, read_u32, required,
};
use crate::eas::status::SearchStatus;
use crate::eas::tokens::tag::{
    airsync as sync, airsyncbase as asb, document_library as dl, gal, rights_management as rm,
    search,
};
use crate::eas::tokens::{ProtocolVersion, Tag};
use crate::eas::types::{BodyPreference, Class, EasDateTime};
use crate::eas::wbxml::{DecodeError, Decoder, Encoder, Event};

pub const MAX_QUERY_DEPTH: u8 = 16;
pub const MAX_QUERY_NODES: usize = 256;
pub const MAX_QUERY_VALUE_LEN: usize = 1024;
pub const MAX_STORE_NAME_LEN: usize = 256;
pub const MAX_CREDENTIAL_LEN: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchStore {
    Mailbox,
    Gal,
    DocumentLibrary,
}

impl SearchStore {
    pub fn parse(name: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(
            name,
            SearchStore,
            "Mailbox" => SearchStore::Mailbox,
            "GAL" => SearchStore::Gal,
            "DocumentLibrary" => SearchStore::DocumentLibrary,
        )
        .copied()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryNode<'a> {
    And(SmallVec<[u16; 4]>),
    Or(SmallVec<[u16; 4]>),
    Text(Cow<'a, str>),
    FreeText(Cow<'a, str>),
    Class(Class),
    CollectionId(Cow<'a, str>),
    ConversationId(Cow<'a, [u8]>),
    EqualTo { property: Tag, value: Cow<'a, str> },
    GreaterThan { property: Tag, value: Cow<'a, str> },
    LessThan { property: Tag, value: Cow<'a, str> },
    Unsupported(Tag),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchQuery<'a> {
    pub nodes: Vec<QueryNode<'a>>,
    pub root: u16,
}

impl<'a> SearchQuery<'a> {
    pub fn root(&self) -> Option<&QueryNode<'a>> {
        self.nodes.get(usize::from(self.root))
    }

    pub fn node(&self, index: u16) -> Option<&QueryNode<'a>> {
        self.nodes.get(usize::from(index))
    }

    pub fn has_and_with_siblings(&self) -> bool {
        match self.root() {
            Some(QueryNode::And(children)) if children.len() > 1 => children
                .iter()
                .any(|child| matches!(self.node(*child), Some(QueryNode::And(_)))),
            _ => false,
        }
    }

    fn push(&mut self, node: QueryNode<'a>, tag: Tag) -> Result<u16, CommandError> {
        if self.nodes.len() >= MAX_QUERY_NODES {
            return Err(CommandError::TooMany {
                tag,
                limit: MAX_QUERY_NODES as u32,
            });
        }
        let index =
            u16::try_from(self.nodes.len()).map_err(|_| CommandError::InvalidValue { tag })?;
        self.nodes.push(node);
        Ok(index)
    }

    fn parse(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut query = SearchQuery::default();
        let node = query.parse_group(dec, search::QUERY, 0)?;
        query.root = query.push(node, search::QUERY)?;
        Ok(query)
    }

    fn parse_group(
        &mut self,
        dec: &mut Decoder<'a>,
        tag: Tag,
        depth: u8,
    ) -> Result<QueryNode<'a>, CommandError> {
        if depth >= MAX_QUERY_DEPTH {
            return Err(CommandError::TooMany {
                tag,
                limit: u32::from(MAX_QUERY_DEPTH),
            });
        }
        let target = dec.depth().saturating_sub(1);
        let mut children = SmallVec::new();
        let mut text: Option<Cow<'a, [u8]>> = None;
        loop {
            let offset = dec.offset();
            match dec.next()? {
                Event::End if dec.depth() == target => break,
                Event::Start { tag: child, .. } => {
                    let node = self.parse_node(dec, child, depth)?;
                    children.push(self.push(node, child)?);
                }
                Event::Text(run) | Event::Opaque(run) => match &mut text {
                    Some(text) => text.to_mut().extend_from_slice(run),
                    None => text = Some(Cow::Borrowed(run)),
                },
                Event::End | Event::Eof => {
                    return Err(DecodeError::Truncated { offset }.into());
                }
            }
        }
        match (text, tag) {
            (Some(text), _) if children.is_empty() => {
                let text = match text {
                    Cow::Borrowed(text) => Cow::Borrowed(
                        std::str::from_utf8(text)
                            .map_err(|_| CommandError::InvalidValue { tag })?,
                    ),
                    Cow::Owned(text) => Cow::Owned(
                        String::from_utf8(text).map_err(|_| CommandError::InvalidValue { tag })?,
                    ),
                };
                Ok(QueryNode::Text(text))
            }
            (_, search::OR) => Ok(QueryNode::Or(children)),
            _ => Ok(QueryNode::And(children)),
        }
    }

    fn parse_node(
        &mut self,
        dec: &mut Decoder<'a>,
        tag: Tag,
        depth: u8,
    ) -> Result<QueryNode<'a>, CommandError> {
        Ok(match tag {
            search::AND | search::OR => self.parse_group(dec, tag, depth.saturating_add(1))?,
            search::FREE_TEXT => QueryNode::FreeText(read_str(dec, tag)?),
            sync::CLASS => QueryNode::Class(
                Class::parse(read_str(dec, tag)?.as_bytes())
                    .ok_or(CommandError::InvalidValue { tag })?,
            ),
            sync::COLLECTION_ID => QueryNode::CollectionId(read_id(dec, tag, MAX_ID_LEN)?),
            search::CONVERSATION_ID => {
                QueryNode::ConversationId(dec.bytes().map_err(|err| CommandError::value(err, tag))?)
            }
            search::EQUAL_TO | search::GREATER_THAN | search::LESS_THAN => {
                let (property, value) = parse_comparison(dec, tag)?;
                match tag {
                    search::EQUAL_TO => QueryNode::EqualTo { property, value },
                    search::GREATER_THAN => QueryNode::GreaterThan { property, value },
                    _ => QueryNode::LessThan { property, value },
                }
            }
            _ => {
                dec.skip_element()?;
                QueryNode::Unsupported(tag)
            }
        })
    }
}

fn parse_comparison<'a>(
    dec: &mut Decoder<'a>,
    tag: Tag,
) -> Result<(Tag, Cow<'a, str>), CommandError> {
    let mut property = None;
    let mut value = None;
    let mut children = Children::of(dec);
    while let Some(child) = children.next(dec)? {
        if child == search::VALUE {
            value = Some(read_id(dec, child, MAX_QUERY_VALUE_LEN)?);
        } else {
            property = Some(child);
        }
    }
    Ok((
        property.ok_or(CommandError::Missing { tag })?,
        required(value, search::VALUE)?,
    ))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchOptions<'a> {
    pub range: Option<ItemRange>,
    pub user_name: Option<Cow<'a, str>>,
    pub password: Option<Cow<'a, str>>,
    pub deep_traversal: bool,
    pub rebuild_results: bool,
    pub mime_support: Option<u8>,
    pub body_preferences: SmallVec<[BodyPreference; 2]>,
    pub body_part_preferences: SmallVec<[BodyPreference; 1]>,
    pub rights_management_support: Option<bool>,
    pub picture: Option<PictureOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest<'a> {
    pub store: SearchStore,
    pub query: SearchQuery<'a>,
    pub options: SearchOptions<'a>,
}

impl<'a> SearchRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut request = None;
        let mut children = Children::root(dec, search::SEARCH)?;
        while let Some(tag) = children.next(dec)? {
            if tag == search::STORE {
                request = Some(Self::parse_store(dec)?);
            }
        }
        required(request, search::STORE)
    }

    fn parse_store(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut store = None;
        let mut query = None;
        let mut options = SearchOptions::default();
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                search::NAME => {
                    let name = read_id(dec, tag, MAX_STORE_NAME_LEN)?;
                    store = Some(
                        SearchStore::parse(name.as_bytes())
                            .ok_or(CommandError::InvalidValue { tag })?,
                    );
                }
                search::QUERY => query = Some(SearchQuery::parse(dec)?),
                search::OPTIONS => options = SearchOptions::parse(dec)?,
                _ => {}
            }
        }
        Ok(SearchRequest {
            store: required(store, search::NAME)?,
            query: required(query, search::QUERY)?,
            options,
        })
    }
}

impl<'a> SearchOptions<'a> {
    fn parse(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut options = SearchOptions::default();
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                search::RANGE => options.range = Some(read_range(dec, tag)?),
                search::USER_NAME => {
                    options.user_name = Some(read_id(dec, tag, MAX_CREDENTIAL_LEN)?)
                }
                search::PASSWORD => options.password = Some(read_id(dec, tag, MAX_CREDENTIAL_LEN)?),
                search::DEEP_TRAVERSAL => {
                    dec.skip_element()?;
                    options.deep_traversal = true;
                }
                search::REBUILD_RESULTS => {
                    dec.skip_element()?;
                    options.rebuild_results = true;
                }
                sync::MIME_SUPPORT => options.mime_support = Some(read_u8(dec, tag)?),
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
                rm::RIGHTS_MANAGEMENT_SUPPORT => {
                    options.rights_management_support = Some(read_bool(dec, tag)?)
                }
                search::PICTURE => {
                    let mut picture = PictureOptions::default();
                    let mut fields = Children::of(dec);
                    while let Some(tag) = fields.next(dec)? {
                        match tag {
                            search::MAX_SIZE => picture.max_size = Some(read_u32(dec, tag)?),
                            search::MAX_PICTURES => {
                                picture.max_pictures = Some(read_u32(dec, tag)?)
                            }
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
}

eas_struct!(GalPicture<'a> {
    status: u32 = gal::STATUS,
    data: Opaque<'a> = gal::DATA,
});

eas_struct!(GalEntry<'a> {
    display_name: Cow<'a, str> = gal::DISPLAY_NAME,
    phone: Cow<'a, str> = gal::PHONE,
    office: Cow<'a, str> = gal::OFFICE,
    title: Cow<'a, str> = gal::TITLE,
    company: Cow<'a, str> = gal::COMPANY,
    alias: Cow<'a, str> = gal::ALIAS,
    first_name: Cow<'a, str> = gal::FIRST_NAME,
    last_name: Cow<'a, str> = gal::LAST_NAME,
    home_phone: Cow<'a, str> = gal::HOME_PHONE,
    mobile_phone: Cow<'a, str> = gal::MOBILE_PHONE,
    email_address: Cow<'a, str> = gal::EMAIL_ADDRESS,
    picture: GalPicture<'a> = gal::PICTURE,
});

eas_struct!(DocumentProperties<'a> {
    link_id: Cow<'a, str> = dl::LINK_ID,
    display_name: Cow<'a, str> = dl::DISPLAY_NAME,
    is_folder: bool = dl::IS_FOLDER,
    creation_date: EasDateTime = dl::CREATION_DATE,
    last_modified_date: EasDateTime = dl::LAST_MODIFIED_DATE,
    is_hidden: bool = dl::IS_HIDDEN,
    content_length: u64 = dl::CONTENT_LENGTH,
    content_type: Cow<'a, str> = dl::CONTENT_TYPE,
});

#[derive(Debug, Clone, PartialEq)]
pub enum SearchProperties<'x> {
    Item(ApplicationData<'x>),
    Gal(GalEntry<'x>),
    Document(DocumentProperties<'x>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult<'x> {
    pub class: Option<Class>,
    pub long_id: Option<&'x str>,
    pub collection_id: Option<&'x str>,
    pub properties: Option<SearchProperties<'x>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchStoreResult<'x> {
    pub status: SearchStatus,
    pub results: Vec<SearchResult<'x>>,
    pub range: Option<ItemRange>,
    pub total: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchResponse<'x> {
    pub status: Option<SearchStatus>,
    pub store: Option<SearchStoreResult<'x>>,
}

impl SearchResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(search::SEARCH);
        if let Some(status) = self.status {
            enc.text_u64(search::STATUS, u64::from(status.0));
        }
        if let Some(store) = &self.store {
            enc.start(search::RESPONSE).start(search::STORE);
            enc.text_u64(search::STATUS, u64::from(store.status.0));
            if store.results.is_empty() && store.status == SearchStatus::SUCCESS {
                enc.empty(search::RESULT);
            }
            for result in &store.results {
                result.encode(enc);
            }
            if let Some(range) = &store.range {
                range.encode(enc, search::RANGE);
            }
            if let Some(total) = store.total {
                enc.text_u64(search::TOTAL, u64::from(total));
            }
            enc.end().end();
        }
        enc.end();
    }
}

impl SearchResult<'_> {
    fn encode(&self, enc: &mut Encoder) {
        enc.start(search::RESULT);
        if let Some(class) = self.class {
            enc.text_str(sync::CLASS, class.as_str());
        }
        if let Some(long_id) = self.long_id {
            enc.text_str(search::LONG_ID, long_id);
        }
        if let Some(collection_id) = self.collection_id {
            enc.text_str(sync::COLLECTION_ID, collection_id);
        }
        if let Some(properties) = &self.properties {
            enc.start(search::PROPERTIES);
            match properties {
                SearchProperties::Item(data) => data.encode_fields(enc),
                SearchProperties::Gal(entry) => entry.encode_fields(enc),
                SearchProperties::Document(document) => document.encode_fields(enc),
            }
            enc.end();
        }
        enc.end();
    }
}
