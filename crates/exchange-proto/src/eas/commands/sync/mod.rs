/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use smallvec::SmallVec;

use super::appdata::{MAX_LIST_ITEMS, RawApplicationData};
use super::{
    Children, CommandError, MAX_ID_LEN, MAX_LIST_LEN, MAX_SYNC_COMMANDS, SyncKeyStr, read_date,
    read_id, read_str, read_u32, required,
};
use crate::eas::tokens::tag::{airsync as sync, airsyncbase as asb, email2};
use crate::eas::tokens::{ProtocolVersion, Tag};
use crate::eas::types::{Class, EasDateTime};
use crate::eas::wbxml::Decoder;

pub mod options;
pub mod response;

pub use options::SyncOptions;
pub use response::{
    ServerCommand, SyncItemResponse, SyncResponse, SyncResponseBody, SyncResponseCollection,
};

pub const MAX_OPTIONS: usize = 2;

#[derive(Debug, Clone, PartialEq)]
pub enum SyncRequest<'a> {
    Empty,
    Full(SyncBody<'a>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncWait {
    Minutes(u32),
    HeartbeatSeconds(u32),
    Both,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SyncBody<'a> {
    pub collections: Vec<SyncCollection<'a>>,
    pub wait: Option<SyncWait>,
    pub window_size: Option<u32>,
    pub partial: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    OutOfOrder,
    MissingCollectionId,
    TooManyOptions,
    BadFilterForClass,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SyncCollection<'a> {
    pub sync_key: SyncKeyStr<'a>,
    pub collection_id: Option<Cow<'a, str>>,
    pub supported: Option<SmallVec<[Tag; 16]>>,
    pub deletes_as_moves: Option<bool>,
    pub get_changes: Option<bool>,
    pub window_size: Option<u32>,
    pub conversation_mode: Option<bool>,
    pub options: SmallVec<[SyncOptions; 2]>,
    pub commands: Vec<ClientCommand<'a>>,
    pub protocol_error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ghosting<'x> {
    Off,
    Except(&'x [Tag]),
}

impl Ghosting<'_> {
    pub fn ghosts(self, tag: Tag) -> bool {
        match self {
            Ghosting::Off => false,
            Ghosting::Except(supported) => !supported.contains(&tag),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientCommand<'a> {
    Add {
        client_id: Cow<'a, str>,
        class: Option<Class>,
        data: RawApplicationData<'a>,
        send: bool,
    },
    Change {
        server_id: Cow<'a, str>,
        instance_id: Option<EasDateTime>,
        data: RawApplicationData<'a>,
        send: bool,
    },
    Delete {
        server_id: Cow<'a, str>,
        instance_id: Option<EasDateTime>,
    },
    Fetch {
        server_id: Cow<'a, str>,
    },
}

impl<'a> SyncRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut body = SyncBody::default();
        let mut wait = None;
        let mut heartbeat = None;
        let mut commands = 0u32;
        let mut children = Children::root(dec, sync::SYNC)?;
        while let Some(tag) = children.next(dec)? {
            match tag {
                sync::COLLECTIONS => {
                    let mut list = Children::of(dec);
                    while let Some(tag) = list.next(dec)? {
                        if tag == sync::COLLECTION {
                            if body.collections.len() >= MAX_LIST_ITEMS {
                                return Err(CommandError::TooMany {
                                    tag,
                                    limit: MAX_LIST_LEN,
                                });
                            }
                            body.collections.push(SyncCollection::parse(
                                dec,
                                version,
                                &mut commands,
                            )?);
                        }
                    }
                }
                sync::WAIT => wait = Some(read_u32(dec, tag)?),
                sync::HEARTBEAT_INTERVAL => heartbeat = Some(read_u32(dec, tag)?),
                sync::WINDOW_SIZE => body.window_size = Some(read_u32(dec, tag)?),
                sync::PARTIAL => {
                    dec.skip_element()?;
                    body.partial = true;
                }
                _ => {}
            }
        }
        body.wait = match (wait, heartbeat) {
            (Some(_), Some(_)) => Some(SyncWait::Both),
            (Some(minutes), None) => Some(SyncWait::Minutes(minutes)),
            (None, Some(seconds)) => Some(SyncWait::HeartbeatSeconds(seconds)),
            (None, None) => None,
        };
        Ok(SyncRequest::Full(body))
    }
}

fn collection_rank(tag: Tag) -> Option<u8> {
    Some(match tag {
        sync::SYNC_KEY => 0,
        sync::COLLECTION_ID => 1,
        sync::SUPPORTED => 2,
        sync::DELETES_AS_MOVES => 3,
        sync::GET_CHANGES => 4,
        sync::WINDOW_SIZE => 5,
        sync::CONVERSATION_MODE => 6,
        sync::OPTIONS => 7,
        sync::COMMANDS => 8,
        _ => return None,
    })
}

impl<'a> SyncCollection<'a> {
    fn parse(
        dec: &mut Decoder<'a>,
        version: ProtocolVersion,
        commands: &mut u32,
    ) -> Result<Self, CommandError> {
        let mut sync_key = None;
        let mut collection = SyncCollection {
            sync_key: SyncKeyStr(Cow::Borrowed("")),
            collection_id: None,
            supported: None,
            deletes_as_moves: None,
            get_changes: None,
            window_size: None,
            conversation_mode: None,
            options: SmallVec::new(),
            commands: Vec::new(),
            protocol_error: None,
        };
        let mut last_rank = 0u8;
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            if let Some(rank) = collection_rank(tag) {
                if rank < last_rank {
                    collection.flag(ProtocolError::OutOfOrder);
                }
                last_rank = rank;
            }
            match tag {
                sync::SYNC_KEY => sync_key = Some(SyncKeyStr(read_id(dec, tag, MAX_ID_LEN)?)),
                sync::COLLECTION_ID => {
                    collection.collection_id = Some(read_id(dec, tag, MAX_ID_LEN)?)
                }
                sync::SUPPORTED => collection.supported = Some(parse_supported(dec)?),
                sync::DELETES_AS_MOVES => {
                    collection.deletes_as_moves = Some(read_bool_or_empty(dec, tag)?)
                }
                sync::GET_CHANGES => collection.get_changes = Some(read_bool_or_empty(dec, tag)?),
                sync::WINDOW_SIZE => collection.window_size = Some(read_u32(dec, tag)?),
                sync::CONVERSATION_MODE => {
                    collection.conversation_mode = Some(read_bool_or_empty(dec, tag)?)
                }
                sync::OPTIONS => {
                    let options = SyncOptions::parse(dec)?;
                    collection.add_options(options);
                }
                sync::COMMANDS => collection.parse_commands(dec, version, commands)?,
                _ => {}
            }
        }
        collection.sync_key = required(sync_key, sync::SYNC_KEY)?;
        if collection.collection_id.is_none() {
            collection.flag(ProtocolError::MissingCollectionId);
        }
        Ok(collection)
    }

    fn flag(&mut self, error: ProtocolError) {
        self.protocol_error.get_or_insert(error);
    }

    fn add_options(&mut self, options: SyncOptions) {
        if options.has_bad_filter() {
            self.flag(ProtocolError::BadFilterForClass);
        }
        let accepted = match self.options.as_slice() {
            [] => true,
            [existing] => matches!(
                (existing.class, options.class),
                (Some(Class::Sms), None | Some(Class::Email))
                    | (None | Some(Class::Email), Some(Class::Sms))
            ),
            _ => false,
        };
        if !accepted {
            self.flag(ProtocolError::TooManyOptions);
        } else {
            self.options.push(options);
        }
    }

    fn parse_commands(
        &mut self,
        dec: &mut Decoder<'a>,
        version: ProtocolVersion,
        commands: &mut u32,
    ) -> Result<(), CommandError> {
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            let command = match tag {
                sync::ADD => ClientCommand::parse_add(dec, version)?,
                sync::CHANGE => ClientCommand::parse_change(dec)?,
                sync::DELETE => ClientCommand::parse_delete(dec)?,
                sync::FETCH => ClientCommand::parse_fetch(dec)?,
                _ => continue,
            };
            if *commands >= MAX_SYNC_COMMANDS {
                return Err(CommandError::TooManyCommands);
            }
            *commands = commands.wrapping_add(1);
            self.commands.push(command);
        }
        Ok(())
    }
}

fn read_bool_or_empty(dec: &mut Decoder<'_>, tag: Tag) -> Result<bool, CommandError> {
    let text = dec.text()?;
    match text.as_ref() {
        b"" | b"1" => Ok(true),
        b"0" => Ok(false),
        _ => Err(CommandError::InvalidValue { tag }),
    }
}

fn parse_supported(dec: &mut Decoder<'_>) -> Result<SmallVec<[Tag; 16]>, CommandError> {
    let mut tags = SmallVec::new();
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        if tags.len() >= MAX_LIST_ITEMS {
            return Err(CommandError::TooMany {
                tag: sync::SUPPORTED,
                limit: MAX_LIST_LEN,
            });
        }
        tags.push(tag);
    }
    Ok(tags)
}

#[derive(Default)]
struct ItemFields<'a> {
    client_id: Option<Cow<'a, str>>,
    server_id: Option<Cow<'a, str>>,
    class: Option<Class>,
    instance_id: Option<EasDateTime>,
    data: Option<RawApplicationData<'a>>,
    send: bool,
}

impl<'a> ItemFields<'a> {
    fn parse(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut fields = ItemFields::default();
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                sync::CLIENT_ID => fields.client_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                sync::SERVER_ID => fields.server_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                sync::CLASS => {
                    let class = read_str(dec, tag)?;
                    fields.class = Some(
                        Class::parse(class.as_bytes()).ok_or(CommandError::InvalidValue { tag })?,
                    );
                }
                asb::INSTANCE_ID => fields.instance_id = Some(read_date(dec, tag)?),
                sync::APPLICATION_DATA => {
                    let (page, content) = dec.element_bytes()?;
                    fields.data = Some(RawApplicationData::new(page, content));
                }
                email2::SEND => {
                    dec.skip_element()?;
                    fields.send = true;
                }
                _ => {}
            }
        }
        Ok(fields)
    }

    fn data(&mut self) -> Result<RawApplicationData<'a>, CommandError> {
        required(self.data.take(), sync::APPLICATION_DATA)
    }
}

impl<'a> ClientCommand<'a> {
    fn parse_add(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut fields = ItemFields::parse(dec)?;
        Ok(ClientCommand::Add {
            data: fields.data()?,
            client_id: required(fields.client_id, sync::CLIENT_ID)?,
            class: fields.class,
            send: fields.send,
        })
    }

    fn parse_change(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut fields = ItemFields::parse(dec)?;
        Ok(ClientCommand::Change {
            data: fields.data()?,
            server_id: required(fields.server_id, sync::SERVER_ID)?,
            instance_id: fields.instance_id,
            send: fields.send,
        })
    }

    fn parse_delete(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let fields = ItemFields::parse(dec)?;
        Ok(ClientCommand::Delete {
            server_id: required(fields.server_id, sync::SERVER_ID)?,
            instance_id: fields.instance_id,
        })
    }

    fn parse_fetch(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let fields = ItemFields::parse(dec)?;
        Ok(ClientCommand::Fetch {
            server_id: required(fields.server_id, sync::SERVER_ID)?,
        })
    }
}
