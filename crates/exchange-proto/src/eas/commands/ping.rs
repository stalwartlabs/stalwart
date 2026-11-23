/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{
    Children, CommandError, Counter, MAX_ID_LEN, MAX_PING_FOLDERS, read_id, read_str, required,
};
use crate::eas::status::PingStatus;
use crate::eas::tokens::{ProtocolVersion, tag::ping};
use crate::eas::types::Class;
use crate::eas::wbxml::{Decoder, Encoder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingFolder<'a> {
    pub id: Cow<'a, str>,
    pub class: Class,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PingRequest<'a> {
    pub heartbeat: Option<u32>,
    pub folders: Option<Vec<PingFolder<'a>>>,
}

impl<'a> PingRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut request = PingRequest::default();
        let mut counter = Counter::new(MAX_PING_FOLDERS);
        let mut children = Children::root(dec, ping::PING)?;
        while let Some(tag) = children.next(dec)? {
            match tag {
                ping::HEARTBEAT_INTERVAL => {
                    let seconds = dec.i32().map_err(|err| CommandError::value(err, tag))?;
                    request.heartbeat = Some(u32::try_from(seconds).unwrap_or_default());
                }
                ping::FOLDERS => {
                    let folders = request.folders.get_or_insert_with(Vec::new);
                    let mut list = Children::of(dec);
                    while let Some(tag) = list.next(dec)? {
                        if tag == ping::FOLDER {
                            counter.bump(tag)?;
                            folders.push(PingFolder::parse(dec)?);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(request)
    }
}

impl<'a> PingFolder<'a> {
    fn parse(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut id = None;
        let mut class = None;
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                ping::ID => id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                ping::CLASS => {
                    class = Some(
                        Class::parse(read_str(dec, tag)?.as_bytes())
                            .ok_or(CommandError::InvalidValue { tag })?,
                    )
                }
                _ => {}
            }
        }
        Ok(PingFolder {
            id: required(id, ping::ID)?,
            class: required(class, ping::CLASS)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingResponse<'x> {
    pub status: PingStatus,
    pub folders: Vec<&'x str>,
    pub max_folders: Option<u32>,
    pub heartbeat: Option<u32>,
}

impl PingResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(ping::PING)
            .text_u64(ping::STATUS, u64::from(self.status.0));
        if !self.folders.is_empty() {
            enc.start(ping::FOLDERS);
            for folder in &self.folders {
                enc.text_str(ping::FOLDER, folder);
            }
            enc.end();
        }
        if let Some(max_folders) = self.max_folders {
            enc.text_u64(ping::MAX_FOLDERS, u64::from(max_folders));
        }
        if let Some(heartbeat) = self.heartbeat {
            enc.text_u64(ping::HEARTBEAT_INTERVAL, u64::from(heartbeat));
        }
        enc.end();
    }
}
