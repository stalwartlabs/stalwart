/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::appdata::email::{Forwardee, Forwardees};
use super::appdata::{Body, Value};
use super::{
    Children, CommandError, MAX_ID_LEN, MAX_LONG_ID_LEN, bounded, read_bytes, read_date, read_id,
    read_str, required,
};
use crate::eas::http::RequestParams;
use crate::eas::status::Status;
use crate::eas::tokens::tag::{airsyncbase as asb, compose_mail as cm, rights_management as rm};
use crate::eas::tokens::{ProtocolVersion, Tag};
use crate::eas::types::EasDateTime;
use crate::eas::wbxml::{Decoder, Encoder};

pub const MAX_CLIENT_ID_LEN: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComposeCommand {
    SendMail,
    SmartReply,
    SmartForward,
}

impl ComposeCommand {
    pub fn root(self) -> Tag {
        match self {
            ComposeCommand::SendMail => cm::SEND_MAIL,
            ComposeCommand::SmartReply => cm::SMART_REPLY,
            ComposeCommand::SmartForward => cm::SMART_FORWARD,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Source<'a> {
    pub folder_id: Option<Cow<'a, str>>,
    pub item_id: Option<Cow<'a, str>>,
    pub long_id: Option<Cow<'a, str>>,
    pub instance_id: Option<EasDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ComposeRequest<'a> {
    pub command: ComposeCommand,
    pub client_id: Cow<'a, str>,
    pub source: Option<Source<'a>>,
    pub account_id: Option<Cow<'a, str>>,
    pub save_in_sent: bool,
    pub replace_mime: bool,
    pub mime: Cow<'a, [u8]>,
    pub template_id: Option<Cow<'a, str>>,
    pub body: Option<Body<'a>>,
    pub forwardees: Vec<Forwardee<'a>>,
}

impl<'a> ComposeRequest<'a> {
    pub fn parse(
        dec: &mut Decoder<'a>,
        _version: ProtocolVersion,
        command: ComposeCommand,
    ) -> Result<Self, CommandError> {
        let mut client_id = None;
        let mut mime = None;
        let mut request = ComposeRequest {
            command,
            client_id: Cow::Borrowed(""),
            source: None,
            account_id: None,
            save_in_sent: false,
            replace_mime: false,
            mime: Cow::Borrowed(&[]),
            template_id: None,
            body: None,
            forwardees: Vec::new(),
        };
        let mut children = Children::root(dec, command.root())?;
        while let Some(tag) = children.next(dec)? {
            match tag {
                cm::CLIENT_ID => client_id = Some(read_id(dec, tag, MAX_CLIENT_ID_LEN)?),
                cm::ACCOUNT_ID => request.account_id = Some(read_str(dec, tag)?),
                cm::SAVE_IN_SENT_ITEMS => {
                    dec.skip_element()?;
                    request.save_in_sent = true;
                }
                cm::REPLACE_MIME => {
                    dec.skip_element()?;
                    request.replace_mime = true;
                }
                cm::MIME => mime = Some(read_bytes(dec, tag)?),
                rm::TEMPLATE_ID => request.template_id = Some(read_str(dec, tag)?),
                cm::SOURCE if command != ComposeCommand::SendMail => {
                    request.source = Some(Source::parse(dec)?)
                }
                asb::BODY => {
                    request.body =
                        Some(Body::decode(dec).map_err(|err| CommandError::value(err, tag))?)
                }
                cm::FORWARDEES => {
                    request.forwardees = Forwardees::decode(dec)
                        .map_err(|err| CommandError::value(err, tag))?
                        .0
                }
                _ => {}
            }
        }
        request.client_id = required(client_id, cm::CLIENT_ID)?;
        request.mime = required(mime, cm::MIME)?;
        if command != ComposeCommand::SendMail && request.source.is_none() {
            return Err(CommandError::Missing { tag: cm::SOURCE });
        }
        Ok(request)
    }

    pub fn from_mime(
        params: &'a RequestParams<'_>,
        mime: &'a [u8],
        command: ComposeCommand,
    ) -> Result<Self, CommandError> {
        let source = match command {
            ComposeCommand::SendMail => None,
            ComposeCommand::SmartReply | ComposeCommand::SmartForward => {
                Some(Source::from_params(params)?)
            }
        };
        Ok(ComposeRequest {
            command,
            client_id: Cow::Borrowed(""),
            source,
            account_id: None,
            save_in_sent: params.save_in_sent,
            replace_mime: false,
            mime: Cow::Borrowed(mime),
            template_id: None,
            body: None,
            forwardees: Vec::new(),
        })
    }
}

impl<'a> Source<'a> {
    fn from_params(params: &'a RequestParams<'_>) -> Result<Self, CommandError> {
        let id = |value: &'a Option<Cow<'_, str>>, tag: Tag, max: usize| {
            value
                .as_deref()
                .map(|value| bounded(value, tag, max).map(Cow::Borrowed))
                .transpose()
        };
        Ok(Source {
            folder_id: id(&params.collection_id, cm::FOLDER_ID, MAX_ID_LEN)?,
            item_id: id(&params.item_id, cm::ITEM_ID, MAX_ID_LEN)?,
            long_id: id(&params.long_id, cm::LONG_ID, MAX_LONG_ID_LEN)?,
            instance_id: params
                .occurrence
                .as_deref()
                .map(|occurrence| {
                    EasDateTime::parse(occurrence.as_bytes()).ok_or(CommandError::InvalidDate {
                        tag: cm::INSTANCE_ID,
                    })
                })
                .transpose()?,
        })
    }

    fn parse(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut source = Source::default();
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                cm::FOLDER_ID => source.folder_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                cm::ITEM_ID => source.item_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                cm::LONG_ID => source.long_id = Some(read_id(dec, tag, MAX_LONG_ID_LEN)?),
                cm::INSTANCE_ID => source.instance_id = Some(read_date(dec, tag)?),
                _ => {}
            }
        }
        Ok(source)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComposeResponse {
    pub command: ComposeCommand,
    pub status: Option<Status>,
}

impl ComposeResponse {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(self.command.root());
        if let Some(status) = self.status {
            enc.text_u64(cm::STATUS, u64::from(status.0));
        }
        enc.end();
    }
}
