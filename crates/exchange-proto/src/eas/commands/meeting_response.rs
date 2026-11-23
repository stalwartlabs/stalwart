/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::appdata::{Body, Compact, Value, eas_struct};
use super::{
    Children, CommandError, Counter, MAX_ID_LEN, MAX_LONG_ID_LEN, MAX_MEETING_RESPONSES, read_id,
    read_u8, required,
};
use crate::common::time::EasDateForm;
use crate::eas::status::MeetingResponseStatus;
use crate::eas::tokens::tag::{airsyncbase as asb, meeting_response as mr, search};
use crate::eas::tokens::{ProtocolVersion, Tag};
use crate::eas::types::EasDateTime;
use crate::eas::wbxml::{Decoder, Encoder};

const INSTANCE_ID_LEN: usize = 24;

eas_struct!(SendResponse<'a> {
    body: Body<'a> = asb::BODY,
    proposed_start_time: Compact = mr::PROPOSED_START_TIME,
    proposed_end_time: Compact = mr::PROPOSED_END_TIME,
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserResponse {
    Accepted,
    Tentative,
    Declined,
}

impl UserResponse {
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(UserResponse::Accepted),
            2 => Some(UserResponse::Tentative),
            3 => Some(UserResponse::Declined),
            _ => None,
        }
    }

    pub fn code(self) -> u8 {
        match self {
            UserResponse::Accepted => 1,
            UserResponse::Tentative => 2,
            UserResponse::Declined => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MeetingResponseItem<'a> {
    pub user_response: UserResponse,
    pub collection_id: Option<Cow<'a, str>>,
    pub request_id: Option<Cow<'a, str>>,
    pub long_id: Option<Cow<'a, str>>,
    pub instance_id: Option<EasDateTime>,
    pub send_response: Option<SendResponse<'a>>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MeetingResponseRequest<'a> {
    pub requests: Vec<MeetingResponseItem<'a>>,
}

impl<'a> MeetingResponseRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut request = MeetingResponseRequest::default();
        let mut counter = Counter::new(MAX_MEETING_RESPONSES);
        let mut children = Children::root(dec, mr::MEETING_RESPONSE)?;
        while let Some(tag) = children.next(dec)? {
            if tag == mr::REQUEST {
                counter.bump(tag)?;
                request.requests.push(MeetingResponseItem::parse(dec)?);
            }
        }
        if request.requests.is_empty() {
            return Err(CommandError::Missing { tag: mr::REQUEST });
        }
        Ok(request)
    }
}

impl<'a> MeetingResponseItem<'a> {
    fn parse(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut user_response = None;
        let mut item = MeetingResponseItem {
            user_response: UserResponse::Accepted,
            collection_id: None,
            request_id: None,
            long_id: None,
            instance_id: None,
            send_response: None,
        };
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                mr::USER_RESPONSE => {
                    user_response = Some(
                        UserResponse::from_code(read_u8(dec, tag)?)
                            .ok_or(CommandError::InvalidValue { tag })?,
                    )
                }
                mr::COLLECTION_ID => item.collection_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                mr::REQUEST_ID => item.request_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                search::LONG_ID => item.long_id = Some(read_id(dec, tag, MAX_LONG_ID_LEN)?),
                mr::INSTANCE_ID => item.instance_id = Some(read_instance_id(dec, tag)?),
                mr::SEND_RESPONSE => {
                    item.send_response = Some(
                        SendResponse::decode(dec).map_err(|err| CommandError::value(err, tag))?,
                    )
                }
                _ => {}
            }
        }
        item.user_response = required(user_response, mr::USER_RESPONSE)?;
        Ok(item)
    }
}

fn read_instance_id(dec: &mut Decoder<'_>, tag: Tag) -> Result<EasDateTime, CommandError> {
    let text = dec.text().map_err(|err| CommandError::value(err, tag))?;
    EasDateTime::parse(&text).ok_or(if text.len() == INSTANCE_ID_LEN {
        CommandError::InvalidDate { tag }
    } else {
        CommandError::InvalidValue { tag }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeetingResponseResult<'x> {
    pub request_id: Option<&'x str>,
    pub status: MeetingResponseStatus,
    pub calendar_id: Option<&'x str>,
    pub instance_id: Option<EasDateTime>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeetingResponseResponse<'x> {
    pub results: Vec<MeetingResponseResult<'x>>,
}

impl MeetingResponseResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(mr::MEETING_RESPONSE);
        for result in &self.results {
            enc.start(mr::RESULT);
            if let Some(request_id) = result.request_id {
                enc.text_str(mr::REQUEST_ID, request_id);
            }
            enc.text_u64(mr::STATUS, u64::from(result.status.0));
            if let Some(calendar_id) = result.calendar_id {
                enc.text_str(mr::CALENDAR_ID, calendar_id);
            }
            if let Some(instance_id) = result.instance_id
                && enc.allows(mr::INSTANCE_ID)
            {
                enc.text_with(mr::INSTANCE_ID, |out| {
                    instance_id.write(out, EasDateForm::Punctuated)
                });
            }
            enc.end();
        }
        enc.end();
    }
}
