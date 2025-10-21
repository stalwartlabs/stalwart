/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Request;
use crate::{
    error::request::{RequestError, RequestErrorType, RequestLimitError},
    object::AnyId,
    request::{Call, deserialize::DeserializeArguments},
    response::{Response, ResponseMethod, serialize::serialize_hex, status::PushObject},
};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use std::{borrow::Cow, collections::HashMap, fmt};
use types::type_state::DataType;

#[derive(Debug)]
pub struct WebSocketRequest<'x> {
    pub id: Option<String>,
    pub request: Request<'x>,
}

#[derive(Debug, serde::Serialize)]
pub struct WebSocketResponse<'x> {
    #[serde(rename = "@type")]
    _type: WebSocketResponseType,

    #[serde(rename = "methodResponses")]
    method_responses: Vec<Call<ResponseMethod<'x>>>,

    #[serde(rename = "sessionState")]
    #[serde(serialize_with = "serialize_hex")]
    session_state: u32,

    #[serde(rename(deserialize = "createdIds"))]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    created_ids: HashMap<String, AnyId>,

    #[serde(rename = "requestId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub enum WebSocketResponseType {
    Response,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct WebSocketPushEnable {
    pub data_types: Vec<DataType>,
    pub push_state: Option<String>,
}

#[derive(Debug)]
pub enum WebSocketMessage<'x> {
    Request(WebSocketRequest<'x>),
    PushEnable(WebSocketPushEnable),
    PushDisable,
}

#[derive(serde::Serialize, Debug)]
pub struct WebSocketPushObject {
    #[serde(flatten)]
    pub push: PushObject,

    #[serde(rename = "pushState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_state: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct WebSocketRequestError<'x> {
    #[serde(rename = "@type")]
    pub type_: WebSocketRequestErrorType,

    #[serde(rename = "type")]
    p_type: RequestErrorType,

    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<RequestLimitError>,
    status: u16,
    detail: Cow<'x, str>,

    #[serde(rename = "requestId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(serde::Serialize, Debug)]
pub enum WebSocketRequestErrorType {
    RequestError,
}

enum MessageType {
    Request,
    PushEnable,
    PushDisable,
    None,
}

impl<'x> WebSocketMessage<'x> {
    pub fn parse(json: &'x [u8], max_calls: usize, max_size: usize) -> trc::Result<Self> {
        if json.len() <= max_size {
            match serde_json::from_slice::<Self>(json) {
                Ok(WebSocketMessage::Request(req))
                    if req.request.method_calls.len() > max_calls =>
                {
                    Err(trc::LimitEvent::CallsIn.into_err())
                }
                Ok(msg) => Ok(msg),
                Err(err) => Err(trc::JmapEvent::NotRequest
                    .into_err()
                    .details(format!("Invalid WebSocket JMAP request {err}"))),
            }
        } else {
            Err(trc::LimitEvent::SizeRequest.into_err())
        }
    }
}

impl<'de: 'x, 'x: 'de> Deserialize<'de> for WebSocketMessage<'x> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(WebSocketMessageVisitor)
    }
}

struct WebSocketMessageVisitor;

impl<'de> Visitor<'de> for WebSocketMessageVisitor {
    type Value = WebSocketMessage<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a WebSocketMessage as a map")
    }

    fn visit_map<V>(self, mut map: V) -> Result<WebSocketMessage<'de>, V::Error>
    where
        V: MapAccess<'de>,
    {
        let mut message_type = MessageType::None;
        let mut request = WebSocketRequest {
            id: None,
            request: Request::default(),
        };
        let mut push_enable = WebSocketPushEnable::default();

        let mut found_request_keys = false;
        let mut found_push_keys = false;

        while let Some(key) = map.next_key::<&str>()? {
            hashify::fnc_map!(key.as_bytes(),
                b"@type" => {
                    message_type = MessageType::parse(map.next_value()?);
                },
                b"dataTypes" => {
                    push_enable.data_types = map.next_value::<Option<Vec<DataType>>>()?.unwrap_or_default();
                    found_push_keys = true;
                },
                b"pushState" => {
                    push_enable.push_state = map.next_value()?;
                    found_push_keys = true;
                },
                b"id" => {
                    request.id = map.next_value()?;
                },
                _ => {
                    request.request.deserialize_argument(key, &mut map)?;
                    found_request_keys = true;
                }
            );
        }

        match message_type {
            MessageType::Request if found_request_keys => Ok(WebSocketMessage::Request(request)),
            MessageType::PushEnable if found_push_keys => {
                Ok(WebSocketMessage::PushEnable(push_enable))
            }
            MessageType::PushDisable if !found_request_keys && !found_push_keys => {
                Ok(WebSocketMessage::PushDisable)
            }
            _ => Err(de::Error::custom("Invalid WebSocket JMAP request")),
        }
    }
}

impl MessageType {
    fn parse(s: &str) -> Self {
        hashify::tiny_map!(s.as_bytes(),
            b"Request" => MessageType::Request,
            b"WebSocketPushEnable" => MessageType::PushEnable,
            b"WebSocketPushDisable" => MessageType::PushDisable,
        )
        .unwrap_or(MessageType::None)
    }
}

impl<'x> WebSocketRequestError<'x> {
    pub fn from_error(error: RequestError<'x>, request_id: Option<String>) -> Self {
        Self {
            type_: WebSocketRequestErrorType::RequestError,
            p_type: error.p_type,
            limit: error.limit,
            status: error.status,
            detail: error.detail,
            request_id,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

impl<'x> From<RequestError<'x>> for WebSocketRequestError<'x> {
    fn from(value: RequestError<'x>) -> Self {
        Self::from_error(value, None)
    }
}

impl<'x> WebSocketResponse<'x> {
    pub fn from_response(response: Response<'x>, request_id: Option<String>) -> Self {
        Self {
            _type: WebSocketResponseType::Response,
            method_responses: response.method_responses,
            session_state: response.session_state,
            created_ids: response.created_ids,
            request_id,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

impl WebSocketPushObject {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}
