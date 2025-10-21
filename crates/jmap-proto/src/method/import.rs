/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    error::set::SetError,
    method::JmapDict,
    object::{
        AnyId,
        email::{EmailProperty, EmailValue},
    },
    request::{
        MaybeInvalid,
        deserialize::{DeserializeArguments, deserialize_request},
        reference::{MaybeIdReference, MaybeResultReference, ResultReference},
    },
    response::Response,
    types::{date::UTCDate, state::State},
};
use jmap_tools::{Key, Value};
use serde::{Deserialize, Deserializer};
use types::{blob::BlobId, id::Id, keyword::Keyword};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, Default)]
pub struct ImportEmailRequest {
    pub account_id: Id,
    pub if_in_state: Option<State>,
    pub emails: VecMap<String, ImportEmail>,
}

#[derive(Debug, Clone, Default)]
pub struct ImportEmail {
    pub blob_id: MaybeInvalid<BlobId>,
    pub mailbox_ids: MaybeResultReference<Vec<MaybeIdReference<Id>>>,
    pub keywords: Vec<Keyword>,
    pub received_at: Option<UTCDate>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportEmailResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "oldState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_state: Option<State>,

    #[serde(rename = "newState")]
    pub new_state: State,

    #[serde(rename = "created")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub created: VecMap<String, Value<'static, EmailProperty, EmailValue>>,

    #[serde(rename = "notCreated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_created: VecMap<String, SetError<EmailProperty>>,
}

impl<'de> DeserializeArguments<'de> for ImportEmailRequest {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = map.next_value()?;
            },
            b"ifInState" => {
                self.if_in_state = map.next_value()?;
            },
            b"emails" => {
                self.emails = map.next_value()?;
            }
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for ImportEmail {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"blobId" => {
                self.blob_id = map.next_value()?;
            },
            b"keywords" => {
                self.keywords = map.next_value::<JmapDict<Keyword>>()?.0;
            },
            b"receivedAt" => {
                self.received_at = map.next_value()?;
            },
            b"mailboxIds" => {
                self.mailbox_ids = MaybeResultReference::Value(map.next_value::<JmapDict<MaybeIdReference<Id>>>()?.0);
            },
            b"#mailboxIds" => {
                self.mailbox_ids = MaybeResultReference::Reference(map.next_value::<ResultReference>()?);
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> Deserialize<'de> for ImportEmail {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<'de> Deserialize<'de> for ImportEmailRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl ImportEmailResponse {
    pub fn update_created_ids(&self, response: &mut Response) {
        for (user_id, obj) in &self.created {
            if let Value::Object(obj) = obj
                && let Some(Value::Element(EmailValue::Id(id))) =
                    obj.get(&Key::Property(EmailProperty::Id))
            {
                response.created_ids.insert(user_id.clone(), AnyId::Id(*id));
            }
        }
    }
}
