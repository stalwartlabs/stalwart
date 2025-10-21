/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    method::PropertyWrapper,
    object::JmapObject,
    request::deserialize::{DeserializeArguments, deserialize_request},
    types::state::State,
};
use serde::{Deserialize, Deserializer};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct ChangesRequest {
    pub account_id: Id,
    pub since_state: State,
    pub max_changes: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChangesResponse<T: JmapObject> {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "oldState")]
    pub old_state: State,

    #[serde(rename = "newState")]
    pub new_state: State,

    #[serde(rename = "hasMoreChanges")]
    pub has_more_changes: bool,

    pub created: Vec<Id>,

    pub updated: Vec<Id>,

    pub destroyed: Vec<Id>,

    #[serde(rename = "updatedProperties")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_properties: Option<Vec<PropertyWrapper<T::Property>>>,
}

impl<'de> DeserializeArguments<'de> for ChangesRequest {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = map.next_value()?;
            },
            b"sinceState" => {
                self.since_state = map.next_value()?;
            },
            b"maxChanges" => {
                self.max_changes = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> Deserialize<'de> for ChangesRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<T: JmapObject> ChangesResponse<T> {
    pub fn has_changes(&self) -> bool {
        !self.created.is_empty() || !self.updated.is_empty() || !self.destroyed.is_empty()
    }
}
