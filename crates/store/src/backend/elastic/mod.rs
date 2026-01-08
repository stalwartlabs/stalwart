/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::search::*;
use reqwest::Client;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};

pub mod main;
pub mod search;

pub struct ElasticSearchStore {
    client: Client,
    url: String,
}

#[derive(Debug, Deserialize)]
pub struct SearchResponse {
    pub hits: Hits,
}

#[derive(Debug, Deserialize)]
pub struct Hits {
    pub total: Total,
    pub hits: Vec<Hit>,
}

#[derive(Debug, Deserialize)]
pub struct Total {
    pub value: u64,
}

#[derive(Debug, Deserialize)]
pub struct Hit {
    #[serde(rename = "_id", deserialize_with = "deserialize_string_to_u64")]
    pub id: u64,
    pub sort: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteByQueryResponse {
    pub deleted: u64,
}

impl SearchField {
    pub fn es_schema(&self) -> Value {
        match self {
            SearchField::AccountId
            | SearchField::DocumentId
            | SearchField::Email(EmailSearchField::Size) => json!({
              "type": "integer"
            }),
            SearchField::Id
            | SearchField::Email(EmailSearchField::SentAt | EmailSearchField::ReceivedAt)
            | SearchField::Calendar(CalendarSearchField::Start)
            | SearchField::Tracing(TracingSearchField::QueueId | TracingSearchField::EventType) => {
                json!({
                  "type": "long"
                })
            }
            SearchField::Email(EmailSearchField::HasAttachment) => json!({
              "type": "boolean"
            }),
            SearchField::Calendar(CalendarSearchField::Uid)
            | SearchField::Contact(ContactSearchField::Uid) => json!({
              "type": "keyword",
            }),
            SearchField::Email(
                EmailSearchField::From | EmailSearchField::To | EmailSearchField::Subject,
            ) => json!({
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword"
                }
              }
            }),
            SearchField::Email(EmailSearchField::Headers) => {
                json!({
                  "type": "object",
                  "enabled": true
                })
            }
            #[cfg(feature = "test_mode")]
            SearchField::Email(EmailSearchField::Bcc | EmailSearchField::Cc) => {
                json!({
                  "type": "text",
                  "fields": {
                    "keyword": {
                      "type": "keyword"
                    }
                  }
                })
            }
            #[cfg(not(feature = "test_mode"))]
            SearchField::Email(EmailSearchField::Bcc | EmailSearchField::Cc) => {
                json!({
                  "type": "text"
                })
            }
            SearchField::Email(EmailSearchField::Body | EmailSearchField::Attachment)
            | SearchField::Calendar(
                CalendarSearchField::Title
                | CalendarSearchField::Description
                | CalendarSearchField::Location
                | CalendarSearchField::Owner
                | CalendarSearchField::Attendee,
            )
            | SearchField::Contact(
                ContactSearchField::Member
                | ContactSearchField::Kind
                | ContactSearchField::Name
                | ContactSearchField::Nickname
                | ContactSearchField::Organization
                | ContactSearchField::Email
                | ContactSearchField::Phone
                | ContactSearchField::OnlineService
                | ContactSearchField::Address
                | ContactSearchField::Note,
            )
            | SearchField::File(FileSearchField::Name | FileSearchField::Content)
            | SearchField::Tracing(TracingSearchField::Keywords) => json!({
              "type": "text"
            }),
        }
    }
}

fn deserialize_string_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    <&str>::deserialize(deserializer)?
        .parse::<u64>()
        .map_err(serde::de::Error::custom)
}
