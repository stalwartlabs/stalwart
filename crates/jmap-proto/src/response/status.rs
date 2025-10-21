/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::types::state::State;
use types::{id::Id, type_state::DataType};
use utils::map::vec_map::VecMap;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "@type")]
pub enum PushObject {
    StateChange {
        changed: VecMap<Id, VecMap<DataType, State>>,
    },
    EmailPush {
        #[serde(rename = "accountId")]
        account_id: Id,
        email: EmailPushObject,
    },
    CalendarAlert {
        #[serde(rename = "accountId")]
        account_id: Id,
        #[serde(rename = "calendarEventId")]
        calendar_event_id: Id,
        uid: String,
        #[serde(rename = "recurrenceId")]
        recurrence_id: Option<String>,
        #[serde(rename = "alertId")]
        alert_id: String,
    },
    Group {
        entries: Vec<PushObject>,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct EmailPushObject {
    pub subject: String,
}
