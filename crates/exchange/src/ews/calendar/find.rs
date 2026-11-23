/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ews::filter::{FilterProp, NameValue, PropValue};
use exchange_proto::ews::{
    calendar::{CalendarField, CalendarProps, CalendarValue},
    types::path::Path,
};
use jiff::Timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EventProp(CalendarField);

impl FilterProp for EventProp {
    fn of_path(path: &Path<'_>) -> Option<Self> {
        CalendarField::of_path(path).map(EventProp)
    }
}

impl EventProp {
    pub(super) fn value<'p>(self, props: CalendarProps<'p>) -> Option<PropValue<'p>> {
        Some(match props.value(self.0)? {
            CalendarValue::Text(text) => PropValue::Text(text),
            CalendarValue::Importance(value) => PropValue::Name(NameValue::Importance(value)),
            CalendarValue::FreeBusy(value) => PropValue::Name(NameValue::FreeBusy(value)),
            CalendarValue::Bool(value) => PropValue::Bool(value),
            CalendarValue::Time(time) => {
                PropValue::Time(Timestamp::from_second(time.to_utc().0.0).ok()?)
            }
        })
    }
}
