/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::jscalendar::JSCalendarProperty;
use groupware::calendar::{
    MAX_USER_ALERTS, MAX_USER_INSTANCES, MAX_USER_KEYWORD_LEN, MAX_USER_KEYWORDS,
    user::UserDataError,
};
use jmap_proto::error::set::SetError;
use types::id::Id;

pub(super) fn user_data_error(err: UserDataError) -> SetError<JSCalendarProperty<Id>> {
    let (property, description) = match err {
        UserDataError::TooManyKeywords => (
            JSCalendarProperty::Keywords,
            format!("An event cannot have more than {MAX_USER_KEYWORDS} keywords."),
        ),
        UserDataError::KeywordTooLong => (
            JSCalendarProperty::Keywords,
            format!("Keywords cannot be longer than {MAX_USER_KEYWORD_LEN} bytes."),
        ),
        UserDataError::TooManyAlerts => (
            JSCalendarProperty::Alerts,
            format!("An event cannot have more than {MAX_USER_ALERTS} alerts."),
        ),
        UserDataError::TooManyInstances => (
            JSCalendarProperty::RecurrenceOverrides,
            format!(
                "Personal properties cannot be set on more than {MAX_USER_INSTANCES} occurrences."
            ),
        ),
        UserDataError::InvalidColor => (
            JSCalendarProperty::Color,
            "The color is not a valid CSS color.".to_string(),
        ),
    };

    SetError::invalid_properties()
        .with_property(property)
        .with_description(description)
}
