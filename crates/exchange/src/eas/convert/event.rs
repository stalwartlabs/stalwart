/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use exchange_proto::convert::ical::{EventText, Organizer};
use mail_builder::{
    MessageBuilder,
    headers::{address::Address, content_type::ContentType},
};
use std::borrow::Cow;

const FALLBACK_NAME: &str = "event";
const MESSAGE_SUFFIX: &str = ".eml";
const CALENDAR_NAME: &str = "event.ics";
const CALENDAR_TYPE: &str = "text/calendar";
const METHOD_PUBLISH: &str = "PUBLISH";

pub struct EventMessage {
    pub name: String,
    pub raw: Vec<u8>,
}

impl EventMessage {
    pub fn forward(text: &EventText<'_>, sender: Organizer<'_>, ics: String) -> Option<Self> {
        let subject = text
            .summary
            .map(header_text)
            .filter(|summary| !summary.trim().is_empty());
        let title = subject.as_deref().unwrap_or(FALLBACK_NAME);
        let mut name = String::with_capacity(title.len() + MESSAGE_SUFFIX.len());
        name.push_str(title);
        name.push_str(MESSAGE_SUFFIX);
        let mut builder =
            MessageBuilder::new().from(Address::new_address(sender.name, sender.address));
        if let Some(subject) = subject.as_deref() {
            builder = builder.subject(subject);
        }
        let raw = builder
            .text_body(text.description.unwrap_or_default())
            .attachment(
                ContentType::new(CALENDAR_TYPE)
                    .attribute("method", METHOD_PUBLISH)
                    .attribute("charset", "utf-8"),
                CALENDAR_NAME,
                ics,
            )
            .write_to_vec()
            .ok()?;
        Some(EventMessage { name, raw })
    }
}

pub fn quoted_original(text: &EventText<'_>) -> Option<Vec<u8>> {
    let description = text
        .description
        .filter(|description| !description.trim().is_empty())?;
    MessageBuilder::new()
        .text_body(description)
        .write_to_vec()
        .ok()
}

fn header_text(text: &str) -> Cow<'_, str> {
    if text.contains(char::is_control) {
        Cow::Owned(
            text.chars()
                .map(|ch| if ch.is_control() { ' ' } else { ch })
                .collect(),
        )
    } else {
        Cow::Borrowed(text)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/eas/convert/event/tests.rs"]
mod tests;
