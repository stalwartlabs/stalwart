/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod body;
mod export;
mod fingerprint;
mod import;
mod mdn;
mod media_type;
mod smime;

use calcard::icalendar::ICalendarMethod;
use mail_parser::Message;

pub use body::{BodyKindRequest, BodySelection, BodySource, select_body, source_text};
pub use export::{export_html, is_inline_part, reference_ids};
pub use fingerprint::{AttachmentOrder, AttachmentSlot, attachment_slots};
pub use import::{is_envelope_key, split_subject};

use crate::convert::{
    ConvertError,
    context::{AddressResolver, ConvertOptions},
    model::{MessageContent, PropBag},
};

pub fn mime_to_message(
    msg: &Message<'_>,
    resolver: &impl AddressResolver,
    opts: &ConvertOptions<'_>,
) -> Result<MessageContent, ConvertError> {
    import::message(msg.root(), resolver, opts)
}

#[derive(Debug, Clone, Copy)]
pub struct CalendarPart<'a> {
    pub method: &'a ICalendarMethod,
    pub text: &'a str,
}

pub fn message_to_mime(
    content: &MessageContent,
    resolver: &impl AddressResolver,
    opts: &ConvertOptions<'_>,
    calendar: Option<CalendarPart<'_>>,
    out: &mut Vec<u8>,
) -> Result<(), ConvertError> {
    export::message(content, resolver, opts, calendar, out)
}

pub fn derive_envelope_props(msg: &Message<'_>, calendar: Option<&'static str>, bag: &mut PropBag) {
    import::envelope(msg.root(), calendar, bag);
}

pub fn decodes_tnef(msg: &Message<'_>) -> bool {
    import::decodes_tnef(msg.root())
}

pub fn tnef_envelope_props(msg: &Message<'_>, tnef: &[u8], max_decoded: u32) -> Option<PropBag> {
    import::tnef_envelope_props(msg.root(), tnef, max_decoded)
}

fn starts_with_ignore_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn ends_with_ignore_case(value: &str, suffix: &str) -> bool {
    value
        .len()
        .checked_sub(suffix.len())
        .and_then(|start| value.as_bytes().get(start..))
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix.as_bytes()))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/convert/mime/tests.rs"]
mod tests;
