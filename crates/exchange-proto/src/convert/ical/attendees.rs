/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, mem};

use ahash::{AHashMap, AHashSet};
use calcard::icalendar::{
    ICalendar, ICalendarEntry, ICalendarParameter, ICalendarParameterValue,
    ICalendarParticipationRole, ICalendarParticipationStatus, ICalendarProperty,
    ICalendarUserTypes, ICalendarValue,
};
use smallvec::smallvec;

use super::{patch::target, props::RECIPIENT_FLAG_ORGANIZER, to_message::address};
use crate::{
    convert::{
        ConvertError,
        context::AddressResolver,
        model::{MessageContent, PropBag},
        tags::{self, recipient_type},
    },
    mapi::prop::{OwnedPropValue, PropId, PropKey, PropType},
};

const SMTP: &str = "SMTP";
const EX: &str = "EX";

struct AddressTags {
    name: PropId,
    address_type: PropId,
    email: PropId,
    smtp: PropId,
}

const RECIPIENT: AddressTags = AddressTags {
    name: tags::DISPLAY_NAME,
    address_type: tags::ADDRESS_TYPE,
    email: tags::EMAIL_ADDRESS,
    smtp: tags::SMTP_ADDRESS,
};
const SENT_REPRESENTING: AddressTags = AddressTags {
    name: tags::SENT_REPRESENTING_NAME,
    address_type: tags::SENT_REPRESENTING_ADDRESS_TYPE,
    email: tags::SENT_REPRESENTING_EMAIL_ADDRESS,
    smtp: tags::SENT_REPRESENTING_SMTP_ADDRESS,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Address<'c> {
    name: Option<Cow<'c, str>>,
    smtp: Cow<'c, str>,
}

impl Address<'_> {
    fn of<'c>(
        bag: &'c PropBag,
        tags: &AddressTags,
        resolver: &'c dyn AddressResolver,
    ) -> Option<Address<'c>> {
        let name = string_prop(bag, tags.name).filter(|name| !name.is_empty());
        let (name, smtp) = match string_prop(bag, tags.smtp)
            .map(str::trim)
            .filter(|smtp| !smtp.is_empty())
        {
            Some(smtp) => (name.map(Cow::Borrowed), Cow::Borrowed(smtp)),
            None => {
                let email = string_prop(bag, tags.email)?.trim();
                let address_type = string_prop(bag, tags.address_type).unwrap_or(SMTP);
                if address_type.eq_ignore_ascii_case(SMTP) {
                    (name.map(Cow::Borrowed), Cow::Borrowed(email))
                } else if address_type.eq_ignore_ascii_case(EX) {
                    let resolved = resolver.resolve_dn(email)?;
                    (
                        Some(name.map_or_else(
                            || Cow::Owned(resolved.display_name.into_owned()),
                            Cow::Borrowed,
                        )),
                        Cow::Owned(resolved.smtp.into_owned()),
                    )
                } else {
                    return None;
                }
            }
        };
        smtp.contains('@').then_some(Address { name, smtp })
    }

    fn entry<const N: usize>(
        &self,
        name: ICalendarProperty,
        params: [ICalendarParameter; N],
    ) -> ICalendarEntry {
        let mut all = Vec::with_capacity(N + 1);
        if let Some(name) = self.name.as_deref() {
            all.push(ICalendarParameter::cn(name.to_string()));
        }
        all.extend(params);
        ICalendarEntry {
            name,
            params: all,
            values: smallvec![mailto(&self.smtp)],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Invitee<'c> {
    address: Address<'c>,
    kind: i32,
}

impl Invitee<'_> {
    fn same_kind(&self, entry: &ICalendarEntry) -> bool {
        self.kind == recipient_kind(entry)
    }

    fn entry(&self) -> ICalendarEntry {
        let role = match self.kind {
            recipient_type::CC => {
                ICalendarParameter::role(ICalendarParticipationRole::OptParticipant)
            }
            recipient_type::BCC => ICalendarParameter::cutype(ICalendarUserTypes::Resource),
            _ => ICalendarParameter::role(ICalendarParticipationRole::ReqParticipant),
        };
        self.address.entry(
            ICalendarProperty::Attendee,
            [
                role,
                ICalendarParameter::partstat(ICalendarParticipationStatus::NeedsAction),
                ICalendarParameter::rsvp(true),
            ],
        )
    }
}

pub(super) fn recipients_changed(
    staged: &[PropBag],
    stored: &[PropBag],
    resolver: &dyn AddressResolver,
) -> bool {
    !invitees(staged, resolver).eq(invitees(stored, resolver))
}

pub(super) fn set_attendees(
    ical: &mut ICalendar,
    content: &MessageContent,
    fallback_organizer: &str,
    resolver: &dyn AddressResolver,
) -> Result<(), ConvertError> {
    let index = target(ical, None)?;
    let component = ical
        .components
        .get_mut(index)
        .ok_or(ConvertError::Unsupported)?;
    let mut previous = AHashMap::new();
    for entry in mem::take(&mut component.entries) {
        match (entry.name == ICalendarProperty::Attendee)
            .then(|| address(&entry).map(str::to_ascii_lowercase))
        {
            Some(Some(smtp)) => {
                previous.insert(smtp, entry);
            }
            _ => component.entries.push(entry),
        }
    }
    let mut emitted = AHashSet::new();
    for invitee in invitees(&content.recipients, resolver) {
        let smtp = invitee.address.smtp.to_ascii_lowercase();
        let entry = match previous.remove(&smtp) {
            Some(entry) if invitee.same_kind(&entry) => entry,
            _ => invitee.entry(),
        };
        if emitted.insert(smtp) {
            component.entries.push(entry);
        }
    }
    let attendees = emitted.len();
    let has_organizer = component.has_property(&ICalendarProperty::Organizer);
    match (attendees, has_organizer) {
        (0, _) => component
            .entries
            .retain(|entry| entry.name != ICalendarProperty::Organizer),
        (_, true) => {}
        (_, false) => {
            let organizer = organizer(content, resolver)
                .or_else(|| {
                    Some(fallback_organizer.trim())
                        .filter(|smtp| smtp.contains('@'))
                        .map(|smtp| Address {
                            name: None,
                            smtp: Cow::Borrowed(smtp),
                        })
                })
                .ok_or(ConvertError::Unsupported)?;
            component
                .entries
                .push(organizer.entry(ICalendarProperty::Organizer, []));
        }
    }
    Ok(())
}

fn organizer<'c>(
    content: &'c MessageContent,
    resolver: &'c dyn AddressResolver,
) -> Option<Address<'c>> {
    content
        .recipients
        .iter()
        .filter(|row| is_organizer_row(row))
        .find_map(|row| Address::of(row, &RECIPIENT, resolver))
        .or_else(|| Address::of(&content.props, &SENT_REPRESENTING, resolver))
}

fn is_organizer_row(row: &PropBag) -> bool {
    int_prop(row, tags::RECIPIENT_FLAGS).is_some_and(|flags| flags & RECIPIENT_FLAG_ORGANIZER != 0)
}

pub(super) fn set_reply(
    ical: &mut ICalendar,
    recipients: &[PropBag],
    sender: &str,
    partstat: ICalendarParticipationStatus,
    resolver: &dyn AddressResolver,
) -> Result<(), ConvertError> {
    let organizer = recipients
        .iter()
        .find_map(|row| Address::of(row, &RECIPIENT, resolver))
        .ok_or(ConvertError::Unsupported)?;
    let sender = Some(sender.trim())
        .filter(|smtp| smtp.contains('@'))
        .ok_or(ConvertError::Unsupported)?;
    let index = target(ical, None)?;
    let component = ical
        .components
        .get_mut(index)
        .ok_or(ConvertError::Unsupported)?;
    component.entries.retain(|entry| {
        !matches!(
            entry.name,
            ICalendarProperty::Attendee | ICalendarProperty::Organizer
        )
    });
    component
        .entries
        .push(organizer.entry(ICalendarProperty::Organizer, []));
    component.entries.push(ICalendarEntry {
        name: ICalendarProperty::Attendee,
        params: vec![ICalendarParameter::partstat(partstat)],
        values: smallvec![mailto(sender)],
    });
    Ok(())
}

fn invitees<'c>(
    recipients: &'c [PropBag],
    resolver: &'c dyn AddressResolver,
) -> impl Iterator<Item = Invitee<'c>> {
    recipients.iter().filter_map(move |row| {
        if is_organizer_row(row) {
            return None;
        }
        Address::of(row, &RECIPIENT, resolver).map(|address| Invitee {
            address,
            kind: int_prop(row, tags::RECIPIENT_TYPE)
                .map_or(recipient_type::TO, |kind| kind & recipient_type::MASK),
        })
    })
}

fn recipient_kind(entry: &ICalendarEntry) -> i32 {
    entry
        .params
        .iter()
        .fold(recipient_type::TO, |kind, param| match &param.value {
            ICalendarParameterValue::Role(ICalendarParticipationRole::OptParticipant) => {
                recipient_type::CC
            }
            ICalendarParameterValue::Role(ICalendarParticipationRole::NonParticipant)
            | ICalendarParameterValue::Cutype(
                ICalendarUserTypes::Resource | ICalendarUserTypes::Room,
            ) => recipient_type::BCC,
            ICalendarParameterValue::Role(_) => recipient_type::TO,
            _ => kind,
        })
}

fn mailto(address: &str) -> ICalendarValue {
    ICalendarValue::Text(format!("mailto:{address}"))
}

fn string_prop(props: &PropBag, id: PropId) -> Option<&str> {
    match props.get(PropKey::tag(id).as_ref(), PropType::Unicode)? {
        OwnedPropValue::Unicode(value) => Some(value),
        _ => None,
    }
}

fn int_prop(props: &PropBag, id: PropId) -> Option<i32> {
    match props.get(PropKey::tag(id).as_ref(), PropType::I32)? {
        OwnedPropValue::I32(value) => Some(*value),
        _ => None,
    }
}
