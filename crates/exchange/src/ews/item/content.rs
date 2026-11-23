/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ItemError, attach::printable, create::address, edit::CarriedEdit};
use crate::{
    eas::convert::compose::{HeaderEdit, NewBody, Overrides},
    mail::FlagEdit,
};
use exchange_proto::ews::{
    schema::{BodyType, UnindexedField},
    types::{address::EmailAddress, item::Item},
};
use mail_builder::headers::address::Address;
use mail_parser::{AddressList, MessageRef};
use std::borrow::Cow;

#[derive(Clone, Copy)]
pub(crate) enum ChangeKind {
    Set,
    Append,
    Delete,
}

#[derive(Clone, Copy)]
enum RecipientEdit<'x> {
    Replace(&'x [EmailAddress<'x>]),
    Append(&'x [EmailAddress<'x>]),
}

#[derive(Default)]
pub(crate) struct ContentEdit<'x> {
    subject: Option<Option<Cow<'x, str>>>,
    body: Option<NewBody<'x>>,
    to: Option<RecipientEdit<'x>>,
    cc: Option<RecipientEdit<'x>>,
    bcc: Option<RecipientEdit<'x>>,
}

#[derive(Default)]
pub(crate) struct DraftEdit<'x> {
    pub content: ContentEdit<'x>,
    pub flags: FlagEdit,
    pub expected_change: Option<u64>,
    pub carried: Vec<CarriedEdit>,
}

impl<'x> ContentEdit<'x> {
    pub fn is_empty(&self) -> bool {
        self.subject.is_none()
            && self.body.is_none()
            && self.to.is_none()
            && self.cc.is_none()
            && self.bcc.is_none()
    }

    pub fn apply(
        &mut self,
        field: UnindexedField,
        kind: ChangeKind,
        value: Option<&'x Item<'x>>,
    ) -> Result<bool, ItemError> {
        match field {
            UnindexedField::ItemSubject => {
                let subject = match (kind, value) {
                    (ChangeKind::Set, Some(value)) => Some(printable(
                        value
                            .fields()
                            .subject
                            .as_deref()
                            .ok_or(ItemError::InvalidPropertySet)?,
                    )),
                    (ChangeKind::Delete, _) => None,
                    (ChangeKind::Append, _) => return Err(ItemError::InvalidPropertyAppend),
                    (ChangeKind::Set, None) => return Err(ItemError::InvalidPropertySet),
                };
                set_once(&mut self.subject, subject)?;
            }
            UnindexedField::ItemBody => {
                let body = match (kind, value) {
                    (ChangeKind::Set, Some(value)) => {
                        let body = value
                            .fields()
                            .body
                            .as_ref()
                            .ok_or(ItemError::InvalidPropertySet)?;
                        match body.body_type {
                            BodyType::Html => NewBody::Html(body.text.as_ref()),
                            _ => NewBody::Text(body.text.as_ref()),
                        }
                    }
                    (ChangeKind::Delete, _) => NewBody::Text(""),
                    (ChangeKind::Append, _) => return Err(ItemError::InvalidPropertyAppend),
                    (ChangeKind::Set, None) => return Err(ItemError::InvalidPropertySet),
                };
                set_once(&mut self.body, body)?;
            }
            UnindexedField::MessageToRecipients
            | UnindexedField::MessageCcRecipients
            | UnindexedField::MessageBccRecipients => {
                let list = match (kind, value) {
                    (ChangeKind::Delete, _) => &[][..],
                    (_, Some(value)) => {
                        let fields = value
                            .message_fields()
                            .ok_or(ItemError::InvalidPropertySet)?;
                        let list = match field {
                            UnindexedField::MessageToRecipients => &fields.to_recipients,
                            UnindexedField::MessageCcRecipients => &fields.cc_recipients,
                            _ => &fields.bcc_recipients,
                        };
                        list.as_ref()
                            .ok_or(ItemError::InvalidPropertySet)?
                            .0
                            .as_slice()
                    }
                    _ => return Err(ItemError::InvalidPropertySet),
                };
                for mailbox in list {
                    address(mailbox)?;
                }
                let edit = match kind {
                    ChangeKind::Set | ChangeKind::Delete => RecipientEdit::Replace(list),
                    ChangeKind::Append => RecipientEdit::Append(list),
                };
                let target = match field {
                    UnindexedField::MessageToRecipients => &mut self.to,
                    UnindexedField::MessageCcRecipients => &mut self.cc,
                    _ => &mut self.bcc,
                };
                set_once(target, edit)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub fn overrides<'y>(&'y self, original: MessageRef<'y>) -> Result<Overrides<'y>, ItemError>
    where
        'x: 'y,
    {
        Ok(Overrides {
            subject: match &self.subject {
                None => HeaderEdit::Keep,
                Some(None) => HeaderEdit::Remove,
                Some(Some(subject)) => HeaderEdit::Set(subject.as_ref()),
            },
            to: recipients(self.to, original.to())?,
            cc: recipients(self.cc, original.cc())?,
            bcc: recipients(self.bcc, original.bcc())?,
            body: self.body,
        })
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), ItemError> {
    match slot {
        Some(_) => Err(ItemError::InvalidPropertySet),
        empty => {
            *empty = Some(value);
            Ok(())
        }
    }
}

fn recipients<'y>(
    edit: Option<RecipientEdit<'y>>,
    current: Option<AddressList<'y>>,
) -> Result<HeaderEdit<Address<'y>>, ItemError> {
    let (kept, added) = match edit {
        None => return Ok(HeaderEdit::Keep),
        Some(RecipientEdit::Replace(list)) => (None, list),
        Some(RecipientEdit::Append(list)) => (current, list),
    };
    let mut addresses = Vec::with_capacity(
        kept.as_ref()
            .map_or(0, |kept| kept.mailboxes().size_hint().0)
            .saturating_add(added.len()),
    );
    if let Some(kept) = kept {
        addresses.extend(kept.mailboxes().filter_map(|mailbox| {
            mailbox
                .address()
                .filter(|email| !email.is_empty())
                .map(|email| Address::new_address(mailbox.name(), email))
        }));
    }
    for mailbox in added {
        addresses.push(address(mailbox)?);
    }
    Ok(if addresses.is_empty() {
        HeaderEdit::Remove
    } else {
        HeaderEdit::Set(Address::new_list(addresses))
    })
}
