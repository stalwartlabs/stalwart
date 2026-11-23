/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod distlist;
pub mod eas;
mod patch;
pub(crate) mod props;
mod related;
mod sink;
mod to_message;

use calcard::{common::Data, vcard::VCard};

use crate::{
    convert::{
        ConvertError,
        context::ConvertOptions,
        model::{MessageContent, PatchReport, PropBag},
    },
    mapi::prop::PropKeyRef,
};

pub use distlist::{AddressType, DISTLIST_CLASS, DistMember, DistTarget, MemberKind};

pub fn is_contact_group(card: &VCard) -> bool {
    distlist::is_group(card)
}

pub fn contact_group_members(card: &VCard) -> impl Iterator<Item = &str> {
    distlist::group_members(card)
}

pub fn distlist_to_message(
    card: &VCard,
    members: Option<&[DistMember<'_>]>,
) -> Result<MessageContent, ConvertError> {
    distlist::to_message(card, members)
}

pub fn distlist_name(props: &PropBag) -> Option<&str> {
    distlist::name(props)
}

pub fn distlist_members<'x>(
    props: &'x PropBag,
    changes: Option<&PropBag>,
) -> Result<Vec<DistMember<'x>>, ConvertError> {
    distlist::members(props, changes)
}

pub fn is_distlist_member_key(key: PropKeyRef<'_>) -> bool {
    distlist::is_member_key(key)
}

pub fn is_distlist_name_key(key: PropKeyRef<'_>) -> bool {
    distlist::is_name_key(key)
}

pub fn patch_distlist(
    card: &mut VCard,
    name: Option<&str>,
    members: Option<&[String]>,
    hidden: &dyn Fn(&str) -> bool,
) {
    distlist::patch(card, name, members, hidden)
}

pub fn is_internet_email_type<'x>(types: impl Iterator<Item = &'x str>) -> bool {
    to_message::is_internet_email(types)
}

pub fn contact_to_message(
    card: &VCard,
    opts: &ConvertOptions<'_>,
) -> Result<MessageContent, ConvertError> {
    to_message::contact(card, opts)
}

pub fn patch_contact_from_message(
    card: &mut VCard,
    changes: &PropBag,
) -> Result<PatchReport, ConvertError> {
    patch::contact(card, changes)
}

pub fn patch_contact_photo(card: &mut VCard, photo: Option<&[u8]>) -> bool {
    let data = match photo {
        Some(bytes) => {
            let Some(media) = patch::image_type(bytes) else {
                return false;
            };
            Some(Box::new(Data {
                content_type: Some(media.to_string()),
                data: bytes.to_vec(),
            }))
        }
        None => None,
    };
    patch::set_photo(card, data);
    true
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/convert/vcard/tests.rs"]
mod tests;
