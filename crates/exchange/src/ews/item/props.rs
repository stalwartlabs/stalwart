/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    ews::filter::FilterProp, mapi::emsmdb::message::object_row::is_carried as is_mapi_carried,
};
use exchange_proto::{
    convert::mime::is_envelope_key,
    ews::{
        schema::{DistinguishedPropertySet, MapiPropertyTypeName, UnindexedField},
        types::{
            path::Path,
            xprop::{ExtendedFieldUri, XPropNamedId, XPropSet, XPropTarget},
        },
    },
    mapi::prop::PropKeyRef,
};

const PR_URL_COMP_NAME: u16 = 0x10F3;
const PR_ICON_INDEX: u16 = 0x1080;
const PR_JUNK_FLAG: u16 = 0x1083;
const IGNORED_TAGS: [u16; 3] = [PR_URL_COMP_NAME, PR_ICON_INDEX, PR_JUNK_FLAG];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ItemProp {
    Subject,
    ItemClass,
    Size,
    Received,
    Sent,
    IsRead,
    HasAttachments,
    Importance,
    From,
    To,
    Cc,
    MessageId,
    ImapUid,
    MessageFlags,
    FlagStatus,
    LastVerb,
    LastModified,
    ContentClass,
    Keywords,
    ImapDeleted,
    TransportHeaders,
    ConversationIndex,
    Location,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnownTarget {
    Tag(u16),
    Id(DistinguishedPropertySet, i32),
    Name(DistinguishedPropertySet, &'static str),
}

const PID_LID_IMAP_DELETED: i32 = 0x8570;
const PID_LID_CATEGORIES: i32 = 0x2328;

pub(crate) const EXTENDED_PROPS: [(KnownTarget, MapiPropertyTypeName, ItemProp); 16] = [
    (
        KnownTarget::Tag(0x0037),
        MapiPropertyTypeName::String,
        ItemProp::Subject,
    ),
    (
        KnownTarget::Tag(0x001A),
        MapiPropertyTypeName::String,
        ItemProp::ItemClass,
    ),
    (
        KnownTarget::Tag(0x0E08),
        MapiPropertyTypeName::Integer,
        ItemProp::Size,
    ),
    (
        KnownTarget::Tag(0x0E06),
        MapiPropertyTypeName::SystemTime,
        ItemProp::Received,
    ),
    (
        KnownTarget::Tag(0x0039),
        MapiPropertyTypeName::SystemTime,
        ItemProp::Sent,
    ),
    (
        KnownTarget::Tag(0x0E23),
        MapiPropertyTypeName::Integer,
        ItemProp::ImapUid,
    ),
    (
        KnownTarget::Tag(0x0E07),
        MapiPropertyTypeName::Integer,
        ItemProp::MessageFlags,
    ),
    (
        KnownTarget::Tag(0x1090),
        MapiPropertyTypeName::Integer,
        ItemProp::FlagStatus,
    ),
    (
        KnownTarget::Tag(0x1081),
        MapiPropertyTypeName::Integer,
        ItemProp::LastVerb,
    ),
    (
        KnownTarget::Tag(0x3008),
        MapiPropertyTypeName::SystemTime,
        ItemProp::LastModified,
    ),
    (
        KnownTarget::Tag(0x007D),
        MapiPropertyTypeName::String,
        ItemProp::TransportHeaders,
    ),
    (
        KnownTarget::Tag(0x1035),
        MapiPropertyTypeName::String,
        ItemProp::MessageId,
    ),
    (
        KnownTarget::Id(DistinguishedPropertySet::Common, PID_LID_IMAP_DELETED),
        MapiPropertyTypeName::Integer,
        ItemProp::ImapDeleted,
    ),
    (
        KnownTarget::Name(DistinguishedPropertySet::InternetHeaders, "content-class"),
        MapiPropertyTypeName::String,
        ItemProp::ContentClass,
    ),
    (
        KnownTarget::Name(DistinguishedPropertySet::PublicStrings, "Keywords"),
        MapiPropertyTypeName::StringArray,
        ItemProp::Keywords,
    ),
    (
        KnownTarget::Id(DistinguishedPropertySet::PublicStrings, PID_LID_CATEGORIES),
        MapiPropertyTypeName::StringArray,
        ItemProp::Keywords,
    ),
];

impl KnownTarget {
    fn matches(self, target: &XPropTarget<'_>) -> bool {
        match (self, target) {
            (KnownTarget::Tag(known), XPropTarget::Tag(tag)) => known == *tag,
            (KnownTarget::Id(set, known), XPropTarget::Named { set: requested, id }) => {
                same_set(set, *requested) && *id == XPropNamedId::Id(known)
            }
            (KnownTarget::Name(set, known), XPropTarget::Named { set: requested, id }) => {
                same_set(set, *requested)
                    && matches!(id, XPropNamedId::Name(name) if name.eq_ignore_ascii_case(known))
            }
            _ => false,
        }
    }
}

fn same_set(known: DistinguishedPropertySet, requested: XPropSet) -> bool {
    requested.guid() == known.data()
}

impl FilterProp for ItemProp {
    fn of_path(path: &Path<'_>) -> Option<Self> {
        match path {
            Path::Field(field) => Self::of_field(*field),
            Path::Extended(uri) => Self::of_extended(uri).map(|(_, prop)| prop),
            Path::Indexed { .. } => None,
        }
    }
}

impl ItemProp {
    fn of_field(field: UnindexedField) -> Option<Self> {
        Some(match field {
            UnindexedField::ItemSubject => ItemProp::Subject,
            UnindexedField::ItemItemClass => ItemProp::ItemClass,
            UnindexedField::ItemSize => ItemProp::Size,
            UnindexedField::ItemDateTimeReceived | UnindexedField::ItemDateTimeCreated => {
                ItemProp::Received
            }
            UnindexedField::ItemDateTimeSent => ItemProp::Sent,
            UnindexedField::MessageIsRead => ItemProp::IsRead,
            UnindexedField::ItemHasAttachments => ItemProp::HasAttachments,
            UnindexedField::ItemImportance => ItemProp::Importance,
            UnindexedField::MessageFrom | UnindexedField::MessageSender => ItemProp::From,
            UnindexedField::MessageToRecipients | UnindexedField::ItemDisplayTo => ItemProp::To,
            UnindexedField::MessageCcRecipients | UnindexedField::ItemDisplayCc => ItemProp::Cc,
            UnindexedField::MessageInternetMessageId => ItemProp::MessageId,
            UnindexedField::ItemLastModifiedTime => ItemProp::LastModified,
            UnindexedField::MessageConversationIndex => ItemProp::ConversationIndex,
            UnindexedField::CalendarLocation => ItemProp::Location,
            _ => return None,
        })
    }

    pub fn of_extended(uri: &ExtendedFieldUri<'_>) -> Option<(usize, Self)> {
        EXTENDED_PROPS
            .iter()
            .enumerate()
            .find(|(_, (target, ptype, _))| *ptype == uri.ptype && target.matches(&uri.target))
            .map(|(index, (_, _, prop))| (index, *prop))
    }

    pub const fn needs_metadata(self) -> bool {
        matches!(
            self,
            ItemProp::Subject
                | ItemProp::ItemClass
                | ItemProp::HasAttachments
                | ItemProp::Importance
                | ItemProp::From
                | ItemProp::To
                | ItemProp::Cc
                | ItemProp::MessageId
                | ItemProp::MessageFlags
                | ItemProp::TransportHeaders
                | ItemProp::Location
        )
    }
}

pub(crate) fn is_ignored_tag(target: &XPropTarget<'_>) -> bool {
    matches!(target, XPropTarget::Tag(tag) if IGNORED_TAGS.contains(tag))
}

pub(crate) fn is_carried_key(key: PropKeyRef<'_>) -> bool {
    is_mapi_carried(key) && !is_envelope_key(key)
}

pub(crate) fn is_carried(uri: &ExtendedFieldUri<'_>, key: PropKeyRef<'_>) -> bool {
    is_carried_key(key)
        && !EXTENDED_PROPS
            .iter()
            .any(|(target, ..)| target.matches(&uri.target))
}
