/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{DavError, DavErrorCondition};
use common::GroupwareResources;
use dav_proto::schema::{
    property::{CardDavProperty, DavProperty, WebDavProperty},
    response::CardCondition,
};
use hyper::StatusCode;

pub mod copy_move;
pub mod delete;
pub mod filter;
pub mod get;
pub mod mkcol;
pub mod proppatch;
pub mod query;
pub mod update;

pub(crate) static CARD_CONTAINER_PROPS: [DavProperty; 23] = [
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::Owner),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::Acl),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::InheritedAclSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::SupportedReportSet),
    DavProperty::WebDav(WebDavProperty::QuotaAvailableBytes),
    DavProperty::WebDav(WebDavProperty::QuotaUsedBytes),
    DavProperty::CardDav(CardDavProperty::AddressbookDescription),
    DavProperty::CardDav(CardDavProperty::SupportedAddressData),
    DavProperty::CardDav(CardDavProperty::SupportedCollationSet),
    DavProperty::CardDav(CardDavProperty::MaxResourceSize),
];

pub(crate) static CARD_ITEM_PROPS: [DavProperty; 20] = [
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::Owner),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::Acl),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::InheritedAclSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::GetContentLanguage),
    DavProperty::WebDav(WebDavProperty::GetContentLength),
    DavProperty::WebDav(WebDavProperty::GetContentType),
    DavProperty::CardDav(CardDavProperty::AddressData {
        properties: Vec::new(),
        version: None,
    }),
];

pub(crate) fn assert_is_unique_uid(
    resources: &GroupwareResources,
    addressbook_id: u32,
    uid: Option<&str>,
) -> crate::Result<()> {
    if let Some(uid) = uid {
        let hits = resources.uid_matches(uid);
        if !hits.is_empty() {
            for path in resources.children(addressbook_id) {
                if hits.contains(path.document_id()) {
                    return Err(DavError::Condition(DavErrorCondition::new(
                        StatusCode::PRECONDITION_FAILED,
                        CardCondition::NoUidConflict(resources.format_resource(path).into()),
                    )));
                }
            }
        }
    }

    Ok(())
}

const URN_UUID_PREFIX: &str = "urn:uuid:";
const UUID_GROUP_LENGTHS: [usize; 5] = [8, 4, 4, 4, 12];

pub(crate) fn is_same_uid(uid: &str, other: &str) -> bool {
    uid == other
        || matches!(
            (uuid_of(uid), uuid_of(other)),
            (Some(uuid), Some(other_uuid)) if uuid.eq_ignore_ascii_case(other_uuid)
        )
}

fn uuid_of(uid: &str) -> Option<&str> {
    let uuid = uid
        .split_at_checked(URN_UUID_PREFIX.len())
        .filter(|(prefix, _)| prefix.eq_ignore_ascii_case(URN_UUID_PREFIX))
        .map_or(uid, |(_, uuid)| uuid);
    let mut groups = uuid.split('-');

    (UUID_GROUP_LENGTHS.iter().all(|&len| {
        groups
            .next()
            .is_some_and(|group| group.len() == len && group.bytes().all(|b| b.is_ascii_hexdigit()))
    }) && groups.next().is_none())
    .then_some(uuid)
}

#[cfg(test)]
mod tests {
    use super::is_same_uid;

    #[test]
    fn uid_spellings_of_the_same_uuid_match() {
        for (uid, other, expected) in [
            (
                "urn:uuid:cddccf70-dc55-4cad-a171-f55f1c5c0162",
                "cddccf70-dc55-4cad-a171-f55f1c5c0162",
                true,
            ),
            (
                "URN:UUID:CDDCCF70-DC55-4CAD-A171-F55F1C5C0162",
                "urn:uuid:cddccf70-dc55-4cad-a171-f55f1c5c0162",
                true,
            ),
            (
                "cddccf70-dc55-4cad-a171-f55f1c5c0162",
                "CDDCCF70-DC55-4CAD-A171-F55F1C5C0162",
                true,
            ),
            ("foo", "foo", true),
            ("urn:uuid:foo", "foo", false),
            (
                "urn:uuid:cddccf70-dc55-4cad-a171-f55f1c5c0162",
                "urn:uuid:0ddccf70-dc55-4cad-a171-f55f1c5c0162",
                false,
            ),
            (
                "urn:isbn:cddccf70-dc55-4cad-a171-f55f1c5c0162",
                "cddccf70-dc55-4cad-a171-f55f1c5c0162",
                false,
            ),
            (
                "cddccf70dc554cada171f55f1c5c0162",
                "cddccf70-dc55-4cad-a171-f55f1c5c0162",
                false,
            ),
            (
                "cddccf70-dc55-4cad-a171-f55f1c5c016g",
                "CDDCCF70-DC55-4CAD-A171-F55F1C5C016G",
                false,
            ),
            (
                "cddccf70-dc55-4cad-a171-f55f1c5c0162-",
                "urn:uuid:cddccf70-dc55-4cad-a171-f55f1c5c0162-",
                false,
            ),
        ] {
            assert_eq!(is_same_uid(uid, other), expected, "{uid} vs {other}");
            assert_eq!(is_same_uid(other, uid), expected, "{other} vs {uid}");
        }
    }
}
