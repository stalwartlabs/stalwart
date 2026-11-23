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
use groupware::contact::write::{CardWriteError, assert_unique_uid};
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
    assert_unique_uid(resources, addressbook_id, uid).map_err(Into::into)
}

impl From<CardWriteError> for DavError {
    fn from(err: CardWriteError) -> Self {
        match err {
            CardWriteError::NotFound => DavError::Code(StatusCode::NOT_FOUND),
            CardWriteError::Forbidden | CardWriteError::UidChanged(None) => {
                DavError::Code(StatusCode::FORBIDDEN)
            }
            CardWriteError::UidChanged(Some(path))
            | CardWriteError::UidConflict { href: path, .. } => {
                DavError::Condition(DavErrorCondition::new(
                    StatusCode::FORBIDDEN,
                    CardCondition::NoUidConflict(path.into()),
                ))
            }
            CardWriteError::Store(err) => DavError::Internal(err),
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/dav/src/card/tests.rs"]
mod tests;
