/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{DavError, DavResourceName};
use common::{
    DavResourcePath, Server,
    auth::AccessToken,
    storage::dav::{DavFileNameError, canonical_calcard_uri, canonical_dav_resource_uri},
};
use groupware::cache::GroupwareCache;
use http_proto::request::decode_path_element;
use hyper::StatusCode;
use std::{borrow::Cow, fmt::Display};
use trc::AddContext;
use types::collection::Collection;

#[derive(Debug)]
pub(crate) struct UriResource<A, R> {
    pub collection: Collection,
    pub account_id: A,
    pub resource: R,
}

pub(crate) enum Urn {
    Lock(u64),
    Sync(SyncToken),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncToken {
    State(u64),
    ChangesPage {
        from: u64,
        snapshot: u64,
        offset: u64,
    },
    InitialPage {
        snapshot: u64,
        after: SyncCursor,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SyncCursor(u128);

impl SyncCursor {
    const PARENT_BITS: u32 = 33;
    const DOCUMENT_BITS: u32 = 32;

    pub fn new(
        account_id: u32,
        is_container: bool,
        document_id: u32,
        parent_id: Option<u32>,
    ) -> Self {
        let parent = parent_id.map_or(0, |parent_id| u128::from(parent_id) + 1);
        let document = u128::from(document_id) << Self::PARENT_BITS;
        let is_item = u128::from(!is_container) << (Self::PARENT_BITS + Self::DOCUMENT_BITS);
        let account = u128::from(account_id) << (Self::PARENT_BITS + Self::DOCUMENT_BITS + 1);
        SyncCursor(account | is_item | document | parent)
    }

    pub fn from_path(account_id: u32, path: &DavResourcePath<'_>) -> Self {
        SyncCursor::new(
            account_id,
            path.is_container(),
            path.document_id(),
            path.parent_id(),
        )
    }
}

pub(crate) type UnresolvedUri<'x> = UriResource<Option<u32>, Option<&'x str>>;
pub(crate) type OwnedUri<'x> = UriResource<u32, Option<&'x str>>;
pub(crate) type DocumentUri = UriResource<u32, u32>;

pub(crate) trait DavUriResource: Sync + Send {
    fn validate_uri_with_status<'x>(
        &self,
        access_token: &AccessToken,
        uri: &'x str,
        error_status: StatusCode,
    ) -> impl Future<Output = crate::Result<UnresolvedUri<'x>>> + Send;

    fn validate_uri<'x>(
        &self,
        access_token: &AccessToken,
        uri: &'x str,
    ) -> impl Future<Output = crate::Result<UnresolvedUri<'x>>> + Send;

    fn map_uri_resource(
        &self,
        access_token: &AccessToken,
        uri: OwnedUri<'_>,
    ) -> impl Future<Output = trc::Result<Option<DocumentUri>>> + Send;
}

impl DavUriResource for Server {
    async fn validate_uri<'x>(
        &self,
        access_token: &AccessToken,
        uri: &'x str,
    ) -> crate::Result<UnresolvedUri<'x>> {
        self.validate_uri_with_status(access_token, uri, StatusCode::NOT_FOUND)
            .await
    }

    async fn validate_uri_with_status<'x>(
        &self,
        access_token: &AccessToken,
        uri: &'x str,
        error_status: StatusCode,
    ) -> crate::Result<UnresolvedUri<'x>> {
        let (_, uri_parts) = uri
            .split_once("/dav/")
            .ok_or(DavError::Code(error_status))?;

        let mut uri_parts = uri_parts
            .trim_end_matches('/')
            .splitn(3, '/')
            .filter(|x| !x.is_empty());
        let mut resource = UriResource {
            collection: uri_parts
                .next()
                .and_then(DavResourceName::parse)
                .ok_or(DavError::Code(error_status))?
                .into(),
            account_id: None,
            resource: None,
        };
        if let Some(account) = uri_parts.next() {
            // Parse account id
            let account_id = if let Some(account_id) = account.strip_prefix('_') {
                account_id
                    .parse::<u32>()
                    .map_err(|_| DavError::Code(error_status))?
            } else {
                let account = decode_path_element(account);
                self.account_id_from_email(&account, false)
                    .await
                    .caused_by(trc::location!())?
                    .ok_or(DavError::Code(error_status))?
            };

            // Validate access
            if resource.collection != Collection::Principal
                && !access_token.has_access(account_id, resource.collection)
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Obtain remaining path
            resource.account_id = Some(account_id);
            resource.resource = uri_parts.next();
        }

        Ok(resource)
    }

    async fn map_uri_resource(
        &self,
        access_token: &AccessToken,
        uri: OwnedUri<'_>,
    ) -> trc::Result<Option<DocumentUri>> {
        if let Some(resource) = uri.resource {
            if let Some(resource) = self
                .fetch_groupware_resources(
                    access_token.account_id(),
                    uri.account_id,
                    uri.collection.into(),
                )
                .await
                .caused_by(trc::location!())?
                .by_path(resource)
            {
                Ok(Some(DocumentUri {
                    collection: if resource.is_container() {
                        uri.collection
                    } else {
                        uri.collection.child_collection().unwrap_or(uri.collection)
                    },
                    account_id: uri.account_id,
                    resource: resource.document_id(),
                }))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}

impl<'x> UnresolvedUri<'x> {
    pub fn into_owned_uri(self) -> crate::Result<OwnedUri<'x>> {
        Ok(OwnedUri {
            collection: self.collection,
            account_id: self
                .account_id
                .ok_or(DavError::Code(StatusCode::FORBIDDEN))?,
            resource: self.resource,
        })
    }
}

impl OwnedUri<'_> {
    pub fn new_owned(
        collection: Collection,
        account_id: u32,
        resource: Option<&str>,
    ) -> OwnedUri<'_> {
        OwnedUri {
            collection,
            account_id,
            resource,
        }
    }
}

pub(crate) fn canonical_dav_uri(uri: &str) -> Result<Cow<'_, str>, DavFileNameError> {
    match uri
        .split_once("/dav/")
        .and_then(|(_, path)| path.split_once('/'))
        .and_then(|(collection, _)| DavResourceName::parse(collection))
    {
        Some(DavResourceName::File) => canonical_dav_resource_uri(uri),
        Some(DavResourceName::Cal | DavResourceName::Card) => Ok(canonical_calcard_uri(uri)),
        Some(DavResourceName::Principal | DavResourceName::Scheduling) | None => {
            Ok(Cow::Borrowed(uri))
        }
    }
}

impl Urn {
    pub fn try_extract_sync_id(token: &str) -> Option<&str> {
        token
            .strip_prefix("urn:stalwart:davsync:")
            .map(|x| x.split_once(':').map(|(x, _)| x).unwrap_or(x))
    }

    pub fn parse(input: &str) -> Option<Self> {
        let inbox = input.strip_prefix("urn:stalwart:")?;
        let (kind, id) = inbox.split_once(':')?;
        match kind {
            "davlock" => u64::from_str_radix(id, 16).ok().map(Urn::Lock),
            "davsync" => SyncToken::parse(id).map(Urn::Sync),
            _ => None,
        }
    }

    pub fn try_unwrap_lock(&self) -> Option<u64> {
        match self {
            Urn::Lock(id) => Some(*id),
            _ => None,
        }
    }

    pub fn try_unwrap_sync(&self) -> Option<SyncToken> {
        match self {
            Urn::Sync(token) => Some(*token),
            _ => None,
        }
    }
}

impl Display for Urn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Urn::Lock(id) => write!(f, "urn:stalwart:davlock:{id:x}",),
            Urn::Sync(token) => write!(f, "urn:stalwart:davsync:{token}"),
        }
    }
}

impl SyncToken {
    fn parse(input: &str) -> Option<Self> {
        let mut parts = input.splitn(3, ':');
        let id = u64::from_str_radix(parts.next()?, 16).ok()?;
        match (parts.next(), parts.next()) {
            (None, None) => Some(SyncToken::State(id)),
            (Some(after), None) => Some(SyncToken::InitialPage {
                snapshot: id,
                after: SyncCursor(u128::from_str_radix(after.strip_prefix('i')?, 16).ok()?),
            }),
            (Some(offset), Some(snapshot)) => Some(SyncToken::ChangesPage {
                from: id,
                snapshot: u64::from_str_radix(snapshot, 16).ok()?,
                offset: u64::from_str_radix(offset, 16).ok()?,
            }),
            (None, Some(_)) => None,
        }
    }
}

impl Display for SyncToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncToken::State(id) => write!(f, "{id:x}"),
            SyncToken::ChangesPage {
                from,
                snapshot,
                offset,
            } => write!(f, "{from:x}:{offset:x}:{snapshot:x}"),
            SyncToken::InitialPage { snapshot, after } => {
                write!(f, "{snapshot:x}:i{:x}", after.0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SyncCursor, SyncToken, Urn};

    const EDGES: [u32; 5] = [0, 1, 2, u32::MAX - 1, u32::MAX];

    #[test]
    fn sync_token_roundtrip() {
        for token in [
            SyncToken::State(0),
            SyncToken::State(u64::MAX),
            SyncToken::ChangesPage {
                from: 1,
                snapshot: 0xabc,
                offset: 3,
            },
            SyncToken::ChangesPage {
                from: u64::MAX,
                snapshot: u64::MAX,
                offset: u64::MAX,
            },
            SyncToken::InitialPage {
                snapshot: 0,
                after: SyncCursor::new(0, true, 0, None),
            },
            SyncToken::InitialPage {
                snapshot: u64::MAX,
                after: SyncCursor::new(u32::MAX, false, u32::MAX, Some(u32::MAX)),
            },
        ] {
            let urn = Urn::Sync(token).to_string();
            assert_eq!(
                Urn::parse(&urn).and_then(|urn| urn.try_unwrap_sync()),
                Some(token),
                "{urn}"
            );
        }
    }

    #[test]
    fn sync_token_rejects_malformed() {
        for urn in [
            "urn:stalwart:davsync:",
            "urn:stalwart:davsync:zz",
            "urn:stalwart:davsync:1:2",
            "urn:stalwart:davsync:1:i",
            "urn:stalwart:davsync:1:ixyz",
            "urn:stalwart:davsync:1:2:",
            "urn:stalwart:davsync:1::3",
            "urn:stalwart:davsync:1:2:3:4",
            "urn:stalwart:davsync:1:i1:2",
        ] {
            assert!(
                Urn::parse(urn)
                    .and_then(|urn| urn.try_unwrap_sync())
                    .is_none(),
                "{urn}"
            );
        }
    }

    #[test]
    fn sync_cursor_matches_tuple_order() {
        let mut keys = Vec::new();
        for account_id in EDGES {
            for is_container in [true, false] {
                for document_id in EDGES {
                    for parent_id in [None, Some(0), Some(1), Some(u32::MAX)] {
                        keys.push((account_id, is_container, document_id, parent_id));
                    }
                }
            }
        }
        let reference =
            |(account_id, is_container, document_id, parent_id): (u32, bool, u32, Option<u32>)| {
                (
                    account_id,
                    !is_container,
                    document_id,
                    parent_id.map_or(0, |parent_id| u64::from(parent_id) + 1),
                )
            };
        let cursor =
            |(account_id, is_container, document_id, parent_id): (u32, bool, u32, Option<u32>)| {
                SyncCursor::new(account_id, is_container, document_id, parent_id)
            };
        for &a in &keys {
            for &b in &keys {
                assert_eq!(
                    cursor(a).cmp(&cursor(b)),
                    reference(a).cmp(&reference(b)),
                    "{a:?} {b:?}"
                );
            }
        }
    }
}
