/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError,
    common::uri::{OwnedUri, UriResource},
};
use common::{
    DavResourcePath, GroupwareResources,
    auth::AccessToken,
    storage::dav::{DavFileNameError, FILE_KIND_SYMLINK, dav_file_name},
};
use dav_proto::schema::property::{DavProperty, WebDavProperty};
use hyper::StatusCode;
use store::{roaring::RoaringBitmap, write::BatchBuilder};
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};

pub mod copy_move;
pub mod delete;
pub mod get;
pub mod mkcol;
pub mod proppatch;
pub mod update;

pub(crate) static FILE_CONTAINER_PROPS: [DavProperty; 19] = [
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
];

pub(crate) static FILE_ITEM_PROPS: [DavProperty; 19] = [
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
];

pub(crate) trait FromDavResource {
    fn from_dav_resource(item: DavResourcePath<'_>) -> Self;
}

pub(crate) struct FileItemId {
    pub document_id: u32,
    pub parent_id: Option<u32>,
    pub is_container: bool,
}

pub(crate) trait DavFileResource {
    fn map_resource<T: FromDavResource>(
        &self,
        resource: &OwnedUri<'_>,
    ) -> crate::Result<UriResource<u32, T>>;

    fn map_parent<'x>(&self, resource: &'x str) -> Option<(Option<DavResourcePath<'_>>, &'x str)>;

    fn map_directory_parent(&self, resource: &str) -> crate::Result<Option<DavResourcePath<'_>>>;

    fn log_descendant_updates(&self, batch: &mut BatchBuilder, account_id: u32, path: &str);

    fn hide_undiscoverable(
        &self,
        discoverable: &RoaringBitmap,
        path: &str,
        hidden_target: StatusCode,
        hidden_parent: StatusCode,
    ) -> crate::Result<()>;
}

impl DavFileResource for GroupwareResources {
    fn map_resource<T: FromDavResource>(
        &self,
        resource: &OwnedUri<'_>,
    ) -> crate::Result<UriResource<u32, T>> {
        resource
            .resource
            .and_then(|r| self.by_path(r))
            .filter(|r| !is_symlink(r))
            .map(|r| UriResource {
                collection: resource.collection,
                account_id: resource.account_id,
                resource: T::from_dav_resource(r),
            })
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))
    }

    fn map_parent<'x>(&self, resource: &'x str) -> Option<(Option<DavResourcePath<'_>>, &'x str)> {
        let (parent, child) = if let Some((parent, child)) = resource.rsplit_once('/') {
            (Some(self.by_path(parent)?), child)
        } else {
            (None, resource)
        };

        Some((parent, child))
    }

    fn map_directory_parent(&self, resource: &str) -> crate::Result<Option<DavResourcePath<'_>>> {
        self.map_parent(resource)
            .map(|(parent, _)| parent)
            .filter(|parent| parent.as_ref().is_none_or(DavResourcePath::is_container))
            .ok_or(DavError::Code(StatusCode::CONFLICT))
    }

    fn log_descendant_updates(&self, batch: &mut BatchBuilder, account_id: u32, path: &str) {
        let mut descendants = self
            .subtree(path)
            .filter(|descendant| descendant.path() != path)
            .peekable();
        if descendants.peek().is_none() {
            return;
        }
        batch
            .with_account_id(account_id)
            .with_collection(Collection::FileNode);
        for descendant in descendants {
            batch
                .with_document(descendant.document_id())
                .log_item_update(SyncCollection::FileNode, None);
        }
        batch.commit_point();
    }

    fn hide_undiscoverable(
        &self,
        discoverable: &RoaringBitmap,
        path: &str,
        hidden_target: StatusCode,
        hidden_parent: StatusCode,
    ) -> crate::Result<()> {
        let mut current = Some(path);
        let mut status = hidden_target;
        while let Some(path) = current {
            if let Some(resource) = self.by_path(path) {
                return if discoverable.contains(resource.document_id()) {
                    Ok(())
                } else {
                    Err(DavError::Code(status))
                };
            }
            status = hidden_parent;
            current = path.rsplit_once('/').map(|(parent, _)| parent);
        }
        Ok(())
    }
}

pub(crate) fn file_name_from_uri(uri: &str) -> crate::Result<String> {
    let segment = uri
        .trim_end_matches('/')
        .rsplit_once('/')
        .map_or(uri, |(_, segment)| segment);
    dav_file_name(segment).map_err(|err| {
        DavError::Code(match err {
            DavFileNameError::TooLong => StatusCode::URI_TOO_LONG,
            DavFileNameError::Empty
            | DavFileNameError::InvalidCharacter
            | DavFileNameError::ReservedName => StatusCode::BAD_REQUEST,
        })
    })
}

pub(crate) fn is_symlink(resource: &DavResourcePath<'_>) -> bool {
    resource.resource.file_kind() == Some(FILE_KIND_SYMLINK)
}

pub(crate) fn validate_file_parent_acl(
    resources: &GroupwareResources,
    access_token: &AccessToken,
    is_member: bool,
    parent_id: Option<u32>,
    acl: Acl,
) -> crate::Result<u32> {
    match parent_id {
        Some(parent_id)
            if is_member || resources.file_acl(access_token, parent_id).contains(acl) =>
        {
            Ok(parent_id + 1)
        }
        None if is_member => Ok(0),
        _ => Err(DavError::Code(StatusCode::FORBIDDEN)),
    }
}

impl FromDavResource for u32 {
    fn from_dav_resource(item: DavResourcePath) -> Self {
        item.document_id()
    }
}

impl FromDavResource for FileItemId {
    fn from_dav_resource(item: DavResourcePath) -> Self {
        FileItemId {
            document_id: item.document_id(),
            parent_id: item.parent_id(),
            is_container: item.is_container(),
        }
    }
}
