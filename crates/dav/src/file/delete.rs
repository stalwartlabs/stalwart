/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavMethod,
    common::{
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
};
use common::{Server, auth::AccessToken};
use dav_proto::RequestHeaders;
use groupware::{DestroyArchive, cache::GroupwareCache};
use http_proto::HttpResponse;
use hyper::StatusCode;
use trc::AddContext;
use types::{acl::Acl, collection::SyncCollection};

pub(crate) trait FileDeleteRequestHandler: Sync + Send {
    fn handle_file_delete_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileDeleteRequestHandler for Server {
    async fn handle_file_delete_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource.account_id;
        let delete_path = resource
            .resource
            .filter(|r| !r.is_empty())
            .ok_or(DavError::Code(StatusCode::FORBIDDEN))?;
        let resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
            .await
            .caused_by(trc::location!())?;

        let access =
            (!access_token.is_member(account_id)).then(|| resources.file_access(access_token));
        if let Some(access) = &access {
            resources.hide_undiscoverable(
                &access.discoverable,
                delete_path,
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
            )?;
        }

        // Find ids to delete
        let mut ids = resources.subtree(delete_path).collect::<Vec<_>>();
        if ids.is_empty() || ids.first().is_some_and(super::is_symlink) {
            return Err(DavError::Code(StatusCode::NOT_FOUND));
        }

        // Sort ids descending from the deepest to the root
        ids.sort_unstable_by_key(|b| std::cmp::Reverse(b.hierarchy_seq()));
        let (document_id, full_delete_path) = ids
            .last()
            .map(|a| (a.document_id(), resources.format_resource(*a)))
            .unwrap();
        let mut sorted_ids = Vec::with_capacity(ids.len());
        sorted_ids.extend(ids.into_iter().map(|a| a.document_id()));

        // Validate ACLs
        if let Some(access) = &access
            && !sorted_ids.iter().all(|id| access.has_acl(*id, Acl::Delete))
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Validate headers
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection: resource.collection,
                document_id: document_id.into(),
                path: delete_path,
                ..Default::default()
            }],
            Default::default(),
            DavMethod::DELETE,
        )
        .await?;

        DestroyArchive(sorted_ids)
            .delete(
                self,
                access_token.account_tenant_ids(),
                account_id,
                full_delete_path.into(),
            )
            .await?;

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    }
}
