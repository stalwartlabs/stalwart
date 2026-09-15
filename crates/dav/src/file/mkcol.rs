/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::proppatch::FilePropPatchRequestHandler;
use crate::{
    DavError, DavMethod, PropStatBuilder,
    common::{
        ExtractETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::{DavFileResource, file_name_from_uri, is_symlink, validate_file_parent_acl},
};
use common::{
    Server,
    auth::AccessToken,
    storage::{dav::MAX_FILE_NODE_DEPTH, index::ObjectIndexBuilder},
};
use dav_proto::{
    RequestHeaders, Return,
    schema::{Namespace, request::MkCol, response::MkColResponse},
};
use groupware::{cache::GroupwareCache, file::FileNode};
use http_proto::HttpResponse;
use hyper::StatusCode;
use registry::schema::enums::StorageQuota;
use store::write::{BatchBuilder, now};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};

pub(crate) trait FileMkColRequestHandler: Sync + Send {
    fn handle_file_mkcol_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: Option<MkCol>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileMkColRequestHandler for Server {
    async fn handle_file_mkcol_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: Option<MkCol>,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
            .await
            .caused_by(trc::location!())?;
        let path = resource_
            .resource
            .ok_or(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))?;
        if !access_token.is_member(account_id) {
            resources.hide_undiscoverable(
                &resources.file_access(access_token).discoverable,
                path,
                StatusCode::FORBIDDEN,
                StatusCode::CONFLICT,
            )?;
        }
        if let Some(existing) = resources.by_path(path) {
            return Err(DavError::Code(if is_symlink(&existing) {
                StatusCode::CONFLICT
            } else {
                StatusCode::METHOD_NOT_ALLOWED
            }));
        }
        let parent = resources.map_directory_parent(path)?;

        // Validate and map parent ACL
        let parent_id = validate_file_parent_acl(
            &resources,
            access_token,
            access_token.is_member(account_id),
            parent.map(|parent| parent.document_id()),
            Acl::AddItems,
        )?;
        let name = file_name_from_uri(headers.uri)?;
        if path.split('/').count() > MAX_FILE_NODE_DEPTH {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Validate quota
        self.assert_object_quota(
            &*self.account(account_id).await?,
            StorageQuota::MaxFolders,
            1,
            || resources.resources.count(true),
        )?;

        // Validate headers
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection: resource_.collection,
                document_id: Some(u32::MAX),
                path,
                ..Default::default()
            }],
            Default::default(),
            DavMethod::MKCOL,
        )
        .await?;

        // Build file container
        let now = now();
        let mut node = FileNode {
            parent_id,
            name,
            created: now as i64,
            modified: now as i64,
            accessed: now as i64,
            changed: now as i64,
            ..Default::default()
        };

        // Apply MKCOL properties
        let mut return_prop_stat = None;
        if let Some(mkcol) = request {
            let mut prop_stat = PropStatBuilder::default();
            if !self.apply_file_properties(&mut node, false, mkcol.props, &mut prop_stat) {
                return Ok(HttpResponse::new(StatusCode::FORBIDDEN).with_xml_body(
                    MkColResponse::new(prop_stat.build())
                        .with_namespace(Namespace::Dav)
                        .to_string(),
                ));
            }
            if headers.ret != Return::Minimal {
                return_prop_stat = Some(prop_stat);
            }
        }

        // Prepare write batch
        let mut batch = BatchBuilder::new();
        let document_id = batch.reserve_document_id(account_id, Collection::FileNode);
        batch
            .with_account_id(account_id)
            .with_collection(Collection::FileNode)
            .create_document(document_id)
            .custom(ObjectIndexBuilder::<(), _>::new().with_changes(node))
            .caused_by(trc::location!())?;
        let etag = self
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?
            .etag();

        if let Some(prop_stat) = return_prop_stat {
            Ok(HttpResponse::new(StatusCode::CREATED)
                .with_xml_body(
                    MkColResponse::new(prop_stat.build())
                        .with_namespace(Namespace::Dav)
                        .to_string(),
                )
                .with_etag_opt(etag))
        } else {
            Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
        }
    }
}
