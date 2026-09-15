/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavMethod,
    common::{
        ETag, ExtractETag,
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
use dav_proto::{RequestHeaders, Return, schema::property::Rfc1123DateTime};
use groupware::{
    cache::GroupwareCache,
    file::{FileNode, FileNodeContent, FileProperties},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use registry::schema::enums::StorageQuota;
use store::write::{BatchBuilder, now};
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    acl::Acl,
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
};

pub(crate) trait FileUpdateRequestHandler: Sync + Send {
    fn handle_file_update_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: Vec<u8>,
        is_patch: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileUpdateRequestHandler for Server {
    async fn handle_file_update_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: Vec<u8>,
        _is_patch: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource.account_id;
        let resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
            .await
            .caused_by(trc::location!())?;
        let resource_name = resource
            .resource
            .ok_or(DavError::Code(StatusCode::CONFLICT))?;

        if bytes.len() > self.core.groupware.max_file_size {
            return Err(DavError::Code(StatusCode::PAYLOAD_TOO_LARGE));
        }

        if !access_token.is_member(account_id) {
            resources.hide_undiscoverable(
                &resources.file_access(access_token).discoverable,
                resource_name.as_ref(),
                StatusCode::FORBIDDEN,
                StatusCode::CONFLICT,
            )?;
        }

        if let Some(existing) = resources.by_path(resource_name.as_ref()) {
            if is_symlink(&existing) {
                return Err(DavError::Code(StatusCode::CONFLICT));
            }
            let document_id = existing.document_id();
            // Update
            let node_ = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::FileNode,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
            let node = node_
                .to_unarchived::<FileNode>()
                .caused_by(trc::location!())?;

            // Validate ACL
            if !access_token.is_member(account_id)
                && !resources
                    .file_acl(access_token, document_id)
                    .contains(Acl::ModifyItems)
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Validate headers
            match self
                .validate_headers(
                    access_token,
                    headers,
                    vec![ResourceState {
                        account_id,
                        collection: resource.collection,
                        document_id: Some(document_id),
                        etag: node.etag().into(),
                        path: resource_name,
                        ..Default::default()
                    }],
                    Default::default(),
                    DavMethod::PUT,
                )
                .await
            {
                Ok(_) => {}
                Err(DavError::Code(StatusCode::PRECONDITION_FAILED))
                    if headers.ret == Return::Representation =>
                {
                    let file = node
                        .inner
                        .file()
                        .ok_or(DavError::Code(StatusCode::PRECONDITION_FAILED))?;
                    let contents = self
                        .blob_store()
                        .get_blob(file.blob_hash.0.as_slice(), 0..usize::MAX)
                        .await
                        .caused_by(trc::location!())?
                        .ok_or(DavError::Code(StatusCode::PRECONDITION_FAILED))?;

                    return Ok(HttpResponse::new(StatusCode::PRECONDITION_FAILED)
                        .with_content_type(
                            file.media_type
                                .as_ref()
                                .map(|v| v.as_str())
                                .unwrap_or("application/octet-stream"),
                        )
                        .with_etag(node.etag())
                        .with_last_modified(
                            Rfc1123DateTime::new(i64::from(node.inner.modified)).to_string(),
                        )
                        .with_header("Preference-Applied", "return=representation")
                        .with_binary_body(contents));
                }
                Err(e) => return Err(e),
            }

            // Verify that the node is a file
            let current_size = if let Some(file) = node.inner.file() {
                if BlobHash::generate(&bytes).as_slice() == file.blob_hash.0.as_slice() {
                    return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
                }
                u32::from(file.size) as u64
            } else {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            };

            // Validate quota
            let extra_bytes = (bytes.len() as u64).saturating_sub(current_size);
            if extra_bytes > 0 {
                self.has_available_quota(self.account(account_id).await?.as_ref(), extra_bytes)
                    .await?;
            }

            // Write blob
            let (blob_hash, blob_hold) = self
                .put_temporary_blob(account_id, &bytes, 60)
                .await
                .caused_by(trc::location!())?;

            // Build node
            let mut new_node = node.deserialize::<FileNode>().caused_by(trc::location!())?;
            if let Some(new_file) = new_node.file_mut() {
                new_file.blob_hash = blob_hash;
                new_file.media_type = headers
                    .content_type
                    .filter(|ct| !ct.is_empty() && *ct != "application/octet-stream")
                    .map(|v| v.to_string());
                new_file.size = bytes.len() as u32;
            }
            new_node.stamp_update(true);

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::FileNode)
                .with_document(document_id)
                .clear(blob_hold)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_current(node)
                        .with_changes(new_node)
                        .with_changed_by(access_token.account_tenant_ids()),
                )
                .caused_by(trc::location!())?;
            let etag = batch.etag();
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
        } else {
            // Insert
            let orig_resource_name = resource_name;
            let parent = resources.map_directory_parent(orig_resource_name)?;
            let name = file_name_from_uri(headers.uri)?;
            if orig_resource_name.split('/').count() > MAX_FILE_NODE_DEPTH {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Validate ACL
            let parent_id = validate_file_parent_acl(
                &resources,
                access_token,
                access_token.is_member(account_id),
                parent.map(|parent| parent.document_id()),
                Acl::AddItems,
            )?;

            // Validate headers
            self.validate_headers(
                access_token,
                headers,
                vec![ResourceState {
                    account_id,
                    collection: resource.collection,
                    document_id: Some(u32::MAX),
                    path: orig_resource_name,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::PUT,
            )
            .await?;

            // Validate object quota
            let account = self.account(account_id).await?;
            self.assert_object_quota(&account, StorageQuota::MaxFiles, 1, || {
                resources.resources.count(false)
            })?;

            // Validate quota
            if !bytes.is_empty() {
                self.has_available_quota(&account, bytes.len() as u64)
                    .await?;
            }

            // Write blob
            let (blob_hash, blob_hold) = self
                .put_temporary_blob(account_id, &bytes, 60)
                .await
                .caused_by(trc::location!())?;

            // Build node
            let now = now();
            let node = FileNode {
                parent_id,
                name,
                content: FileNodeContent::File(FileProperties {
                    blob_hash,
                    size: bytes.len() as u32,
                    media_type: headers.content_type.map(|v| v.to_string()),
                    executable: false,
                }),
                created: now as i64,
                modified: now as i64,
                accessed: now as i64,
                changed: now as i64,
                ..Default::default()
            };

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            let document_id = batch.reserve_document_id(account_id, Collection::FileNode);
            batch
                .with_account_id(account_id)
                .with_collection(Collection::FileNode)
                .create_document(document_id)
                .clear(blob_hold)
                .custom(
                    ObjectIndexBuilder::<(), _>::new()
                        .with_changes(node)
                        .with_changed_by(access_token.account_tenant_ids()),
                )
                .caused_by(trc::location!())?;
            let etag = self
                .commit_batch(batch)
                .await
                .caused_by(trc::location!())?
                .etag();

            Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
        }
    }
}
