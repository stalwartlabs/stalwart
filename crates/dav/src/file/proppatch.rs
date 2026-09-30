/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavMethod, PropStatBuilder,
    common::{
        ExtractETag,
        dead::{DeadPatch, DeadTarget, DisplayName},
        lock::{LockRequestHandler, ResourceState},
        propfind::requested_href,
        uri::DavUriResource,
    },
    file::{DavFileResource, FileItemId, file_etag},
};
use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders, Return,
    schema::{
        property::{DavProperty, DavValue, ResourceType, WebDavProperty},
        request::{DavPropertyValue, PropertyUpdate},
        response::{BaseCondition, MultiStatus, Response},
    },
};
use groupware::{PresenceUpdate, cache::GroupwareCache, file::FileNode};
use http_proto::HttpResponse;
use hyper::StatusCode;
use store::write::BatchBuilder;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};

pub(crate) trait FilePropPatchRequestHandler: Sync + Send {
    fn handle_file_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn apply_file_properties(
        &self,
        file: &mut FileNode,
        properties: Vec<DavPropertyValue>,
        items: &mut PropStatBuilder,
    );
}

impl FilePropPatchRequestHandler for Server {
    async fn handle_file_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        mut request: PropertyUpdate,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let uri = headers.raw_uri;
        let account_id = resource_.account_id;
        let files = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
            .await
            .caused_by(trc::location!())?;
        if !access_token.is_member(account_id)
            && let Some(path) = resource_.resource
        {
            files.hide_undiscoverable(
                &files.file_access(access_token).discoverable,
                path,
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
            )?;
        }
        let resource = files.map_resource::<FileItemId>(&resource_)?;
        let document_id = resource.resource.document_id;
        let href = requested_href(uri, resource.resource.is_container);

        if !request.has_changes() {
            return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
        }

        // Fetch node
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
        let current_etag = file_etag(node.inner);

        // Validate ACL
        if !access_token.is_member(account_id) {
            let acl = files.file_acl(access_token, document_id);
            let (mut content, mut properties) = (false, false);
            for property in request
                .set
                .iter()
                .map(|value| &value.property)
                .chain(request.remove.iter())
            {
                if matches!(
                    property,
                    DavProperty::WebDav(WebDavProperty::GetContentType)
                ) {
                    content = true;
                } else {
                    properties = true;
                }
            }
            if (content && !acl.contains(Acl::ModifyItems))
                || (properties && !acl.contains(Acl::Modify))
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
        }

        // Validate headers
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection: resource.collection,
                document_id: document_id.into(),
                etag: current_etag.clone().into(),
                path: resource_.resource.unwrap(),
                ..Default::default()
            }],
            Default::default(),
            DavMethod::PROPPATCH,
        )
        .await?;

        // Apply live properties
        let dead = DeadPatch::take(&mut request, DisplayName::Stored);
        let has_live_changes = !request.set.is_empty() || !request.remove.is_empty();
        let mut new_node = node.deserialize::<FileNode>().caused_by(trc::location!())?;
        let mut items = PropStatBuilder::default();
        if !request.set_first {
            remove_file_properties(
                &mut new_node,
                std::mem::take(&mut request.remove),
                &mut items,
            );
        }
        self.apply_file_properties(&mut new_node, request.set, &mut items);
        remove_file_properties(&mut new_node, request.remove, &mut items);

        // Apply dead properties
        let mut dead_write = dead
            .apply(
                self,
                DeadTarget::item(
                    account_id,
                    Collection::FileNode,
                    document_id,
                    node.inner.metadata_kinds(),
                ),
                &mut items,
            )
            .await
            .caused_by(trc::location!())?;

        let is_success = !items.has_errors();
        let etag = if is_success {
            let mut batch = BatchBuilder::new();
            if let Some(write) = dead_write
                .as_mut()
                .and_then(|dead_write| dead_write.write.take())
            {
                write.build(&mut batch).caused_by(trc::location!())?;
            }
            if has_live_changes {
                if let Some(dead_write) = &dead_write {
                    new_node.set_presence(dead_write.file_presence);
                }
                new_node
                    .update(
                        access_token.account_tenant_ids(),
                        node,
                        account_id,
                        document_id,
                        false,
                        &mut batch,
                    )
                    .caused_by(trc::location!())?;
            } else if let Some(dead_write) = &dead_write {
                PresenceUpdate(node)
                    .write(
                        dead_write.file_presence,
                        account_id,
                        document_id,
                        &mut batch,
                    )
                    .caused_by(trc::location!())?;
            }
            let etag = batch.etag().unwrap_or(current_etag);
            if !batch.is_empty() {
                self.commit_batch(batch).await.caused_by(trc::location!())?;
            }
            etag
        } else {
            items.fail_dependencies();
            current_etag
        };

        if headers.ret != Return::Minimal || !is_success {
            Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                .with_xml_body(
                    MultiStatus::new(vec![Response::new_propstat(href, items.build())]).to_string(),
                )
                .with_etag(etag))
        } else {
            Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag(etag))
        }
    }

    fn apply_file_properties(
        &self,
        file: &mut FileNode,
        properties: Vec<DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) {
        for property in properties {
            match (&property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    file.created = dt;
                    items.insert_ok(property.property);
                }
                (DavProperty::WebDav(WebDavProperty::GetContentType), DavValue::String(name))
                    if file.file().is_some() =>
                {
                    if name.len() <= self.core.groupware.live_property_size {
                        if let Some(file) = file.file_mut() {
                            file.media_type = Some(name);
                        }
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                    }
                }
                (
                    DavProperty::WebDav(WebDavProperty::ResourceType),
                    DavValue::ResourceTypes(types),
                ) if file.is_directory() => {
                    if types.0.len() != 1 || types.0.first() != Some(&ResourceType::Collection) {
                        items.insert_precondition_failed(
                            property.property,
                            StatusCode::FORBIDDEN,
                            BaseCondition::ValidResourceType,
                        );
                    } else {
                        items.insert_ok(property.property);
                    }
                }
                (_, DavValue::Null) => {
                    items.insert_ok(property.property);
                }
                _ => {
                    items.insert_error_with_description(
                        property.property,
                        StatusCode::CONFLICT,
                        "Property cannot be modified",
                    );
                }
            }
        }
    }
}

fn remove_file_properties(
    node: &mut FileNode,
    properties: Vec<DavProperty>,
    items: &mut PropStatBuilder,
) {
    for property in properties {
        match &property {
            DavProperty::WebDav(WebDavProperty::GetContentType) if node.file().is_some() => {
                if let Some(file) = node.file_mut() {
                    file.media_type = None;
                }
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            _ => {
                items.insert_error_with_description(
                    property,
                    StatusCode::CONFLICT,
                    "Property cannot be deleted",
                );
            }
        }
    }
}
