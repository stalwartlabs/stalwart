/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::{
    auth::ScimConditional,
    context::{ScimContext, group_account},
    error::Result,
    groups,
    request::{not_modified, respond_with_etag},
};
use http_proto::{HttpRequest, HttpResponse};
use hyper::StatusCode;
use registry::schema::{enums::Permission, prelude::Object};
use scim_proto::{etag::weak_etag, message::search::SearchRequest};
use serde_json::Value;
use types::id::Id;

impl ScimContext<'_> {
    pub async fn group_get(
        &self,
        req: &HttpRequest,
        id: Id,
        request: &SearchRequest<'_>,
    ) -> Result<HttpResponse> {
        self.assert_permission(Permission::SysAccountGet)?;

        let object = self.account(id).await?;
        group_account(&object)?;

        let member_ids = self.group_member_ids(id).await?;
        let version = weak_etag(groups::version(object.revision, &member_ids));

        if req.scim_if_none_match(&version) {
            return Ok(not_modified(&version));
        }

        let resource = self.group_render(id, &object, &member_ids, request).await?;

        respond_with_etag(StatusCode::OK, &resource, version)
    }

    pub async fn group_render(
        &self,
        id: Id,
        object: &Object,
        member_ids: &[Id],
        request: &SearchRequest<'_>,
    ) -> Result<Value> {
        self.group_to_scim(
            id,
            object.revision,
            group_account(object)?,
            member_ids,
            &request.attribute_selection()?,
        )
        .await
    }
}
