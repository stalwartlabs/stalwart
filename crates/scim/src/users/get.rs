/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::{
    auth::ScimConditional,
    context::{ScimContext, user_account},
    error::Result,
    request::{not_modified, respond_with_etag},
};
use http_proto::{HttpRequest, HttpResponse};
use hyper::StatusCode;
use registry::schema::{enums::Permission, prelude::Object};
use scim_proto::{etag::weak_etag, message::search::SearchRequest};
use serde_json::Value;
use types::id::Id;

impl ScimContext<'_> {
    pub async fn user_get(
        &self,
        req: &HttpRequest,
        id: Id,
        request: &SearchRequest<'_>,
    ) -> Result<HttpResponse> {
        self.assert_permission(Permission::SysAccountGet)?;

        let object = self.account(id).await?;

        user_account(&object)?;

        let version = weak_etag(object.revision);

        if req.scim_if_none_match(&version) {
            return Ok(not_modified(&version));
        }

        let resource = self.user_render(id, &object, request).await?;

        respond_with_etag(StatusCode::OK, &resource, version)
    }

    pub async fn user_render(
        &self,
        id: Id,
        object: &Object,
        request: &SearchRequest<'_>,
    ) -> Result<Value> {
        self.user_to_scim(
            id,
            object.revision,
            user_account(object)?,
            &request.attribute_selection()?,
        )
        .await
    }
}
