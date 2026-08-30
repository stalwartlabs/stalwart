/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::{context::ScimContext, error::Result};
use common::{Server, auth::AccessToken};
use http_proto::HttpRequest;
use hyper::header;
use registry::schema::enums::Permission;
use scim_proto::{etag, message::error::Error};
use types::id::Id;

pub trait ScimAuthorization {
    fn is_basic_authentication(&self) -> bool;
    fn scim_access_token<'x>(
        &self,
        access_token: Option<&'x AccessToken>,
    ) -> Result<&'x AccessToken>;
}

pub trait ScimEnabled {
    fn assert_scim_enabled(&self) -> Result<()>;
}

impl ScimAuthorization for HttpRequest {
    fn is_basic_authentication(&self) -> bool {
        self.headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .get(..5)
                    .is_some_and(|scheme| scheme.eq_ignore_ascii_case("basic"))
            })
    }

    fn scim_access_token<'x>(
        &self,
        access_token: Option<&'x AccessToken>,
    ) -> Result<&'x AccessToken> {
        if self.is_basic_authentication() {
            return Err(Error::unauthorized()
                .with_detail("HTTP Basic authentication is not supported, present a bearer token.")
                .into());
        }

        let access_token = access_token.ok_or_else(|| {
            Error::unauthorized()
                .with_detail("This endpoint requires an authenticated bearer token.")
        })?;

        access_token.enforce_permission(Permission::ScimAccess)?;

        Ok(access_token)
    }
}

impl ScimEnabled for Server {
    fn assert_scim_enabled(&self) -> Result<()> {
        if self.is_enterprise_edition() {
            Ok(())
        } else {
            Err(Error::forbidden(concat!(
                "SCIM provisioning is only available in the Enterprise edition. ",
                "Obtain your trial license at https://license.stalw.art/trial."
            ))
            .into())
        }
    }
}

impl ScimContext<'_> {
    pub fn assert_permission(&self, permission: Permission) -> Result<()> {
        self.access_token
            .enforce_permission(permission)
            .map_err(Into::into)
    }

    pub fn assert_not_service_principal(&self, id: Id) -> Result<()> {
        if id.document_id() != self.access_token.account_id() {
            Ok(())
        } else {
            Err(Error::forbidden(
                "A SCIM client cannot deprovision or deactivate its own service principal.",
            )
            .into())
        }
    }
}

pub trait ScimConditional {
    fn scim_if_none_match(&self, version: &str) -> bool;
    fn scim_assert_if_match(&self, version: &str) -> Result<()>;
}

impl ScimConditional for HttpRequest {
    fn scim_if_none_match(&self, version: &str) -> bool {
        self.headers()
            .get(header::IF_NONE_MATCH)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|header| etag::matches(header, version))
    }

    fn scim_assert_if_match(&self, version: &str) -> Result<()> {
        match self.headers().get(header::IF_MATCH) {
            Some(header) => {
                if header
                    .to_str()
                    .is_ok_and(|header| etag::matches(header, version))
                {
                    Ok(())
                } else {
                    Err(Error::precondition_failed()
                        .with_detail("The resource has been modified since it was last retrieved.")
                        .into())
                }
            }
            None => Ok(()),
        }
    }
}
