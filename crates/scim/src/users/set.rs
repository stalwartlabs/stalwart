/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::{
    auth::ScimConditional,
    context::{ScimContext, account_of, revision_of, user_account},
    error::{IntoScimError, Result, no_content},
    request::respond_with_etag,
    users,
};
use http_proto::{HttpRequest, HttpResponse};
use hyper::{StatusCode, header};
use jmap::registry::mapping::principal::{AccountUpdate, validate_account};
use registry::{
    schema::{
        enums::Permission,
        prelude::Object,
        structs::{Account, UserAccount, UserRoles},
    },
    types::datetime::UTCDateTime,
};
use scim_proto::{
    ResourceType,
    etag::weak_etag,
    message::{error::Error, search::SearchRequest},
    schema::user::User,
};
use types::id::Id;

pub const CLIENT_ID: &str = "scim";

impl ScimContext<'_> {
    pub async fn user_create(
        &self,
        body: &[u8],
        request: &SearchRequest<'_>,
    ) -> Result<HttpResponse> {
        self.assert_permission(Permission::SysAccountCreate)?;

        let user = User::parse(body)?;
        let (id, object) = self.user_insert(&user).await?;
        let resource = self.user_render(id, &object, request).await?;

        respond_with_etag(StatusCode::CREATED, &resource, weak_etag(object.revision)).map(
            |response| {
                response.with_header(header::LOCATION, self.location(ResourceType::User, id))
            },
        )
    }

    pub async fn user_insert(&self, user: &User<'_>) -> Result<(Id, Object)> {
        self.assert_permission(Permission::SysAccountCreate)?;

        let user_name = user
            .user_name
            .as_deref()
            .filter(|user_name| !user_name.is_empty())
            .ok_or_else(|| {
                Error::invalid_value("The 'userName' attribute is required to create a User.")
            })?;

        let mut account = UserAccount {
            created_at: UTCDateTime::now(),
            roles: UserRoles::User,
            member_tenant_id: self.tenant_id().map(Id::from),
            external_id: user.external_id.as_deref().map(str::to_string),
            description: users::display_name(user),
            ..Default::default()
        };

        self.set_user_name(&mut account, user_name).await?;
        self.apply_user(&mut account, user, false).await?;

        let mut account = Account::User(account);
        self.validate(&mut account, AccountUpdate::Create(CLIENT_ID))
            .await?;

        let mut object = Object::from(account);
        let id = self.insert(&object, ResourceType::User).await?;
        object.revision = revision_of(&object);

        Ok((id, object))
    }

    pub async fn user_replace(
        &self,
        req: &HttpRequest,
        id: Id,
        body: &[u8],
        request: &SearchRequest<'_>,
    ) -> Result<HttpResponse> {
        self.assert_permission(Permission::SysAccountUpdate)?;

        let user = User::parse(body)?;
        let old_object = self.account(id).await?;

        user_account(&old_object)?;
        req.scim_assert_if_match(&weak_etag(old_object.revision))?;

        let updated = self.user_update(id, &user, &old_object).await?;
        let object = updated.as_ref().unwrap_or(&old_object);
        let resource = self.user_render(id, object, request).await?;

        respond_with_etag(StatusCode::OK, &resource, weak_etag(object.revision))
    }

    pub async fn user_update(
        &self,
        id: Id,
        user: &User<'_>,
        old_object: &Object,
    ) -> Result<Option<Object>> {
        self.assert_permission(Permission::SysAccountUpdate)?;

        let mut account = user_account(old_object)?.clone();

        let Some(user_name) = user
            .user_name
            .as_deref()
            .filter(|user_name| !user_name.is_empty())
        else {
            return Err(Error::invalid_value(
                "The 'userName' attribute is required to replace a User.",
            )
            .into());
        };

        account.external_id = user.external_id.as_deref().map(str::to_string);
        account.description = users::display_name(user);
        self.set_user_name(&mut account, user_name).await?;
        self.apply_user(&mut account, user, true).await?;

        if !user.active.unwrap_or(true) {
            self.assert_not_service_principal(id)?;
        }

        self.user_write(id, account, old_object).await
    }

    async fn apply_user(
        &self,
        account: &mut UserAccount,
        user: &User<'_>,
        reset_absent: bool,
    ) -> Result<()> {
        match user
            .locale
            .as_deref()
            .or(user.preferred_language.as_deref())
            .filter(|locale| !locale.is_empty())
        {
            Some(locale) => users::set_locale(account, locale)?,
            None if reset_absent => account.locale = users::DEFAULT_LOCALE,
            None => {}
        }

        users::set_time_zone(
            account,
            user.timezone.as_deref().filter(|value| !value.is_empty()),
        )?;

        if let Some(emails) = user.emails.as_deref() {
            self.set_emails(account, emails).await?;
        } else if reset_absent {
            account.aliases = Default::default();
        }

        match user.active {
            Some(active) => users::set_active(&mut account.permissions, active),
            None if reset_absent => users::set_active(&mut account.permissions, true),
            None => {}
        }

        Ok(())
    }

    pub async fn user_destroy(&self, req: &HttpRequest, id: Id) -> Result<HttpResponse> {
        self.assert_permission(Permission::SysAccountDestroy)?;

        let object = self.account(id).await?;

        user_account(&object)?;
        req.scim_assert_if_match(&weak_etag(object.revision))?;

        self.user_delete(id, &object).await?;

        Ok(no_content())
    }

    pub async fn user_delete(&self, id: Id, object: &Object) -> Result<()> {
        self.assert_permission(Permission::SysAccountDestroy)?;
        self.assert_not_service_principal(id)?;

        user_account(object)?;
        self.delete(id, object).await
    }

    pub async fn user_write(
        &self,
        id: Id,
        account: UserAccount,
        old_object: &Object,
    ) -> Result<Option<Object>> {
        if user_account(old_object)? == &account {
            return Ok(None);
        }

        let mut account = Account::User(account);
        self.validate(&mut account, AccountUpdate::Update(account_of(old_object)?))
            .await?;

        let mut object = Object::from(account);
        self.update(id, &object, old_object, ResourceType::User)
            .await?;
        object.revision = revision_of(&object);

        Ok(Some(object))
    }

    pub async fn validate(&self, account: &mut Account, update: AccountUpdate<'_>) -> Result<()> {
        match validate_account(self.server, self.access_token, account, update).await? {
            Ok(_) => Ok(()),
            Err(error) => Err(error.into_scim_error().into()),
        }
    }
}
