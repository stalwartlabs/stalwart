/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::propfind::PrincipalPropFind;
use common::{Server, auth::AccessToken};
use dav_proto::schema::{
    property::{DavProperty, PrincipalProperty, WebDavProperty},
    request::{FilterTest, PrincipalPropertySearch, PropFind},
    response::MultiStatus,
};
use groupware::strip_mailto_scheme;
use http_proto::HttpResponse;
use hyper::StatusCode;
use registry::schema::prelude::{ObjectType, Property};
use store::{registry::RegistryQuery, roaring::RoaringBitmap};
use trc::AddContext;
use types::collection::Collection;

pub(crate) trait PrincipalPropSearch: Sync + Send {
    fn handle_principal_property_search(
        &self,
        access_token: &AccessToken,
        request: PrincipalPropertySearch,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn principal_property_matches(
        &self,
        access_token: &AccessToken,
        property: &DavProperty,
        text: &str,
    ) -> impl Future<Output = crate::Result<RoaringBitmap>> + Send;
}

impl PrincipalPropSearch for Server {
    async fn handle_principal_property_search(
        &self,
        access_token: &AccessToken,
        mut request: PrincipalPropertySearch,
    ) -> crate::Result<HttpResponse> {
        let mut matches: Option<RoaringBitmap> = None;
        'outer: for search in &request.property_search {
            for property in &search.properties {
                if request.test == FilterTest::AllOf
                    && matches.as_ref().is_some_and(RoaringBitmap::is_empty)
                {
                    break 'outer;
                }
                let ids = self
                    .principal_property_matches(access_token, property, &search.match_)
                    .await?;
                matches = Some(match (matches, request.test) {
                    (None, _) => ids,
                    (Some(current), FilterTest::AllOf) => current & ids,
                    (Some(current), FilterTest::AnyOf) => current | ids,
                });
            }
        }

        let mut response = MultiStatus::new(Vec::with_capacity(16));
        if let Some(mut ids) = matches {
            if !self.core.groupware.allow_directory_query {
                ids &= RoaringBitmap::from_iter(access_token.all_ids());
            }

            if !ids.is_empty() {
                if request.properties.is_empty() {
                    request
                        .properties
                        .push(DavProperty::WebDav(WebDavProperty::DisplayName));
                }
                let request = PropFind::Prop(request.properties);
                self.prepare_principal_propfind_response(
                    access_token,
                    Collection::Principal,
                    ids.into_iter(),
                    &request,
                    &mut response,
                )
                .await?;
            }
        }

        Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
    }

    async fn principal_property_matches(
        &self,
        access_token: &AccessToken,
        property: &DavProperty,
        text: &str,
    ) -> crate::Result<RoaringBitmap> {
        let text = match property {
            DavProperty::WebDav(WebDavProperty::DisplayName) => text.trim(),
            DavProperty::Principal(PrincipalProperty::CalendarUserAddressSet) => {
                let address = strip_mailto_scheme(text.trim());
                if address.contains('@') {
                    let mut matches = RoaringBitmap::new();
                    if let Some(account_id) = self
                        .account_id_from_email(address, false)
                        .await
                        .caused_by(trc::location!())?
                        && (access_token.tenant_id().is_none()
                            || self
                                .account(account_id)
                                .await
                                .caused_by(trc::location!())?
                                .id_tenant
                                == access_token.tenant_id())
                    {
                        matches.insert(account_id);
                    }
                    return Ok(matches);
                }
                address
            }
            _ => return Ok(RoaringBitmap::new()),
        };

        if text.is_empty() {
            return Ok(RoaringBitmap::new());
        }

        self.registry()
            .query::<RoaringBitmap>(
                RegistryQuery::new(ObjectType::Account)
                    .with_tenant(access_token.tenant_id())
                    .text(Property::Text, text),
            )
            .await
            .caused_by(trc::location!())
            .map_err(Into::into)
    }
}
