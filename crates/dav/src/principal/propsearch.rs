/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::propfind::PrincipalPropFind;
use common::{Server, auth::AccessToken};
use dav_proto::schema::{
    property::{DavProperty, WebDavProperty},
    request::{PrincipalPropertySearch, PropFind},
    response::MultiStatus,
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use registry::schema::prelude::{Object, Property};
use store::{registry::RegistryQuery, roaring::RoaringBitmap};
use trc::AddContext;
use types::collection::Collection;

pub(crate) trait PrincipalPropSearch: Sync + Send {
    fn handle_principal_property_search(
        &self,
        access_token: &AccessToken,
        request: PrincipalPropertySearch,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl PrincipalPropSearch for Server {
    async fn handle_principal_property_search(
        &self,
        access_token: &AccessToken,
        mut request: PrincipalPropertySearch,
    ) -> crate::Result<HttpResponse> {
        let mut search_for = None;

        for prop_search in request.property_search {
            if matches!(
                prop_search.property,
                DavProperty::WebDav(WebDavProperty::DisplayName)
            ) && !prop_search.match_.is_empty()
            {
                search_for = Some(prop_search.match_);
            }
        }

        let mut response = MultiStatus::new(Vec::with_capacity(16));
        if let Some(search_for) = search_for {
            let ids = self
                .registry()
                .query::<RoaringBitmap>(
                    RegistryQuery::new(Object::Account)
                        .equal_opt(Property::MemberTenantId, access_token.tenant_id())
                        .text(search_for),
                )
                .await
                .caused_by(trc::location!())?;

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
}
