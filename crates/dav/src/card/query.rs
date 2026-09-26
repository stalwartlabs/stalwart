/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::filter::CardFilterPlan;
use crate::{
    DavError,
    common::{
        DavQuery,
        propfind::PropFindRequestHandler,
        search::{QueryScope, TextIndex},
        uri::DavUriResource,
    },
};
use calcard::vcard::{ArchivedVCard, VCardProperty, VCardVersion};
use common::{DavResourcePath, Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders,
    schema::{property::CardDavPropertyName, request::AddressbookQuery, response::MultiStatus},
};
use groupware::cache::GroupwareCache;
use http_proto::HttpResponse;
use hyper::StatusCode;
use std::fmt::Write;
use store::write::SearchIndex;
use trc::AddContext;
use types::{acl::Acl, collection::SyncCollection};

pub(crate) trait CardQueryRequestHandler: Sync + Send {
    fn handle_card_query_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: AddressbookQuery,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardQueryRequestHandler for Server {
    async fn handle_card_query_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: AddressbookQuery,
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
                SyncCollection::AddressBook,
            )
            .await
            .caused_by(trc::location!())?;
        let Some(resource) = resources.by_path(
            resource_
                .resource
                .ok_or(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))?,
        ) else {
            return Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                .with_xml_body(MultiStatus::not_found(headers.uri).to_string()));
        };

        let shared_ids = (!access_token.is_member(account_id))
            .then(|| resources.shared_items(access_token, [Acl::ReadItems], false));
        let is_visible = |item: &DavResourcePath<'_>| {
            shared_ids
                .as_ref()
                .is_none_or(|ids| ids.contains(item.document_id()))
        };
        let scope = if resource.is_container() {
            QueryScope::new(
                resources
                    .children(resource.document_id())
                    .filter(is_visible),
            )
        } else {
            QueryScope::new(std::iter::once(resource).filter(is_visible))
        };

        let candidates = request
            .filter
            .candidates(&scope, TextIndex::new(self, SearchIndex::Contacts));
        let items = scope
            .resolve(
                self,
                SearchIndex::Contacts,
                account_id,
                candidates,
                &resources,
            )
            .await;

        self.handle_dav_query(
            access_token,
            DavQuery::addressbook_query(request, items, headers),
        )
        .await
    }
}

pub(crate) fn serialize_vcard_with_props(
    card: &ArchivedVCard,
    props: &[CardDavPropertyName],
    version: VCardVersion,
) -> String {
    let mut vcard = String::with_capacity(128);
    if !props.is_empty() {
        let _ = write!(&mut vcard, "BEGIN:VCARD\r\n");

        for entry in card.entries.iter() {
            for item in props {
                if entry.name == item.name
                    && item.group.as_deref().is_none_or(|group| {
                        entry
                            .group
                            .as_ref()
                            .is_some_and(|entry_group| entry_group.eq_ignore_ascii_case(group))
                    })
                {
                    if item.name != VCardProperty::Version {
                        let _ = entry.write_with_version(&mut vcard, !item.no_value, version);
                    } else {
                        let _ = write!(&mut vcard, "VERSION:{version}\r\n");
                    }
                    break;
                }
            }
        }
        let _ = write!(&mut vcard, "END:VCARD\r\n");
    } else {
        let _ = card.write_to(&mut vcard, version);
    }

    vcard
}
