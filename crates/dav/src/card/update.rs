/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavErrorCondition, DavMethod,
    common::{
        create::CreateLockHandler,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
};
use calcard::{Entry, Parser};
use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders, Return,
    schema::{property::Rfc1123DateTime, response::CardCondition},
};
use groupware::{
    cache::GroupwareCache,
    contact::write::{CardCreate, CardWriter},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use trc::AddContext;
use types::collection::{Collection, SyncCollection};

pub(crate) trait CardUpdateRequestHandler: Sync + Send {
    fn handle_card_update_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: &[u8],
        is_patch: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardUpdateRequestHandler for Server {
    async fn handle_card_update_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: &[u8],
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
                SyncCollection::AddressBook,
            )
            .await
            .caused_by(trc::location!())?;
        let resource_name = resource
            .resource
            .ok_or(DavError::Code(StatusCode::CONFLICT))?;

        if bytes.len() > self.core.groupware.max_vcard_size {
            return Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CardCondition::MaxResourceSize(self.core.groupware.max_vcard_size as u32),
            )));
        }
        let vcard_raw = std::str::from_utf8(bytes).map_err(|_| {
            DavError::Condition(
                DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CardCondition::SupportedAddressData,
                )
                .with_details("The request body is not valid UTF-8."),
            )
        })?;

        let vcard = match Parser::new(vcard_raw).strict().entry() {
            Entry::VCard(vcard) => vcard,
            _ => {
                return Err(DavError::Condition(
                    DavErrorCondition::new(
                        StatusCode::PRECONDITION_FAILED,
                        CardCondition::SupportedAddressData,
                    )
                    .with_details("Failed to parse vCard data."),
                ));
            }
        };
        let media_size = vcard.embedded_size();
        if self.core.groupware.max_media_size != 0
            && media_size > self.core.groupware.max_media_size
        {
            return Err(DavError::Condition(
                DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CardCondition::MaxResourceSize(self.core.groupware.max_media_size as u32),
                )
                .with_details(format!(
                    "The size of the embedded media ({media_size} bytes) exceeds the maximum of {} bytes.",
                    self.core.groupware.max_media_size
                )),
            ));
        }

        let writer = CardWriter {
            server: self,
            access_token,
            account_id,
            resources: &resources,
        };

        if let Some(resource) = resources.by_path(resource_name) {
            if resource.is_container() {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            let stored = writer
                .prepare_update(resource.parent_id().unwrap(), resource.document_id())
                .await?;
            let card = stored.card().caused_by(trc::location!())?;

            match self
                .validate_headers(
                    access_token,
                    headers,
                    vec![ResourceState {
                        account_id,
                        collection: Collection::ContactCard,
                        document_id: Some(stored.document_id()),
                        etag: format!("\"{}\"", card.inner.etag.to_native()).into(),
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
                    let content = stored.content().caused_by(trc::location!())?;
                    let mut vcard = String::with_capacity(u32::from(card.inner.size) as usize);
                    let _ = content.inner.card.write_to(
                        &mut vcard,
                        headers
                            .vcard_version
                            .unwrap_or(self.core.groupware.vcard_version),
                    );

                    return Ok(HttpResponse::new(StatusCode::PRECONDITION_FAILED)
                        .with_content_type("text/vcard; charset=utf-8")
                        .with_etag(format!("\"{}\"", card.inner.etag.to_native()))
                        .with_last_modified(
                            Rfc1123DateTime::new(i64::from(card.inner.modified)).to_string(),
                        )
                        .with_header("Preference-Applied", "return=representation")
                        .with_binary_body(vcard));
                }
                Err(e) => return Err(e),
            }

            let written = writer.update(stored, vcard).await?;

            Ok(HttpResponse::new(StatusCode::NO_CONTENT)
                .with_etag_opt(written.serves_submitted.then_some(written.etag)))
        } else if let Some((Some(parent), name)) = resources.map_parent(resource_name) {
            if !parent.is_container() {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            let new = writer.prepare_create(parent.document_id())?;

            self.validate_headers(
                access_token,
                headers,
                vec![ResourceState {
                    account_id,
                    collection: resource.collection,
                    document_id: Some(u32::MAX),
                    path: resource_name,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::PUT,
            )
            .await?;

            let lock = self
                .lock_create(
                    access_token,
                    account_id,
                    SyncCollection::AddressBook,
                    resource_name,
                    headers,
                )
                .await?;
            let written = writer
                .create(
                    new,
                    CardCreate {
                        name: name.to_string(),
                        vcard,
                        size: Some(bytes.len()),
                    },
                )
                .await;
            self.release_create_lock(&lock).await;
            let written = written?;

            Ok(HttpResponse::new(StatusCode::CREATED).with_etag(written.etag))
        } else {
            Err(DavError::Code(StatusCode::CONFLICT))?
        }
    }
}
