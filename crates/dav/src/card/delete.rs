/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavMethod,
    common::{
        ContainerOperation, ETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::RequestHeaders;
use groupware::{
    DestroyArchive,
    cache::GroupwareCache,
    contact::{AddressBook, write::CardWriter},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use store::write::BatchBuilder;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::PrincipalField,
};

pub(crate) trait CardDeleteRequestHandler: Sync + Send {
    fn handle_card_delete_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardDeleteRequestHandler for Server {
    async fn handle_card_delete_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource.account_id;
        let delete_path = resource
            .resource
            .filter(|r| !r.is_empty())
            .ok_or(DavError::Code(StatusCode::FORBIDDEN))?;
        let resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::AddressBook,
            )
            .await
            .caused_by(trc::location!())?;

        // Check resource type
        let delete_resource = resources
            .by_path(delete_path)
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let document_id = delete_resource.document_id();

        if delete_resource.is_container() {
            let book_ = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::AddressBook,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

            let book = book_
                .to_unarchived::<AddressBook>()
                .caused_by(trc::location!())?;

            // Validate ACL
            if !access_token.is_member(account_id)
                && !book
                    .inner
                    .acls
                    .effective_acl(access_token)
                    .contains_all(ContainerOperation::Remove.required_acls())
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Validate headers
            self.validate_headers(
                access_token,
                headers,
                vec![ResourceState {
                    account_id,
                    collection: Collection::AddressBook,
                    document_id: document_id.into(),
                    etag: book.etag().into(),
                    path: delete_path,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::DELETE,
            )
            .await?;

            // Delete addressbook and cards
            let mut batch = BatchBuilder::new();
            let children = resources
                .subtree(delete_path)
                .filter(|r| !r.is_container())
                .map(|r| (r.document_id(), r.resource.metadata_kinds()))
                .collect::<Vec<_>>();
            let cleanup = self
                .preload_container_cleanup(
                    access_token.changed_by(),
                    account_id,
                    Collection::ContactCard,
                    &children
                        .iter()
                        .filter(|(_, kinds)| !kinds.is_empty())
                        .map(|(document_id, _)| *document_id)
                        .collect(),
                )
                .await
                .caused_by(trc::location!())?;
            DestroyArchive(book)
                .delete_with_cards(
                    self,
                    access_token.changed_by(),
                    account_id,
                    document_id,
                    children
                        .into_iter()
                        .map(|(document_id, _)| document_id)
                        .collect(),
                    &cleanup,
                    resources.format_resource(delete_resource).into(),
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;

            // Reset default address book id
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .clear_if_equals(PrincipalField::DefaultAddressBookId, document_id);
            self.commit_batch(batch).await.caused_by(trc::location!())?;
        } else {
            let writer = CardWriter {
                server: self,
                access_token,
                account_id,
                resources: &resources,
            };
            let deletion = writer
                .prepare_delete(delete_resource.parent_id().unwrap(), document_id)
                .await?;

            self.validate_headers(
                access_token,
                headers,
                vec![ResourceState {
                    account_id,
                    collection: Collection::ContactCard,
                    document_id: document_id.into(),
                    etag: format!(
                        "\"{}\"",
                        deletion
                            .card()
                            .caused_by(trc::location!())?
                            .inner
                            .etag
                            .to_native()
                    )
                    .into(),
                    path: delete_path,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::DELETE,
            )
            .await?;

            writer
                .delete(deletion, resources.format_resource(delete_resource).into())
                .await?;
        }

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    }
}
