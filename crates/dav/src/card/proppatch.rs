/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavMethod, PropStatBuilder,
    common::{
        ETag, ExtractETag,
        dead::{DeadPatch, DeadTarget, DisplayName},
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};
use common::{
    Server,
    auth::AccessToken,
    storage::index::{PresenceFlags, RewritePresence},
};
use dav_proto::{
    RequestHeaders, Return,
    schema::{
        Namespace,
        property::{CardDavProperty, DavProperty, DavValue, ResourceType, WebDavProperty},
        request::{DavPropertyValue, PropertyUpdate, PropertyUpdateOp},
        response::{BaseCondition, MultiStatus, Response},
    },
};
use groupware::{
    cache::GroupwareCache,
    contact::{AddressBook, ContactCard},
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
    acl::Acl,
    collection::{Collection, SyncCollection},
};

pub(crate) trait CardPropPatchRequestHandler: Sync + Send {
    fn handle_card_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn apply_addressbook_properties(
        &self,
        personal_id: u32,
        address_book: &mut AddressBook,
        properties: impl IntoIterator<Item = DavPropertyValue>,
        items: &mut PropStatBuilder,
    );

    fn apply_card_properties(
        &self,
        card: &mut ContactCard,
        properties: impl IntoIterator<Item = DavPropertyValue>,
        items: &mut PropStatBuilder,
    );
}

impl CardPropPatchRequestHandler for Server {
    async fn handle_card_proppatch_request(
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
        let uri = headers.uri;
        let account_id = resource_.account_id;
        let resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::AddressBook,
            )
            .await
            .caused_by(trc::location!())?;
        let resource = resource_
            .resource
            .and_then(|r| resources.by_path(r))
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let document_id = resource.document_id();
        let collection = if resource.is_container() {
            Collection::AddressBook
        } else {
            Collection::ContactCard
        };

        if !request.has_changes() {
            return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
        }

        // Verify ACL
        if !access_token.is_member(account_id) {
            let (acl, document_id) = if resource.is_container() {
                (Acl::Modify, resource.document_id())
            } else {
                (Acl::ModifyItems, resource.parent_id().unwrap())
            };

            if !resources.has_access_to_container(access_token, document_id, acl) {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
        }

        // Fetch archive
        let archive = self
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                collection,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let etag = if resource.is_container() {
            archive.etag()
        } else {
            format!(
                "\"{}\"",
                archive
                    .unarchive::<ContactCard>()
                    .caused_by(trc::location!())?
                    .etag
                    .to_native()
            )
        };

        // Validate headers
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection,
                document_id: document_id.into(),
                etag: etag.clone().into(),
                path: resource_.resource.unwrap(),
                ..Default::default()
            }],
            Default::default(),
            DavMethod::PROPPATCH,
        )
        .await?;

        let dead = DeadPatch::take(&mut request.ops, DisplayName::Live);
        let has_live_changes = !request.ops.is_empty();
        let mut batch = BatchBuilder::new();
        let mut items = PropStatBuilder::default();

        let (is_success, etag) = if resource.is_container() {
            // Deserialize
            let book = archive
                .to_unarchived::<AddressBook>()
                .caused_by(trc::location!())?;
            let mut new_book = archive
                .deserialize::<AddressBook>()
                .caused_by(trc::location!())?;
            let personal_id = access_token.personal_id(account_id, Collection::AddressBook);

            // Apply live properties
            for op in request.ops {
                match op {
                    PropertyUpdateOp::Set(value) => self.apply_addressbook_properties(
                        personal_id,
                        &mut new_book,
                        [value],
                        &mut items,
                    ),
                    PropertyUpdateOp::Remove(property) => remove_addressbook_properties(
                        personal_id,
                        &mut new_book,
                        [property],
                        &mut items,
                    ),
                }
            }

            // Apply dead properties
            let mut dead_write = dead
                .apply(
                    self,
                    DeadTarget::container(
                        account_id,
                        Collection::AddressBook,
                        document_id,
                        book.inner.metadata_kinds(),
                    ),
                    &mut items,
                )
                .await
                .caused_by(trc::location!())?;

            if items.has_errors() {
                (false, etag)
            } else {
                if let Some(write) = dead_write
                    .as_mut()
                    .and_then(|dead_write| dead_write.write.take())
                {
                    write
                        .build(document_id.into(), &mut batch)
                        .caused_by(trc::location!())?;
                }
                if has_live_changes {
                    if let Some(dead_write) = &dead_write {
                        new_book.set_metadata_kinds(dead_write.kinds);
                    }
                    new_book
                        .update(
                            access_token.account_tenant_ids(),
                            book,
                            account_id,
                            document_id,
                            &mut batch,
                        )
                        .caused_by(trc::location!())?;
                } else if let Some(dead_write) = &dead_write {
                    AddressBook::rewrite_presence(
                        &book,
                        dead_write.kinds,
                        account_id,
                        document_id,
                        &mut batch,
                    )
                    .caused_by(trc::location!())?;
                }
                (true, batch.etag().unwrap_or(etag))
            }
        } else {
            // Deserialize
            let card = archive
                .to_unarchived::<ContactCard>()
                .caused_by(trc::location!())?;
            let mut new_card = archive
                .deserialize::<ContactCard>()
                .caused_by(trc::location!())?;

            // Apply live properties
            for op in request.ops {
                match op {
                    PropertyUpdateOp::Set(value) => {
                        self.apply_card_properties(&mut new_card, [value], &mut items)
                    }
                    PropertyUpdateOp::Remove(property) => {
                        remove_card_properties(&mut new_card, [property], &mut items)
                    }
                }
            }

            // Apply dead properties
            let mut dead_write = dead
                .apply(
                    self,
                    DeadTarget::item(
                        account_id,
                        Collection::ContactCard,
                        document_id,
                        card.inner.metadata_kinds(),
                    ),
                    &mut items,
                )
                .await
                .caused_by(trc::location!())?;

            if items.has_errors() {
                (false, etag)
            } else {
                let mut new_etag = None;
                if let Some(write) = dead_write
                    .as_mut()
                    .and_then(|dead_write| dead_write.write.take())
                {
                    write
                        .build(document_id.into(), &mut batch)
                        .caused_by(trc::location!())?;
                }
                if has_live_changes {
                    if let Some(dead_write) = &dead_write {
                        new_card.set_metadata_kinds(dead_write.kinds);
                    }
                    new_etag = new_card
                        .update_meta(
                            access_token.account_tenant_ids(),
                            card,
                            account_id,
                            document_id,
                            None,
                            &mut batch,
                        )
                        .caused_by(trc::location!())?
                        .into();
                } else if let Some(dead_write) = &dead_write {
                    ContactCard::rewrite_presence(
                        &card,
                        dead_write.kinds,
                        account_id,
                        document_id,
                        &mut batch,
                    )
                    .caused_by(trc::location!())?;
                }
                (true, new_etag.unwrap_or(etag))
            }
        };

        if is_success {
            if !batch.is_empty() {
                self.commit_batch(batch).await.caused_by(trc::location!())?;
            }
        } else {
            items.fail_dependencies();
        }

        if headers.ret != Return::Minimal || !is_success {
            Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                .with_xml_body(
                    MultiStatus::new(vec![Response::new_propstat(uri, items.build())])
                        .with_namespace(Namespace::CardDav)
                        .to_string(),
                )
                .with_etag(etag))
        } else {
            Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag(etag))
        }
    }

    fn apply_addressbook_properties(
        &self,
        personal_id: u32,
        address_book: &mut AddressBook,
        properties: impl IntoIterator<Item = DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) {
        for property in properties {
            match (&property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        address_book.preferences_mut(personal_id).name = name;
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
                    DavProperty::CardDav(CardDavProperty::AddressbookDescription),
                    DavValue::String(name),
                ) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        address_book.preferences_mut(personal_id).description = Some(name);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                    }
                }
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    address_book.created = dt;
                    items.insert_ok(property.property);
                }
                (
                    DavProperty::WebDav(WebDavProperty::ResourceType),
                    DavValue::ResourceTypes(types),
                ) => {
                    if !types.0.iter().all(|rt| {
                        matches!(rt, ResourceType::Collection | ResourceType::AddressBook)
                    }) {
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

    fn apply_card_properties(
        &self,
        card: &mut ContactCard,
        properties: impl IntoIterator<Item = DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) {
        for property in properties {
            match (&property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        card.display_name = Some(name);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                    }
                }
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    card.created = dt;
                    items.insert_ok(property.property);
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

fn remove_card_properties(
    card: &mut ContactCard,
    properties: impl IntoIterator<Item = DavProperty>,
    items: &mut PropStatBuilder,
) {
    for property in properties {
        match &property {
            DavProperty::WebDav(WebDavProperty::DisplayName) => {
                card.display_name = None;
                items.insert_ok(property);
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

fn remove_addressbook_properties(
    personal_id: u32,
    book: &mut AddressBook,
    properties: impl IntoIterator<Item = DavProperty>,
    items: &mut PropStatBuilder,
) {
    for property in properties {
        match &property {
            DavProperty::CardDav(CardDavProperty::AddressbookDescription) => {
                book.preferences_mut(personal_id).description = None;
                items.insert_ok(property);
            }
            DavProperty::WebDav(WebDavProperty::DisplayName) => {
                book.preferences_mut(personal_id).name.clear();
                items.insert_ok(property);
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
