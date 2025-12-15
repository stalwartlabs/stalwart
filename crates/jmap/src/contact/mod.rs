/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::jscontact::JSContactProperty;
use common::{DavName, DavResources, Server};
use jmap_proto::error::set::SetError;
use trc::AddContext;
use types::{collection::Collection, field::ContactField, id::Id};

pub mod copy;
pub mod get;
pub mod parse;
pub mod query;
pub mod set;

pub(super) async fn assert_is_unique_uid(
    server: &Server,
    resources: &DavResources,
    account_id: u32,
    addressbook_ids: &[DavName],
    uid: Option<&str>,
) -> trc::Result<Result<(), SetError<JSContactProperty<Id>>>> {
    if let Some(uid) = uid {
        let hits = server
            .document_ids_matching(
                account_id,
                Collection::ContactCard,
                ContactField::Uid,
                uid.as_bytes(),
            )
            .await
            .caused_by(trc::location!())?;
        if !hits.is_empty() {
            for document_id in resources
                .paths
                .iter()
                .filter(move |item| {
                    item.parent_id
                        .is_some_and(|id| addressbook_ids.iter().any(|ab| ab.parent_id == id))
                })
                .map(|path| resources.resources[path.resource_idx].document_id)
            {
                if hits.contains(document_id) {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(JSContactProperty::Uid)
                        .with_description(format!(
                            "Contact with UID {uid} already exists with id {}.",
                            Id::from(document_id)
                        ))));
                }
            }
        }
    }

    Ok(Ok(()))
}
