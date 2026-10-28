/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{StoredIdentities, get::IdentityGet};
use common::{Server, storage::index::ObjectIndexBuilder};
use email::identity::{EmailAddress, Identity};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::identity::{self, IdentityProperty, IdentityValue},
    references::resolve::ResolveCreatedReference,
    request::MaybeInvalid,
    types::state::State,
};
use jmap_tools::{Key, Value};
use registry::schema::enums::StorageQuota;
use std::future::Future;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, BatchBuilder},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    id::Id,
};
use utils::sanitize_email;

type CreatedValue = Value<'static, IdentityProperty, IdentityValue>;

const DEFAULTED: [IdentityProperty; 5] = [
    IdentityProperty::Name,
    IdentityProperty::ReplyTo,
    IdentityProperty::Bcc,
    IdentityProperty::TextSignature,
    IdentityProperty::HtmlSignature,
];

#[derive(Clone, Copy)]
struct Omitted([bool; DEFAULTED.len()]);

impl Omitted {
    fn from_create(object: &Value<'_, IdentityProperty, IdentityValue>) -> Self {
        Omitted(
            DEFAULTED.map(|property| object.as_object_and_get(&Key::Property(property)).is_none()),
        )
    }

    fn server_set(self) -> impl Iterator<Item = (IdentityProperty, CreatedValue)> {
        [
            (IdentityProperty::Name, Value::Str("".into())),
            (IdentityProperty::ReplyTo, Value::Null),
            (IdentityProperty::Bcc, Value::Null),
            (IdentityProperty::TextSignature, Value::Str("".into())),
            (IdentityProperty::HtmlSignature, Value::Str("".into())),
        ]
        .into_iter()
        .zip(self.0)
        .filter_map(|(entry, is_omitted)| is_omitted.then_some(entry))
        .chain([(IdentityProperty::MayDelete, Value::Bool(true))])
    }
}

pub trait IdentitySet: Sync + Send {
    fn identity_set(
        &self,
        request: SetRequest<'_, identity::Identity>,
    ) -> impl Future<Output = trc::Result<SetResponse<identity::Identity>>> + Send;
}

impl IdentitySet for Server {
    async fn identity_set(
        &self,
        mut request: SetRequest<'_, identity::Identity>,
    ) -> trc::Result<SetResponse<identity::Identity>> {
        let account_id = request.account_id.document_id();
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = response.collect_will_destroy(request.unwrap_destroy());
        let identities = if request.has_creates() || !will_destroy.is_empty() {
            self.identities(account_id).await?
        } else {
            StoredIdentities::default()
        };
        let mut identity_count = identities.len() as u64;
        let account_info = self
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;

        // Process creates
        let mut batch = BatchBuilder::new();
        let mut pending_creates = Vec::new();
        'create: for (id, object) in request.unwrap_create() {
            let mut identity = Identity::default();
            let omitted = Omitted::from_create(&object);

            for (property, mut value) in object.into_expanded_object() {
                if let Err(err) = response
                    .resolve_self_references(&mut value, 0, false)
                    .and_then(|_| {
                        validate_identity_value(None, &property, value, &mut identity, true)
                    })
                {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            }

            // Validate email address
            if !identity.email.is_empty() {
                if !account_info
                    .addresses()
                    .iter()
                    .any(|e| e == &identity.email)
                {
                    response.not_created.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(IdentityProperty::Email)
                            .with_description(
                                "E-mail address not configured for this account.".to_string(),
                            ),
                    );
                    continue 'create;
                }
            } else {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(IdentityProperty::Email)
                        .with_description("Missing e-mail address."),
                );
                continue 'create;
            }

            // Validate quota
            if identity_count
                >= self.object_quota(
                    account_info.object_quotas(),
                    StorageQuota::MaxEmailIdentities,
                ) as u64
            {
                response.not_created.append(
                    id,
                    SetError::new(SetErrorType::OverQuota).with_description(concat!(
                        "There are too many identities, ",
                        "please delete some before adding a new one."
                    )),
                );
                continue 'create;
            }

            // Insert record
            let slot = batch.reserve_document_id(account_id, Collection::Identity);
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Identity)
                .create_document(slot)
                .custom(ObjectIndexBuilder::<(), _>::new().with_changes(identity))
                .caused_by(trc::location!())?
                .commit_point();
            identity_count += 1;
            pending_creates.push((id, slot, omitted));
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update() {
            let id = match id {
                MaybeInvalid::Value(id) => id,
                invalid => {
                    response.not_updated.append(invalid, SetError::not_found());
                    continue 'update;
                }
            };
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain identity
            let document_id = id.document_id();
            let identity_ = if let Some(identity_) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::Identity,
                    document_id,
                ))
                .await?
            {
                identity_
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };
            let identity = identity_
                .to_unarchived::<Identity>()
                .caused_by(trc::location!())?;
            let mut new_identity = identity
                .deserialize::<Identity>()
                .caused_by(trc::location!())?;

            for (property, mut value) in object.into_expanded_object() {
                if let Err(err) = response
                    .resolve_self_references(&mut value, 0, false)
                    .and_then(|_| {
                        validate_identity_value(
                            Some(id),
                            &property,
                            value,
                            &mut new_identity,
                            false,
                        )
                    })
                {
                    response.not_updated.append(id, err);
                    continue 'update;
                }
            }

            // Update record
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Identity)
                .with_document(document_id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_current(identity)
                        .with_changes(new_identity),
                )
                .caused_by(trc::location!())?
                .commit_point();
            response.updated.append(id, None);
        }

        // Process deletions
        for id in will_destroy {
            let document_id = id.document_id();
            if let Some(identity) = identities.get(document_id) {
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Identity)
                    .with_document(document_id)
                    .custom(
                        ObjectIndexBuilder::<_, ()>::new().with_current(
                            identity
                                .to_unarchived::<Identity>()
                                .caused_by(trc::location!())?,
                        ),
                    )
                    .caused_by(trc::location!())?
                    .commit_point();
                response.destroyed.push(id);
            } else {
                response.not_destroyed.append(id, SetError::not_found());
            }
        }

        // Write changes
        if !batch.is_empty() {
            let assigned_ids = self.commit_batch(batch).await.caused_by(trc::location!())?;

            response.new_state =
                State::Exact(assigned_ids.last_change_id(account_id, SyncCollection::Identity))
                    .into();

            for (id, slot, omitted) in pending_creates {
                response.created_with_properties(id, assigned_ids.slot(slot), omitted.server_set());
            }
        }

        Ok(response)
    }
}

fn validate_identity_value(
    expected_id: Option<Id>,
    property: &Key<'_, IdentityProperty>,
    value: Value<'_, IdentityProperty, IdentityValue>,
    identity: &mut Identity,
    is_create: bool,
) -> Result<(), SetError<IdentityProperty>> {
    let Key::Property(property) = property else {
        return Err(SetError::invalid_properties()
            .with_property(property.to_owned())
            .with_description("Invalid property."));
    };

    match (property, value) {
        (IdentityProperty::Name, Value::Str(value)) if value.len() < 255 => {
            identity.name = value.into_owned();
        }
        (IdentityProperty::Email, Value::Str(value)) if is_create && value.len() < 255 => {
            identity.email = sanitize_email(&value).ok_or_else(|| {
                SetError::invalid_properties()
                    .with_property(IdentityProperty::Email)
                    .with_description("Invalid e-mail address.")
            })?;
        }
        (IdentityProperty::TextSignature, Value::Str(value)) if value.len() < 2048 => {
            identity.text_signature = value.into_owned();
        }
        (IdentityProperty::HtmlSignature, Value::Str(value)) if value.len() < 2048 => {
            identity.html_signature = value.into_owned();
        }
        (IdentityProperty::ReplyTo | IdentityProperty::Bcc, Value::Array(value)) => {
            let mut addresses = Vec::with_capacity(value.len());
            for addr in value {
                let mut address = EmailAddress {
                    name: None,
                    email: "".into(),
                };
                let mut is_valid = false;
                if let Value::Object(obj) = addr {
                    for (key, value) in obj.into_vec() {
                        match (key, value) {
                            (Key::Property(IdentityProperty::Email), Value::Str(value))
                                if value.len() < 255 =>
                            {
                                is_valid = true;
                                address.email = value.into_owned();
                            }
                            (Key::Property(IdentityProperty::Name), Value::Str(value))
                                if value.len() < 255 =>
                            {
                                address.name = Some(value.into_owned());
                            }
                            (Key::Property(IdentityProperty::Name), Value::Null) => (),
                            _ => {
                                is_valid = false;
                                break;
                            }
                        }
                    }
                }

                if is_valid && !address.email.is_empty() {
                    addresses.push(address);
                } else {
                    return Err(SetError::invalid_properties()
                        .with_property(property.clone())
                        .with_description("Invalid e-mail address object."));
                }
            }

            match property {
                IdentityProperty::ReplyTo => {
                    identity.reply_to = Some(addresses);
                }
                IdentityProperty::Bcc => {
                    identity.bcc = Some(addresses);
                }
                _ => unreachable!(),
            }
        }
        (IdentityProperty::Name, Value::Null) => {
            identity.name.clear();
        }
        (IdentityProperty::TextSignature, Value::Null) => {
            identity.text_signature.clear();
        }
        (IdentityProperty::HtmlSignature, Value::Null) => {
            identity.html_signature.clear();
        }
        (IdentityProperty::ReplyTo, Value::Null) => identity.reply_to = None,
        (IdentityProperty::Bcc, Value::Null) => identity.bcc = None,
        (IdentityProperty::Id, value) => {
            if !expected_id.is_some_and(|expected| crate::matches_id(&value, expected)) {
                return Err(SetError::invalid_properties()
                    .with_property(IdentityProperty::Id)
                    .with_description("The id property is immutable."));
            }
        }
        (property, _) => {
            return Err(SetError::invalid_properties()
                .with_property(property.clone())
                .with_description("Field could not be set."));
        }
    }

    Ok(())
}
