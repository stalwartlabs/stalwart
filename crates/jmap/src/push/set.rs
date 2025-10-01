/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::get::PushSubscriptionFetch;
use base64::{Engine, engine::general_purpose};
use common::{Server, auth::AccessToken};
use email::push::{Keys, PushSubscription};
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::push_subscription::{self, PushSubscriptionProperty, PushSubscriptionValue},
    references::resolve::ResolveCreatedReference,
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use rand::distr::Alphanumeric;
use std::future::Future;
use store::{
    Serialize,
    rand::{Rng, rng},
    write::{Archiver, BatchBuilder, now},
};
use trc::AddContext;
use types::{collection::Collection, field::Field};
use utils::map::bitmap::Bitmap;

const EXPIRES_MAX: i64 = 7 * 24 * 3600; // 7 days
const VERIFICATION_CODE_LEN: usize = 32;

pub trait PushSubscriptionSet: Sync + Send {
    fn push_subscription_set(
        &self,
        request: SetRequest<'_, push_subscription::PushSubscription>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse<push_subscription::PushSubscription>>> + Send;
}

impl PushSubscriptionSet for Server {
    async fn push_subscription_set(
        &self,
        mut request: SetRequest<'_, push_subscription::PushSubscription>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse<push_subscription::PushSubscription>> {
        let account_id = access_token.primary_id();
        let push_ids = self
            .get_document_ids(account_id, Collection::PushSubscription)
            .await?
            .unwrap_or_default();
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();

        // Process creates
        let mut batch = BatchBuilder::new();
        'create: for (id, object) in request.unwrap_create() {
            let mut push = PushSubscription::default();

            if push_ids.len() as usize >= self.core.jmap.push_max_total {
                response.not_created.append(id, SetError::forbidden().with_description(
                    "There are too many subscriptions, please delete some before adding a new one.",
                ));
                continue 'create;
            }

            for (property, mut value) in object.into_expanded_object() {
                if let Err(err) = response
                    .resolve_self_references(&mut value)
                    .and_then(|_| validate_push_value(&property, value, &mut push, true))
                {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            }

            if push.device_client_id.is_empty() || push.url.is_empty() {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_properties([
                            PushSubscriptionProperty::DeviceClientId,
                            PushSubscriptionProperty::Url,
                        ])
                        .with_description("Missing required properties"),
                );
                continue 'create;
            }

            // Add expiry time if missing
            if push.expires == 0 {
                push.expires = now() + EXPIRES_MAX as u64;
            }
            let expires = UTCDate::from_timestamp(push.expires as i64);

            // Generate random verification code
            push.verification_code = rng()
                .sample_iter(Alphanumeric)
                .take(VERIFICATION_CODE_LEN)
                .map(char::from)
                .collect::<String>();

            // Insert record
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::PushSubscription, 1)
                .await
                .caused_by(trc::location!())?;
            batch
                .with_account_id(account_id)
                .with_collection(Collection::PushSubscription)
                .create_document(document_id)
                .set(
                    Field::ARCHIVE,
                    Archiver::new(push)
                        .serialize()
                        .caused_by(trc::location!())?,
                )
                .commit_point();
            response.created.insert(
                id,
                Map::with_capacity(1)
                    .with_key_value(
                        PushSubscriptionProperty::Id,
                        PushSubscriptionValue::Id(document_id.into()),
                    )
                    .with_key_value(PushSubscriptionProperty::Keys, Value::Null)
                    .with_key_value(
                        PushSubscriptionProperty::Expires,
                        PushSubscriptionValue::Date(expires),
                    )
                    .into(),
            );
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update().into_valid() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain push subscription
            let document_id = id.document_id();
            let mut push = if let Some(push) = self
                .get_archive(account_id, Collection::PushSubscription, document_id)
                .await?
            {
                push.deserialize::<email::push::PushSubscription>()
                    .caused_by(trc::location!())?
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };

            for (property, mut value) in object.into_expanded_object() {
                if let Err(err) = response
                    .resolve_self_references(&mut value)
                    .and_then(|_| validate_push_value(&property, value, &mut push, false))
                {
                    response.not_updated.append(id, err);
                    continue 'update;
                }
            }

            // Update record
            batch
                .with_account_id(account_id)
                .with_collection(Collection::PushSubscription)
                .update_document(document_id)
                .set(
                    Field::ARCHIVE,
                    Archiver::new(push)
                        .serialize()
                        .caused_by(trc::location!())?,
                )
                .commit_point();
            response.updated.append(id, None);
        }

        // Process deletions
        for id in will_destroy {
            let document_id = id.document_id();
            if push_ids.contains(document_id) {
                // Update record
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::PushSubscription)
                    .delete_document(document_id)
                    .clear(Field::ARCHIVE)
                    .commit_point();
                response.destroyed.push(id);
            } else {
                response.not_destroyed.append(id, SetError::not_found());
            }
        }

        // Write changes
        if !batch.is_empty() {
            self.commit_batch(batch).await.caused_by(trc::location!())?;
        }

        // Update push subscriptions
        if response.has_changes() {
            self.update_push_subscriptions(account_id).await;
        }

        Ok(response)
    }
}

fn validate_push_value(
    property: &Key<PushSubscriptionProperty>,
    value: Value<'_, PushSubscriptionProperty, PushSubscriptionValue>,
    push: &mut PushSubscription,
    is_create: bool,
) -> Result<(), SetError<PushSubscriptionProperty>> {
    let Key::Property(property) = property else {
        return Err(SetError::invalid_properties()
            .with_property(property.to_owned())
            .with_description("Invalid property."));
    };

    match (property, value) {
        (PushSubscriptionProperty::DeviceClientId, Value::Str(value))
            if is_create && value.len() < 255 =>
        {
            push.device_client_id = value.into_owned();
        }
        (PushSubscriptionProperty::Url, Value::Str(value))
            if is_create && value.len() < 512 && value.starts_with("https://") =>
        {
            push.url = value.into_owned();
        }
        (PushSubscriptionProperty::Keys, Value::Object(value)) if is_create && value.len() == 2 => {
            if let (Some(auth), Some(p256dh)) = (
                value
                    .get(&Key::Property(PushSubscriptionProperty::Auth))
                    .and_then(|v| v.as_str())
                    .and_then(|v| general_purpose::URL_SAFE.decode(v.as_ref()).ok()),
                value
                    .get(&Key::Property(PushSubscriptionProperty::P256dh))
                    .and_then(|v| v.as_str())
                    .and_then(|v| general_purpose::URL_SAFE.decode(v.as_ref()).ok()),
            ) {
                push.keys = Some(Keys { auth, p256dh });
            } else {
                return Err(SetError::invalid_properties()
                    .with_property(property.clone())
                    .with_description("Failed to decode keys."));
            }
        }
        (PushSubscriptionProperty::Expires, Value::Element(PushSubscriptionValue::Date(value))) => {
            let current_time = now() as i64;
            let expires = value.timestamp();
            push.expires = if expires > current_time && (expires - current_time) > EXPIRES_MAX {
                current_time + EXPIRES_MAX
            } else {
                expires
            } as u64;
        }
        (PushSubscriptionProperty::Expires, Value::Null) => {
            push.expires = now() + EXPIRES_MAX as u64;
        }
        (PushSubscriptionProperty::Types, Value::Array(value)) => {
            push.types.clear();

            for item in value {
                if let Value::Element(PushSubscriptionValue::Types(dt)) = item {
                    push.types.insert(dt);
                } else {
                    return Err(SetError::invalid_properties()
                        .with_property(property.clone())
                        .with_description("Invalid data type."));
                }
            }
        }
        (PushSubscriptionProperty::VerificationCode, Value::Str(value)) if !is_create => {
            if push.verification_code == value {
                push.verified = true;
            } else {
                return Err(SetError::invalid_properties()
                    .with_property(property.clone())
                    .with_description("Verification code does not match.".to_string()));
            }
        }
        (PushSubscriptionProperty::Keys, Value::Null) => {
            push.keys = None;
        }
        (PushSubscriptionProperty::Types, Value::Null) => {
            push.types = Bitmap::all();
        }
        (PushSubscriptionProperty::VerificationCode, Value::Null) => {}
        (property, _) => {
            return Err(SetError::invalid_properties()
                .with_property(property.clone())
                .with_description("Field could not be set."));
        }
    }

    if is_create && push.types.is_empty() {
        push.types = Bitmap::all();
    }

    Ok(())
}
