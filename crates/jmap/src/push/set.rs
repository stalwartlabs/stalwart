/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose};
use common::{Server, auth::AccessToken, ipc::PushEvent};
use email::push::{Keys, PushSubscription, PushSubscriptions};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
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
    Serialize, ValueKey,
    rand::{Rng, rng},
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, now},
};
use trc::{AddContext, ServerEvent};
use types::{collection::Collection, field::PrincipalField};
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
        // Load existing push subscriptions
        let account_id = access_token.primary_id();
        let subscriptions_archive = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                account_id,
                Collection::Principal,
                0,
                PrincipalField::PushSubscriptions,
            ))
            .await?;
        let mut subscriptions = if let Some(subscriptions) = &subscriptions_archive {
            subscriptions
                .deserialize::<PushSubscriptions>()
                .caused_by(trc::location!())?
        } else {
            PushSubscriptions::default()
        };

        let num_subscriptions = subscriptions.subscriptions.len();
        let mut max_id = 0;
        let current_time = now();
        subscriptions.subscriptions.retain(|s| {
            max_id = max_id.max(s.id);

            s.expires > current_time
        });
        let mut has_changes = num_subscriptions != subscriptions.subscriptions.len();

        // Prepare response
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();

        // Process creates
        'create: for (id, object) in request.unwrap_create() {
            let mut push = PushSubscription::default();

            if subscriptions.subscriptions.len()
                >= access_token.object_quota(Collection::PushSubscription) as usize
            {
                response.not_created.append(id, SetError::new(SetErrorType::OverQuota).with_description(
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

            // Set id
            max_id += 1;
            let document_id = max_id;
            push.id = document_id;

            // Insert record
            subscriptions.subscriptions.push(push);
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
            has_changes = true;
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
            let Some(push) = subscriptions
                .subscriptions
                .iter_mut()
                .find(|p| p.id == document_id)
            else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };

            for (property, mut value) in object.into_expanded_object() {
                if let Err(err) = response
                    .resolve_self_references(&mut value)
                    .and_then(|_| validate_push_value(&property, value, push, false))
                {
                    response.not_updated.append(id, err);
                    continue 'update;
                }
            }

            has_changes = true;
            response.updated.append(id, None);
        }

        // Process deletions
        for id in will_destroy {
            let document_id = id.document_id();
            if let Some(idx) = subscriptions
                .subscriptions
                .iter()
                .position(|p| p.id == document_id)
            {
                subscriptions.subscriptions.swap_remove(idx);
                has_changes = true;
                response.destroyed.push(id);
            } else {
                response.not_destroyed.append(id, SetError::not_found());
            }
        }

        // Update push subscriptions
        if has_changes {
            // Save changes
            let mut batch = BatchBuilder::new();

            if subscriptions_archive.is_none() {
                batch
                    .with_account_id(u32::MAX)
                    .with_collection(Collection::Principal)
                    .with_document(account_id)
                    .tag(PrincipalField::PushSubscriptions);
            } else if subscriptions.subscriptions.is_empty() {
                batch
                    .with_account_id(u32::MAX)
                    .with_collection(Collection::Principal)
                    .with_document(account_id)
                    .untag(PrincipalField::PushSubscriptions);
            }

            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0);

            if let Some(subscriptions_archive) = subscriptions_archive {
                batch.assert_value(PrincipalField::PushSubscriptions, subscriptions_archive);
            }

            if !subscriptions.subscriptions.is_empty() {
                batch.set(
                    PrincipalField::PushSubscriptions,
                    Archiver::new(subscriptions)
                        .serialize()
                        .caused_by(trc::location!())?,
                );
            } else {
                batch.clear(PrincipalField::PushSubscriptions);
            }

            self.commit_batch(batch).await.caused_by(trc::location!())?;

            // Notify push manager
            if self
                .inner
                .ipc
                .push_tx
                .clone()
                .send(PushEvent::PushServerUpdate {
                    account_id,
                    broadcast: true,
                })
                .await
                .is_err()
            {
                trc::event!(
                    Server(ServerEvent::ThreadError),
                    Details = "Error sending push updates.",
                    CausedBy = trc::location!()
                );
            }
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
