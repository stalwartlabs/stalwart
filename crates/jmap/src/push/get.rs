/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, ipc::PushEvent};
use email::push::PushSubscriptions;
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::push_subscription::{self, PushSubscriptionProperty, PushSubscriptionValue},
    types::date::UTCDate,
};
use jmap_tools::{Map, Value};
use std::future::Future;
use store::{
    Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, now},
};
use trc::{AddContext, ServerEvent};
use types::{collection::Collection, field::PrincipalField, id::Id};
use utils::map::bitmap::Bitmap;

pub trait PushSubscriptionFetch: Sync + Send {
    fn push_subscription_get(
        &self,
        request: GetRequest<push_subscription::PushSubscription>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<push_subscription::PushSubscription>>> + Send;
}

impl PushSubscriptionFetch for Server {
    async fn push_subscription_get(
        &self,
        mut request: GetRequest<push_subscription::PushSubscription>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<push_subscription::PushSubscription>> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            PushSubscriptionProperty::Id,
            PushSubscriptionProperty::DeviceClientId,
            PushSubscriptionProperty::VerificationCode,
            PushSubscriptionProperty::Expires,
            PushSubscriptionProperty::Types,
        ]);

        let account_id = access_token.primary_id();

        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: None,
            list: Vec::new(),
            not_found: vec![],
        };

        let Some(subscriptions_) = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                account_id,
                Collection::Principal,
                0,
                PrincipalField::PushSubscriptions,
            ))
            .await?
        else {
            for id in ids.unwrap_or_default() {
                response.not_found.push(id);
            }
            return Ok(response);
        };
        let subscriptions = subscriptions_
            .to_unarchived::<PushSubscriptions>()
            .caused_by(trc::location!())?;

        let ids = if let Some(ids) = ids {
            ids
        } else {
            subscriptions
                .inner
                .subscriptions
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(|s| Id::from(s.id.to_native()))
                .collect::<Vec<_>>()
        };

        for id in ids {
            // Obtain the push subscription object
            let document_id = id.document_id();
            let Some(push) = subscriptions
                .inner
                .subscriptions
                .iter()
                .find(|p| p.id.to_native() == document_id)
            else {
                response.not_found.push(id);
                continue;
            };

            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                match property {
                    PushSubscriptionProperty::Id => {
                        result.insert_unchecked(PushSubscriptionProperty::Id, id);
                    }
                    PushSubscriptionProperty::Url | PushSubscriptionProperty::Keys => {
                        return Err(trc::JmapEvent::Forbidden.into_err().details(
                            "The 'url' and 'keys' properties are not readable".to_string(),
                        ));
                    }
                    PushSubscriptionProperty::DeviceClientId => {
                        result.insert_unchecked(
                            PushSubscriptionProperty::DeviceClientId,
                            &push.device_client_id,
                        );
                    }
                    PushSubscriptionProperty::Types => {
                        let mut types = Vec::new();
                        for typ in Bitmap::from(&push.types).into_iter() {
                            types.push(Value::Element(PushSubscriptionValue::Types(typ)));
                        }
                        result
                            .insert_unchecked(PushSubscriptionProperty::Types, Value::Array(types));
                    }
                    PushSubscriptionProperty::Expires => {
                        if push.expires > 0 {
                            result.insert_unchecked(
                                PushSubscriptionProperty::Expires,
                                Value::Element(PushSubscriptionValue::Date(
                                    UTCDate::from_timestamp(u64::from(push.expires) as i64),
                                )),
                            );
                        } else {
                            result.insert_unchecked(PushSubscriptionProperty::Expires, Value::Null);
                        }
                    }
                    property => {
                        result.insert_unchecked(property.clone(), Value::Null);
                    }
                }
            }
            response.list.push(result.into());
        }

        // Purge old subscriptions
        let current_time = now();
        if subscriptions
            .inner
            .subscriptions
            .iter()
            .any(|s| s.expires.to_native() < current_time)
        {
            let mut updated_subscriptions = subscriptions.deserialize::<PushSubscriptions>()?;
            updated_subscriptions
                .subscriptions
                .retain(|s| s.expires >= current_time);
            let mut batch = BatchBuilder::new();

            if updated_subscriptions.subscriptions.is_empty() {
                batch
                    .with_account_id(u32::MAX)
                    .with_collection(Collection::Principal)
                    .with_account_id(account_id)
                    .tag(PrincipalField::PushSubscriptions);
            }

            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .assert_value(PrincipalField::PushSubscriptions, subscriptions);

            if !updated_subscriptions.subscriptions.is_empty() {
                batch.set(
                    PrincipalField::PushSubscriptions,
                    Archiver::new(updated_subscriptions)
                        .serialize()
                        .caused_by(trc::location!())?,
                );
            } else {
                batch.clear(PrincipalField::PushSubscriptions);
            }

            self.commit_batch(batch).await.caused_by(trc::location!())?;

            // Update push servers
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
