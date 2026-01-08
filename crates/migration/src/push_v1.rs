/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::object::Object;
use crate::{
    get_document_ids,
    object::{FromLegacy, Property, Value},
};
use base64::{Engine, engine::general_purpose};
use common::Server;
use email::push::{Keys, PushSubscription, PushSubscriptions};
use store::{
    Serialize, ValueKey,
    write::{Archiver, BatchBuilder, ValueClass},
};
use trc::AddContext;
use types::{
    collection::Collection,
    field::{Field, PrincipalField},
    type_state::DataType,
};

pub(crate) async fn migrate_push_subscriptions_v011(
    server: &Server,
    account_id: u32,
) -> trc::Result<u64> {
    // Obtain email ids
    let push_subscription_ids = get_document_ids(server, account_id, Collection::PushSubscription)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_push_subscriptions = push_subscription_ids.len();
    if num_push_subscriptions == 0 {
        return Ok(0);
    }
    let mut subscriptions = Vec::with_capacity(num_push_subscriptions as usize);

    for push_subscription_id in &push_subscription_ids {
        match server
            .store()
            .get_value::<Object<Value>>(ValueKey {
                account_id,
                collection: Collection::PushSubscription.into(),
                document_id: push_subscription_id,
                class: ValueClass::Property(Field::ARCHIVE.into()),
            })
            .await
        {
            Ok(Some(legacy)) => {
                let mut subscription = PushSubscription::from_legacy(legacy);
                subscription.id = push_subscription_id;
                subscriptions.push(subscription);
            }
            Ok(None) => (),
            Err(err) => {
                return Err(err
                    .account_id(account_id)
                    .document_id(push_subscription_id)
                    .caused_by(trc::location!()));
            }
        }
    }

    if !subscriptions.is_empty() {
        // Save changes
        let num_push_subscriptions = subscriptions.len() as u64;
        let mut batch = BatchBuilder::new();

        batch
            .with_account_id(u32::MAX)
            .with_collection(Collection::Principal)
            .with_document(account_id)
            .tag(PrincipalField::PushSubscriptions)
            .with_account_id(account_id)
            .with_collection(Collection::PushSubscription);

        for subscription in &subscriptions {
            batch.with_document(subscription.id).clear(Field::ARCHIVE);
        }

        batch
            .with_collection(Collection::Principal)
            .with_document(0)
            .set(
                PrincipalField::PushSubscriptions,
                Archiver::new(PushSubscriptions { subscriptions })
                    .serialize()
                    .caused_by(trc::location!())?,
            );

        server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;

        Ok(num_push_subscriptions)
    } else {
        Ok(0)
    }
}

impl FromLegacy for PushSubscription {
    fn from_legacy(legacy: Object<Value>) -> Self {
        let (verification_code, verified) = legacy
            .get(&Property::VerificationCode)
            .as_string()
            .map(|c| (c.to_string(), true))
            .or_else(|| {
                legacy
                    .get(&Property::Value)
                    .as_string()
                    .map(|c| (c.to_string(), false))
            })
            .unwrap_or_default();

        PushSubscription {
            id: 0,
            url: legacy
                .get(&Property::Url)
                .as_string()
                .unwrap_or_default()
                .to_string(),
            device_client_id: legacy
                .get(&Property::DeviceClientId)
                .as_string()
                .unwrap_or_default()
                .to_string(),
            expires: legacy
                .get(&Property::Expires)
                .as_date()
                .map(|s| s.timestamp() as u64)
                .unwrap_or_default(),
            verification_code,
            verified,
            types: legacy
                .get(&Property::Types)
                .as_list()
                .map(|l| l.as_slice())
                .unwrap_or_default()
                .iter()
                .filter_map(|v| v.as_string().and_then(DataType::parse))
                .collect(),
            keys: convert_keys(legacy.get(&Property::Keys)),
            email_push: vec![],
        }
    }
}

fn convert_keys(value: &Value) -> Option<Keys> {
    let mut addr = Keys {
        p256dh: Default::default(),
        auth: Default::default(),
    };
    if let Value::Object(obj) = value {
        for (key, value) in &obj.properties {
            match (key, value) {
                (Property::Auth, Value::Text(value)) => {
                    addr.auth = general_purpose::URL_SAFE.decode(value).unwrap_or_default();
                }
                (Property::P256dh, Value::Text(value)) => {
                    addr.p256dh = general_purpose::URL_SAFE.decode(value).unwrap_or_default();
                }
                _ => {}
            }
        }
    }
    if !addr.p256dh.is_empty() && !addr.auth.is_empty() {
        Some(addr)
    } else {
        None
    }
}
