/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use email::push::{Keys, PushSubscription, PushSubscriptions};
use store::{
    Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, now},
};
use trc::AddContext;
use types::{
    collection::Collection,
    field::{Field, PrincipalField},
    type_state::DataType,
};
use utils::map::bitmap::Bitmap;

use crate::get_document_ids;

pub(crate) async fn migrate_push_subscriptions_v013(
    server: &Server,
    account_id: u32,
) -> trc::Result<u64> {
    // Obtain email ids
    let push_ids = get_document_ids(server, account_id, Collection::PushSubscription)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_pushes = push_ids.len();
    if num_pushes == 0 {
        return Ok(0);
    }
    let mut subscriptions = Vec::with_capacity(num_pushes as usize);

    for push_id in &push_ids {
        match server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::PushSubscription,
                push_id,
            ))
            .await
        {
            Ok(Some(legacy)) => match legacy.deserialize_untrusted::<PushSubscriptionV2>() {
                Ok(old_push) => {
                    subscriptions.push(PushSubscription {
                        id: push_id,
                        url: old_push.url,
                        device_client_id: old_push.device_client_id,
                        expires: old_push.expires,
                        verification_code: old_push.verification_code,
                        verified: old_push.verified,
                        types: old_push.types,
                        keys: old_push.keys,
                        email_push: Vec::new(),
                    });
                }
                Err(err) => {
                    return Err(err.account_id(push_id).caused_by(trc::location!()));
                }
            },
            Ok(None) => (),
            Err(err) => {
                return Err(err.account_id(push_id).caused_by(trc::location!()));
            }
        }
    }

    if !subscriptions.is_empty() {
        // Save changes
        let num_push_subscriptions = subscriptions.len() as u64;
        let now = now();
        let mut batch = BatchBuilder::new();

        // Delete archived and document ids
        batch
            .with_account_id(account_id)
            .with_collection(Collection::PushSubscription);
        for subscription in &subscriptions {
            batch.with_document(subscription.id).clear(Field::ARCHIVE);
        }

        subscriptions.retain(|s| s.verified && s.expires > now);

        if !subscriptions.is_empty() {
            batch
                .with_account_id(u32::MAX)
                .with_collection(Collection::Principal)
                .with_document(account_id)
                .tag(PrincipalField::PushSubscriptions)
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .set(
                    PrincipalField::PushSubscriptions,
                    Archiver::new(PushSubscriptions { subscriptions })
                        .serialize()
                        .caused_by(trc::location!())?,
                );
        }

        server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;

        Ok(num_push_subscriptions)
    } else {
        Ok(0)
    }
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Default, Debug, Clone, PartialEq, Eq,
)]
pub struct PushSubscriptionV2 {
    pub url: String,
    pub device_client_id: String,
    pub expires: u64,
    pub verification_code: String,
    pub verified: bool,
    pub types: Bitmap<DataType>,
    pub keys: Option<Keys>,
}
