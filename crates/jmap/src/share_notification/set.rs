/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::share_notification::ShareNotification,
    request::IntoValid,
};
use store::write::{BatchBuilder, ValueClass};
use trc::AddContext;

pub trait ShareNotificationSet: Sync + Send {
    fn share_notification_set(
        &self,
        request: SetRequest<'_, ShareNotification>,
    ) -> impl Future<Output = trc::Result<SetResponse<ShareNotification>>> + Send;
}

impl ShareNotificationSet for Server {
    async fn share_notification_set(
        &self,
        mut request: SetRequest<'_, ShareNotification>,
    ) -> trc::Result<SetResponse<ShareNotification>> {
        let account_id = request.account_id.document_id();
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;

        for (id, _) in request.unwrap_create() {
            response.not_created.append(
                id,
                SetError::forbidden().with_description("Cannot create share notifications."),
            );
        }

        // Process updates
        for (id, _) in request.unwrap_update().into_valid() {
            response.not_updated.append(
                id,
                SetError::forbidden().with_description("Cannot update share notifications."),
            );
        }

        // Process deletions
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        for id in request.unwrap_destroy().into_valid() {
            batch.clear(ValueClass::ShareNotification {
                notification_id: id.id(),
                notify_account_id: account_id,
            });
            response.destroyed.push(id);
        }

        // Write changes
        if !batch.is_empty() {
            self.commit_batch(batch).await.caused_by(trc::location!())?;
        }

        Ok(response)
    }
}
