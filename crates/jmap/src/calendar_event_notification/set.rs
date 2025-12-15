/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use groupware::{DestroyArchive, cache::GroupwareCache, calendar::CalendarEventNotification};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::calendar_event_notification,
    request::IntoValid,
    types::state::State,
};
use store::{ValueKey, write::{AlignedBytes, Archive, BatchBuilder}};
use trc::AddContext;
use types::collection::{Collection, SyncCollection};

pub trait CalendarEventNotificationSet: Sync + Send {
    fn calendar_event_notification_set(
        &self,
        request: SetRequest<'_, calendar_event_notification::CalendarEventNotification>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<
        Output = trc::Result<SetResponse<calendar_event_notification::CalendarEventNotification>>,
    > + Send;
}

impl CalendarEventNotificationSet for Server {
    async fn calendar_event_notification_set(
        &self,
        mut request: SetRequest<'_, calendar_event_notification::CalendarEventNotification>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
    ) -> trc::Result<SetResponse<calendar_event_notification::CalendarEventNotification>> {
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(
                access_token,
                account_id,
                SyncCollection::CalendarEventNotification,
            )
            .await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;

        let mut batch = BatchBuilder::new();
        for (id, _) in request.unwrap_create() {
            response.not_created.append(
                id,
                SetError::forbidden().with_description("Cannot create event notifications."),
            );
        }

        // Process updates
        for (id, _) in request.unwrap_update().into_valid() {
            response.not_updated.append(
                id,
                SetError::forbidden().with_description("Cannot update event notifications."),
            );
        }

        // Process deletions
        for id in request.unwrap_destroy().into_valid() {
            let document_id = id.document_id();

            if !cache.has_item_id(&document_id) {
                response.not_destroyed.append(id, SetError::not_found());
                continue;
            };

            let _event = if let Some(event) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEventNotification,
                    document_id,
                ))
                .await?
            {
                event
            } else {
                response.not_destroyed.append(id, SetError::not_found());
                continue;
            };
            let event = _event
                .to_unarchived::<CalendarEventNotification>()
                .caused_by(trc::location!())?;

            DestroyArchive(event)
                .delete(access_token, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?;

            response.destroyed.push(id);
        }

        // Write changes
        if !batch.is_empty() {
            let change_id = self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
                .caused_by(trc::location!())?;

            response.new_state = State::Exact(change_id).into();
        }

        Ok(response)
    }
}
