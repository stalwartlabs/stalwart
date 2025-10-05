/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::get::GetRequest,
    object::calendar_event_notification::{
        CalendarEventNotification, CalendarEventNotificationGetResponse,
    },
};

pub trait CalendarEventNotificationGet: Sync + Send {
    fn calendar_event_notification_get(
        &self,
        request: GetRequest<CalendarEventNotification>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<CalendarEventNotificationGetResponse>> + Send;
}

impl CalendarEventNotificationGet for Server {
    async fn calendar_event_notification_get(
        &self,
        mut request: GetRequest<CalendarEventNotification>,
        access_token: &AccessToken,
    ) -> trc::Result<CalendarEventNotificationGetResponse> {
        todo!()
    }
}
