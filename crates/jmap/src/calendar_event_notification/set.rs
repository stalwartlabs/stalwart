/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use http_proto::HttpSessionData;
use jmap_proto::{
    method::set::{SetRequest, SetResponse},
    object::calendar_event_notification::CalendarEventNotification,
};

pub trait CalendarEventNotificationSet: Sync + Send {
    fn calendar_event_notification_set(
        &self,
        request: SetRequest<'_, CalendarEventNotification>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<CalendarEventNotification>>> + Send;
}

impl CalendarEventNotificationSet for Server {
    async fn calendar_event_notification_set(
        &self,
        mut request: SetRequest<'_, CalendarEventNotification>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
    ) -> trc::Result<SetResponse<CalendarEventNotification>> {
        todo!()
    }
}
