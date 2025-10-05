/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::query::{QueryRequest, QueryResponse},
    object::calendar_event_notification::CalendarEventNotification,
};

pub trait CalendarEventNotificationQuery: Sync + Send {
    fn calendar_event_notification_query(
        &self,
        request: QueryRequest<CalendarEventNotification>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl CalendarEventNotificationQuery for Server {
    async fn calendar_event_notification_query(
        &self,
        mut request: QueryRequest<CalendarEventNotification>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        todo!()
    }
}
