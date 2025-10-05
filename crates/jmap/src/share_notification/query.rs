/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::query::{QueryRequest, QueryResponse},
    object::share_notification::ShareNotification,
};

pub trait ShareNotificationQuery: Sync + Send {
    fn share_notification_query(
        &self,
        request: QueryRequest<ShareNotification>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl ShareNotificationQuery for Server {
    async fn share_notification_query(
        &self,
        mut request: QueryRequest<ShareNotification>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        todo!()
    }
}
