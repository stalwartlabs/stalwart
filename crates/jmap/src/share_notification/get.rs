/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::share_notification::ShareNotification,
};

pub trait ShareNotificationGet: Sync + Send {
    fn share_notification_get(
        &self,
        request: GetRequest<ShareNotification>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<ShareNotification>>> + Send;
}

impl ShareNotificationGet for Server {
    async fn share_notification_get(
        &self,
        mut request: GetRequest<ShareNotification>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<ShareNotification>> {
        todo!()
    }
}
