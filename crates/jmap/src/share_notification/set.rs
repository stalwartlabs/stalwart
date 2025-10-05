/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use http_proto::HttpSessionData;
use jmap_proto::{
    method::set::{SetRequest, SetResponse},
    object::share_notification::ShareNotification,
};

pub trait ShareNotificationSet: Sync + Send {
    fn share_notification_set(
        &self,
        request: SetRequest<'_, ShareNotification>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<ShareNotification>>> + Send;
}

impl ShareNotificationSet for Server {
    async fn share_notification_set(
        &self,
        mut request: SetRequest<'_, ShareNotification>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
    ) -> trc::Result<SetResponse<ShareNotification>> {
        todo!()
    }
}
