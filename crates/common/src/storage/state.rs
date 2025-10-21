/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IPC_CHANNEL_BUFFER, Server,
    auth::AccessToken,
    ipc::{PushEvent, PushNotification},
};
use tokio::sync::mpsc;
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

impl Server {
    pub async fn subscribe_push_manager(
        &self,
        access_token: &AccessToken,
        types: Bitmap<DataType>,
    ) -> trc::Result<mpsc::Receiver<PushNotification>> {
        let (tx, rx) = mpsc::channel::<PushNotification>(IPC_CHANNEL_BUFFER);
        let push_tx = self.inner.ipc.push_tx.clone();

        push_tx
            .send(PushEvent::Subscribe {
                account_ids: access_token.member_ids().collect(),
                types,
                tx,
            })
            .await
            .map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .reason(err)
                    .caused_by(trc::location!())
            })?;

        Ok(rx)
    }
}
