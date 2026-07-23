/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IPC_CHANNEL_BUFFER, Server,
    auth::AccessToken,
    ipc::{BroadcastEvent, PushEvent, PushNotification},
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

    #[inline(always)]
    pub fn notify_task_queue(&self) {
        self.inner.ipc.task_tx.notify_one();
    }

    pub async fn broadcast_push_notification(&self, notification: PushNotification) -> bool {
        match self
            .inner
            .ipc
            .push_tx
            .clone()
            .send(PushEvent::Publish {
                notification,
                broadcast: true,
            })
            .await
        {
            Ok(_) => true,
            Err(_) => {
                trc::event!(
                    Server(trc::ServerEvent::ThreadError),
                    Details = "Error sending state change.",
                    CausedBy = trc::location!()
                );

                false
            }
        }
    }

    pub async fn cluster_broadcast(&self, event: BroadcastEvent) {
        if let Some(broadcast_tx) = &self.inner.ipc.broadcast_tx.clone()
            && broadcast_tx.send(event).await.is_err()
        {
            trc::event!(
                Server(trc::ServerEvent::ThreadError),
                Details = "Error sending broadcast event.",
                CausedBy = trc::location!()
            );
        }
    }
}
