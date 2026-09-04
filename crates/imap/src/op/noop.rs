/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;
use tokio::sync::OwnedSemaphorePermit;

use crate::core::{Session, State};
use common::network::SessionStream;
use imap_proto::{Command, StatusResponse, receiver::Request};

impl<T: SessionStream> Session<T> {
    pub async fn handle_noop(
        &mut self,
        request: Request<Command>,
        _permit: Option<OwnedSemaphorePermit>,
    ) -> trc::Result<()> {
        let op_start = Instant::now();

        if let State::Selected { data, mailbox, .. } = &self.state {
            data.write_changes(
                Some(mailbox),
                false,
                true,
                self.is_qresync || self.is_uidonly,
                self.is_uidonly,
                self.version.is_rev2(),
                self.is_utf8,
            )
            .await?;
        }

        trc::event!(
            Imap(trc::ImapEvent::Noop),
            SpanId = self.session_id,
            Elapsed = op_start.elapsed()
        );

        self.write_bytes(
            StatusResponse::completed(request.command)
                .with_tag(request.tag)
                .into_bytes(),
        )
        .await
    }
}
