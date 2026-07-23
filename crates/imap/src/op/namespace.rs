/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::Session;
use common::network::SessionStream;
use imap_proto::{
    Command, StatusResponse,
    protocol::{ImapResponse, namespace::Response},
    receiver::Request,
};
use registry::schema::enums::Permission;

impl<T: SessionStream> Session<T> {
    pub async fn handle_namespace(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapNamespace)?;

        trc::event!(
            Imap(trc::ImapEvent::Namespace),
            SpanId = self.session_id,
            Elapsed = trc::Value::Duration(0)
        );

        self.write_bytes(
            StatusResponse::completed(Command::Namespace)
                .with_tag(request.tag)
                .serialize(
                    Response {
                        shared_prefix: if self.state.session_data().mailboxes.lock().len() > 1 {
                            Some(self.server.core.email.shared_folder.as_str().into())
                        } else {
                            None
                        },
                    }
                    .serialize(),
                ),
        )
        .await
    }
}
