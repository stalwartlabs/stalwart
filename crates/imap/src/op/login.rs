/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::Session;
use common::network::SessionStream;
use directory::Credentials;
use imap_proto::{Command, receiver::Request};

impl<T: SessionStream> Session<T> {
    pub async fn handle_login(&mut self, request: Request<Command>) -> trc::Result<()> {
        let arguments = request.parse_login()?;

        self.authenticate(
            Credentials::Basic {
                username: arguments.username.to_string(),
                secret: arguments.password.to_string(),
            },
            arguments.tag,
        )
        .await
    }
}
