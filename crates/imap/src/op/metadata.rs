/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::Session;
use common::network::SessionStream;
use imap_proto::{Command, receiver::Request};
use registry::schema::enums::Permission;

impl<T: SessionStream> Session<T> {
    pub async fn handle_get_metadata(&mut self, request: Request<Command>) -> trc::Result<()> {
        self.assert_has_permission(Permission::ImapMetadataGet)?;
        request.parse_get_metadata(self.is_utf8)?;
        todo!()
    }

    pub async fn handle_set_metadata(&mut self, request: Request<Command>) -> trc::Result<()> {
        request.parse_set_metadata(self.is_utf8)?;
        todo!()
    }
}
