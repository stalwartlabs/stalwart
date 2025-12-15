/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::{Session, StatusResponse};
use common::listener::SessionStream;
use directory::Permission;
use email::sieve::{SieveScript, ingest::SieveScriptIngest};
use std::time::Instant;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{collection::Collection, field::SieveField};

impl<T: SessionStream> Session<T> {
    pub async fn handle_listscripts(&mut self) -> trc::Result<Vec<u8>> {
        // Validate access
        self.assert_has_permission(Permission::SieveListScripts)?;

        let op_start = Instant::now();
        let account_id = self.state.access_token().primary_id();
        let document_ids = self
            .server
            .document_ids(account_id, Collection::SieveScript, SieveField::Name)
            .await
            .caused_by(trc::location!())?;

        if document_ids.is_empty() {
            return Ok(StatusResponse::ok("").into_bytes());
        }

        let mut response = Vec::with_capacity(128);
        let count = document_ids.len();
        let active_script_id = self.server.sieve_script_get_active_id(account_id).await?;

        for document_id in document_ids {
            if let Some(script_) = self
                .server
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::SieveScript,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
            {
                let script = script_
                    .unarchive::<SieveScript>()
                    .caused_by(trc::location!())?;
                response.push(b'\"');
                for ch in script.name.as_bytes() {
                    if [b'\\', b'\"'].contains(ch) {
                        response.push(b'\\');
                    }
                    response.push(*ch);
                }
                if active_script_id == Some(document_id) {
                    response.extend_from_slice(b"\" ACTIVE\r\n");
                } else {
                    response.extend_from_slice(b"\"\r\n");
                }
            }
        }

        trc::event!(
            ManageSieve(trc::ManageSieveEvent::ListScripts),
            SpanId = self.session_id,
            Total = count,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok("").serialize(response))
    }
}
