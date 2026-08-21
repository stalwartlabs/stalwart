/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::{Command, ResponseCode, Session, StatusResponse};
use common::network::SessionStream;
use email::sieve::SieveScript;
use imap_proto::receiver::Request;
use registry::schema::enums::Permission;
use std::time::Instant;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::collection::Collection;

impl<T: SessionStream> Session<T> {
    pub async fn handle_getscript(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
        // Validate access
        self.assert_has_permission(Permission::SieveGetScript)?;

        let op_start = Instant::now();
        let name = request
            .tokens
            .into_iter()
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Expected script name as a parameter.")
            })?;
        let account_id = self.state.access_token().account_id();
        let document_id = self.get_script_id(account_id, &name).await?;
        let sieve_ = self
            .server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::SieveScript,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Script not found")
                    .code(ResponseCode::NonExistent)
            })?;
        let sieve = sieve_
            .unarchive::<SieveScript>()
            .caused_by(trc::location!())?;
        let script = self
            .server
            .blob_store()
            .get_blob(sieve.blob_hash.0.as_ref(), 0..usize::MAX)
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Script blob not found")
                    .code(ResponseCode::NonExistent)
            })?;

        let mut response = Vec::with_capacity(script.len() + 32);
        response.push(b'{');
        response.extend_from_slice(script.len().to_string().as_bytes());
        response.extend_from_slice(b"}\r\n");
        response.extend(script);
        response.extend_from_slice(b"\r\n");

        trc::event!(
            ManageSieve(trc::ManageSieveEvent::GetScript),
            SpanId = self.session_id,
            Id = name,
            DocumentId = document_id,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok("").serialize(response))
    }
}
