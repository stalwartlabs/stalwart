/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::listener::SessionStream;
use directory::Permission;
use imap_proto::receiver::Request;
use store::{SerializeInfallible, write::BatchBuilder};
use trc::AddContext;
use types::{collection::Collection, field::PrincipalField};

use crate::core::{Command, Session, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_setactive(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
        // Validate access
        self.assert_has_permission(Permission::SieveSetActive)?;

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

        // De/activate script
        let account_id = self.state.access_token().primary_id();
        let mut batch = BatchBuilder::new();
        if !name.is_empty() {
            let document_id = self.get_script_id(account_id, &name).await?;
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .set(PrincipalField::ActiveScriptId, document_id.serialize());
        } else {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .clear(PrincipalField::ActiveScriptId);
        }
        self.server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;

        trc::event!(
            ManageSieve(trc::ManageSieveEvent::SetActive),
            SpanId = self.session_id,
            Id = name,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok("Success").into_bytes())
    }
}
