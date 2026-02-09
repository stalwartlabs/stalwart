/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::network::SessionStream;
use imap_proto::receiver::Request;
use registry::schema::enums::Permission;
use trc::AddContext;

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_havespace(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
        // Validate access
        self.assert_has_permission(Permission::SieveHaveSpace)?;

        let op_start = Instant::now();
        let mut tokens = request.tokens.into_iter();
        let name = tokens
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Expected script name as a parameter.")
            })?;
        let size: usize = tokens
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Expected script size as a parameter.")
            })?
            .parse::<usize>()
            .map_err(|_| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Invalid size parameter.")
            })?;

        // Validate name
        let account_id = self.state.access_token().account_id();
        let account = self.server.account(account_id).await?;
        self.validate_name(account_id, &name).await?;

        // Validate quota
        if account.disk_quota() == 0
            || size as i64
                + self
                    .server
                    .get_used_quota_account(account_id)
                    .await
                    .caused_by(trc::location!())?
                <= account.disk_quota() as i64
        {
            trc::event!(
                ManageSieve(trc::ManageSieveEvent::HaveSpace),
                SpanId = self.session_id,
                Size = size,
                Elapsed = op_start.elapsed()
            );

            Ok(StatusResponse::ok("").into_bytes())
        } else {
            Err(trc::ManageSieveEvent::Error
                .into_err()
                .details("Quota exceeded.")
                .code(ResponseCode::QuotaMaxSize))
        }
    }
}
