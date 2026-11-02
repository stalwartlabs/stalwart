/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::Session;
use common::network::SessionStream;
use compact_str::format_compact;
use imap_proto::{
    Command, StatusResponse,
    protocol::{ProtocolVersion, capability::Capability, enable},
    receiver::Request,
};
use registry::schema::enums::Permission;
use std::{mem::replace, time::Instant};

impl<T: SessionStream> Session<T> {
    pub async fn handle_enable(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapEnable)?;

        let op_start = Instant::now();

        let arguments = request.parse_enable()?;
        let mut response = enable::Response {
            enabled: Vec::with_capacity(arguments.capabilities.len()),
        };

        for capability in arguments.capabilities {
            let newly_enabled = match capability {
                Capability::IMAP4rev2 => {
                    self.is_utf8 = true;
                    replace(&mut self.version, ProtocolVersion::Rev2) != ProtocolVersion::Rev2
                }
                Capability::IMAP4rev1 => {
                    replace(&mut self.version, ProtocolVersion::Rev1) != ProtocolVersion::Rev1
                }
                Capability::CondStore => !replace(&mut self.is_condstore, true),
                Capability::QResync => {
                    self.is_condstore = true;
                    !replace(&mut self.is_qresync, true)
                }
                Capability::Utf8Accept => !replace(&mut self.is_utf8, true),
                Capability::ObjectIdPlus => !replace(&mut self.is_objectid, true),
                Capability::UidOnly => {
                    self.client.allows_uid_only() && !replace(&mut self.is_uidonly, true)
                }
                _ => false,
            };
            if newly_enabled {
                response.enabled.push(capability);
            }
        }

        trc::event!(
            Imap(trc::ImapEvent::Enable),
            SpanId = self.session_id,
            Details = response
                .enabled
                .iter()
                .map(|c| trc::Value::from(format_compact!("{c:?}")))
                .collect::<Vec<_>>(),
            Elapsed = op_start.elapsed()
        );

        self.write_bytes(
            StatusResponse::ok("ENABLE successful.")
                .with_tag(arguments.tag)
                .serialize_after(&response),
        )
        .await
    }
}
