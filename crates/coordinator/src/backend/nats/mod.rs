/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use crate::Coordinator;
use async_nats::Client;
use registry::schema::structs::NatsCoordinator;

pub mod pubsub;

#[derive(Debug)]
pub struct NatsPubSub {
    client: Client,
}

impl NatsPubSub {
    pub async fn open(config: NatsCoordinator) -> Result<Coordinator, String> {
        if config.addresses.is_empty() {
            return Err("No Nats addresses specified".to_string());
        }

        let mut opts = async_nats::ConnectOptions::new()
            .max_reconnects(config.max_reconnects.map(|v| v as usize))
            .connection_timeout(config.timeout_connection.into_inner())
            .request_timeout(config.timeout_request.into_inner().into())
            .ping_interval(config.ping_interval.into_inner())
            .client_capacity(config.capacity_client as usize)
            .subscription_capacity(config.capacity_subscription as usize)
            .read_buffer_capacity(config.capacity_read_buffer as u16)
            .require_tls(config.use_tls);

        if config.no_echo {
            opts = opts.no_echo();
        }

        if let (Some(user), Some(pass)) = (config.auth_username, config.auth_secret) {
            opts = opts.user_and_password(user.to_string(), pass.to_string());
        } else if let Some(credentials) = config.credentials {
            opts = opts
                .credentials(&credentials)
                .map_err(|err| format!("Failed to parse Nats credentials: {}", err))?;
        }

        async_nats::connect_with_options(config.addresses, opts)
            .await
            .map(|client| Coordinator::Nats(Arc::new(NatsPubSub { client })))
            .map_err(|err| format!("Failed to connect to Nats: {}", err))
    }
}
