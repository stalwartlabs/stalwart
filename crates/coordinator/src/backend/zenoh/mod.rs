/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::schema::structs::ZenohCoordinator;

use crate::Coordinator;
pub mod pubsub;

#[derive(Debug)]
pub struct ZenohPubSub {
    session: zenoh::Session,
}

impl ZenohPubSub {
    pub async fn open(config: ZenohCoordinator) -> Result<Coordinator, String> {
        let zenoh_config = zenoh::Config::from_json5(&config.config)
            .map_err(|err| format!("Invalid Zenoh config: {}", err))?;
        zenoh::open(zenoh_config)
            .await
            .map_err(|err| format!("Failed to create Zenoh session: {}", err))
            .map(|session| ZenohPubSub { session })
            .map(|store| Coordinator::Zenoh(std::sync::Arc::new(store)))
    }
}
