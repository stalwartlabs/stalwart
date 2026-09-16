/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use std::sync::LazyLock;

use imap_proto::{ResponseCode, StatusResponse, protocol::capability::Capability};

pub mod core;
pub mod op;

static SERVER_GREETING: &str = "Stalwart IMAP4rev2 at your service.";

pub(crate) static GREETING_WITH_TLS: LazyLock<Vec<u8>> =
    LazyLock::new(|| build_greeting(true, true));

pub(crate) static GREETING_WITH_TLS_LOGIN_DISABLED: LazyLock<Vec<u8>> =
    LazyLock::new(|| build_greeting(true, false));

pub(crate) static GREETING_WITHOUT_TLS: LazyLock<Vec<u8>> =
    LazyLock::new(|| build_greeting(false, true));

pub(crate) static GREETING_WITHOUT_TLS_LOGIN_DISABLED: LazyLock<Vec<u8>> =
    LazyLock::new(|| build_greeting(false, false));

fn build_greeting(offer_tls: bool, allow_auth: bool) -> Vec<u8> {
    StatusResponse::ok(SERVER_GREETING)
        .with_code(ResponseCode::Capability {
            capabilities: Capability::all_capabilities(false, offer_tls, allow_auth, 0, 0),
        })
        .into_bytes()
}

pub struct ImapError;
