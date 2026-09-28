/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use encodify::{base32::STALWART, base64::URL_SAFE_NO_PAD};
use store::{
    U32_LEN,
    rand::{self},
};

pub struct ApiKey {
    pub account_id: u32,
    pub credential_id: u32,
    pub secret: [u8; 20],
}

const API_KEY_LEN: usize = U32_LEN * 2 + 20;

pub struct AppPassword {
    pub credential_id: u32,
    pub secret: [u8; 18],
}

impl ApiKey {
    pub fn new(account_id: u32, credential_id: u32) -> Self {
        ApiKey {
            account_id,
            credential_id,
            secret: rand::random::<[u8; 20]>(),
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        let mut decoded = [0u8; API_KEY_LEN];
        URL_SAFE_NO_PAD
            .decode_slice(token.strip_prefix("API_")?, &mut decoded)
            .ok()
            .filter(|&len| len == API_KEY_LEN)?;

        Some(ApiKey {
            account_id: u32::from_be_bytes(decoded.get(0..U32_LEN)?.try_into().ok()?),
            credential_id: u32::from_be_bytes(decoded.get(U32_LEN..U32_LEN * 2)?.try_into().ok()?),
            secret: decoded.get(U32_LEN * 2..)?.try_into().ok()?,
        })
    }

    pub fn build(&self) -> String {
        let mut bytes = Vec::with_capacity(API_KEY_LEN);
        bytes.extend_from_slice(&self.account_id.to_be_bytes());
        bytes.extend_from_slice(&self.credential_id.to_be_bytes());
        bytes.extend_from_slice(&self.secret);
        let mut token = String::from("API_");
        URL_SAFE_NO_PAD.encode_append(bytes, &mut token);
        token
    }
}

impl AppPassword {
    pub fn new(credential_id: u32) -> Self {
        AppPassword {
            credential_id,
            secret: rand::random::<[u8; 18]>(),
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        let token = token.strip_prefix("app")?;
        let mut reader = STALWART.decoder(token.as_bytes().get(1..)?);
        let mut credential_id = [0u8; 4];
        let mut secret = [0u8; 18];

        for byte in credential_id.iter_mut() {
            *byte = reader.next()?;
        }

        for byte in secret.iter_mut() {
            *byte = reader.next()?;
        }

        if reader.next().is_none() {
            Some(AppPassword {
                credential_id: u32::from_be_bytes(credential_id),
                secret,
            })
        } else {
            None
        }
    }

    pub fn build(&self) -> String {
        let mut token = String::from("app_");
        let mut encoder = STALWART.encoder(&mut token);
        encoder.push(&self.credential_id.to_be_bytes());
        encoder.push(&self.secret);
        encoder.finish();
        token
    }
}
