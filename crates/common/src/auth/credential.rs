/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::io::Write;
use store::{
    U32_LEN,
    rand::{self},
};
use utils::codec::base32_custom::{Base32Reader, Base32Writer};

pub struct ApiKey {
    pub account_id: u32,
    pub credential_id: u32,
    pub secret: [u8; 20],
}

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
        let decoded = URL_SAFE_NO_PAD.decode(token.strip_prefix("API_")?).ok()?;

        Some(ApiKey {
            account_id: u32::from_be_bytes(decoded.get(0..U32_LEN)?.try_into().ok()?),
            credential_id: u32::from_be_bytes(decoded.get(U32_LEN..U32_LEN * 2)?.try_into().ok()?),
            secret: decoded.get(U32_LEN * 2..)?.try_into().ok()?,
        })
    }

    pub fn build(&self) -> String {
        let mut bytes = Vec::with_capacity(U32_LEN * 2 + self.secret.len());
        bytes.extend_from_slice(&self.account_id.to_be_bytes());
        bytes.extend_from_slice(&self.credential_id.to_be_bytes());
        bytes.extend_from_slice(&self.secret);
        format!("API_{}", URL_SAFE_NO_PAD.encode(bytes))
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
        let token = token.strip_prefix("app ")?;
        let mut reader = Base32Reader::new(token.as_bytes());
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
        let mut writer = Base32Writer::with_capacity(std::mem::size_of::<Self>().div_ceil(5) * 8);
        writer.push_string("app ");
        let _ = writer.write(&self.credential_id.to_be_bytes());
        let _ = writer.write_all(&self.secret);
        writer.finalize()
    }
}
