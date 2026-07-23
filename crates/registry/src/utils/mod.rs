/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::schema::prelude::{DkimSignature, Roles, SecretText};
use types::id::Id;

pub mod account;
pub mod archived_item;
pub mod cron;
pub mod dkim;
pub mod http;
pub mod report;
pub mod secret;
pub mod task;

impl Roles {
    pub fn role_ids(&self) -> Option<&[Id]> {
        match self {
            Roles::Default => None,
            Roles::Custom(custom_roles) => Some(custom_roles.role_ids.as_slice()),
        }
    }
}

impl DkimSignature {
    pub fn private_key(&self) -> &SecretText {
        match self {
            DkimSignature::Dkim1Ed25519Sha256(signature) => &signature.private_key,
            DkimSignature::Dkim1RsaSha256(signature) => &signature.private_key,
            DkimSignature::Dkim2Ed25519Sha256(signature) => &signature.private_key,
            DkimSignature::Dkim2RsaSha256(signature) => &signature.private_key,
        }
    }

    pub fn private_key_mut(&mut self) -> &mut SecretText {
        match self {
            DkimSignature::Dkim1Ed25519Sha256(signature) => &mut signature.private_key,
            DkimSignature::Dkim1RsaSha256(signature) => &mut signature.private_key,
            DkimSignature::Dkim2Ed25519Sha256(signature) => &mut signature.private_key,
            DkimSignature::Dkim2RsaSha256(signature) => &mut signature.private_key,
        }
    }
}
