/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::{AccountCache, DomainCache, EmailCache, RoleCache, TenantCache},
    config::smtp::auth::DkimSigner,
};
use std::sync::Arc;

impl Server {
    pub async fn domain(&self, domain: &str) -> trc::Result<Option<Arc<DomainCache>>> {
        todo!()
    }

    pub async fn email(&self, address: &str) -> trc::Result<Option<EmailCache>> {
        todo!()
    }

    pub async fn account(&self, id: u32) -> trc::Result<Arc<AccountCache>> {
        /*

        Err(trc::AuthEvent::Error
                .into_err()
                .details("Account not found.")
                .caused_by(trc::location!()))
         */
        todo!()
    }

    pub async fn role(&self, id: u32) -> trc::Result<Arc<RoleCache>> {
        todo!()
    }

    pub async fn tenant(&self, id: u32) -> trc::Result<Arc<TenantCache>> {
        todo!()
    }

    pub async fn dkim_signers(&self, domain: &str) -> trc::Result<Option<Arc<[DkimSigner]>>> {
        todo!()
    }
}
