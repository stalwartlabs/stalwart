/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Account, Credentials, Directory, Recipient};
use trc::AddContext;

impl Directory {
    pub async fn authenticate(&self, credentials: &Credentials) -> trc::Result<Option<Account>> {
        match &self {
            Directory::Ldap(store) => store.authenticate(credentials).await,
            Directory::Sql(store) => store.authenticate(credentials).await,
            Directory::OpenId(store) => store.authenticate(credentials).await,
        }
        .caused_by(trc::location!())
    }

    pub async fn recipient(&self, address: &str) -> trc::Result<Recipient> {
        match &self {
            Directory::Ldap(store) => store.recipient(address).await,
            Directory::Sql(store) => store.recipient(address).await,
            Directory::OpenId(_) => Ok(Recipient::Invalid), // OIDC directories do not support recipient lookups
        }
        .caused_by(trc::location!())
    }

    pub fn has_bearer_token_support(&self) -> bool {
        matches!(self, Directory::OpenId(_))
    }

    pub fn can_lookup_recipients(&self) -> bool {
        !matches!(self, Directory::OpenId(_))
    }
}
