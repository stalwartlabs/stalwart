/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::LdapConnectionManager;
use deadpool::managed;
use ldap3::{Ldap, LdapConnAsync, LdapError, exop::WhoAmI};
use std::time::Duration;

const RECYCLE_PROBE_AFTER_IDLE: Duration = Duration::from_secs(5);

impl managed::Manager for LdapConnectionManager {
    type Type = Ldap;
    type Error = LdapError;

    async fn create(&self) -> Result<Ldap, LdapError> {
        let (conn, mut ldap) =
            LdapConnAsync::with_settings(self.settings.clone(), &self.address).await?;

        ldap3::drive!(conn);

        if let Some(bind) = &self.bind_dn {
            ldap.simple_bind(&bind.dn, &bind.password)
                .await?
                .success()?;
        }

        Ok(ldap)
    }

    async fn recycle(
        &self,
        conn: &mut Ldap,
        metrics: &managed::Metrics,
    ) -> managed::RecycleResult<LdapError> {
        if conn.is_closed() {
            Err(managed::RecycleError::message("LDAP connection closed"))
        } else if metrics.last_used() < RECYCLE_PROBE_AFTER_IDLE {
            Ok(())
        } else {
            conn.extended(WhoAmI)
                .await
                .map(|_| ())
                .map_err(managed::RecycleError::Backend)
        }
    }
}
