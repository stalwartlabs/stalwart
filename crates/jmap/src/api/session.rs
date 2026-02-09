/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::request::capability::{
    Account, Capabilities, Capability, EmptyCapabilities, Session,
};
use registry::schema::enums::Permission;
use std::future::Future;
use trc::AddContext;
use types::id::Id;
use utils::map::vec_map::VecMap;

pub trait SessionHandler: Sync + Send {
    fn handle_session_resource(
        &self,
        base_url: String,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<Session>> + Send;
}

impl SessionHandler for Server {
    async fn handle_session_resource(
        &self,
        base_url: String,
        access_token: &AccessToken,
    ) -> trc::Result<Session> {
        let mut session = Session::new(base_url, &self.core.jmap.capabilities);
        session.set_state(access_token.state());
        let account_capabilities = &self.core.jmap.capabilities.account;

        // Set primary account
        let account = self
            .account(access_token.account_id())
            .await
            .caused_by(trc::location!())?;
        session.username = account.name().to_string();
        let account_id = Id::from(access_token.account_id());
        let mut account = Account {
            name: account.name().to_string(),
            is_personal: true,
            is_read_only: false,
            account_capabilities: VecMap::with_capacity(account_capabilities.len()),
        };
        for capability in access_token.account_capabilities() {
            session.primary_accounts.append(capability, account_id);
            account.account_capabilities.append(
                capability,
                account_capabilities
                    .get(&capability)
                    .map(|v| v.to_account_capabilities(account_id.into(), true))
                    .unwrap_or_else(|| Capabilities::Empty(EmptyCapabilities::default())),
            );
        }
        session.accounts.append(account_id, account);

        // Add secondary accounts
        for &account_id in access_token.secondary_ids() {
            let is_owner = access_token.is_member(account_id);
            let account = self.account(account_id).await.caused_by(trc::location!())?;

            let account_id = Id::from(account_id);
            let mut account = Account {
                name: account.name().to_string(),
                is_personal: false,
                is_read_only: false,
                account_capabilities: VecMap::with_capacity(account_capabilities.len()),
            };
            for capability in access_token.account_capabilities() {
                account.account_capabilities.append(
                    capability,
                    account_capabilities
                        .get(&capability)
                        .map(|v| v.to_account_capabilities(account_id.into(), is_owner))
                        .unwrap_or_else(|| Capabilities::Empty(EmptyCapabilities::default())),
                );
            }
            session.accounts.append(account_id, account);
        }

        Ok(session)
    }
}

trait AccountCapabilities {
    fn account_capabilities(&self) -> impl Iterator<Item = Capability>;
}

impl AccountCapabilities for AccessToken {
    fn account_capabilities(&self) -> impl Iterator<Item = Capability> {
        Capability::all_capabilities()
            .iter()
            .filter(move |capability| {
                let permission = match capability {
                    Capability::Mail => Permission::JmapEmailGet,
                    Capability::Submission => Permission::JmapEmailSubmissionSet,
                    Capability::VacationResponse => Permission::JmapVacationResponseGet,
                    Capability::Contacts => Permission::JmapContactCardGet,
                    Capability::ContactsParse => Permission::JmapContactCardParse,
                    Capability::Calendars => Permission::JmapCalendarEventGet,
                    Capability::CalendarsParse => Permission::JmapCalendarEventParse,
                    Capability::Sieve => Permission::JmapSieveScriptGet,
                    Capability::Blob => Permission::JmapBlobGet,
                    Capability::Quota => Permission::JmapQuotaGet,
                    Capability::FileNode => Permission::JmapFileNodeGet,
                    Capability::WebSocket
                    | Capability::Principals
                    | Capability::PrincipalsAvailability => return true,
                    Capability::Core | Capability::PrincipalsOwner => return false,
                };
                self.has_permission(permission)
            })
            .copied()
    }
}
