/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::request::capability::{
    Account, Capabilities, Capability, EmptyCapabilities, PrincipalOwnerCapabilities, Session,
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

pub trait JmapAccount {
    fn jmap_account(&self, access_token: &AccessToken, account_id: u32, name: String) -> Account;

    fn jmap_account_capabilities(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Iterator<Item = (Capability, Capabilities)>;
}

impl JmapAccount for Server {
    fn jmap_account(&self, access_token: &AccessToken, account_id: u32, name: String) -> Account {
        let mut account_capabilities =
            VecMap::with_capacity(self.core.jmap.capabilities.account.len() + 1);
        account_capabilities.extend(self.jmap_account_capabilities(access_token, account_id));
        account_capabilities.append(
            Capability::PrincipalsOwner,
            Capabilities::PrincipalsOwner(PrincipalOwnerCapabilities {
                account_id_for_principal: Id::from(access_token.account_id()),
                principal_id: Id::from(account_id),
            }),
        );
        Account {
            name,
            is_personal: account_id == access_token.account_id(),
            is_read_only: access_token.is_read_only(account_id),
            account_capabilities,
        }
    }

    fn jmap_account_capabilities(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Iterator<Item = (Capability, Capabilities)> {
        let account_capabilities = &self.core.jmap.capabilities.account;
        let is_owner = access_token.is_member(account_id);
        let current_user_principal_id = Some(Id::from(access_token.account_id()));
        access_token
            .account_capabilities()
            .filter(move |capability| {
                is_owner
                    || !matches!(
                        capability,
                        Capability::Submission
                            | Capability::VacationResponse
                            | Capability::Sieve
                            | Capability::Quota
                            | Capability::EmailPush
                    )
            })
            .map(move |capability| {
                (
                    capability,
                    account_capabilities
                        .get(&capability)
                        .map(|v| v.to_account_capabilities(current_user_principal_id, is_owner))
                        .unwrap_or_else(|| Capabilities::Empty(EmptyCapabilities::default())),
                )
            })
    }
}

impl SessionHandler for Server {
    async fn handle_session_resource(
        &self,
        base_url: String,
        access_token: &AccessToken,
    ) -> trc::Result<Session> {
        let mut session = Session::new(base_url, &self.core.jmap.capabilities);
        session.set_state(access_token.state());

        // Set primary account
        let account = self
            .account(access_token.account_id())
            .await
            .caused_by(trc::location!())?;
        session.username = account.name().to_string();
        let account_id = Id::from(access_token.account_id());
        for capability in access_token.account_capabilities() {
            session.primary_accounts.append(capability, account_id);
        }
        session.accounts.append(
            account_id,
            self.jmap_account(
                access_token,
                access_token.account_id(),
                account.name().to_string(),
            ),
        );

        // Add secondary accounts
        for &account_id in access_token.secondary_ids() {
            let Some(account) = self
                .try_account(account_id)
                .await
                .caused_by(trc::location!())?
            else {
                trc::event!(
                    Auth(trc::AuthEvent::Warning),
                    AccountId = account_id,
                    Reason = "Skipping orphan secondary account id in session",
                );
                continue;
            };
            session.accounts.append(
                Id::from(account_id),
                self.jmap_account(access_token, account_id, account.name().to_string()),
            );
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
                    Capability::Mail | Capability::MailShare | Capability::EmailPush => {
                        Permission::JmapEmailGet
                    }
                    Capability::Submission => Permission::JmapEmailSubmissionCreate,
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
                    | Capability::PrincipalsAvailability
                    | Capability::Stalwart => return true,
                    Capability::Core | Capability::PrincipalsOwner | Capability::WebPushVapid => {
                        return false;
                    }
                };
                self.has_permission(permission)
            })
            .copied()
    }
}
