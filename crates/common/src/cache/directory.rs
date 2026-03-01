/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use crate::{Server, auth::DomainCache};
use registry::{
    schema::{
        prelude::{Object, ObjectType},
        structs::{Account, EmailAlias, GroupAccount, Roles, UserAccount},
    },
    types::{datetime::UTCDateTime, id::ObjectId},
};
use store::registry::write::{RegistryWrite, RegistryWriteResult};
use trc::AddContext;
use types::id::Id;

pub(crate) struct AccountWithId {
    pub id: u32,
    pub account: Account,
}

impl Server {
    pub(crate) async fn synchronize_account(
        &self,
        account: directory::Account,
    ) -> trc::Result<AccountWithId> {
        let (local, domain) = self.validate_address(&account.email).await?;
        match self
            .account_id_from_parts(local, domain.id)
            .await
            .caused_by(trc::location!())?
        {
            Some(account_id) => {
                let current_account = self
                    .registry()
                    .get(ObjectId::new(ObjectType::Account, account_id.into()))
                    .await
                    .caused_by(trc::location!())?
                    .ok_or_else(|| {
                        trc::AuthEvent::Error
                            .into_err()
                            .details("Account ID from directory does not exist in registry")
                            .ctx(trc::Key::AccountName, account.email.clone())
                            .ctx(trc::Key::AccountId, account_id)
                    })?;
                let mut updated_account = Account::from(current_account.clone())
                    .into_user()
                    .ok_or_else(|| {
                        trc::AuthEvent::Error
                            .into_err()
                            .details(
                                "Account ID from directory does not correspond to a user account",
                            )
                            .ctx(trc::Key::AccountName, account.email.clone())
                            .ctx(trc::Key::AccountId, account_id)
                    })?;
                let mut has_changes = false;
                if let Some(secret) = account.secret
                    && secret != updated_account.secret
                {
                    has_changes = true;
                    updated_account.secret = secret;
                }
                if account.description.is_some()
                    && account.description != updated_account.description
                {
                    updated_account.description = account.description;
                    has_changes = true;
                }
                for alias in account.email_aliases {
                    if let Some((local, alias_domain)) = self.validate_alias(&alias).await?
                        && alias_domain.id_tenant == domain.id_tenant
                        && self
                            .rcpt_id_from_parts(local, alias_domain.id)
                            .await?
                            .is_none()
                    {
                        updated_account.aliases.push(EmailAlias {
                            name: local.to_string(),
                            domain_id: Id::from(alias_domain.id),
                            enabled: true,
                            description: None,
                        });
                        has_changes = true;
                    }
                }
                let mut member_group_ids = Vec::with_capacity(account.groups.len());
                for email in account.groups {
                    member_group_ids.push(
                        self.synchronize_group(directory::Group {
                            email,
                            ..Default::default()
                        })
                        .await
                        .caused_by(trc::location!())?
                        .into(),
                    );
                }
                if !member_group_ids.is_empty()
                    && ((updated_account.member_group_ids.len() != member_group_ids.len())
                        || !updated_account
                            .member_group_ids
                            .iter()
                            .all(|id| member_group_ids.contains(id)))
                {
                    updated_account.member_group_ids = member_group_ids;
                    has_changes = true;
                }

                if has_changes {
                    let updated_account = Object::from(Account::User(updated_account));
                    match self
                        .registry()
                        .write(RegistryWrite::update(
                            Id::from(account_id),
                            &updated_account,
                            &current_account,
                        ))
                        .await
                        .caused_by(trc::location!())?
                    {
                        RegistryWriteResult::Success(id) => Ok(AccountWithId {
                            id: id.document_id(),
                            account: updated_account.into(),
                        }),
                        failure => Err(trc::AuthEvent::Error
                            .into_err()
                            .caused_by(trc::location!())
                            .details("Failed to synchronize account with directory")
                            .reason(failure)),
                    }
                } else {
                    Ok(AccountWithId {
                        id: account_id,
                        account: Account::User(updated_account),
                    })
                }
            }
            None => {
                let mut aliases = Vec::with_capacity(account.email_aliases.len());
                for alias in account.email_aliases {
                    if let Some((local, alias_domain)) = self.validate_alias(&alias).await?
                        && alias_domain.id_tenant == domain.id_tenant
                        && self
                            .rcpt_id_from_parts(local, alias_domain.id)
                            .await?
                            .is_none()
                    {
                        aliases.push(EmailAlias {
                            name: local.to_string(),
                            domain_id: Id::from(alias_domain.id),
                            enabled: true,
                            description: None,
                        });
                    }
                }
                let mut member_group_ids = Vec::with_capacity(account.groups.len());
                for email in account.groups {
                    member_group_ids.push(
                        self.synchronize_group(directory::Group {
                            email,
                            ..Default::default()
                        })
                        .await
                        .caused_by(trc::location!())?
                        .into(),
                    );
                }
                let account = Object::from(Account::User(UserAccount {
                    name: local.to_string(),
                    domain_id: Id::from(domain.id),
                    aliases,
                    created_at: UTCDateTime::now(),
                    description: account.description,
                    member_group_ids,
                    member_tenant_id: domain.id_tenant.map(Id::from),
                    roles: Roles::Default,
                    secret: account.secret.unwrap_or_default(),
                    ..Default::default()
                }));

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                if self.core.is_enterprise_edition() && !self.can_create_account().await? {
                    return Err(trc::AuthEvent::Error.into_err().details(
                        "Account creation not possible: license key account limit reached",
                    ));
                }
                // SPDX-SnippetEnd

                match self
                    .registry()
                    .write(RegistryWrite::insert(&account))
                    .await
                    .caused_by(trc::location!())?
                {
                    RegistryWriteResult::Success(id) => Ok(AccountWithId {
                        id: id.document_id(),
                        account: account.into(),
                    }),
                    failure => Err(trc::AuthEvent::Error
                        .into_err()
                        .caused_by(trc::location!())
                        .details("Failed to create account from directory")
                        .reason(failure)),
                }
            }
        }
    }

    pub(crate) async fn synchronize_group(&self, group: directory::Group) -> trc::Result<u32> {
        let (local, domain) = self.validate_address(&group.email).await?;

        match self
            .account_id_from_parts(local, domain.id)
            .await
            .caused_by(trc::location!())?
        {
            Some(account_id) => {
                let current_account = self
                    .registry()
                    .get(ObjectId::new(ObjectType::Account, account_id.into()))
                    .await
                    .caused_by(trc::location!())?
                    .ok_or_else(|| {
                        trc::AuthEvent::Error
                            .into_err()
                            .details("Account ID from directory does not exist in registry")
                            .ctx(trc::Key::AccountName, group.email.clone())
                            .ctx(trc::Key::AccountId, account_id)
                    })?;
                let mut updated_account = Account::from(current_account.clone())
                    .into_group()
                    .ok_or_else(|| {
                        trc::AuthEvent::Error
                            .into_err()
                            .details(
                                "Account ID from directory does not correspond to a group account",
                            )
                            .ctx(trc::Key::AccountName, group.email.clone())
                            .ctx(trc::Key::AccountId, account_id)
                    })?;
                let mut has_changes = false;
                if group.description.is_some() && group.description != updated_account.description {
                    updated_account.description = group.description;
                    has_changes = true;
                }
                for alias in group.email_aliases {
                    if let Some((local, alias_domain)) = self.validate_alias(&alias).await?
                        && alias_domain.id_tenant == domain.id_tenant
                        && self
                            .rcpt_id_from_parts(local, alias_domain.id)
                            .await?
                            .is_none()
                    {
                        updated_account.aliases.push(EmailAlias {
                            name: local.to_string(),
                            domain_id: Id::from(alias_domain.id),
                            enabled: true,
                            description: None,
                        });
                        has_changes = true;
                    }
                }

                if has_changes {
                    match self
                        .registry()
                        .write(RegistryWrite::update(
                            Id::from(account_id),
                            &Object::from(Account::Group(updated_account)),
                            &current_account,
                        ))
                        .await
                        .caused_by(trc::location!())?
                    {
                        RegistryWriteResult::Success(id) => Ok(id.document_id()),
                        failure => Err(trc::AuthEvent::Error
                            .into_err()
                            .caused_by(trc::location!())
                            .details("Failed to synchronize account with directory")
                            .reason(failure)),
                    }
                } else {
                    Ok(account_id)
                }
            }
            None => {
                let mut aliases = Vec::with_capacity(group.email_aliases.len());
                for alias in group.email_aliases {
                    if let Some((local, alias_domain)) = self.validate_alias(&alias).await?
                        && alias_domain.id_tenant == domain.id_tenant
                        && self
                            .rcpt_id_from_parts(local, alias_domain.id)
                            .await?
                            .is_none()
                    {
                        aliases.push(EmailAlias {
                            name: local.to_string(),
                            domain_id: Id::from(alias_domain.id),
                            enabled: true,
                            description: None,
                        });
                    }
                }

                let account = Object::from(Account::Group(GroupAccount {
                    name: local.to_string(),
                    domain_id: Id::from(domain.id),
                    aliases,
                    created_at: UTCDateTime::now(),
                    description: group.description,
                    member_tenant_id: domain.id_tenant.map(Id::from),
                    roles: Roles::Default,
                    ..Default::default()
                }));

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                if self.core.is_enterprise_edition() && !self.can_create_account().await? {
                    return Err(trc::AuthEvent::Error.into_err().details(
                        "Account creation not possible: license key account limit reached",
                    ));
                }
                // SPDX-SnippetEnd

                match self
                    .registry()
                    .write(RegistryWrite::insert(&account))
                    .await
                    .caused_by(trc::location!())?
                {
                    RegistryWriteResult::Success(id) => Ok(id.document_id()),
                    failure => Err(trc::AuthEvent::Error
                        .into_err()
                        .caused_by(trc::location!())
                        .details("Failed to create account from directory")
                        .reason(failure)),
                }
            }
        }
    }

    async fn validate_address<'x>(
        &self,
        email: &'x str,
    ) -> trc::Result<(&'x str, Arc<DomainCache>)> {
        if email.is_empty() {
            return Err(trc::AuthEvent::Error
                .into_err()
                .details("Account email cannot be empty"));
        }
        match email.rsplit_once('@') {
            Some((local, domain)) => self
                .domain(domain)
                .await
                .caused_by(trc::location!())?
                .map(|domain| (local, domain))
                .ok_or_else(|| {
                    trc::AuthEvent::Error
                        .into_err()
                        .details("Account domain does not exist or has been disabled")
                        .ctx(trc::Key::Domain, domain.to_string())
                }),
            None => {
                trc::event!(
                    Auth(trc::AuthEvent::Warning),
                    AccountName = email.to_string().clone(),
                    Details = "Directory account is not an email, appended default domain",
                );
                self.domain_by_id(self.core.email.default_domain_id)
                    .await
                    .caused_by(trc::location!())?
                    .ok_or_else(|| {
                        trc::AuthEvent::Error
                            .into_err()
                            .details("Default domain does not exist or has been disabled")
                            .ctx(trc::Key::Id, self.core.email.default_domain_id)
                    })
                    .map(|domain| (email, domain))
            }
        }
    }

    async fn validate_alias<'x>(
        &self,
        email: &'x str,
    ) -> trc::Result<Option<(&'x str, Arc<DomainCache>)>> {
        match email.rsplit_once('@') {
            Some((local, domain)) => self
                .domain(domain)
                .await
                .caused_by(trc::location!())
                .map(|domain| domain.map(|domain| (local, domain))),
            None => Ok(None),
        }
    }
}
