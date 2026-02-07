/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{LdapDirectory, LdapMappings};
use crate::{
    Account, Credentials, Group, IntoError, Recipient, backend::ldap::AuthBind,
    core::secret::verify_secret_hash,
};
use ldap3::{Ldap, LdapConnAsync, ResultEntry, Scope, SearchEntry};
use store::xxhash_rust;
use utils::sanitize_email;

impl LdapDirectory {
    pub async fn authenticate(&self, credentials: &Credentials) -> trc::Result<Account> {
        let (username, secret) = match credentials {
            Credentials::Basic { username, secret } => (username, secret),
            Credentials::Bearer { token, .. } => (token, token),
        };
        let mut conn = self.pool.get().await.map_err(|err| err.into_error())?;

        let mut account = match &self.auth_bind {
            AuthBind::BindTemplate {
                template,
                can_search,
            } => {
                let (auth_bind_conn, mut ldap) = LdapConnAsync::with_settings(
                    self.pool.manager().settings.clone(),
                    &self.pool.manager().address,
                )
                .await
                .map_err(|err| err.into_error().caused_by(trc::location!()))?;

                ldap3::drive!(auth_bind_conn);

                let dn = template.build(username);

                if ldap
                    .simple_bind(&dn, secret)
                    .await
                    .map_err(|err| err.into_error().caused_by(trc::location!()))?
                    .success()
                    .is_err()
                {
                    return Err(trc::AuthEvent::Failed
                        .into_err()
                        .details("Invalid credentials for auth bind using template")
                        .details(dn));
                }

                let filter = self.mappings.filter_login.build(username);
                let result = if *can_search {
                    self.find_object(&mut ldap, &filter).await
                } else {
                    self.find_object(&mut conn, &filter).await
                };

                match result {
                    Ok(Some(mut result)) => {
                        if result.account.email.is_empty() {
                            result.account.email = username.into();
                        }
                        result.account
                    }
                    Err(err)
                        if err.matches(trc::EventType::Store(trc::StoreEvent::LdapError))
                            && err
                                .value(trc::Key::Code)
                                .and_then(|v| v.to_uint())
                                .is_some_and(|rc| [49, 50].contains(&rc)) =>
                    {
                        return Err(trc::AuthEvent::Failed
                            .into_err()
                            .details("Error codes 49 or 50 returned by LDAP server")
                            .details(vec![dn, filter]));
                    }
                    Ok(None) => {
                        return Err(trc::AuthEvent::Failed
                            .into_err()
                            .details("Auth bind successful but filter yielded no results")
                            .details(vec![dn, filter]));
                    }
                    Err(err) => return Err(err),
                }
            }
            AuthBind::Bind => {
                let filter = self.mappings.filter_login.build(username);
                if let Some(mut result) = self.find_object(&mut conn, &filter).await? {
                    // Perform bind auth using the found dn
                    let (auth_bind_conn, mut ldap) = LdapConnAsync::with_settings(
                        self.pool.manager().settings.clone(),
                        &self.pool.manager().address,
                    )
                    .await
                    .map_err(|err| err.into_error().caused_by(trc::location!()))?;

                    ldap3::drive!(auth_bind_conn);

                    if ldap
                        .simple_bind(&result.dn, secret)
                        .await
                        .map_err(|err| err.into_error().caused_by(trc::location!()))?
                        .success()
                        .is_ok()
                    {
                        if result.account.email.is_empty() {
                            result.account.email = username.into();
                        }
                        result.account
                    } else {
                        return Err(trc::AuthEvent::Failed
                            .into_err()
                            .details("Secret rejected during auth bind using lookup filter")
                            .details(vec![result.dn, filter]));
                    }
                } else {
                    return Err(trc::AuthEvent::Failed
                        .into_err()
                        .details("Auth bind lookup filter yielded no results")
                        .details(vec![filter]));
                }
            }
            AuthBind::None => {
                let filter = self.mappings.filter_login.build(username);
                if let Some(result) = self.find_object(&mut conn, &filter).await? {
                    if let Some(account_secret) = &result.account.secret {
                        if !verify_secret_hash(account_secret, secret.as_bytes()).await? {
                            return Err(trc::AuthEvent::Failed
                                .into_err()
                                .details("Invalid credentials")
                                .details(vec![filter]));
                        }
                    } else {
                        return Err(trc::AuthEvent::Error
                            .into_err()
                            .details("Account does not have a secret")
                            .details(vec![filter]));
                    }

                    result.account
                } else {
                    return Err(trc::AuthEvent::Failed
                        .into_err()
                        .details("Authentication filter yielded no results")
                        .details(vec![filter]));
                }
            }
        };

        if !account.groups.is_empty() {
            for name in std::mem::take(&mut account.groups)
                .into_iter()
                .filter(|name| name.contains('='))
            {
                let (rs, _res) = conn
                    .search(
                        &name,
                        Scope::Base,
                        "objectClass=*",
                        &self.mappings.attr_email,
                    )
                    .await
                    .map_err(|err| err.into_error().caused_by(trc::location!()))?
                    .success()
                    .map_err(|err| err.into_error().caused_by(trc::location!()))?;
                for entry in rs {
                    'outer: for (attr, value) in SearchEntry::construct(entry).attrs {
                        if self.mappings.attr_email.contains(&attr.to_lowercase())
                            && let Some(email) =
                                value.first().map(|s| s.as_str()).and_then(sanitize_email)
                        {
                            account.groups.push(email);
                            break 'outer;
                        }
                    }
                }
            }
        }

        Ok(account)
    }

    pub async fn recipient(&self, address: &str) -> trc::Result<Recipient> {
        let mut conn = self.pool.get().await.map_err(|err| err.into_error())?;
        let filter = self.mappings.filter_mailbox.build(address);
        if let Some(result) = self.find_object(&mut conn, &filter).await? {
            let mut account = result.account;

            if !account.groups.is_empty() {
                for name in std::mem::take(&mut account.groups)
                    .into_iter()
                    .filter(|name| name.contains('='))
                {
                    let (rs, _res) = conn
                        .search(
                            &name,
                            Scope::Base,
                            "objectClass=*",
                            &self.mappings.attr_email,
                        )
                        .await
                        .map_err(|err| err.into_error().caused_by(trc::location!()))?
                        .success()
                        .map_err(|err| err.into_error().caused_by(trc::location!()))?;
                    for entry in rs {
                        'outer: for (attr, value) in SearchEntry::construct(entry).attrs {
                            if self.mappings.attr_email.contains(&attr.to_lowercase())
                                && let Some(email) =
                                    value.first().map(|s| s.as_str()).and_then(sanitize_email)
                            {
                                account.groups.push(email);
                                break 'outer;
                            }
                        }
                    }
                }
            }
            if result.is_group {
                Ok(Recipient::Group(Group {
                    email: account.email,
                    email_aliases: account.email_aliases,
                    description: account.description,
                }))
            } else {
                Ok(Recipient::Account(account))
            }
        } else {
            trc::event!(
                Store(trc::StoreEvent::LdapWarning),
                Reason = "Mailbox filter yielded no results",
                Details = filter
            );
            Ok(Recipient::Invalid)
        }
    }
}

impl LdapDirectory {
    async fn find_object(&self, conn: &mut Ldap, filter: &str) -> trc::Result<Option<LdapResult>> {
        conn.search(
            &self.mappings.base_dn,
            Scope::Subtree,
            filter,
            &self.mappings.attrs_principal,
        )
        .await
        .map_err(|err| err.into_error().caused_by(trc::location!()))?
        .success()
        .map(|(rs, _)| {
            trc::event!(
                Store(trc::StoreEvent::LdapQuery),
                Details = filter.to_string(),
                Result = rs.first().map(result_to_trace).unwrap_or_default()
            );

            rs.into_iter()
                .next()
                .map(|entry| self.mappings.map_entry(SearchEntry::construct(entry)))
        })
        .map_err(|err| err.into_error().caused_by(trc::location!()))
    }
}

struct LdapResult {
    dn: String,
    account: Account,
    is_group: bool,
}

impl LdapMappings {
    fn map_entry(&self, entry: SearchEntry) -> LdapResult {
        let mut account = Account::default();
        let mut is_group = false;

        for (attr, value) in entry.attrs {
            let attr = attr.to_lowercase();
            if self.attr_email.contains(&attr) {
                account.email = value
                    .into_iter()
                    .filter_map(|v| sanitize_email(&v))
                    .next()
                    .unwrap_or_default();
            } else if self.attr_secret.contains(&attr) {
                account.secret = value.into_iter().next();
            } else if self.attr_secret_changed.contains(&attr) {
                // Create a disabled AppPassword, used to indicate that the password has been changed
                // but cannot be used for authentication.
                if account.secret.is_none() {
                    account.secret = value.into_iter().next().map(|item| {
                        format!("$app${}$", xxhash_rust::xxh3::xxh3_64(item.as_bytes()))
                    });
                }
            } else if self.attr_email_alias.contains(&attr) {
                for item in value.into_iter().filter_map(|v| sanitize_email(&v)) {
                    account.email_aliases.push(item);
                }
            } else if let Some(idx) = self.attr_description.iter().position(|a| a == &attr) {
                if (account.description.is_none() || idx == 0)
                    && let Some(desc) = value.into_iter().next()
                {
                    account.description = Some(desc);
                }
            } else if self.attr_groups.contains(&attr) {
                account.groups.extend(value);
            } else if self.attr_class.contains(&attr) {
                for value in value {
                    is_group |= value.eq_ignore_ascii_case(&self.group_class);
                }
            }
        }

        LdapResult {
            dn: entry.dn,
            account,
            is_group,
        }
    }
}

fn result_to_trace(rs: &ResultEntry) -> trc::Value {
    let se = SearchEntry::construct(rs.clone());
    se.attrs
        .into_iter()
        .map(|(k, v)| trc::Value::Array(vec![trc::Value::from(k), trc::Value::from(v.join(", "))]))
        .chain([trc::Value::from(se.dn)])
        .collect::<Vec<_>>()
        .into()
}
