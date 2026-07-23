/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{LdapDirectory, LdapMappings};
use crate::{Account, Credentials, Group, IntoError, Recipient, core::secret::verify_secret_hash};
use ldap3::{Ldap, LdapConnAsync, ResultEntry, Scope, SearchEntry};
use store::xxhash_rust;
use utils::sanitize_email;

impl LdapDirectory {
    pub async fn authenticate(&self, credentials: &Credentials) -> trc::Result<Account> {
        let (username, secret) = match credentials {
            Credentials::Basic {
                username, secret, ..
            } => (username, secret),
            Credentials::Bearer { token, .. } => (token, token),
        };
        let mut conn = self.pool.get().await.map_err(|err| err.into_error())?;

        let mut result = if self.auth_bind {
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
                        result.account.email =
                            sanitize_email(username).unwrap_or_else(|| username.to_lowercase());
                    }
                    result
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
        } else {
            let filter = self.mappings.filter_login.build(username);
            if let Some(mut result) = self.find_object(&mut conn, &filter).await? {
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
                if result.account.email.is_empty() {
                    result.account.email =
                        sanitize_email(username).unwrap_or_else(|| username.to_lowercase());
                }
                result
            } else {
                return Err(trc::AuthEvent::Failed
                    .into_err()
                    .details("Authentication filter yielded no results")
                    .details(vec![filter]));
            }
        };

        self.add_group_membership(&mut conn, &mut result).await?;

        Ok(result.account)
    }

    pub async fn recipient(&self, address: &str) -> trc::Result<Recipient> {
        let mut conn = self.pool.get().await.map_err(|err| err.into_error())?;
        let filter = self.mappings.filter_mailbox.build(address);
        if let Some(mut result) = self.find_object(&mut conn, &filter).await? {
            if !result.is_group {
                self.add_group_membership(&mut conn, &mut result).await?;
                Ok(Recipient::Account(result.account))
            } else {
                Ok(Recipient::Group(Group {
                    email: result.account.email,
                    email_aliases: result.account.email_aliases,
                    description: result.account.description,
                }))
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

    async fn add_group_membership(
        &self,
        conn: &mut Ldap,
        result: &mut LdapResult,
    ) -> trc::Result<()> {
        if let Some(group_dns) = result.account.groups.take() {
            let mut groups = Vec::new();
            for name in group_dns.into_iter().filter(|name| name.contains('=')) {
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
                            groups.push(email);
                            break 'outer;
                        }
                    }
                }
            }
            result.account.groups = if groups.is_empty() {
                None
            } else {
                Some(groups)
            };
        } else if let Some(filter) = &self.mappings.filter_member_of {
            let filter = filter.build(&result.dn);
            let rs = conn
                .search(
                    &self.mappings.base_dn,
                    Scope::Subtree,
                    &filter,
                    &self.mappings.attr_email,
                )
                .await
                .map_err(|err| err.into_error().caused_by(trc::location!()))?
                .success()
                .map_err(|err| err.into_error().caused_by(trc::location!()))?
                .0;
            let had_entries = !rs.is_empty();
            let mut groups = Vec::new();
            for entry in rs {
                for (attr, value) in SearchEntry::construct(entry).attrs {
                    if self.mappings.attr_email.contains(&attr.to_lowercase()) {
                        groups.extend(value.into_iter().filter_map(|v| {
                            sanitize_email(&v).or_else(|| {
                                trc::event!(
                                    Store(trc::StoreEvent::LdapWarning),
                                    Reason = "Group entry missing valid email attribute",
                                    Details = v
                                );
                                None
                            })
                        }));
                    }
                }
            }
            result.account.groups = if had_entries && groups.is_empty() {
                None
            } else {
                Some(groups)
            };
        } else {
            result.account.groups = Some(Vec::new());
        }

        Ok(())
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
                account.groups.get_or_insert_default().extend(value);
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
