/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ldap3::{Ldap, LdapConnAsync, ResultEntry, Scope, SearchEntry};
use mail_send::Credentials;
use store::xxhash_rust;
use trc::AddContext;

use crate::{
    IntoError, Principal, PrincipalData, QueryBy, ROLE_ADMIN, ROLE_USER, Type,
    backend::{
        RcptType,
        internal::{
            lookup::DirectoryStore,
            manage::{self, ManageDirectory, UpdatePrincipal},
        },
    },
};

use super::{LdapDirectory, LdapMappings};

impl LdapDirectory {
    pub async fn query(
        &self,
        by: QueryBy<'_>,
        return_member_of: bool,
    ) -> trc::Result<Option<Principal>> {
        let mut conn = self.pool.get().await.map_err(|err| err.into_error())?;

        let (mut external_principal, member_of, stored_principal) = match by {
            QueryBy::Name(username) => {
                if let Some((mut principal, member_of)) = self
                    .find_principal(&mut conn, &self.mappings.filter_name.build(username))
                    .await?
                {
                    principal.name = username.into();
                    (principal, member_of, None)
                } else {
                    return Ok(None);
                }
            }
            QueryBy::Id(uid) => {
                if let Some(stored_principal_) = self
                    .data_store
                    .query(QueryBy::Id(uid), return_member_of)
                    .await?
                {
                    if let Some((principal, member_of)) = self
                        .find_principal(
                            &mut conn,
                            &self.mappings.filter_name.build(stored_principal_.name()),
                        )
                        .await?
                    {
                        (principal, member_of, Some(stored_principal_))
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            }
            QueryBy::Credentials(credentials) => {
                let (username, secret) = match credentials {
                    Credentials::Plain { username, secret } => (username, secret),
                    Credentials::OAuthBearer { token } => (token, token),
                    Credentials::XOauth2 { username, secret } => (username, secret),
                };

                if let Some(auth_bind) = &self.auth_bind {
                    let (auth_bind_conn, mut ldap) = LdapConnAsync::with_settings(
                        self.pool.manager().settings.clone(),
                        &self.pool.manager().address,
                    )
                    .await
                    .map_err(|err| err.into_error().caused_by(trc::location!()))?;

                    ldap3::drive!(auth_bind_conn);

                    let dn = auth_bind.filter.build(username);

                    trc::event!(Store(trc::StoreEvent::LdapBind), Details = dn.clone());

                    if ldap
                        .simple_bind(&dn, secret)
                        .await
                        .map_err(|err| err.into_error().caused_by(trc::location!()))?
                        .success()
                        .is_err()
                    {
                        return Ok(None);
                    }

                    let filter = &self.mappings.filter_name.build(username);
                    let principal = if auth_bind.search {
                        self.find_principal(&mut ldap, filter).await
                    } else {
                        self.find_principal(&mut conn, filter).await
                    };
                    match principal {
                        Ok(Some((mut principal, member_of))) => {
                            principal.name = username.into();
                            (principal, member_of, None)
                        }
                        Err(err)
                            if err.matches(trc::EventType::Store(trc::StoreEvent::LdapError))
                                && err
                                    .value(trc::Key::Code)
                                    .and_then(|v| v.to_uint())
                                    .is_some_and(|rc| [49, 50].contains(&rc)) =>
                        {
                            return Ok(None);
                        }
                        Ok(None) => return Ok(None),
                        Err(err) => return Err(err),
                    }
                } else if let Some((mut principal, member_of)) = self
                    .find_principal(&mut conn, &self.mappings.filter_name.build(username))
                    .await?
                {
                    if principal.verify_secret(secret).await? {
                        principal.name = username.into();
                        (principal, member_of, None)
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            }
        };

        // Query groups
        if !member_of.is_empty() && return_member_of {
            let mut data = Vec::with_capacity(member_of.len());
            for mut name in member_of {
                if name.contains('=') {
                    let (rs, _res) = conn
                        .search(
                            &name,
                            Scope::Base,
                            "objectClass=*",
                            &self.mappings.attr_name,
                        )
                        .await
                        .map_err(|err| err.into_error().caused_by(trc::location!()))?
                        .success()
                        .map_err(|err| err.into_error().caused_by(trc::location!()))?;
                    for entry in rs {
                        'outer: for (attr, value) in SearchEntry::construct(entry).attrs {
                            if self.mappings.attr_name.contains(&attr) {
                                if let Some(group) = value.into_iter().next() {
                                    if !group.is_empty() {
                                        name = group;
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }
                }

                data.push(
                    self.data_store
                        .get_or_create_principal_id(&name, Type::Group)
                        .await
                        .caused_by(trc::location!())?,
                );
            }

            external_principal.data.push(PrincipalData::MemberOf(data));
        }

        // Obtain account ID if not available
        let mut principal = if let Some(stored_principal) = stored_principal {
            stored_principal
        } else {
            let id = self
                .data_store
                .get_or_create_principal_id(external_principal.name(), Type::Individual)
                .await
                .caused_by(trc::location!())?;

            self.data_store
                .query(QueryBy::Id(id), return_member_of)
                .await
                .caused_by(trc::location!())?
                .ok_or_else(|| manage::not_found(id).caused_by(trc::location!()))?
        };

        // Keep the internal store up to date with the LDAP server
        let changes = principal.update_external(external_principal);
        if !changes.is_empty() {
            self.data_store
                .update_principal(
                    UpdatePrincipal::by_id(principal.id)
                        .with_updates(changes)
                        .create_domains(),
                )
                .await
                .caused_by(trc::location!())?;
        }

        Ok(Some(principal))
    }

    pub async fn email_to_id(&self, address: &str) -> trc::Result<Option<u32>> {
        let filter = self.mappings.filter_email.build(address.as_ref());
        let rs = self
            .pool
            .get()
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &filter,
                &self.mappings.attr_name,
            )
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .success()
            .map(|(rs, _res)| rs)
            .map_err(|err| err.into_error().caused_by(trc::location!()))?;

        trc::event!(
            Store(trc::StoreEvent::LdapQuery),
            Details = filter,
            Result = rs.iter().map(result_to_trace).collect::<Vec<_>>()
        );

        for entry in rs {
            let entry = SearchEntry::construct(entry);
            for attr in &self.mappings.attr_name {
                if let Some(name) = entry.attrs.get(attr).and_then(|v| v.first()) {
                    if !name.is_empty() {
                        return self
                            .data_store
                            .get_or_create_principal_id(name, Type::Individual)
                            .await
                            .map(Some);
                    }
                }
            }
        }

        Ok(None)
    }

    pub async fn rcpt(&self, address: &str) -> trc::Result<RcptType> {
        let filter = self.mappings.filter_email.build(address.as_ref());
        let result = self
            .pool
            .get()
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &filter,
                &self.mappings.attr_email_address,
            )
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .next()
            .await
            .map(|entry| {
                let result = if entry.is_some() {
                    RcptType::Mailbox
                } else {
                    RcptType::Invalid
                };

                trc::event!(
                    Store(trc::StoreEvent::LdapQuery),
                    Details = filter,
                    Result = entry.as_ref().map(result_to_trace).unwrap_or_default()
                );

                result
            })
            .map_err(|err| err.into_error().caused_by(trc::location!()))?;

        if result != RcptType::Invalid {
            Ok(result)
        } else {
            self.data_store.rcpt(address).await.map(|result| {
                if matches!(result, RcptType::List(_)) {
                    result
                } else {
                    RcptType::Invalid
                }
            })
        }
    }

    pub async fn vrfy(&self, address: &str) -> trc::Result<Vec<String>> {
        self.data_store.vrfy(address).await
    }

    pub async fn expn(&self, address: &str) -> trc::Result<Vec<String>> {
        self.data_store.expn(address).await
    }

    pub async fn is_local_domain(&self, domain: &str) -> trc::Result<bool> {
        self.data_store.is_local_domain(domain).await
    }
}

impl LdapDirectory {
    async fn find_principal(
        &self,
        conn: &mut Ldap,
        filter: &str,
    ) -> trc::Result<Option<(Principal, Vec<String>)>> {
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

            rs.into_iter().next().map(|entry| {
                self.mappings
                    .entry_to_principal(SearchEntry::construct(entry))
            })
        })
        .map_err(|err| err.into_error().caused_by(trc::location!()))
    }
}

impl LdapMappings {
    fn entry_to_principal(&self, entry: SearchEntry) -> (Principal, Vec<String>) {
        let mut principal = Principal::new(0, Type::Individual);
        let mut role = ROLE_USER;
        let mut member_of = vec![];

        for (attr, value) in entry.attrs {
            if self.attr_name.contains(&attr) {
                if !self.attr_email_address.contains(&attr) {
                    principal.name = value.into_iter().next().unwrap_or_default();
                } else {
                    for (idx, item) in value.into_iter().enumerate() {
                        principal.emails.insert(0, item.to_lowercase());
                        if idx == 0 {
                            principal.name = item;
                        }
                    }
                }
            } else if self.attr_secret.contains(&attr) {
                for item in value {
                    principal.secrets.push(item);
                }
            } else if self.attr_secret_changed.contains(&attr) {
                // Create a disabled AppPassword, used to indicate that the password has been changed
                // but cannot be used for authentication.
                for item in value {
                    principal.secrets.push(format!(
                        "$app${}$",
                        xxhash_rust::xxh3::xxh3_64(item.as_bytes())
                    ));
                }
            } else if self.attr_email_address.contains(&attr) {
                for item in value {
                    principal.emails.insert(0, item.to_lowercase());
                }
            } else if self.attr_email_alias.contains(&attr) {
                for item in value {
                    principal.emails.push(item.to_lowercase());
                }
            } else if let Some(idx) = self.attr_description.iter().position(|a| a == &attr) {
                if principal.description.is_none() || idx == 0 {
                    principal.description = value.into_iter().next();
                }
            } else if self.attr_groups.contains(&attr) {
                member_of.extend(value);
            } else if self.attr_quota.contains(&attr) {
                if let Ok(quota) = value.into_iter().next().unwrap_or_default().parse::<u64>() {
                    principal.quota = quota.into();
                }
            } else if self.attr_type.contains(&attr) {
                for value in value {
                    match value.to_ascii_lowercase().as_str() {
                        "admin" | "administrator" | "root" | "superuser" => {
                            role = ROLE_ADMIN;
                            principal.typ = Type::Individual
                        }
                        "posixaccount" | "individual" | "person" | "inetorgperson" => {
                            principal.typ = Type::Individual
                        }
                        "posixgroup" | "groupofuniquenames" | "group" => {
                            principal.typ = Type::Group
                        }
                        _ => continue,
                    }
                    break;
                }
            }
        }

        principal.data.push(PrincipalData::Roles(vec![role]));
        (principal, member_of)
    }
}

fn result_to_trace(rs: &ResultEntry) -> trc::Value {
    SearchEntry::construct(rs.clone())
        .attrs
        .into_iter()
        .map(|(k, v)| trc::Value::Array(vec![trc::Value::from(k), trc::Value::from(v.join(", "))]))
        .collect::<Vec<_>>()
        .into()
}
