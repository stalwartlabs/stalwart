/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Bind, LdapConnectionManager, LdapDirectory, LdapFilter, LdapFilterItem, LdapMappings};
use crate::{Directory, backend::ldap::AuthBind};
use deadpool::{Runtime, managed::Pool};
use ldap3::LdapConnSettings;
use registry::schema::structs;

impl LdapDirectory {
    pub fn open(config: structs::LdapDirectory) -> Result<Directory, String> {
        let bind_dn = if let Some(dn) = config.bind_dn {
            Bind::new(
                dn,
                config.bind_secret.ok_or_else(|| {
                    "LDAP bind password is required when bind DN is set".to_string()
                })?,
            )
            .into()
        } else {
            None
        };

        let manager = LdapConnectionManager::new(
            config.url,
            LdapConnSettings::new()
                .set_conn_timeout(config.timeout.into_inner())
                .set_starttls(config.use_tls)
                .set_no_tls_verify(config.allow_invalid_certs),
            bind_dn,
        );

        let mut mappings = LdapMappings {
            base_dn: config.base_dn,
            filter_login: LdapFilter::new(&config.filter_login)?,
            filter_mailbox: LdapFilter::new(&config.filter_mailbox)?,
            attr_class: config.attr_class,
            attr_groups: config.attr_groups,
            attr_description: config.attr_description,
            attr_secret: config.attr_secret,
            attr_secret_changed: config.attr_secret_changed,
            attr_email: config.attr_email,
            attr_email_alias: config.attr_email_alias,
            group_class: config.group_class,
            attrs_principal: vec![],
        };

        for attr in [
            &mappings.attr_description,
            &mappings.attr_secret,
            &mappings.attr_secret_changed,
            &mappings.attr_groups,
            &mappings.attr_email_alias,
            &mappings.attr_email,
            &mappings.attr_class,
        ] {
            mappings
                .attrs_principal
                .extend(attr.iter().filter(|a| !a.is_empty()).cloned());
        }

        let auth_bind = match config.password_verification {
            structs::LdapPasswordVerification::Local => AuthBind::None,
            structs::LdapPasswordVerification::Bind(bind) => {
                if let Some(template) = bind.bind_auth_template {
                    AuthBind::BindTemplate {
                        template: LdapFilter::new(&template)?,
                        can_search: bind.bind_auth_search,
                    }
                } else {
                    AuthBind::Bind
                }
            }
        };

        let pool = Pool::builder(manager)
            .runtime(Runtime::Tokio1)
            .max_size(config.pool_max_connections as usize)
            .create_timeout(config.pool_timeout_create.into_inner().into())
            .wait_timeout(config.pool_timeout_wait.into_inner().into())
            .recycle_timeout(config.pool_timeout_recycle.into_inner().into())
            .build()
            .map_err(|err| format!("Failed to build LDAP pool: {err}"))?;

        Ok(Directory::Ldap(LdapDirectory {
            mappings,
            pool,
            auth_bind,
        }))
    }
}

impl LdapFilter {
    fn new(value: &str) -> Result<Self, String> {
        let mut filter = Vec::new();
        let mut token = String::new();
        let mut value = value.chars();

        while let Some(ch) = value.next() {
            match ch {
                '?' => {
                    // For backwards compatibility, we treat '?' as a placeholder for the full value.
                    if !token.is_empty() {
                        filter.push(LdapFilterItem::Static(token));
                        token = String::new();
                    }
                    filter.push(LdapFilterItem::Full);
                }
                '{' => {
                    if !token.is_empty() {
                        filter.push(LdapFilterItem::Static(token));
                        token = String::new();
                    }
                    for ch in value.by_ref() {
                        if ch == '}' {
                            break;
                        } else {
                            token.push(ch);
                        }
                    }
                    match token.as_str() {
                        "user" | "username" | "email" => filter.push(LdapFilterItem::Full),
                        "local" => filter.push(LdapFilterItem::LocalPart),
                        "domain" => filter.push(LdapFilterItem::DomainPart),
                        _ => {
                            return Err(format!("Unknown LDAP filter placeholder: {}", token));
                        }
                    }
                    token.clear();
                }
                _ => token.push(ch),
            }
        }

        if !token.is_empty() {
            filter.push(LdapFilterItem::Static(token));
        }

        if filter.len() >= 2 {
            Ok(LdapFilter { filter })
        } else {
            Err(format!(
                "Missing parameter placeholders in value {:?}",
                value
            ))
        }
    }
}
