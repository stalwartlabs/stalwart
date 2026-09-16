/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use deadpool::managed::Pool;
use ldap3::{LdapConnSettings, ldap_escape};

pub mod config;
pub mod lookup;
pub mod pool;

pub struct LdapDirectory {
    pool: Pool<LdapConnectionManager>,
    mappings: LdapMappings,
    auth_bind: bool,
}

#[derive(Debug, Default)]
pub struct LdapMappings {
    base_dn: String,
    filter_login: LdapFilter,
    filter_mailbox: LdapFilter,
    filter_member_of: Option<LdapFilter>,
    attr_class: Vec<String>,
    attr_groups: Vec<String>,
    attr_description: Vec<String>,
    attr_secret: Vec<String>,
    attr_secret_changed: Vec<String>,
    attr_email: Vec<String>,
    attr_email_alias: Vec<String>,
    attrs_principal: Vec<String>,
    group_class: String,
}

#[derive(Debug, Default)]
pub(crate) struct LdapFilter {
    filter: Vec<LdapFilterItem>,
}

#[derive(Debug)]
enum LdapFilterItem {
    Static(String),
    Full,
    LocalPart,
    DomainPart,
}

impl LdapFilter {
    pub fn build(&self, value: &str) -> String {
        let mut result = String::with_capacity(value.len() + 16);

        for item in &self.filter {
            match item {
                LdapFilterItem::Static(s) => result.push_str(s),
                LdapFilterItem::Full => result.push_str(ldap_escape(value).as_ref()),
                LdapFilterItem::LocalPart => {
                    result.push_str(
                        ldap_escape(
                            value
                                .rsplit_once('@')
                                .map(|(local, _)| local)
                                .unwrap_or(value),
                        )
                        .as_ref(),
                    );
                }
                LdapFilterItem::DomainPart => {
                    if let Some((_, domain)) = value.rsplit_once('@') {
                        result.push_str(ldap_escape(domain).as_ref());
                    }
                }
            }
        }

        result
    }
}

pub(crate) struct LdapConnectionManager {
    address: String,
    settings: LdapConnSettings,
    bind_dn: Option<Bind>,
}

pub(crate) struct Bind {
    dn: String,
    password: String,
}

impl LdapConnectionManager {
    pub fn new(address: String, settings: LdapConnSettings, bind_dn: Option<Bind>) -> Self {
        Self {
            address,
            settings,
            bind_dn,
        }
    }
}

impl Bind {
    pub fn new(dn: String, password: String) -> Self {
        Self { dn, password }
    }
}

#[cfg(test)]
mod tests {
    use super::LdapFilter;

    #[test]
    fn filter_placeholders_are_escaped() {
        let filter = LdapFilter::new("(&(uid={local})(dc={domain})(mail=?))").unwrap();

        assert_eq!(
            filter.build("*)(uid=*@ex)(dc=*"),
            "(&(uid=\\2a\\29\\28uid=\\2a)(dc=ex\\29\\28dc=\\2a)(mail=\\2a\\29\\28uid=\\2a@ex\\29\\28dc=\\2a))"
        );
        assert_eq!(
            filter.build("john@example.com"),
            "(&(uid=john)(dc=example.com)(mail=john@example.com))"
        );
    }
}
