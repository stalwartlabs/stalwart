/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use crate::backend::oidc::OpenIdDirectory;
use backend::{ldap::LdapDirectory, sql::SqlDirectory};
use deadpool::managed::PoolError;
use ldap3::LdapError;
use std::{collections::HashMap, fmt::Debug, sync::Arc};

pub mod backend;
pub mod core;

pub enum Credentials {
    Basic {
        username: String,
        secret: String,
    },
    Bearer {
        username: Option<String>,
        token: String,
    },
}

pub enum Directory {
    Ldap(LdapDirectory),
    Sql(SqlDirectory),
    OpenId(OpenIdDirectory),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    Account(Account),
    Group(Group),
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Account {
    pub email: String,
    pub email_aliases: Vec<String>,
    pub secret: Option<String>,
    pub groups: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Group {
    pub email: String,
    pub email_aliases: Vec<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Directories {
    pub default_directory: Option<Arc<Directory>>,
    pub directories: HashMap<u32, Arc<Directory>, nohash_hasher::BuildNoHashHasher<u32>>,
}

impl Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory").finish()
    }
}

trait IntoError {
    fn into_error(self) -> trc::Error;
}

impl IntoError for PoolError<LdapError> {
    fn into_error(self) -> trc::Error {
        match self {
            PoolError::Backend(error) => error.into_error(),
            PoolError::Timeout(_) => trc::StoreEvent::PoolError
                .into_err()
                .details("Connection timed out"),
            err => trc::StoreEvent::PoolError.reason(err),
        }
    }
}

impl IntoError for LdapError {
    fn into_error(self) -> trc::Error {
        if let LdapError::LdapResult { result } = &self {
            trc::StoreEvent::LdapError
                .ctx(trc::Key::Code, result.rc)
                .reason(self)
        } else {
            trc::StoreEvent::LdapError.reason(self)
        }
    }
}
