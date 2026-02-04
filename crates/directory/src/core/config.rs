/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Directories,
    backend::{ldap::LdapDirectory, oidc::OpenIdDirectory, sql::SqlDirectory},
};
use ahash::AHashMap;
use registry::schema::{
    prelude::Object,
    structs::{self, Authentication},
};
use std::sync::Arc;
use store::registry::bootstrap::Bootstrap;

impl Directories {
    pub async fn build(bp: &mut Bootstrap) -> Self {
        let mut directories = AHashMap::new();

        for directory in bp.list_infallible::<structs::Directory>().await {
            let id = directory.id;
            let result = match directory.object {
                structs::Directory::Ldap(directory) => LdapDirectory::open(directory),
                structs::Directory::Sql(directory) => {
                    SqlDirectory::open(directory, &bp.data_store).await
                }
                structs::Directory::Oidc(directory) => OpenIdDirectory::open(directory),
            };

            match result {
                Ok(directory) => {
                    directories.insert(id, Arc::new(directory));
                }
                Err(err) => {
                    bp.build_error(id, err);
                }
            }
        }

        let mut default_directory = None;
        let auth = bp.setting_infallible::<Authentication>().await;
        if let Some(id) = auth.directory_id {
            if let Some(directory) = directories.get(&id) {
                default_directory = Some(directory.clone());
            } else {
                bp.build_error(
                    Object::Authentication.singleton(),
                    format!("Default directory with id {} not found", id),
                );
            }
        }

        Directories {
            default_directory,
            directories,
        }
    }
}
