/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Directories,
    backend::{ldap::LdapDirectory, oidc::OpenIdDirectory, sql::SqlDirectory},
};
use registry::schema::{
    prelude::Object,
    structs::{self, Authentication},
};
use std::{collections::HashMap, sync::Arc};
use store::registry::bootstrap::Bootstrap;

impl Directories {
    pub async fn build(bp: &mut Bootstrap) -> Self {
        let mut directories = HashMap::default();

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
                    directories.insert(id.id() as u32, Arc::new(directory));
                }
                Err(err) => {
                    bp.build_error(id, err);
                }
            }
        }

        let default_directory = match bp.setting_infallible::<Authentication>().await {
            Authentication::Internal => Ok(None),
            Authentication::Ldap(directory) => LdapDirectory::open(directory).map(Some),
            Authentication::Sql(directory) => SqlDirectory::open(directory, &bp.data_store)
                .await
                .map(Some),
            Authentication::Oidc(directory) => OpenIdDirectory::open(directory).map(Some),
        };

        Directories {
            default_directory: match default_directory {
                Ok(default_directory) => default_directory.map(Arc::new),
                Err(err) => {
                    bp.build_error(Object::Authentication.singleton(), err);
                    None
                }
            },
            directories,
        }
    }
}
