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
    prelude::ObjectType,
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
                structs::Directory::Ldap(directory) => LdapDirectory::open(directory).await,
                structs::Directory::Sql(directory) => {
                    SqlDirectory::open(directory, &bp.data_store).await
                }
                structs::Directory::Oidc(directory) => OpenIdDirectory::open(directory).await,
            };

            match result {
                Ok(directory) => {
                    directories.insert(id.id().id() as u32, Arc::new(directory));
                }
                Err(err) => {
                    bp.build_error(id, err);
                }
            }
        }

        let auth = bp.setting_infallible::<Authentication>().await;
        let default_directory = if let Some(directory_id) = auth.directory_id {
            match directories.get(&(directory_id.id() as u32)) {
                Some(default_directory) => default_directory.clone().into(),
                None => {
                    bp.build_error(
                        ObjectType::Authentication.singleton(),
                        format!("Default directory with ID {} not found", directory_id),
                    );
                    None
                }
            }
        } else {
            None
        };
        let bearer_directory = if let Some(directory_id) = auth.bearer_directory_id {
            match directories.get(&(directory_id.id() as u32)) {
                Some(bearer_directory) if bearer_directory.has_bearer_token_support() => {
                    bearer_directory.clone().into()
                }
                Some(_) => {
                    bp.build_error(
                        ObjectType::Authentication.singleton(),
                        format!(
                            "Bearer directory with ID {} does not support bearer tokens",
                            directory_id
                        ),
                    );
                    None
                }
                None => {
                    bp.build_error(
                        ObjectType::Authentication.singleton(),
                        format!("Bearer directory with ID {} not found", directory_id),
                    );
                    None
                }
            }
        } else {
            None
        };

        Directories {
            default_directory,
            bearer_directory,
            directories,
        }
    }
}
