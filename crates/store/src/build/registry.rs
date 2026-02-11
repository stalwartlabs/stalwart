/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::RegistryStore;
use std::path::PathBuf;

impl RegistryStore {
    pub fn init(local: PathBuf) -> Self {
        let todo = "environment variables and reading from files";

        /*

                match std::fs::read_to_string(&cfg_local_path) {
            Ok(value) => {
                config.parse(&value).failed("Invalid local registry file");
            }
            Err(err) => {
                config.new_build_error("*", format!("Could not read registry file: {err}"));
            }
        }

         */

        todo!()
    }
}
