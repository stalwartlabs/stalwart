/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, ValidationResult};
use common::Server;
use jmap_proto::error::set::SetError;
use registry::schema::prelude::Property;

pub(crate) async fn validate_sieve_script(
    server: &Server,
    script: &str,
    old_script: Option<&str>,
    is_system_script: bool,
) -> ValidationResult {
    if old_script.is_none_or(|old_script| old_script != script) {
        if is_system_script {
            if let Err(err) = server
                .core
                .sieve
                .trusted_compiler
                .compile(script.as_bytes())
            {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(Property::Contents)
                    .with_description(format!(
                        "Failed to compile system Sieve script: {err}"
                    ))));
            }
        } else {
            if let Err(err) = server
                .core
                .sieve
                .untrusted_compiler
                .compile(script.as_bytes())
            {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(Property::Contents)
                    .with_description(format!(
                        "Failed to compile user Sieve script: {err}"
                    ))));
            }
        }
    }

    Ok(Ok(ObjectResponse::default()))
}
